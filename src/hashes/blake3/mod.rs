use std::collections::HashMap;

pub mod ed25519_challenge;
mod short;
pub mod utils;

use bitcoin::{
    hex::FromHex,
    opcodes::all::{OP_2DUP, OP_2OVER, OP_PICK, OP_SWAP},
    script::Instruction,
    ScriptBuf,
};
use bitcoin_script_stack::{optimizer, stack::StackTracker};
use itertools::Itertools;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::arithmetic::bigint::U256;
use crate::hashes::blake3::utils::{
    compress, get_flags_for_block, TablesVars, IV, MSG_PERMUTATION,
};
use crate::support::script::ScriptCompilation;

const SHORT_32_PHYSICAL_TO_SEMANTIC_WORD: [usize; 8] = [1, 4, 3, 7, 6, 2, 0, 5];
// Each entry maps a physical position within a word to its semantic nibble.
const SHORT_32_PHYSICAL_TO_SEMANTIC_DIGIT: [usize; 8] = [7, 0, 5, 6, 1, 2, 3, 4];

fn assert_valid_limb_len(limb_len: u8) {
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );
}

fn is_opcode(instruction: &Instruction<'_>, opcode: bitcoin::Opcode) -> bool {
    matches!(instruction, Instruction::Op(candidate) if *candidate == opcode)
}

fn is_small_integer(instruction: &Instruction<'_>, value: u8) -> bool {
    matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() == 0x50 + value)
}

fn optimize_stack_identities(script: ScriptBuf) -> ScriptBuf {
    let instructions = script
        .instructions_minimal()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    let mut optimized = ScriptBuf::new();
    let mut index = 0;
    while index < instructions.len() {
        if index + 3 < instructions.len()
            && is_small_integer(&instructions[index], 3)
            && is_opcode(&instructions[index + 1], OP_PICK)
            && is_small_integer(&instructions[index + 2], 3)
            && is_opcode(&instructions[index + 3], OP_PICK)
        {
            optimized.push_opcode(OP_2OVER);
            index += 4;
            continue;
        }
        if index + 2 < instructions.len()
            && is_opcode(&instructions[index], bitcoin::opcodes::all::OP_DUP)
            && is_small_integer(&instructions[index + 1], 2)
            && is_opcode(&instructions[index + 2], OP_PICK)
        {
            optimized.push_opcode(OP_2DUP);
            optimized.push_opcode(OP_SWAP);
            index += 3;
            continue;
        }
        optimized.push_instruction(instructions[index]);
        index += 1;
    }
    optimized
}

fn optimize_to_fixed_point(mut script: ScriptBuf) -> ScriptBuf {
    loop {
        let optimized = optimize_stack_identities(optimizer::optimize(script.clone()));
        if optimized == script {
            return optimized;
        }
        script = optimized;
    }
}

fn blake3(
    stack: &mut StackTracker,
    mut msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
    limb_len: u8,
) {
    assert_valid_limb_len(limb_len);

    if msg_len == 0 {
        let empty_msg_hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(empty_msg_hash).unwrap();
        let empty_msg_hash_nibbles = empty_msg_hash_bytearray
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f]);

        stack.custom(
            script!(for nibble in empty_msg_hash_nibbles {
                {
                    nibble
                }
            }),
            0,
            false,
            0,
            "push empty string hash in nibble form",
        );
        stack.define(8_u32 * 8, "blake3-hash");
        return;
    }

    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );
    let num_blocks = msg_len.div_ceil(64);
    let limb_count = 256u32.div_ceil(u32::from(limb_len));
    let sparse_short_block = num_blocks == 1 && msg_len <= 32;

    if define_var {
        for i in (0..num_blocks).rev() {
            stack.define(limb_count, &format!("msg{}p0", i));
            stack.define(limb_count, &format!("msg{}p1", i));
        }
    }

    for _ in 0..num_blocks {
        stack.to_altstack();
        stack.to_altstack();
    }

    stack.custom(
        script!(
            OP_DEPTH
            { 0 } OP_EQUALVERIFY
        ),
        0,
        false,
        0,
        "ensure that the stack is actually empty",
    );

    let tables = TablesVars::new(stack, use_full_tables);

    for _ in 0..num_blocks {
        stack.from_altstack();
        stack.from_altstack();
    }

    for i in 0..num_blocks {
        if i == num_blocks - 1 && msg_len <= 32 {
            stack.custom(
                script!(
                    for _ in 0..limb_count / 2 {
                        OP_2DROP
                    }
                    if limb_count % 2 == 1 {
                        OP_DROP
                    }

                    if !sparse_short_block {
                        // This half-block is outside the declared message.
                        // Avoid validating and unpacking ignored witness
                        // values, then synthesize the zero padding expected by
                        // the generic compression path.
                        OP_0 OP_DUP OP_2DUP
                        for _ in 0..20 {
                            OP_3DUP
                        }
                        for _ in 0..64 {
                            OP_TOALTSTACK
                        }
                    }
                ),
                1,
                false,
                0,
                &format!("replace ignored msg{}p1 with padding", i),
            );
        } else {
            stack.custom(
                script!(
                    {U256::verify_bigint_on_stack_with_limb_size(u32::from(limb_len))}
                    {U256::transform_limbsize(u32::from(limb_len), 4)}
                    for _ in 0..64{
                        OP_TOALTSTACK
                    }
                ),
                1,
                false,
                0,
                &format!("unpack msg{}p1", i),
            );
        }

        stack.custom(
            script!(
                {U256::verify_bigint_on_stack_with_limb_size(u32::from(limb_len))}
                {U256::transform_limbsize(u32::from(limb_len), 4)}
                if !sparse_short_block {
                    for _ in 0..64{
                        OP_FROMALTSTACK
                    }
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        if !sparse_short_block && i == (num_blocks - 1) && msg_len != 64 {
            let j = msg_len % 4;
            let pad_bytes = 64 + j - msg_len - 4;

            stack.custom(
                script!(
                    for _ in 0..pad_bytes {
                        OP_2DROP
                    }

                    for _ in 0..(j*2) {
                        OP_TOALTSTACK
                    }

                    for _ in 0..(4-j) {
                        OP_2DROP
                    }

                    for j in 0..(4-j) * 2 {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        }
                    }

                    for _ in 0..(j*2){
                        OP_FROMALTSTACK
                    }

                    for j in 0..(pad_bytes*2) {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        }
                    }
                ),
                0,
                false,
                0,
                "padding",
            );
        }

        if sparse_short_block {
            let message_word_count = msg_len.div_ceil(4);
            let partial_word_bytes = msg_len % 4;
            let unused_word_nibbles = (8 - message_word_count) * 8;
            let partial_word_nibbles = partial_word_bytes * 2;
            let partial_padding_nibbles = 8 - partial_word_nibbles;

            stack.custom(
                script! {
                    for _ in 0..unused_word_nibbles / 2 {
                        OP_2DROP
                    }

                    if partial_word_bytes != 0 {
                        for _ in 0..partial_word_nibbles {
                            OP_TOALTSTACK
                        }
                        for _ in 0..partial_padding_nibbles / 2 {
                            OP_2DROP
                        }
                        for _ in 0..partial_padding_nibbles {
                            OP_0
                        }
                        for _ in 0..partial_word_nibbles {
                            OP_FROMALTSTACK
                        }
                    }
                },
                0,
                false,
                0,
                "discard sparse short-block padding",
            );
        }

        let mut original_message = Vec::new();
        let message_word_count = if sparse_short_block {
            msg_len.div_ceil(4)
        } else {
            16
        };
        for i in 0..message_word_count {
            let m = stack.define(8, &format!("msg_{}", i));
            original_message.push(m);
        }

        let mut message = HashMap::new();
        for m in 0..message_word_count {
            message.insert(m as u8, original_message[m as usize]);
        }

        compress(
            stack,
            i != 0,
            0,
            msg_len.min(64),
            get_flags_for_block(i, num_blocks),
            message,
            &tables,
            8,
            i == num_blocks - 1,
        );

        for _ in 0..8 {
            stack.drop(stack.get_var_from_stack(0));
        }

        if msg_len > 64 {
            msg_len -= 64;
        }
    }
    tables.drop(stack);

    stack.from_altstack_joined(8_u32 * 8, "blake3-hash");
}

fn chunk_message(message_bytes: &[u8]) -> Vec<[u8; 64]> {
    let len = message_bytes.len();
    let needed_padding_bytes = if len % 64 == 0 { 0 } else { 64 - (len % 64) };

    message_bytes
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0u8, needed_padding_bytes))
        .chunks(4)
        .into_iter()
        .flat_map(|chunk| chunk.collect::<Vec<u8>>().into_iter().rev())
        .chunks(64)
        .into_iter()
        .map(|mut chunk| std::array::from_fn(|_| chunk.next().unwrap()))
        .collect()
}

fn pack_256_bits(bytes: &[u8], limb_len: u8) -> Vec<u32> {
    debug_assert_eq!(bytes.len(), 32);

    let limb_bits = u32::from(limb_len);
    let limb_mask = (1_u64 << limb_bits) - 1;
    let mut accumulator = 0_u64;
    let mut accumulator_bits = 0_u32;
    let mut limbs = Vec::with_capacity(256_usize.div_ceil(usize::from(limb_len)));

    for byte in bytes.iter().rev() {
        accumulator |= u64::from(*byte) << accumulator_bits;
        accumulator_bits += 8;

        while accumulator_bits >= limb_bits {
            limbs.push((accumulator & limb_mask) as u32);
            accumulator >>= limb_bits;
            accumulator_bits -= limb_bits;
        }
    }

    if accumulator_bits != 0 {
        limbs.push(accumulator as u32);
    }

    limbs.reverse();
    limbs
}

pub fn blake3_push_message_script_with_limb(message_bytes: &[u8], limb_len: u8) -> Script {
    assert!(
        message_bytes.len() <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    assert_valid_limb_len(limb_len);
    let chunks = chunk_message(message_bytes);
    let mut limbs = Vec::new();

    for chunk in chunks.into_iter().rev() {
        for half in chunk.chunks_exact(32) {
            limbs.extend(pack_256_bits(half, limb_len));
        }
    }

    script! {
        for limb in limbs {
            {limb}
        }
    }
}

const SUM_OF_FULL_TABLES: usize = 331;
const UNPACKED_BLOCK: usize = 128;
const MAX_BLAKE3_ELEMENT_COUNT: usize = SUM_OF_FULL_TABLES + UNPACKED_BLOCK + 132;

pub fn maximum_number_of_altstack_elements_using_blake3(message_len: usize, limb_len: u8) -> i32 {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    assert_valid_limb_len(limb_len);

    if message_len == 0 {
        return 1000 - 64;
    }

    let n = message_len.div_ceil(64);
    let limb_count = 256usize.div_ceil(limb_len as usize) * 2;
    let m = (n - 1) * limb_count;
    1000_i32 - MAX_BLAKE3_ELEMENT_COUNT as i32 - m as i32
}

pub fn blake3_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut stack = StackTracker::new();
    let use_full_tables = true;
    let message_len = message_len as u32;
    blake3(&mut stack, message_len, true, use_full_tables, limb_len);
    Script::new("optimized BLAKE3").push_script(optimize_to_fixed_point(
        stack.get_script().compile_with_policy(),
    ))
}

pub fn blake3_compute_script(message_len: usize) -> Script {
    blake3_compute_script_with_limb(message_len, 29)
}

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// BLAKE3 mode for the short witness-backed profile.
///
/// Every mode differs from unkeyed hashing only in the root compression's
/// input chaining value and one mode flag. Keys and contexts are fixed when
/// the script is generated, so no mode adds witness items or Script work
/// beyond different constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blake3Mode {
    /// Ordinary unkeyed BLAKE3.
    Hash,
    /// `keyed_hash` under a generation-time 32-byte key.
    KeyedHash([u8; 32]),
    /// The material phase of `derive_key`. Construct it with
    /// [`Blake3Mode::derive_key`], which runs the context phase on the host.
    DeriveKey { context_key: [u8; 32] },
}

impl Blake3Mode {
    /// Derive-key mode for a hardcoded context string of at most 1,024 bytes.
    ///
    /// BLAKE3 requires the context to be a compile-time constant, so the
    /// context phase is computed here and only the material phase is
    /// generated as Script.
    pub fn derive_key(context: &str) -> Self {
        let context_key = host_hash_single_chunk(&IV, context.as_bytes(), DERIVE_KEY_CONTEXT);
        Self::DeriveKey {
            context_key: words_to_le_bytes(&context_key[..8]),
        }
    }

    fn key_words(&self) -> [u32; 8] {
        match self {
            Self::Hash => IV,
            Self::KeyedHash(key) | Self::DeriveKey { context_key: key } => {
                std::array::from_fn(|index| {
                    u32::from_le_bytes(key[4 * index..4 * index + 4].try_into().unwrap())
                })
            }
        }
    }

    fn flags(&self) -> u32 {
        match self {
            Self::Hash => 0,
            Self::KeyedHash(_) => KEYED_HASH,
            Self::DeriveKey { .. } => DERIVE_KEY_MATERIAL,
        }
    }
}

fn words_to_le_bytes<const N: usize>(words: &[u32]) -> [u8; N] {
    let bytes = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.try_into().unwrap()
}

fn host_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// Host BLAKE3 compression returning all sixteen output words.
fn host_compress(cv: &[u32; 8], block: &[u8], block_len: u32, flags: u32) -> [u32; 16] {
    let mut padded = [0_u8; 64];
    padded[..block.len()].copy_from_slice(block);
    let mut message: [u32; 16] = std::array::from_fn(|index| {
        u32::from_le_bytes(padded[4 * index..4 * index + 4].try_into().unwrap())
    });
    let mut state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3], 0, 0,
        block_len, flags,
    ];
    for round in 0..7 {
        host_g(&mut state, 0, 4, 8, 12, message[0], message[1]);
        host_g(&mut state, 1, 5, 9, 13, message[2], message[3]);
        host_g(&mut state, 2, 6, 10, 14, message[4], message[5]);
        host_g(&mut state, 3, 7, 11, 15, message[6], message[7]);
        host_g(&mut state, 0, 5, 10, 15, message[8], message[9]);
        host_g(&mut state, 1, 6, 11, 12, message[10], message[11]);
        host_g(&mut state, 2, 7, 8, 13, message[12], message[13]);
        host_g(&mut state, 3, 4, 9, 14, message[14], message[15]);
        if round != 6 {
            message = std::array::from_fn(|index| message[MSG_PERMUTATION[index] as usize]);
        }
    }
    std::array::from_fn(|index| {
        if index < 8 {
            state[index] ^ state[index + 8]
        } else {
            state[index] ^ cv[index - 8]
        }
    })
}

/// Host single-chunk BLAKE3 returning the 64-byte root output block.
fn host_hash_single_chunk(key: &[u32; 8], input: &[u8], mode_flags: u32) -> [u32; 16] {
    assert!(
        input.len() <= 1024,
        "host BLAKE3 input must fit one 1,024-byte chunk"
    );
    let block_count = input.len().div_ceil(64).max(1);
    let mut cv = *key;
    for (index, block) in input
        .chunks(64)
        .chain(input.is_empty().then_some(&[][..]))
        .enumerate()
    {
        let mut flags = mode_flags;
        if index == 0 {
            flags |= CHUNK_START;
        }
        if index + 1 == block_count {
            return host_compress(&cv, block, block.len() as u32, flags | CHUNK_END | ROOT);
        }
        cv = host_compress(&cv, block, 64, flags)[..8]
            .try_into()
            .unwrap();
    }
    unreachable!("the final block returns")
}

/// Semantic `(word, digit)` of each direct-u4 witness item, deepest first.
/// Digit 0 is the most significant nibble of a little-endian message word, so
/// each word supplies its bytes in reverse order, high nibble first. At
/// exactly 32 bytes, words and digits are physically permuted.
fn blake3_short_layout(message_len: usize) -> Vec<(usize, usize)> {
    assert!(
        message_len <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );
    if message_len == 32 {
        return SHORT_32_PHYSICAL_TO_SEMANTIC_WORD
            .iter()
            .flat_map(|word| {
                SHORT_32_PHYSICAL_TO_SEMANTIC_DIGIT
                    .iter()
                    .map(move |digit| (*word, *digit))
            })
            .collect();
    }
    (0..message_len.div_ceil(4))
        .flat_map(|word| {
            let bytes = (message_len - 4 * word).min(4);
            (8 - 2 * bytes..8).map(move |digit| (word, digit))
        })
        .collect()
}

fn blake3_short_generated(
    message_len: usize,
    output_word_count: usize,
    mode: &Blake3Mode,
    extended_output: bool,
) -> short::Generated {
    assert!(
        (1..=32).contains(&message_len),
        "short BLAKE3 message length must be in the range [1, 32]"
    );
    let layout = blake3_short_layout(message_len);
    short::short_compute_script(&short::ShortSpec {
        message_len: message_len as u32,
        key: mode.key_words(),
        flags: CHUNK_START | CHUNK_END | ROOT | mode.flags(),
        output_words: output_word_count,
        extended_output,
        layout: &layout,
    })
}

fn blake3_short(
    message_len: usize,
    output_word_count: usize,
    mode: &Blake3Mode,
    extended_output: bool,
) -> ScriptBuf {
    blake3_short_generated(message_len, output_word_count, mode, extended_output).script
}

fn blake3_short_message_nibbles(message: &[u8]) -> Vec<u8> {
    blake3_short_layout(message.len())
        .into_iter()
        .map(|(word, digit)| {
            let mut bytes = [0_u8; 4];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = message.get(4 * word + index).copied().unwrap_or(0);
            }
            ((u32::from_le_bytes(bytes) >> (28 - 4 * digit)) & 0x0f) as u8
        })
        .collect()
}

/// Returns minimally encoded witness items for [`blake3_short_compute_script`].
///
/// Four-byte words use BLAKE3's little-endian byte order. At exactly 32 bytes,
/// words and their nibble registers are physically permuted; this helper
/// applies both permutations. The generator accepts any fixed layout, and the
/// permutation is kept for compatibility with existing witnesses.
pub fn blake3_short_message_witness(message: &[u8]) -> Vec<Vec<u8>> {
    blake3_short_message_nibbles(message)
        .into_iter()
        .map(|nibble| if nibble == 0 { vec![] } else { vec![nibble] })
        .collect()
}

/// Pushes a short message in the same routed nibble layout as
/// [`blake3_short_message_witness`].
pub fn blake3_push_short_message_script(message: &[u8]) -> Script {
    let nibbles = blake3_short_message_nibbles(message);

    script! {
        for nibble in nibbles {
            {nibble}
        }
    }
}

/// Computes unkeyed BLAKE3 for a witness-backed message of at most 32 bytes.
///
/// The input is two numeric nibble items per message byte in the layout emitted
/// by [`blake3_push_short_message_script`]. Every nibble is range-checked before
/// it can address lookup memory. The declared length is fixed in the generated
/// script, and the main stack must contain exactly those input items.
pub fn blake3_short_compute_script(message_len: usize) -> Script {
    if message_len == 0 {
        return blake3_compute_script(0);
    }
    assert!(
        message_len <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );

    Script::new("optimized short BLAKE3").push_script(blake3_short(
        message_len,
        8,
        &Blake3Mode::Hash,
        false,
    ))
}

/// Computes the first 128 bits of unkeyed BLAKE3 for a witness-backed message
/// of at most 32 bytes. The input contract matches
/// [`blake3_short_compute_script`], while the output contains only the first
/// four little-endian digest words (32 u4 items).
pub fn blake3_short_compute_script_truncated_128(message_len: usize) -> Script {
    if message_len == 0 {
        let empty = <[u8; 32]>::from_hex(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        .unwrap();
        let nibbles = empty[..16]
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .collect::<Vec<_>>();
        return Script::new("truncated empty BLAKE3").push_script(
            script! {
                OP_DEPTH 0 OP_EQUALVERIFY
                for nibble in nibbles {
                    { nibble }
                }
            }
            .compile_with_policy(),
        );
    }
    assert!(
        message_len <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );

    Script::new("optimized truncated short BLAKE3").push_script(blake3_short(
        message_len,
        4,
        &Blake3Mode::Hash,
        false,
    ))
}

/// Computes BLAKE3 in `mode` for a witness-backed message of at most 32
/// bytes, returning the first `output_len` bytes of its output stream.
///
/// `output_len` is 16, 32, or 64. A 64-byte output is the complete root
/// compression output, so it needs no additional compression: the second half
/// XORs the root's high state words with the generation-time chaining value.
/// The input contract matches [`blake3_short_compute_script`]; the output is
/// two u4 items per byte, first byte deepest. An empty message is checked to
/// have no input and returns the host-computed constant output.
pub fn blake3_short_mode_compute_script(
    message_len: usize,
    mode: Blake3Mode,
    output_len: usize,
) -> Script {
    assert!(
        message_len <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );
    let (output_word_count, extended_output) = match output_len {
        16 => (4, false),
        32 => (8, false),
        64 => (8, true),
        _ => panic!("short BLAKE3 output length must be 16, 32, or 64 bytes"),
    };

    if message_len == 0 {
        let output: [u8; 64] = words_to_le_bytes(&host_hash_single_chunk(
            &mode.key_words(),
            &[],
            mode.flags(),
        ));
        let nibbles = output[..output_len]
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .collect::<Vec<_>>();
        return Script::new("empty-message BLAKE3 output").push_script(
            script! {
                OP_DEPTH 0 OP_EQUALVERIFY
                for nibble in nibbles {
                    { nibble }
                }
            }
            .compile_with_policy(),
        );
    }

    Script::new("optimized short BLAKE3 mode").push_script(blake3_short(
        message_len,
        output_word_count,
        &mode,
        extended_output,
    ))
}

fn verify_output_bytes(expected_output: &[u8], name: &str) -> Script {
    let expected_nibbles = expected_output
        .into_iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .rev()
        .collect::<Vec<_>>();

    Script::new(name).push_script(
        script! {
            for (index, nibble) in expected_nibbles.iter().enumerate() {
                {*nibble}
                if index + 1 == expected_nibbles.len() {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        }
        .compile_with_policy(),
    )
}

pub fn blake3_verify_output_script(expected_output: [u8; 32]) -> Script {
    verify_output_bytes(&expected_output, "verify BLAKE3 output")
}

/// Verifies the 64-byte output of [`blake3_short_mode_compute_script`].
pub fn blake3_verify_extended_output_script(expected_output: [u8; 64]) -> Script {
    verify_output_bytes(&expected_output, "verify extended BLAKE3 output")
}

/// Verifies the first 128 bits returned by
/// [`blake3_short_compute_script_truncated_128`].
pub fn blake3_verify_output_prefix_script(expected_output: [u8; 16]) -> Script {
    verify_output_bytes(&expected_output, "verify truncated BLAKE3 output")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_raw_script_with_inputs_strict, execute_script,
        execute_script_buf_without_stack_limit, execute_script_with_inputs,
        execute_script_with_inputs_strict, ExecuteInfo,
    };
    use bitcoin::ScriptBuf;

    const USEFUL_LIMB_LENGTHS: [u8; 2] = [4, 29];

    fn final_stack(script: Script) -> (bool, Vec<Vec<u8>>) {
        let result = execute_script(script);
        let stack = (0..result.final_stack.len())
            .map(|index| result.final_stack.get(index))
            .collect();
        (result.success, stack)
    }

    #[test]
    fn stack_identity_peepholes_are_exact() {
        let values = [-1_i32, 0, 1, 17];
        for a in values {
            for b in values {
                for c in values {
                    for d in values {
                        let original = final_stack(script! {
                            { a } { b } { c } { d }
                            { 3 } OP_PICK { 3 } OP_PICK OP_TRUE
                        });
                        let replacement = final_stack(script! {
                            { a } { b } { c } { d }
                            OP_2OVER OP_TRUE
                        });
                        assert_eq!(original, replacement, "2OVER: {a} {b} {c} {d}");
                    }
                }
            }
        }
        for a in values {
            for b in values {
                let original = final_stack(script! {
                    { a } { b } OP_DUP { 2 } OP_PICK OP_TRUE
                });
                let replacement = final_stack(script! {
                    { a } { b } OP_2DUP OP_SWAP OP_TRUE
                });
                assert_eq!(original, replacement, "2DUP SWAP: {a} {b}");
            }
        }

        // Symbolically compare every shallow depth, including failure.
        let pick = |stack: &mut Vec<usize>, depth: usize| {
            let index = stack.len().checked_sub(depth + 1)?;
            stack.push(stack[index]);
            Some(())
        };
        for depth in 0..=8 {
            let mut original = (0..depth).collect::<Vec<_>>();
            let original = pick(&mut original, 3)
                .and_then(|()| pick(&mut original, 3))
                .map(|()| original);
            let mut replacement = (0..depth).collect::<Vec<_>>();
            let replacement = (depth >= 4).then(|| {
                replacement.extend([replacement[depth - 4], replacement[depth - 3]]);
                replacement
            });
            assert_eq!(original, replacement, "2OVER depth {depth}");

            let mut original = (0..depth).collect::<Vec<_>>();
            let original = original.last().copied().and_then(|top| {
                original.push(top);
                pick(&mut original, 2).map(|()| original)
            });
            let mut replacement = (0..depth).collect::<Vec<_>>();
            let replacement = (depth >= 2).then(|| {
                replacement.extend([replacement[depth - 1], replacement[depth - 2]]);
                replacement
            });
            assert_eq!(original, replacement, "2DUP SWAP depth {depth}");
        }

        let once = optimize_stack_identities(
            script! {
                { 3 } OP_PICK { 3 } OP_PICK
                OP_DUP { 2 } OP_PICK
            }
            .compile_with_policy(),
        );
        assert_eq!(
            once,
            script! { OP_2OVER OP_2DUP OP_SWAP }.compile_with_policy()
        );
        assert_eq!(optimize_stack_identities(once.clone()), once);

        let exact32 = blake3_short_compute_script(32).compile_with_policy();
        assert_eq!(optimize_to_fixed_point(exact32.clone()), exact32);
    }

    fn verify_blake_output_with_limbs(message: &[u8], expected_hash: [u8; 32], limb_lens: &[u8]) {
        for limb_len in limb_lens.iter().copied() {
            let mut bytes = blake3_push_message_script_with_limb(message, limb_len)
                .compile_with_policy()
                .to_bytes();
            bytes.extend(
                blake3_compute_script_with_limb(message.len(), limb_len)
                    .compile_with_policy()
                    .to_bytes(),
            );
            bytes.extend(
                blake3_verify_output_script(expected_hash)
                    .compile_with_policy()
                    .to_bytes(),
            );
            let script = ScriptBuf::from_bytes(bytes);
            assert!(execute_script_buf_without_stack_limit(script).success);
        }
    }

    fn verify_blake_outputs_cached_with_limbs<const LEN: usize>(
        messages: &[[u8; LEN]],
        expected_hashes: &[[u8; 32]],
        limb_lens: &[u8],
    ) {
        assert_eq!(messages.len(), expected_hashes.len());
        for limb_len in limb_lens.iter().copied() {
            let compute = blake3_compute_script_with_limb(LEN, limb_len).compile_with_policy();
            for (i, message) in messages.iter().enumerate() {
                let expected_hash = expected_hashes[i];
                let mut bytes = blake3_push_message_script_with_limb(message, limb_len)
                    .compile_with_policy()
                    .to_bytes();
                bytes.extend_from_slice(compute.as_bytes());
                bytes.extend(
                    blake3_verify_output_script(expected_hash)
                        .compile_with_policy()
                        .to_bytes(),
                );
                let script = ScriptBuf::from_bytes(bytes);
                assert!(execute_script_buf_without_stack_limit(script).success);
            }
        }
    }

    #[test]
    fn test_zero_length() {
        let message = [];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_short_direct_nibbles_all_lengths() {
        for message_len in 0..=32 {
            let message = (0..message_len)
                .map(|index| ((index * 73 + message_len * 19) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected_hash = *blake3::hash(&message).as_bytes();
            let compute = blake3_short_compute_script(message_len);
            let verify = blake3_verify_output_script(expected_hash);
            let result = execute_script(script! {
                { blake3_push_short_message_script(&message) }
                { compute.clone() }
                { verify.clone() }
            });
            assert!(result.success, "length {message_len}: {result}");
            assert!(
                result.stats.max_nb_stack_items <= 1000,
                "length {message_len} peaked at {} stack items",
                result.stats.max_nb_stack_items
            );

            let witness_result = execute_script_with_inputs(
                script! {
                    { compute }
                    { verify }
                },
                blake3_short_message_witness(&message),
            );
            assert!(
                witness_result.success,
                "witness length {message_len}: {witness_result}"
            );
        }
    }

    #[test]
    fn test_short_truncated_128_all_lengths() {
        for message_len in 0..=32 {
            let message = (0..message_len)
                .map(|index| ((index * 97 + message_len * 23) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected = *blake3::hash(&message).as_bytes();
            let result = execute_script(script! {
                { blake3_push_short_message_script(&message) }
                { blake3_short_compute_script_truncated_128(message_len) }
                { blake3_verify_output_prefix_script(expected[..16].try_into().unwrap()) }
            });
            assert!(result.success, "length {message_len}: {result}");
        }
    }

    #[test]
    fn test_short_truncated_128_rejects_malformed_inputs() {
        let compute = blake3_short_compute_script_truncated_128(1);
        for invalid_nibble in [-1, 16] {
            let result = execute_script(script! {
                { invalid_nibble } 0
                { compute.clone() }
            });
            assert!(!result.success, "accepted invalid nibble {invalid_nibble}");
        }

        let extra_input = execute_script(script! {
            0 0 0
            { compute }
        });
        assert!(!extra_input.success, "accepted an extra witness item");

        let extra_empty_input = execute_script(script! {
            0
            { blake3_short_compute_script_truncated_128(0) }
        });
        assert!(
            !extra_empty_input.success,
            "accepted input for an empty message"
        );
    }

    #[test]
    fn test_short_direct_nibbles_reject_malformed_inputs() {
        let compute = blake3_short_compute_script(1);
        for invalid_nibble in [-1, 16] {
            let result = execute_script(script! {
                { 0 }
                { invalid_nibble }
                { compute.clone() }
            });
            assert!(!result.success);
        }

        let too_few = execute_script(script! {
            { 0 }
            { compute.clone() }
        });
        assert!(!too_few.success);

        let extra = execute_script(script! {
            { 0 }
            { 0 }
            { 0 }
            { compute }
        });
        assert!(!extra.success);
    }

    const MODE_TEST_KEY: [u8; 32] = *b"whats the Elvish word for friend";
    const MODE_TEST_CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    fn reference_output(mode: &str, message: &[u8]) -> [u8; 64] {
        let mut hasher = match mode {
            "hash" => blake3::Hasher::new(),
            "keyed_hash" => blake3::Hasher::new_keyed(&MODE_TEST_KEY),
            "derive_key" => blake3::Hasher::new_derive_key(MODE_TEST_CONTEXT),
            _ => unreachable!(),
        };
        let mut output = [0; 64];
        hasher.update(message).finalize_xof().fill(&mut output);
        output
    }

    fn test_modes() -> [(&'static str, Blake3Mode); 3] {
        [
            ("hash", Blake3Mode::Hash),
            ("keyed_hash", Blake3Mode::KeyedHash(MODE_TEST_KEY)),
            ("derive_key", Blake3Mode::derive_key(MODE_TEST_CONTEXT)),
        ]
    }

    fn mode_output_matches(
        message: &[u8],
        mode: Blake3Mode,
        output_len: usize,
        expected: &[u8],
    ) -> ExecuteInfo {
        let compute = blake3_short_mode_compute_script(message.len(), mode, output_len);
        let verify = verify_output_bytes(&expected[..output_len], "verify mode output");
        execute_script_with_inputs_strict(
            script! {
                { compute }
                { verify }
            },
            blake3_short_message_witness(message),
        )
    }

    #[test]
    fn test_short_modes_match_official_extended_vectors() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestVectors {
            key: String,
            context_string: String,
            cases: Vec<TestVector>,
        }

        #[derive(Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
            keyed_hash: String,
            derive_key: String,
        }

        let vectors: TestVectors = serde_json::from_str(
            &std::fs::read_to_string("src/hashes/blake3/test_vectors.json").unwrap(),
        )
        .unwrap();
        assert_eq!(vectors.key.as_bytes(), MODE_TEST_KEY);
        assert_eq!(vectors.context_string, MODE_TEST_CONTEXT);

        let mut checked = 0;
        for case in vectors.cases.iter().filter(|case| case.input_len <= 32) {
            let message = (0..251_u8).cycle().take(case.input_len).collect::<Vec<_>>();
            for ((name, mode), expected) in
                test_modes()
                    .into_iter()
                    .zip([&case.hash, &case.keyed_hash, &case.derive_key])
            {
                let expected = <[u8; 64]>::from_hex(&expected[..128]).unwrap();
                let result = mode_output_matches(&message, mode, 64, &expected);
                assert!(result.success, "{name} length {}: {result}", case.input_len);
                checked += 1;
            }
        }
        assert_eq!(checked, 27, "official vectors cover lengths 0..=8");
    }

    /// Deterministic xorshift64 bytes for seeded random messages.
    fn seeded_message(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    fn execute_short(
        compute: &ScriptBuf,
        verify: &ScriptBuf,
        witness: Vec<Vec<u8>>,
    ) -> ExecuteInfo {
        let mut bytes = compute.to_bytes();
        bytes.extend(verify.as_bytes());
        execute_raw_script_with_inputs_strict(bytes, witness)
    }

    #[test]
    fn test_short_modes_match_reference_all_lengths_and_outputs() {
        for message_len in 0..=32 {
            let mut messages = vec![(0..message_len)
                .map(|index| ((index * 41 + message_len * 7) & 0xff) as u8)
                .collect::<Vec<_>>()];
            messages.extend(
                (0..4).map(|seed| seeded_message(seed * 33 + message_len as u64, message_len)),
            );
            messages.push(vec![0xff; message_len]);
            for (name, mode) in test_modes() {
                for output_len in [16, 32, 64] {
                    let compute = blake3_short_mode_compute_script(message_len, mode, output_len)
                        .compile_with_policy();
                    for message in &messages {
                        let expected = reference_output(name, message);
                        let verify = verify_output_bytes(&expected[..output_len], "verify")
                            .compile_with_policy();
                        let result =
                            execute_short(&compute, &verify, blake3_short_message_witness(message));
                        assert!(
                            result.success,
                            "{name} length {message_len} output {output_len} message {message:02x?}: {result}"
                        );
                        assert!(result.stats.max_nb_stack_items <= 1000);
                    }
                }
            }
        }
    }

    /// Every witness item is hostile. Out-of-range values, oversized numbers,
    /// missing or extra items and a wrong digest must make the script fail at
    /// every position. Non-minimal encodings of an in-range nibble fail under
    /// the interpreter's minimal-number rule (the default here); with that
    /// policy rule disabled they denote the same nibble and produce the same
    /// digest, so they cannot select a different message.
    #[test]
    fn test_short_rejects_malformed_witness_items_at_every_position() {
        use bitcoin_scriptexec::Options;

        let consensus_numbers = Options {
            require_minimal: false,
            ..Default::default()
        };
        for (message_len, mode, output_len) in [
            (1, Blake3Mode::Hash, 32),
            (7, Blake3Mode::Hash, 32),
            (31, Blake3Mode::Hash, 16),
            (32, Blake3Mode::Hash, 32),
            (32, Blake3Mode::KeyedHash(MODE_TEST_KEY), 64),
        ] {
            let name = match mode {
                Blake3Mode::Hash => "hash",
                _ => "keyed_hash",
            };
            let compute = blake3_short_mode_compute_script(message_len, mode, output_len)
                .compile_with_policy();
            let message = seeded_message(message_len as u64, message_len);
            let expected = reference_output(name, &message);
            let verify =
                verify_output_bytes(&expected[..output_len], "verify").compile_with_policy();
            let valid = blake3_short_message_witness(&message);
            assert!(execute_short(&compute, &verify, valid.clone()).success);

            let mut wrong = expected;
            wrong[output_len - 1] ^= 1;
            let wrong_verify =
                verify_output_bytes(&wrong[..output_len], "verify").compile_with_policy();
            assert!(!execute_short(&compute, &wrong_verify, valid.clone()).success);

            for position in 0..valid.len() {
                let nibble = valid[position].first().copied().unwrap_or(0);
                let mut out_of_range = vec![
                    vec![0x10],
                    vec![0x81],
                    vec![0x8f],
                    vec![0x00, 0x01],
                    vec![nibble, 0x01],
                    vec![nibble, 0, 0, 0, 0],
                ];
                if nibble != 0 {
                    out_of_range.push(vec![nibble | 0x80]);
                    out_of_range.push(vec![nibble, 0x80]);
                }
                for invalid in out_of_range {
                    let mut witness = valid.clone();
                    witness[position] = invalid.clone();
                    let result = execute_short(&compute, &verify, witness.clone());
                    assert!(
                        !result.success,
                        "{message_len} accepted {invalid:02x?} at {position}"
                    );
                    let mut bytes = compute.to_bytes();
                    bytes.extend(verify.as_bytes());
                    let result = crate::support::execution::execute_script_buf_with_options(
                        ScriptBuf::from_bytes(bytes),
                        witness,
                        consensus_numbers.clone(),
                    )
                    .unwrap();
                    assert!(
                        !result.success,
                        "{message_len} accepted {invalid:02x?} at {position} without minimal numbers"
                    );
                }
                let mut non_minimal_encodings = vec![vec![nibble, 0x00]];
                if nibble == 0 {
                    // Zero and negative zero.
                    non_minimal_encodings.extend([vec![0x00], vec![0x80]]);
                }
                for non_minimal in non_minimal_encodings {
                    let mut witness = valid.clone();
                    witness[position] = non_minimal.clone();
                    let result = execute_short(&compute, &verify, witness.clone());
                    assert!(!result.success, "accepted non-minimal {non_minimal:02x?}");
                    let mut bytes = compute.to_bytes();
                    bytes.extend(verify.as_bytes());
                    let result = crate::support::execution::execute_script_buf_with_options(
                        ScriptBuf::from_bytes(bytes),
                        witness,
                        consensus_numbers.clone(),
                    )
                    .unwrap();
                    assert!(
                        result.success,
                        "non-minimal {non_minimal:02x?} at {position} changed the digest"
                    );
                }
            }

            for witness in [
                valid[1..].to_vec(),
                valid[..valid.len() - 1].to_vec(),
                [valid.clone(), vec![vec![]]].concat(),
                [vec![vec![]], valid.clone()].concat(),
            ] {
                assert!(!execute_short(&compute, &verify, witness).success);
            }
        }
    }

    #[test]
    fn test_derive_key_contexts_match_reference() {
        let multi_block = (0..150).map(|index| (b'a' + index % 26) as char);
        for context in [String::new(), "ctx".into(), multi_block.collect()] {
            let mode = Blake3Mode::derive_key(&context);
            for message_len in [0, 1, 32] {
                let message = vec![0xa5; message_len];
                let mut expected = [0; 64];
                blake3::Hasher::new_derive_key(&context)
                    .update(&message)
                    .finalize_xof()
                    .fill(&mut expected);
                let result = mode_output_matches(&message, mode, 64, &expected);
                assert!(
                    result.success,
                    "context length {} message length {message_len}: {result}",
                    context.len()
                );
            }
        }
    }

    #[test]
    fn test_short_hash_mode_preserves_existing_scripts() {
        for message_len in [1, 8, 28, 29, 32] {
            assert_eq!(
                blake3_short_mode_compute_script(message_len, Blake3Mode::Hash, 32)
                    .compile_with_policy(),
                blake3_short_compute_script(message_len).compile_with_policy()
            );
            assert_eq!(
                blake3_short_mode_compute_script(message_len, Blake3Mode::Hash, 16)
                    .compile_with_policy(),
                blake3_short_compute_script_truncated_128(message_len).compile_with_policy()
            );
        }
    }

    #[test]
    fn test_short_modes_are_domain_separated() {
        let message = [0x5a; 32];
        let keyed = Blake3Mode::KeyedHash(MODE_TEST_KEY);
        let unkeyed = reference_output("hash", &message);
        let result = mode_output_matches(&message, keyed, 32, &unkeyed);
        assert!(!result.success, "keyed script accepted the unkeyed digest");

        let derive = Blake3Mode::derive_key(MODE_TEST_CONTEXT);
        let keyed_output = reference_output("keyed_hash", &message);
        let result = mode_output_matches(&message, derive, 32, &keyed_output);
        assert!(
            !result.success,
            "derive-key script accepted the keyed digest"
        );
    }

    #[test]
    fn test_short_modes_reject_malformed_inputs() {
        for (name, mode) in test_modes() {
            for message_len in [1, 32] {
                let compute = blake3_short_mode_compute_script(message_len, mode, 64);
                let valid = blake3_short_message_witness(&vec![0x11; message_len]);
                for (position, invalid) in [(0, vec![0x10]), (valid.len() - 1, vec![0x81])] {
                    let mut witness = valid.clone();
                    witness[position] = invalid;
                    let result = execute_script_with_inputs_strict(compute.clone(), witness);
                    assert!(!result.success, "{name} {message_len} accepted bad nibble");
                }

                let mut extra = valid.clone();
                extra.push(vec![]);
                let result = execute_script_with_inputs_strict(compute.clone(), extra);
                assert!(!result.success, "{name} {message_len} accepted extra item");

                let result = execute_script_with_inputs_strict(compute, valid[1..].to_vec());
                assert!(
                    !result.success,
                    "{name} {message_len} accepted missing item"
                );
            }

            let empty = blake3_short_mode_compute_script(0, mode, 64);
            let result = execute_script_with_inputs_strict(empty, vec![vec![]]);
            assert!(!result.success, "{name} empty message accepted input");
        }
    }

    /// The generator's stack model is exact: the executed peak of each
    /// fragment followed by its verifier equals the modelled peak.
    #[test]
    fn test_short_modelled_peak_matches_execution() {
        for (message_len, output_words, extended) in [
            (1, 8, false),
            (13, 4, false),
            (32, 8, false),
            (32, 4, false),
            (32, 8, true),
        ] {
            let mode = Blake3Mode::Hash;
            let output_len = output_words * 4 * if extended { 2 } else { 1 };
            let message = seeded_message(7, message_len);
            let expected = reference_output("hash", &message);
            let compute = blake3_short_mode_compute_script(message_len, mode, output_len)
                .compile_with_policy();
            let verify =
                verify_output_bytes(&expected[..output_len], "verify").compile_with_policy();
            let result = execute_short(&compute, &verify, blake3_short_message_witness(&message));
            assert!(result.success, "{result}");
            assert_eq!(
                result.stats.max_nb_stack_items,
                blake3_short_generated(message_len, output_words, &mode, extended).peak,
                "length {message_len} output {output_len}"
            );
        }
    }

    /// Lifecycle split of the 32-byte compute fragments recorded in the
    /// catalog: table setup and the final cleanup that drops the tables and
    /// leftover state below the outputs.
    #[test]
    fn test_short_32_table_lifecycle_bytes() {
        for (output_words, extended, setup, cleanup, script) in
            [(8, false, 362, 183, 43930), (4, false, 362, 199, 43466)]
        {
            let generated = blake3_short_generated(32, output_words, &Blake3Mode::Hash, extended);
            assert_eq!(
                (
                    generated.setup_bytes,
                    generated.cleanup_bytes,
                    generated.script.len()
                ),
                (setup, cleanup, script)
            );
        }
    }

    #[test]
    #[should_panic(expected = "output length must be 16, 32, or 64 bytes")]
    fn test_short_modes_reject_unsupported_output_length() {
        blake3_short_mode_compute_script(32, Blake3Mode::Hash, 48);
    }

    #[test]
    #[should_panic(expected = "host BLAKE3 input must fit one 1,024-byte chunk")]
    fn test_derive_key_rejects_multi_chunk_context() {
        Blake3Mode::derive_key(&"c".repeat(1025));
    }

    #[test]
    #[should_panic(expected = "short BLAKE3 messages must be at most 32 bytes")]
    fn test_short_direct_nibbles_reject_long_messages() {
        blake3_short_compute_script(33);
    }

    #[test]
    fn test_max_length() {
        let message = [0x00; 1024];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    #[should_panic(
        expected = "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    )]
    fn test_too_long() {
        let message = [0x00; 1025];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_single_byte() {
        let messages: Vec<[u8; 1]> = (0..=255).map(|byte| [byte]).collect();
        let expected_hashes: Vec<[u8; 32]> = messages
            .iter()
            .map(|message| *blake3::hash(message).as_bytes())
            .collect();
        verify_blake_outputs_cached_with_limbs(&messages, &expected_hashes, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_full_block_and_31_bit_limbs() {
        let message: [u8; 64] = std::array::from_fn(|index| index as u8);
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &[4, 29, 31]);
    }

    #[test]
    fn test_half_and_full_block_boundaries() {
        for message_len in [31, 32, 33, 63, 64, 65] {
            let message = (0..251_u8).cycle().take(message_len).collect::<Vec<_>>();
            let expected_hash = *blake3::hash(&message).as_bytes();
            verify_blake_output_with_limbs(&message, expected_hash, &[29]);
        }
    }

    #[test]
    fn test_compute_script_is_optimizer_fixed_point() {
        for message_len in [64, 1024] {
            let script = blake3_compute_script_with_limb(message_len, 29).compile_with_policy();
            assert_eq!(optimize_to_fixed_point(script.clone()), script);
        }

        let short = blake3_short_compute_script(32).compile_with_policy();
        assert_eq!(optimize_to_fixed_point(short.clone()), short);
    }

    #[test]
    #[should_panic(expected = "limb length must be in the range [4, 32)")]
    fn test_invalid_limb_length_for_empty_message() {
        blake3_compute_script_with_limb(0, 3);
    }

    fn test_official_test_vectors_with_limbs(limb_lens: &[u8]) {
        use serde::Deserialize;
        use std::fs::File;
        use std::io::BufReader;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestVector>,
        }

        #[derive(Debug, Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors() -> Vec<(Vec<u8>, [u8; 32])> {
            let path = "src/hashes/blake3/test_vectors.json";
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);
            let test_vectors: TestVectors = serde_json::from_reader(reader).unwrap();
            test_vectors
                .cases
                .iter()
                .filter(|vector| vector.input_len <= 1024)
                .map(|vector| {
                    let message = (0..251u8).cycle().take(vector.input_len).collect();
                    let expected_hash = <[u8; 32]>::from_hex(&vector.hash[0..64]).unwrap();
                    (message, expected_hash)
                })
                .collect()
        }

        let test_vectors = read_test_vectors();
        for (message, expected_hash) in test_vectors {
            verify_blake_output_with_limbs(&message, expected_hash, limb_lens);
        }
    }

    #[test]
    fn test_official_test_vectors() {
        test_official_test_vectors_with_limbs(&USEFUL_LIMB_LENGTHS)
    }

    // Fragment-only tapscript resource probe with the stack limit enforced.
    // All message and padding items coexist in the witness at entry, with zero
    // auxiliary hints. Staging and hashing are
    // compiled together; the 64 digest nibbles and padding remain observable.
    // A complete-leaf cleanup would let the optimizer remove the empty hash's
    // constant output and invalidate the stack-bound measurement.
    fn test_blake3_stack_space(
        blake3_script: Script,
        message_len: usize,
        limb_len: u8,
        extra_elements: i32,
    ) -> crate::support::execution::ExecuteInfo {
        assert!(extra_elements >= 0);
        let message = vec![0u8; message_len];
        let mut witness = Vec::new();
        for chunk in chunk_message(&message).into_iter().rev() {
            for half in chunk.chunks_exact(32) {
                for limb in pack_256_bits(half, limb_len) {
                    let mut encoded = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut encoded, i64::from(limb));
                    witness.push(encoded[..len].to_vec());
                }
            }
        }
        witness.extend((0..extra_elements).map(|_| vec![0x81]));
        let data_items = witness.len();
        let witness_bytes =
            bitcoin::consensus::serialize(&bitcoin::Witness::from_slice(&witness)).len();
        let compiled = script! {
            for _ in 0..extra_elements { OP_TOALTSTACK }
            { blake3_script }
        }
        .compile_with_policy();
        let script_bytes = compiled.len();
        let compilation = if script_bytes > crate::support::script::MAX_OPTIMIZER_INPUT_BYTES {
            "unoptimized"
        } else {
            "optimized"
        };
        let result = crate::support::execution::execute_raw_script_with_inputs_strict(
            compiled.to_bytes(),
            witness,
        );
        println!(
            "BLAKE3_RESOURCE message_bytes={message_len} limb_bits={limb_len} message_items={} padding_items={extra_elements} data_items={data_items} hint_items=0 witness_bytes={witness_bytes} script_bytes={script_bytes} compilation={compilation} combined_peak={} context=tapscript stack_limit_enforced={} deployment=unclassified error={:?}",
            data_items - extra_elements as usize, result.stats.max_nb_stack_items,
            result.stack_limit_enforced, result.error,
        );
        result
    }

    fn test_maximum_alstack_element_calculation_with_limbs(limb_lens: &[u8]) {
        use bitcoin_scriptexec::ExecError;
        for limb_len in limb_lens.iter().copied() {
            for message_len in std::iter::once(0).chain((64..=1024).step_by(64)) {
                let blake3_script = blake3_compute_script_with_limb(message_len, limb_len);
                let maximum_extra_elements =
                    maximum_number_of_altstack_elements_using_blake3(message_len, limb_len);
                if maximum_extra_elements < 0 {
                    let result = test_blake3_stack_space(blake3_script, message_len, limb_len, 0);
                    assert_eq!(
                        result.error,
                        Some(ExecError::StackSize),
                        "limb {limb_len}, message {message_len}, no padding"
                    );
                } else {
                    let result = test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        maximum_extra_elements,
                    );
                    assert!(result.stack_limit_enforced);
                    assert_eq!(
                        result.error, None,
                        "limb {limb_len}, message {message_len}, padding {maximum_extra_elements}"
                    );
                    // Hashing is a fragment with 64 outputs, so complete-leaf
                    // clean-stack success is deliberately false.
                    assert!(!result.success);
                    let expected = blake3::hash(&vec![0u8; message_len])
                        .as_bytes()
                        .iter()
                        .flat_map(|byte| [byte >> 4, byte & 0x0f])
                        .map(|nibble| if nibble == 0 { vec![] } else { vec![nibble] })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        result.final_stack.0.iter_str().collect::<Vec<_>>(),
                        expected,
                        "limb {limb_len}, message {message_len}: digest nibbles"
                    );
                    assert_eq!(
                        result.stats.max_nb_stack_items, 1000,
                        "limb {limb_len}, message {message_len}: capacity must be tight"
                    );
                    let overflow = test_blake3_stack_space(
                        blake3_script,
                        message_len,
                        limb_len,
                        maximum_extra_elements + 1,
                    );
                    assert_eq!(overflow.error, Some(ExecError::StackSize),
                        "limb {limb_len}, message {message_len}, capacity {maximum_extra_elements}: valid peak {}, next peak {}",
                        result.stats.max_nb_stack_items, overflow.stats.max_nb_stack_items);
                }
            }
        }
    }

    #[test]
    fn test_maximum_alstack_element_calculation() {
        test_maximum_alstack_element_calculation_with_limbs(&USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_failure_on_invalid_input() {
        let zero = script! {
            {0} {0} {0} {0} {0} {0} {0} {0} {0}
        };
        let fake_zero = script! {
            {0} {0} {0} {0} {0} {0} {0} {0} {-1}
        };
        let res = execute_script(script! {
            {zero.clone()} {zero.clone()} {blake3_compute_script(64)}
            for _ in 0..64 {
                OP_TOALTSTACK
            }
            {zero.clone()} {fake_zero.clone()} {blake3_compute_script(64)}
        });
        assert_eq!(res.success, false);
        assert_eq!(res.last_opcode, Some(bitcoin::opcodes::all::OP_VERIFY));
    }

    #[test]
    fn test_failure_on_oversized_input_limb() {
        let valid = script! {
            for _ in 0..9 {
                {0}
            }
        };
        let oversized_regular_limb = script! {
            for _ in 0..8 {
                {0}
            }
            {1 << 29}
        };
        let oversized_head_limb = script! {
            {1 << 24}
            for _ in 0..8 {
                {0}
            }
        };

        for invalid in [oversized_regular_limb, oversized_head_limb] {
            let result = execute_script(script! {
                {valid.clone()}
                {invalid}
                {blake3_compute_script(64)}
            });
            assert!(!result.success);
            assert_eq!(result.last_opcode, Some(bitcoin::opcodes::all::OP_VERIFY));
        }
    }

    #[test]
    fn test_ignored_final_half_block_is_not_validated() {
        let valid_message_half = script! {
            for _ in 0..9 {
                {0}
            }
        };
        let ignored_invalid_half = script! {
            for _ in 0..9 {
                {-1}
            }
        };
        let expected_hash = *blake3::hash(&[0]).as_bytes();

        let result = execute_script(script! {
            {valid_message_half}
            {ignored_invalid_half}
            {blake3_compute_script(1)}
            {blake3_verify_output_script(expected_hash)}
        });
        assert!(result.success);
    }
}
