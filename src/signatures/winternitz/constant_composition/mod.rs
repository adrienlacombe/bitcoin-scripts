//! Reversible 160-bit messages encoded as fixed-composition Winternitz assignments.
use super::{ChainHash, Hash160, Preimage16, PreimageSize};
use crate::support::script::{script, Script};
use bitcoin::Witness;
use core::{fmt, marker::PhantomData};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use std::sync::OnceLock;

const COMPOSITION: [u8; 25] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 14,
];
const RADIX: usize = COMPOSITION.len();
const MAX_DIGIT: usize = RADIX - 1;
const fn chain_count() -> usize {
    let mut total = 0;
    let mut i = 0;
    while i < RADIX {
        total += COMPOSITION[i] as usize;
        i += 1;
    }
    total
}
const CHAINS: usize = chain_count();
const OPENINGS: usize = CHAINS - COMPOSITION[MAX_DIGIT] as usize;
const DOMAIN: &[u8] = b"bitcoin-lab/winternitz20-constant-composition/v1";

#[derive(Clone, Copy)]
enum SelectorMode {
    Clamp,
    Bounded,
    Isolated,
}

/// A terminal Winternitz verifier for an unchanged, reversibly encoded 20-byte message.
///
/// Each key is assigned one digit in a fixed-composition code. The witness
/// presents openings in ascending digit order, so each slot's hash count is
/// known at script construction. A selector removes its public key from a
/// trusted stack pool, ensuring that no key can fill two slots. The remaining
/// keys belong to the maximum digit and require no opening or selector.
///
/// Pool selectors are upper-clamped to the last remaining key. These aliases
/// preserve the selected key and assignment; negative selectors and ScriptNum
/// encodings longer than four bytes fail. The bounded variant explicitly rejects upper aliases. Raw opening
/// widths are relaxed: every supplied node is hashed at least once.
///
/// The composable fragments preserve unrelated main/altstack state. The smaller
/// isolated fragment requires the signature to occupy the entire main stack.
/// All variants leave no result; the surrounding protocol must supply its terminal predicate.
/// As with every Winternitz key, its seed must never sign a second message.
#[derive(Debug)]
pub struct ConstantCompositionWinternitz20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16>(
    PhantomData<(H, P)>,
);

/// Consumed by signing. Do not restore its seed after signing a message.
pub struct ConstantCompositionSigningKey20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16>
{
    seed: [u8; 32],
    marker: PhantomData<(H, P)>,
}
impl<H: ChainHash, P: PreimageSize<H>> ConstantCompositionSigningKey20<H, P> {
    /// Borrows the secret seed for sensitive durable storage.
    pub fn expose_seed(&self) -> &[u8; 32] {
        &self.seed
    }
}
impl<H: ChainHash, P: PreimageSize<H>> fmt::Debug for ConstantCompositionSigningKey20<H, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConstantCompositionSigningKey20([redacted])")
    }
}

/// Independent endpoint commitments in original key-index order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantCompositionPublicKey20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16> {
    commitments: [H::Commitment; CHAINS],
    marker: PhantomData<P>,
}
impl<H: ChainHash, P: PreimageSize<H>> ConstantCompositionPublicKey20<H, P> {
    /// Restores the endpoints for this exact hash, preimage mode, and codebook.
    pub fn from_commitments(commitments: [H::Commitment; CHAINS]) -> Self {
        Self {
            commitments,
            marker: PhantomData,
        }
    }
    pub fn commitments(&self) -> &[H::Commitment; CHAINS] {
        &self.commitments
    }
}

/// Key-indexed digits and nodes. Maximum-digit assignments need no opening
/// because their endpoint commitments are already embedded in Script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantCompositionSignature20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16> {
    nodes: [P::Value; CHAINS],
    digits: [u8; CHAINS],
    marker: PhantomData<H>,
}
impl<H: ChainHash, P: PreimageSize<H>> ConstantCompositionSignature20<H, P> {
    /// The full assignment in original key-index order, not witness-slot order.
    pub fn digits(&self) -> &[u8; CHAINS] {
        &self.digits
    }
    pub fn chain_values(&self) -> &[P::Value; CHAINS] {
        &self.nodes
    }
    /// Serializes forward `[selector, node]` chunks in ascending digit order.
    /// The verifier stages these items on the altstack before creating its key pool. Within a digit group, key indices ascend.
    /// Each selector is the chosen key's zero-based position among the remaining
    /// keys in ascending original-index order. Maximum-digit keys are implicit.
    ///
    /// There are exactly `2 * OPENINGS` signature data items and zero auxiliary
    /// hints. Every item coexists at script entry. Selectors use minimal ScriptNum.
    pub fn to_witness(&self) -> Witness {
        let mut remaining: Vec<_> = (0..CHAINS).collect();
        let mut chunks = Vec::with_capacity(OPENINGS);
        for digit in 0..MAX_DIGIT {
            for i in 0..CHAINS {
                if self.digits[i] as usize == digit {
                    let selector = remaining.iter().position(|&key| key == i).unwrap();
                    remaining.remove(selector);
                    chunks.push((self.nodes[i].as_ref().to_vec(), integer(selector)));
                }
            }
        }
        debug_assert_eq!(chunks.len(), OPENINGS);
        debug_assert_eq!(remaining.len(), COMPOSITION[MAX_DIGIT] as usize);
        let mut witness = Witness::new();
        for (node, selector) in chunks {
            witness.push(selector);
            witness.push(node);
        }
        witness
    }
}

/// Wrong count, invalid composition, or an assignment outside the 160-bit encoder image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidConstantCompositionEncoding;
impl fmt::Display for InvalidConstantCompositionEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid constant-composition 20-byte message encoding")
    }
}
impl std::error::Error for InvalidConstantCompositionEncoding {}

impl<H: ChainHash, P: PreimageSize<H>> ConstantCompositionWinternitz20<H, P> {
    pub const MESSAGE_BYTES: usize = 20;
    pub const RADIX: usize = RADIX;
    pub const MAX_DIGIT: usize = MAX_DIGIT;
    pub const COMPOSITION: [u8; RADIX] = COMPOSITION;
    pub const CHAINS: usize = CHAINS;
    pub const TOTAL_DIGITS: usize = CHAINS;
    pub const OPENINGS: usize = OPENINGS;
    pub const WITNESS_DATA_ITEMS: usize = 2 * OPENINGS;
    pub const HASH_BYTES: usize = H::VALUE_BYTES;
    pub const COMMITMENT_BYTES: usize = H::COMMITMENT_BYTES;
    pub const PREIMAGE_BYTES: usize = P::START_BYTES;

    pub fn signing_key_from_seed(seed: [u8; 32]) -> ConstantCompositionSigningKey20<H, P> {
        ConstantCompositionSigningKey20 {
            seed,
            marker: PhantomData,
        }
    }
    pub fn generate_signing_key() -> ConstantCompositionSigningKey20<H, P> {
        let mut seed = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::signing_key_from_seed(seed)
    }
    pub fn public_key(
        key: &ConstantCompositionSigningKey20<H, P>,
    ) -> ConstantCompositionPublicKey20<H, P> {
        let namespace = namespace::<H, P>(&key.seed);
        ConstantCompositionPublicKey20::from_commitments(core::array::from_fn(|i| {
            let start = chain_start::<H, P>(&namespace, i);
            H::commit(chain_hash::<H>(start.as_ref(), MAX_DIGIT))
        }))
    }
    /// Signs exactly these 20 bytes with a reversible code; performs no message search.
    pub fn sign(
        key: ConstantCompositionSigningKey20<H, P>,
        message: &[u8; 20],
    ) -> ConstantCompositionSignature20<H, P> {
        let namespace = namespace::<H, P>(&key.seed);
        let digits = Self::encode_message(message);
        let nodes = core::array::from_fn(|i| {
            let start = chain_start::<H, P>(&namespace, i);
            if digits[i] == 0 {
                start
            } else {
                P::from_hash(chain_hash::<H>(start.as_ref(), digits[i] as usize))
            }
        });
        ConstantCompositionSignature20 {
            nodes,
            digits,
            marker: PhantomData,
        }
    }
    pub fn encode_message(message: &[u8; 20]) -> [u8; CHAINS] {
        unrank(BigUint::from_bytes_be(message))
    }
    pub fn decode_message(digits: &[u8]) -> Result<[u8; 20], InvalidConstantCompositionEncoding> {
        let rank = rank(digits)?;
        if rank >= (BigUint::one() << 160usize) {
            return Err(InvalidConstantCompositionEncoding);
        }
        let bytes = rank.to_bytes_be();
        let mut message = [0; 20];
        message[20 - bytes.len()..].copy_from_slice(&bytes);
        Ok(message)
    }
    /// Exact multinomial code size, at least 2^160.
    pub fn codeword_count() -> BigUint {
        codeword_count().clone()
    }
    /// Consumes the signature, upper-clamping each pool selector before removing
    /// a trusted key. Leaves no result and preserves unrelated stack state.
    pub fn checksig_verify_and_clear(public_key: &ConstantCompositionPublicKey20<H, P>) -> Script {
        Self::verifier(public_key, SelectorMode::Clamp)
    }
    /// Rejects selectors outside the current pool. This validates the complete
    /// composition but does not check the offchain encoder's rank < 2^160 condition.
    pub fn checksig_verify_bounded_and_clear(
        public_key: &ConstantCompositionPublicKey20<H, P>,
    ) -> Script {
        Self::verifier(public_key, SelectorMode::Bounded)
    }
    /// Requires exactly `WITNESS_DATA_ITEMS` on the entire main stack, then
    /// consumes them. Caller-owned altstack state is preserved; no result remains.
    ///
    /// After staging the complete main stack, only trusted public keys remain
    /// accessible to each `OP_ROLL`. Its intrinsic bounds check therefore safely
    /// replaces the composable verifier's selector clamps. Out-of-pool selectors
    /// fail rather than aliasing the last key. As with the other variants, the
    /// composition is enforced but the offchain encoder's rank bound is not.
    pub fn checksig_verify_isolated_and_clear(
        public_key: &ConstantCompositionPublicKey20<H, P>,
    ) -> Script {
        Self::verifier(public_key, SelectorMode::Isolated)
    }
    fn verifier(
        public_key: &ConstantCompositionPublicKey20<H, P>,
        selector_mode: SelectorMode,
    ) -> Script {
        script! {
            if matches!(selector_mode, SelectorMode::Isolated) {
                OP_DEPTH { 2 * OPENINGS } OP_EQUALVERIFY
            }
            // Stage only this signature's data above any caller-owned altstack
            // state. The first selector and then its node are retrieved first.
            for _ in 0..2 * OPENINGS { OP_TOALTSTACK }
            // Top of the pool is the lowest remaining original key index.
            for endpoint in public_key.commitments.iter().rev() {
                { endpoint.as_ref().to_vec() }
            }
            for slot in 0..OPENINGS {
                OP_FROMALTSTACK
                if matches!(selector_mode, SelectorMode::Bounded) {
                    OP_DUP { CHAINS - slot } OP_LESSTHAN OP_VERIFY
                } else if matches!(selector_mode, SelectorMode::Clamp) {
                    { CHAINS - slot - 1 } OP_MIN
                }
                OP_ROLL
                OP_FROMALTSTACK
                for _ in 0..MAX_DIGIT - slot_digit(slot) {
                    { H::hash_script() }
                }
                { H::commit_script() } OP_EQUALVERIFY
            }
            // The unselected keys must occupy the public maximum-digit slots.
            for _ in 0..COMPOSITION[MAX_DIGIT] as usize / 2 { OP_2DROP }
            if COMPOSITION[MAX_DIGIT] % 2 != 0 { OP_DROP }
        }
    }
}

const fn slot_digit(slot: usize) -> usize {
    let mut offset = 0;
    let mut digit = 0;
    while digit < MAX_DIGIT {
        offset += COMPOSITION[digit] as usize;
        if slot < offset {
            return digit;
        }
        digit += 1;
    }
    panic!("invalid opening slot")
}
fn integer(value: usize) -> Vec<u8> {
    let mut bytes = [0; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value as i64);
    bytes[..length].to_vec()
}
fn namespace<H: ChainHash, P: PreimageSize<H>>(seed: &[u8; 32]) -> H::Value {
    H::hash_parts(&[DOMAIN, H::DOMAIN, P::DOMAIN_PREFIX, &COMPOSITION, seed])
}
fn chain_start<H: ChainHash, P: PreimageSize<H>>(namespace: &H::Value, index: usize) -> P::Value {
    P::from_start(H::hash_parts(&[
        namespace.as_ref(),
        &(index as u32).to_be_bytes(),
    ]))
}
fn chain_hash<H: ChainHash>(start: &[u8], steps: usize) -> H::Value {
    assert!(steps > 0);
    let mut node = H::hash_parts(&[start]);
    for _ in 1..steps {
        node = H::hash_parts(&[node.as_ref()]);
    }
    node
}
fn codeword_count() -> &'static BigUint {
    static COUNT: OnceLock<BigUint> = OnceLock::new();
    COUNT.get_or_init(|| {
        let mut result = factorial(CHAINS);
        for count in COMPOSITION {
            result /= factorial(count as usize);
        }
        assert!(result >= (BigUint::one() << 160usize));
        result
    })
}
fn factorial(value: usize) -> BigUint {
    (1..=value).fold(BigUint::one(), |product, factor| product * factor)
}
fn unrank(mut rank: BigUint) -> [u8; CHAINS] {
    let mut counts = COMPOSITION.map(usize::from);
    let mut total = codeword_count().clone();
    assert!(rank < total);
    let mut remaining = CHAINS;
    let digits = core::array::from_fn(|_| {
        for digit in 0..RADIX {
            if counts[digit] == 0 {
                continue;
            }
            let bucket = &total * counts[digit] / remaining;
            if rank < bucket {
                total = bucket;
                counts[digit] -= 1;
                remaining -= 1;
                return digit as u8;
            }
            rank -= bucket;
        }
        unreachable!("rank lies within the remaining multiset")
    });
    assert_eq!(remaining, 0);
    assert!(rank.is_zero());
    digits
}
fn rank(digits: &[u8]) -> Result<BigUint, InvalidConstantCompositionEncoding> {
    if digits.len() != CHAINS {
        return Err(InvalidConstantCompositionEncoding);
    }
    let mut counts = COMPOSITION.map(usize::from);
    let mut total = codeword_count().clone();
    let mut remaining = CHAINS;
    let mut rank = BigUint::zero();
    for &digit in digits {
        let digit = digit as usize;
        if digit >= RADIX || counts[digit] == 0 {
            return Err(InvalidConstantCompositionEncoding);
        }
        for smaller in 0..digit {
            rank += &total * counts[smaller] / remaining;
        }
        total = &total * counts[digit] / remaining;
        counts[digit] -= 1;
        remaining -= 1;
    }
    Ok(rank)
}

#[cfg(test)]
#[path = "tests/host.rs"]
mod host_tests;
#[cfg(test)]
#[path = "tests/isolated.rs"]
mod isolated_tests;
#[cfg(test)]
#[path = "tests/signature.rs"]
mod tests;
