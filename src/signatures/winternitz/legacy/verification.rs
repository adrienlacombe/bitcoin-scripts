use super::utils::*;
use crate::support::script::*;
use bitcoin::{
    hashes::{hash160, Hash},
    Witness,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;

/// Parameters for the [`Winternitz`] struct.
#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Copy)]
pub struct Parameters {
    /// Number of digits per message (including zero padding at the end).
    pub(super) message_digit_len: u32,
    /// Number of bits per digit.
    pub(super) log2_base: u32,
    /// Number of digits per checksum.
    pub(super) checksum_digit_len: u32,
}

impl Parameters {
    /// Creates parameters for messages of the given number of digits of the given base.
    ///
    /// The log2_base must be in the range `4..=8`.
    pub const fn new(message_digit_len: u32, log2_base: u32) -> Self {
        assert!(
            4 <= log2_base && log2_base <= 8,
            "log2_base must be in the range 4..=8"
        );
        Parameters {
            message_digit_len,
            log2_base,
            checksum_digit_len: log_base_ceil(
                ((1 << log2_base) - 1) * message_digit_len + 1,
                1 << log2_base,
            ),
        }
    }

    /// Creates parameters for messages of the given bit length and for digits of the given base.
    ///
    /// The log2_base must be in the range `4..=8`.
    pub const fn new_by_bit_length(message_n_bits: u32, log2_base: u32) -> Self {
        let message_digit_len = message_n_bits.div_ceil(log2_base);
        Self::new(message_digit_len, log2_base)
    }

    /// Maximum value of a digit
    pub const fn max_digit(&self) -> u32 {
        (1 << self.log2_base) - 1
    }

    /// Maximum byte length of supported messages.
    pub const fn message_byte_len(&self) -> u32 {
        (self.message_digit_len * self.log2_base).div_ceil(8)
    }

    /// Total number of digits (message plus checksum).
    pub const fn total_digit_len(&self) -> u32 {
        self.message_digit_len + self.checksum_digit_len
    }
}

/// Returns the secret key for given digit, appending the representation of it in bigger endian bytes to the message secret key
pub fn secret_key_for_digit(secret_key: &SecretKey, mut digit_index: u32) -> hash160::Hash {
    let mut secret_i = secret_key.clone();
    while digit_index > 0 {
        secret_i.push((digit_index & 255) as u8);
        digit_index >>= 8;
    }
    hash160::Hash::hash(&secret_i)
}

/// Returns the signature of a given digit, requires the digit index to modify the secret key for each digit
pub fn digit_signature(secret_key: &SecretKey, digit_index: u32, message_digit: u32) -> HashOut {
    let mut hash = secret_key_for_digit(secret_key, digit_index);
    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }
    *hash.as_byte_array()
}

/// Returns the public key of a given digit, requires the digit index to modify the secret key for each digit
fn public_key_for_digit(ps: &Parameters, secret_key: &SecretKey, digit_index: u32) -> HashOut {
    let mut hash = secret_key_for_digit(secret_key, digit_index);
    let mut all_possible_digits = vec![hash];
    for _ in 0..ps.max_digit() {
        hash = hash160::Hash::hash(&hash[..]);
        all_possible_digits.push(hash)
    }
    all_possible_digits.sort();
    for i in 0..ps.max_digit() as usize {
        if all_possible_digits[i] == all_possible_digits[i + 1] {
            eprintln!("WARNING: Given secret key has repetitive hashes for digit {}, it won't work with brute force verifier", digit_index);
        }
    }
    *hash.as_byte_array()
}

/// Returns the public key for the given secret key and the parameters
pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::with_capacity(ps.total_digit_len() as usize);
    for i in 0..ps.total_digit_len() {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

/// Computes the checksum for the given message.
fn checksum(ps: &Parameters, message_digits: &[u32]) -> u32 {
    debug_assert_eq!(message_digits.len(), ps.message_digit_len as usize);

    let sum: u32 = message_digits.iter().sum();
    ps.max_digit() * ps.message_digit_len - sum
}

/// Appends the checksum to the end of the message.
fn add_message_checksum(ps: &Parameters, mut message_digits: Vec<u32>) -> Vec<u32> {
    debug_assert_eq!(message_digits.len(), ps.message_digit_len as usize);

    let checksum_digits = checksum_to_digits(
        checksum(ps, &message_digits),
        ps.max_digit() + 1,
        ps.checksum_digit_len,
    );
    message_digits.extend(checksum_digits);
    message_digits
}

/// Creates and verifies Winternitz signatures.
pub trait Verifier {
    /// Creates a Winternitz signature for the given `secret_key` and `digits`.
    ///
    /// ## Output format
    ///
    /// - `hash(digits[0])`
    /// - `digits[0]`
    /// - `hash(digits[1])`
    /// - `digits[1]`
    /// - ...
    /// - `hash(digits[n + m - 1])`
    /// - `digits[n + m - 1]`
    ///
    /// There are `n` message digits followed by `m` checksum digits.
    /// The checksum is computed internally.
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, message_digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, message_digits);
        let mut result = Witness::new();
        for i in 0..ps.total_digit_len() {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            // FIXME: Do trailing zeroes violate Bitcoin Script's minimum data push requirement?
            //        Maybe the script! macro removes the zeroes.
            //        There is a 1/256 chance that a signature contains a trailing zero.
            result.push(sig);
            result.push(bitcoin_representation(digits[i as usize] as i32));
        }
        result
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// The checksum is verified by a separate Bitcoin script.
    ///
    /// ## Precondition
    ///
    /// - `hash(digits[0])`
    /// - `digits[0]`
    /// - `hash(digits[1])`
    /// - `digits[1]`
    /// - ...
    /// - `hash(digits[n + m - 1])`
    /// - `digits[n + m - 1]` (stack top)
    ///
    /// For `n` message digits followed by `m` checksum digits.
    ///
    /// ## Postcondition
    ///
    /// - `digits[n + m - 1]`
    /// - `digits[n + m - 2]`
    /// - ...
    /// - `digits[0]` (alt stack top)
    ///
    /// The input is consumed from the stack.
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script;
}

/// Converts the message on the stack after signature verification.
pub trait Converter {
    /// Returns a Bitcoin script that converts the message on the stack.
    fn get_script(ps: &Parameters) -> Script;

    /// Returns the number of stack elements of the conversion output.
    fn length_of_final_message(ps: &Parameters) -> u32;
}

/// Marker for the set of used Winternitz algorithms.
pub struct Winternitz<VERIFIER: Verifier, CONVERTER: Converter> {
    phantom0: PhantomData<VERIFIER>,
    phantom1: PhantomData<CONVERTER>,
}

impl<VERIFIER: Verifier, CONVERTER: Converter> Default for Winternitz<VERIFIER, CONVERTER> {
    fn default() -> Self {
        Self::new()
    }
}

impl<VERIFIER: Verifier, CONVERTER: Converter> Winternitz<VERIFIER, CONVERTER> {
    /// Creates a marker for the given [`Verifier`] and [`Converter`].
    pub const fn new() -> Self {
        Winternitz {
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    /// Creates a Winternitz signature for the given `secret_key` and `digits`.
    ///
    /// ## See
    ///
    /// [`Verifier::sign_digits`]
    pub fn sign_digits(
        &self,
        ps: &Parameters,
        secret_key: &SecretKey,
        digits: Vec<u32>,
    ) -> Witness {
        VERIFIER::sign_digits(ps, secret_key, digits)
    }

    /// Creates a Winternitz signature for the given `secret_key` and `message`.
    ///
    /// The message is internally converted into digits.
    ///
    /// ## See
    ///
    /// [`Verifier::sign_digits`]
    pub fn sign(&self, ps: &Parameters, secret_key: &SecretKey, message: &[u8]) -> Witness {
        VERIFIER::sign_digits(
            ps,
            secret_key,
            message_to_digits(ps.message_digit_len, ps.log2_base, message),
        )
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The converted message is on the stack top.
    /// The checksum is consumed.
    ///
    /// ## See
    ///
    /// - [`Verifier::verify_digits`]
    /// - [`Converter::get_script`]
    pub fn checksig_verify(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            { VERIFIER::verify_digits(ps, public_key) }
            { self.verify_checksum(ps) }
            { CONVERTER::get_script(ps) }
        }
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// Signature (in the verifier's format) is at the stack top.
    ///
    /// ## Postcondition
    ///
    /// The message and checksum are consumed.
    ///
    /// ## See
    ///
    /// [`Verifier::verify_digits`]
    pub fn checksig_verify_and_clear_stack(
        &self,
        ps: &Parameters,
        public_key: &PublicKey,
    ) -> Script {
        script! {
            { VERIFIER::verify_digits(ps, public_key) }
            // A terminal consumer needs only the message sum. Reducing the
            // authenticated digits directly avoids reconstructing and then
            // discarding a full copy of the message on the main stack.
            // Compare the decoded checksum itself, retaining byte equality
            // even when a one-digit checksum has not passed through arithmetic.
            OP_FROMALTSTACK OP_NEGATE
            for _ in 1..ps.message_digit_len {
                OP_FROMALTSTACK OP_SUB
            }
            { ps.max_digit() * ps.message_digit_len }
            OP_ADD
            OP_FROMALTSTACK
            for _ in 0..ps.checksum_digit_len - 1 {
                for _ in 0..ps.log2_base {
                    OP_DUP OP_ADD
                }
                OP_FROMALTSTACK OP_ADD
            }
            OP_EQUALVERIFY
        }
    }

    /// Returns a Bitcoin script that verifies the message checksum.
    ///
    /// ## Precondition
    ///
    /// - `digits[n + m - 1]`
    /// - `digits[n + m - 2]`
    /// - ...
    /// - `digits[0]` (alt stack top)
    ///
    /// On the alt stack, there are `m` checksum digits followed by `n` message digits.
    /// The digits order is flipped.
    ///
    /// ## Postcondition
    ///
    /// - `digits[0]`
    /// - `digits[1]`
    /// - ...
    /// - `digits[n - 1]` (stack top)
    ///
    /// The input is consumed from the alt stack.
    fn verify_checksum(&self, ps: &Parameters) -> Script {
        script! {
            OP_FROMALTSTACK OP_DUP OP_NEGATE
            for _ in 1..ps.message_digit_len {
                OP_FROMALTSTACK OP_TUCK OP_SUB // sum the digits and tuck them before the sum so they are stored for later
            }
            { ps.max_digit() * ps.message_digit_len }
            OP_ADD
            OP_FROMALTSTACK
            for _ in 0..ps.checksum_digit_len - 1 {
                for _ in 0..ps.log2_base {
                    OP_DUP OP_ADD
                }
                OP_FROMALTSTACK
                OP_ADD
            }
            OP_EQUALVERIFY
        }
    }
}

/// Winternitz signature verification using lists and `OP_PICK`.
///
/// ## Verification Algorithm
///
/// Generates hashes for each possible value and then uses `OP_PICK` to get the corresponding one from the created list.
/// As a small improvement, it also divides the length of the list by 2 in the start.
///
/// ## Signature format
///
/// - `hash(digits[0])`
/// - `digits[0]`
/// - `hash(digits[1])`
/// - `digits[1]`
/// - ...
/// - `hash(digits[n + m - 1])`
/// - `digits[n + m - 1]`
///
/// There are `n` message digits followed by `m` checksum digits.
///
/// ## Approximate Max Stack Depth Used During Verification
///
/// 2 * `total_digit_len` + (2 ^ `log2_base`) / 2
pub struct ListpickVerifier {}

impl Verifier for ListpickVerifier {
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_digit_len() {
                //two OP_SWAP's are necessary since the signature hash is never on top of the stack. Order of them can be optimized in the future to negate one of the OP_SWAP's.
                OP_SWAP
                OP_SIZE
                { 20 } OP_EQUALVERIFY
                OP_SWAP
                // See https://github.com/BitVM/BitVM/issues/35
                { ps.max_digit() }
                OP_MIN
                OP_DUP
                OP_TOALTSTACK
                { ps.max_digit().div_ceil(2) }
                OP_2DUP
                OP_LESSTHAN
                OP_IF
                    OP_DROP
                    OP_TOALTSTACK
                    for _ in 0..ps.max_digit().div_ceil(2)  {
                        OP_HASH160
                    }
                OP_ELSE
                    OP_SUB
                    OP_TOALTSTACK
                OP_ENDIF
                for _ in 0..ps.max_digit()/2 {
                    OP_DUP OP_HASH160
                }
                OP_FROMALTSTACK
                OP_PICK
                { (public_key[ps.total_digit_len() as usize - 1 - digit_index as usize]).to_vec() }
                OP_EQUALVERIFY
                for _ in 0..(ps.max_digit() + 1) / 4 {
                    OP_2DROP
                }
            }
        }
    }
}

/// Winternitz signature verification using brute force.
///
/// ## Verification Algorithm
///
/// Tries each possible digit value.
///
/// ## Signature Format
///
/// - `hash(digit[0])`
/// - `hash(digit[1])`
/// - ...
/// - `hash(digit[n + m - 1])`
///
/// There are `n` message digits followed by `m` checksum digits.
///
/// ## Approximate Max Stack Depth Used During Verification
///
/// `total_length()`
pub struct BruteforceVerifier {}

impl Verifier for BruteforceVerifier {
    /// Creates a Winternitz signature for the given `secret_key` and `digits`.
    ///
    /// ## Signature Format
    ///
    /// - `hash(digit[0])`
    /// - `hash(digit[1])`
    /// - ...
    /// - `hash(digit[n + m - 1])`
    ///
    /// There are `n` message digits followed by `m` checksum digits.
    /// The checksum is computed internally.
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, message_digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, message_digits);
        let mut result = Witness::new();
        for i in 0..ps.total_digit_len() {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            result.push(sig);
        }
        result
    }

    /// Returns a Bitcoin script that verifies a Winternitz signature for the given `public_key`.
    ///
    /// ## Precondition
    ///
    /// - `hash(digits[0])`
    /// - `hash(digits[1])`
    /// - ...
    /// - `hash(digits[n + m - 1])` (stack top)
    ///
    /// There are `n` message digits followed by `m` checksum digits.
    ///
    /// ## Postcondition
    ///
    /// - `digits[n - 1]`
    /// - `digits[n - 2]`
    /// - ...
    /// - `digits[0]` (alt stack top)
    ///
    /// The input is consumed from the stack.
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_digit_len() {
                OP_SIZE
                { 20 } OP_EQUALVERIFY
                { public_key[(ps.total_digit_len() - 1 - digit_index) as usize].to_vec() }
                OP_SWAP
                { -1 } OP_TOALTSTACK // To avoid illegal stack access, same -1 is checked later
                OP_2DUP
                OP_EQUAL
                OP_IF
                    {ps.max_digit()}
                    OP_TOALTSTACK
                OP_ENDIF
                for i in 0..ps.max_digit() {
                    OP_HASH160
                    OP_2DUP
                    OP_EQUAL
                    OP_IF
                        { ps.max_digit() - i - 1 }
                        OP_TOALTSTACK
                    OP_ENDIF
                }
                OP_2DROP
                OP_FROMALTSTACK
                OP_DUP
                { -1 }
                OP_NUMNOTEQUAL OP_VERIFY
                OP_FROMALTSTACK
                { -1 } OP_EQUALVERIFY // Verify the sentinel value -1 to avoid altstack overflow in the rare case where pk == hash160^n(pk).
                OP_TOALTSTACK
            }
        }
    }
}

/// Winternitz signature verification using binary search.
///
/// ## Verification Algorithm
///
/// Simulates a for loop of hashing using binary search on the digit.
///
/// ## Signature Format
///
/// - `hash(digits[0])`
/// - `digits[0]`
/// - `hash(digits[1])`
/// - `digits[1]`
/// - ...
/// - `hash(digits[n + m - 1])`
/// - `digits[n + m - 1]`
///
/// There are `n` message digits followed by `m` checksum digits.
///
/// ## Approximate Max Stack Depth Used During Verification
///
/// 2 * `total_length()`
pub struct BinarysearchVerifier {}

impl Verifier for BinarysearchVerifier {
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_digit_len() {
                //two OP_SWAP's are necessary since the signature hash is never on top of the stack. Order of them can be optimized in the future to negate one of the OP_SWAP's.
                OP_SWAP
                OP_SIZE
                { 20 } OP_EQUALVERIFY
                OP_SWAP
                // One can try send digits out of the range, i.e. negative or bigger than D for it to act as in range, but due to bitcoin consensus rules,
                // OP_IF's fail to execute if their input is not 0 or 1, so OP_IF below marked with (*) does this check already
                // Note that this behaviour might change in the future with bitcoin consensus rules, so the test [`test_if_binary_search_verifier_allows_out_of_range_digits`] is added to confirm that this works
                // OP_0
                // OP_MAX
                // {ps.max_digit() }
                // OP_MIN
                OP_DUP
                OP_TOALTSTACK
                { ps.max_digit() } OP_SWAP OP_SUB
                for bit in (0..ps.log2_base).rev() {
                    if bit != 0 {
                        {1 << bit}
                        OP_2DUP
                        OP_GREATERTHANOREQUAL
                        OP_IF
                            OP_SUB
                            OP_SWAP
                            for _ in 0..(1 << bit) {
                                OP_HASH160
                            }
                            OP_SWAP
                            OP_DUP
                        OP_ENDIF
                        OP_DROP
                    } else {
                        OP_IF //(*)
                            OP_HASH160
                        OP_ENDIF
                    }
                }
                { (public_key[(ps.total_digit_len() - 1 - digit_index) as usize]).to_vec() }
                OP_EQUALVERIFY
            }
        }
    }
}

/// Leaves the digits on the stack as they are.
pub struct VoidConverter {}

impl Converter for VoidConverter {
    fn length_of_final_message(ps: &Parameters) -> u32 {
        ps.message_digit_len
    }

    fn get_script(ps: &Parameters) -> Script {
        let _ = ps;
        script! {}
    }
}

/// Converts the digits into bytes and leaves them on the stack.
pub struct ToBytesConverter {}

impl Converter for ToBytesConverter {
    fn length_of_final_message(ps: &Parameters) -> u32 {
        ps.message_byte_len()
    }

    fn get_script(ps: &Parameters) -> Script {
        if ps.log2_base == 8 {
            //already bytes
            script! {}
        } else if ps.log2_base == 4 {
            script! {
                for i in 0..ps.message_digit_len / 2 {
                    OP_SWAP
                    for _ in 0..ps.log2_base {
                        OP_DUP OP_ADD
                    }
                    OP_ADD
                    if i != (ps.message_digit_len / 2) - 1 {
                        OP_TOALTSTACK
                    }
                }
                if ps.message_digit_len > 1 {
                    for _ in 0..ps.message_digit_len / 2 - 1{
                        OP_FROMALTSTACK
                    }
                }
            }
        } else {
            let mut lens: Vec<u32> = vec![];
            let mut split_save = vec![];
            for i in 0..ps.message_digit_len {
                let start = i * ps.log2_base;
                let next_stop = start + 8 - (start % 8);
                let split = next_stop - start;
                split_save.push(split);
                if split >= ps.log2_base {
                    lens.push(ps.log2_base);
                } else {
                    lens.push(split);
                    lens.push(ps.log2_base - split);
                }
            }
            lens.reverse();
            let mut last_bytes_var = (8 - (ps.message_digit_len * ps.log2_base % 8)) % 8;
            let mut is_last_zero_var = true;
            let mut last_bytes_save = vec![];
            let mut is_last_zero_save = vec![];
            for l in lens.clone() {
                last_bytes_save.push(last_bytes_var);
                if last_bytes_var >= 8 {
                    last_bytes_var = 0;
                    is_last_zero_var = true;
                }
                is_last_zero_save.push(is_last_zero_var);
                is_last_zero_var = false;
                last_bytes_var += l;
            }

            script! {
                for split in split_save {
                    if split >= ps.log2_base {
                        OP_TOALTSTACK
                    } else {
                        OP_0
                        for j in (split..ps.log2_base).rev() {
                            if j != ps.log2_base - 1 {
                                OP_DUP OP_ADD
                            }
                            OP_SWAP
                            {1 << j}
                            OP_2DUP
                            OP_GREATERTHANOREQUAL
                            OP_IF
                                OP_SUB
                                OP_SWAP
                                OP_1ADD
                                OP_SWAP
                                OP_DUP
                            OP_ENDIF
                            OP_DROP
                            OP_SWAP
                        }
                        OP_SWAP
                        OP_TOALTSTACK
                        OP_TOALTSTACK
                    }
                }
                OP_0
                for (l, (last_bytes, is_last_zero)) in lens.into_iter().zip(last_bytes_save.into_iter().zip(is_last_zero_save.into_iter())) {
                    if last_bytes >= 8 {
                        OP_0
                    }
                    if !is_last_zero {
                        for _ in 0..l {
                            OP_DUP OP_ADD
                        }
                    }
                    OP_FROMALTSTACK OP_ADD
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/verification.rs"]
mod test;
