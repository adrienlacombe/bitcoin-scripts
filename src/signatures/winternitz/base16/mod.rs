//! A strict, low-allocation base-16 Winternitz implementation.
//!
//! This module deliberately does not share the legacy verifier/converter
//! machinery. Its fixed witness layout lets the generated Script validate the
//! chain value before touching the digit and saves one stack swap per chain.

use super::shared::chain_hash::{ChainHash, Hash160};
#[cfg(test)]
use super::shared::preimage::FullWidth;
use super::shared::preimage::{Preimage16, PreimageSize};
use crate::support::script::{script, Script};
use bitcoin::Witness;
use core::{fmt, marker::PhantomData};
use rand::RngCore;

/// Bytes in a HASH160 chain value.
#[cfg(test)]
const HASH_BYTES: usize = 20;
/// Winternitz base.
pub const BASE: u8 = 16;
/// Maximum base-16 digit.
pub const MAX_DIGIT: u8 = BASE - 1;

mod strided;

/// One intermediate chain node: 20 bytes for HASH160, 32 for SHA-256 profiles.
pub type FastChainValue<H = Hash160> = <H as ChainHash>::Value;

/// A stored endpoint commitment; it can be shorter than an intermediate node.
pub type FastCommitment<H = Hash160> = <H as ChainHash>::Commitment;

/// A one-time signing key bound to a fixed message length.
///
/// The type intentionally implements neither `Copy` nor `Clone`, and signing
/// consumes it. This prevents accidental reuse through the ordinary API. It
/// cannot prevent restoring the same seed twice, so applications must still
/// maintain durable one-time-key state.
pub struct FastSigningKey<
    const MESSAGE_BYTES: usize,
    H: ChainHash = Hash160,
    P: PreimageSize<H> = Preimage16,
> {
    seed: [u8; 32],
    hash: PhantomData<(H, P)>,
}

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastSigningKey<MESSAGE_BYTES, H, P>
{
    /// Restores a signing key from a deterministic 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        FastWinternitz::<MESSAGE_BYTES>::assert_parameters();
        Self {
            seed,
            hash: PhantomData,
        }
    }

    /// Generates a signing key with the operating system RNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Borrows the secret seed.
    ///
    /// Exposing this is necessary for durable key storage. Persist it as
    /// sensitive material and never restore it after a successful signature.
    pub fn expose_seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>> fmt::Debug
    for FastSigningKey<MESSAGE_BYTES, H, P>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastSigningKey")
            .field("message_bytes", &MESSAGE_BYTES)
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// Chain endpoints committed by a Fast Winternitz verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPublicKey<
    const MESSAGE_BYTES: usize,
    H: ChainHash = Hash160,
    P: PreimageSize<H> = Preimage16,
> {
    chain_ends: Box<[FastCommitment<H>]>,
    preimage: PhantomData<P>,
}

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastPublicKey<MESSAGE_BYTES, H, P>
{
    /// Reconstructs a public key from persisted chain endpoints.
    pub fn from_chain_ends(
        chain_ends: Vec<FastCommitment<H>>,
    ) -> Result<Self, InvalidFastPublicKeyLength> {
        FastWinternitz::<MESSAGE_BYTES>::assert_parameters();
        if chain_ends.len() != FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS {
            return Err(InvalidFastPublicKeyLength {
                expected: FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS,
                actual: chain_ends.len(),
            });
        }
        Ok(Self {
            chain_ends: chain_ends.into_boxed_slice(),
            preimage: PhantomData,
        })
    }

    /// Returns endpoint commitments in message/checksum digit order.
    /// Sha256Hash160 stores HASH160 of each completed SHA-256 chain.
    pub fn chain_ends(&self) -> &[FastCommitment<H>] {
        &self.chain_ends
    }
}

/// Public-key endpoint count did not match the message-length parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFastPublicKeyLength {
    /// Required number of endpoints.
    pub expected: usize,
    /// Supplied number of endpoints.
    pub actual: usize,
}

impl fmt::Display for InvalidFastPublicKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wrong Fast Winternitz public-key length: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for InvalidFastPublicKeyLength {}

/// A Fast Winternitz signature before Bitcoin witness serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastSignature<
    const MESSAGE_BYTES: usize,
    H: ChainHash = Hash160,
    P: PreimageSize<H> = Preimage16,
> {
    chain_values: Box<[P::Value]>,
    digits: Box<[u8]>,
}

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastSignature<MESSAGE_BYTES, H, P>
{
    /// Returns the authenticated message digits followed by checksum digits.
    ///
    /// Message bytes use high-nibble/low-nibble order. Checksum digits use a
    /// little-endian mixed power-of-two radix so the terminal verifier can
    /// decode them with a forward Horner pass while consuming backwards.
    pub fn digits(&self) -> &[u8] {
        &self.digits
    }

    /// Returns selected signature nodes. In Preimage16 mode, only digit-zero
    /// openings are 16 bytes; all later nodes have the native hash width.
    pub fn chain_values(&self) -> &[P::Value] {
        &self.chain_values
    }

    /// Serializes as `[digit_0, chain_0, digit_1, chain_1, ...]`.
    ///
    /// The chain value is therefore on top when Script consumes each pair in
    /// reverse order. Digits use canonical ScriptNum witness encodings.
    pub fn to_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (&digit, chain_value) in self.digits.iter().zip(self.chain_values.iter()) {
            if digit == 0 {
                witness.push([]);
            } else {
                witness.push([digit]);
            }
            witness.push(chain_value.as_ref());
        }
        witness
    }

    /// Serializes for the locking-size-optimized verifier.
    ///
    /// Message pairs are `[chain_0, digit_0, ..., chain_n, digit_n]`.
    /// Checksum pairs follow in reverse chain-index order. This makes Script
    /// consume checksum digits least-significant first, then message digits in
    /// reverse order, while the authenticated digits ultimately reach the
    /// checksum routine in its cheapest Horner order.
    pub fn to_size_optimized_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for index in 0..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            witness.push(self.chain_values[index].as_ref());
            push_digit(&mut witness, self.digits[index]);
        }
        for checksum_index in (0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS).rev() {
            let index = FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS + checksum_index;
            witness.push(self.chain_values[index].as_ref());
            push_digit(&mut witness, self.digits[index]);
        }
        witness
    }

    /// Serializes for the bitwise recovery verifier.
    ///
    /// Each chunk contains the authenticated digit bits from least to most
    /// significant followed by its selected chain node. The verifier checks
    /// the bits with `MINIMALIF`, reconstructs the digit, and returns it using
    /// the same message-nibble contract as the numeric profiles.
    pub fn to_bitwise_size_optimized_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (chain_index, (&digit, chain_value)) in
            self.digits.iter().zip(self.chain_values.iter()).enumerate()
        {
            for bit_index in 0..FastWinternitz::<MESSAGE_BYTES>::chain_digit_bits(chain_index) {
                push_digit(&mut witness, (digit >> bit_index) & 1);
            }
            witness.push(chain_value.as_ref());
        }
        witness
    }

    /// Serializes for the bitwise terminal verifier.
    ///
    /// Each chain contributes the canonical bits of `chain_max - digit` and
    /// the selected node. From bottom to top a base-16 chunk is
    /// `[bit_8, bit_4, bit_2, chain, bit_1]`, letting Script consume a bit and
    /// hash the exposed chain node without preserving the digit.
    pub fn to_bitwise_terminal_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (chain_index, (&digit, chain_value)) in
            self.digits.iter().zip(self.chain_values.iter()).enumerate()
        {
            let digit_bits = FastWinternitz::<MESSAGE_BYTES>::chain_digit_bits(chain_index);
            let remaining = FastWinternitz::<MESSAGE_BYTES>::chain_max_digit(chain_index) - digit;
            for bit_index in (1..digit_bits).rev() {
                push_digit(&mut witness, (remaining >> bit_index) & 1);
            }
            witness.push(chain_value.as_ref());
            push_digit(&mut witness, remaining & 1);
        }
        witness
    }
}

/// Fixed-message-length, base-16 Winternitz with a native hash choice.
///
/// Use `FastWinternitz::<32, Sha256>` for SHA-256; omitting the hash keeps
/// HASH160. Initial secrets default to 16 bytes for every hash choice.
/// To restore older native-width keys, specify `FullWidth` explicitly.
/// Keys carry the hash choice in their type, so algorithms cannot be mixed.
///
/// ```
/// use bitcoin_lab::signatures::winternitz::{FastWinternitz, Sha256};
/// type WotsSha256 = FastWinternitz<32, Sha256>;
/// assert_eq!(WotsSha256::HASH_BYTES, 32);
/// let key = WotsSha256::generate_signing_key();
/// let public_key = WotsSha256::public_key(&key);
/// let signature = WotsSha256::sign(key, &[0x42; 32]);
/// let verifier = WotsSha256::checksig_verify_clamped_and_clear(&public_key);
/// let witness = signature.to_size_optimized_witness();
/// ```
///
/// Use SHA-256 chain steps with 20-byte HASH160 endpoint commitments to reduce
/// locking-script bytes. This retains HASH160's generic collision bound.
///
/// ```
/// use bitcoin_lab::signatures::winternitz::{FastWinternitz, Sha256Hash160, Preimage16};
/// type CompactWots = FastWinternitz<32, Sha256Hash160, Preimage16>;
/// assert_eq!(CompactWots::HASH_BYTES, 32);
/// assert_eq!(CompactWots::COMMITMENT_BYTES, 20);
/// let key = CompactWots::generate_signing_key();
/// let pk = CompactWots::public_key(&key);
/// let signature = CompactWots::sign(key, &[0; 32]);
/// let verifier = CompactWots::checksig_verify_strided_and_clear(&pk);
/// let witness = signature.to_strided_witness();
/// assert_eq!(witness.len(), 201);
/// ```
///
/// ```compile_fail
/// use bitcoin_lab::signatures::winternitz::{FastWinternitz, Sha256};
/// let key = FastWinternitz::<32>::signing_key_from_seed([0x42; 32]);
/// FastWinternitz::<32, Sha256>::public_key(&key);
/// ```
///
/// Initial secrets default to 16 bytes; later hash nodes remain native width:
///
/// ```
/// use bitcoin_lab::signatures::winternitz::FastWinternitz;
/// type ShortWots = FastWinternitz<32>;
/// assert_eq!(ShortWots::PREIMAGE_BYTES, 16);
/// assert_eq!(ShortWots::HASH_BYTES, 20);
/// let key = ShortWots::generate_signing_key();
/// let pk = ShortWots::public_key(&key);
/// let sig = ShortWots::sign(key, &[0; 32]);
/// assert_eq!(sig.chain_values()[0].as_ref().len(), 16);
/// let verifier = ShortWots::checksig_verify_clamped_and_clear(&pk);
/// let witness = sig.to_size_optimized_witness();
/// ```
///
/// ```compile_fail
/// use bitcoin_lab::signatures::winternitz::{FastWinternitz, Hash160, FullWidth};
/// let key = FastWinternitz::<32>::generate_signing_key();
/// FastWinternitz::<32, Hash160, FullWidth>::public_key(&key);
/// ```
pub struct FastWinternitz<
    const MESSAGE_BYTES: usize,
    H: ChainHash = Hash160,
    P: PreimageSize<H> = Preimage16,
>(PhantomData<(H, P)>);

/// Fast Winternitz over a 4-byte message.
pub type FastWots4 = FastWinternitz<4>;
/// Fast Winternitz over a 16-byte message.
pub type FastWots16 = FastWinternitz<16>;
/// Fast Winternitz over a 32-byte message.
pub type FastWots32 = FastWinternitz<32>;
/// Fast Winternitz over a 64-byte message.
pub type FastWots64 = FastWinternitz<64>;
/// Fast Winternitz over an 80-byte message.
pub type FastWots80 = FastWinternitz<80>;

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastWinternitz<MESSAGE_BYTES, H, P>
{
    /// Native hash output width; initial secrets and commitments may be shorter.
    pub const HASH_BYTES: usize = H::VALUE_BYTES;

    /// Stored public commitment width.
    pub const COMMITMENT_BYTES: usize = H::COMMITMENT_BYTES;

    /// Initial secret preimage width, exposed by a signature only at digit zero.
    pub const PREIMAGE_BYTES: usize = P::START_BYTES;

    /// Number of base-16 message digits.
    pub const MESSAGE_DIGITS: usize = MESSAGE_BYTES * 2;
    /// Number of bits required by the Winternitz checksum.
    pub const CHECKSUM_BITS: usize =
        binary_digits(Self::MESSAGE_DIGITS.saturating_mul(MAX_DIGIT as usize));
    /// Number of mixed-radix checksum digits, each using at most four bits.
    pub const CHECKSUM_DIGITS: usize = (Self::CHECKSUM_BITS + 3) / 4;
    /// Total number of hash chains.
    pub const TOTAL_DIGITS: usize = Self::MESSAGE_DIGITS + Self::CHECKSUM_DIGITS;

    const fn assert_parameters() {
        assert!(MESSAGE_BYTES > 0, "message length must be nonzero");
        assert!(
            Self::TOTAL_DIGITS <= u32::MAX as usize,
            "too many Winternitz chains"
        );
        assert!(
            Self::CHECKSUM_BITS < usize::BITS as usize,
            "checksum exceeds host word size"
        );
    }

    const fn checksum_digit_bits(checksum_index: usize) -> usize {
        let narrow = Self::CHECKSUM_BITS / Self::CHECKSUM_DIGITS;
        let wide_digits = Self::CHECKSUM_BITS % Self::CHECKSUM_DIGITS;
        if checksum_index >= Self::CHECKSUM_DIGITS - wide_digits {
            narrow + 1
        } else {
            narrow
        }
    }

    const fn checksum_digit_shift(checksum_index: usize) -> usize {
        let mut shift = 0;
        let mut index = 0;
        while index < checksum_index {
            shift += Self::checksum_digit_bits(index);
            index += 1;
        }
        shift
    }

    const fn checksum_digit_place(checksum_index: usize) -> usize {
        1usize << Self::checksum_digit_shift(checksum_index)
    }

    const fn chain_digit_bits(chain_index: usize) -> usize {
        if chain_index < Self::MESSAGE_DIGITS {
            4
        } else {
            Self::checksum_digit_bits(chain_index - Self::MESSAGE_DIGITS)
        }
    }

    const fn chain_max_digit(chain_index: usize) -> u8 {
        ((1usize << Self::chain_digit_bits(chain_index)) - 1) as u8
    }

    /// Generates a fresh one-time signing key.
    pub fn generate_signing_key() -> FastSigningKey<MESSAGE_BYTES, H, P> {
        FastSigningKey::generate()
    }

    /// Restores a deterministic one-time signing key.
    pub fn signing_key_from_seed(seed: [u8; 32]) -> FastSigningKey<MESSAGE_BYTES, H, P> {
        FastSigningKey::from_seed(seed)
    }

    /// Derives all public chain endpoints.
    ///
    /// The hot loop uses fixed-size values and performs no per-chain heap
    /// allocation, cloning, or sorting.
    pub fn public_key(
        key: &FastSigningKey<MESSAGE_BYTES, H, P>,
    ) -> FastPublicKey<MESSAGE_BYTES, H, P> {
        Self::assert_parameters();
        let namespace = derive_preimage_namespace::<MESSAGE_BYTES, H, P>(&key.seed);
        let chain_ends = (0..Self::TOTAL_DIGITS)
            .map(|chain_index| {
                let start = P::from_start(derive_chain_start::<H>(&namespace, chain_index as u32));
                // Every supported chain has at least one link. Only its
                // initial secret is shortened; all hashes remain full width.
                H::commit(hash_chain::<H>(
                    H::hash_parts(&[start.as_ref()]),
                    Self::chain_max_digit(chain_index) - 1,
                ))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        FastPublicKey {
            chain_ends,
            preimage: PhantomData,
        }
    }

    /// Signs one fixed-size message and consumes the one-time signing key.
    pub fn sign(
        key: FastSigningKey<MESSAGE_BYTES, H, P>,
        message: &[u8; MESSAGE_BYTES],
    ) -> FastSignature<MESSAGE_BYTES, H, P> {
        Self::assert_parameters();
        let digits = message_and_checksum_digits(message);
        debug_assert_eq!(digits.len(), Self::TOTAL_DIGITS);
        let namespace = derive_preimage_namespace::<MESSAGE_BYTES, H, P>(&key.seed);
        let chain_values = digits
            .iter()
            .enumerate()
            .map(|(chain_index, &digit)| {
                let start = P::from_start(derive_chain_start::<H>(&namespace, chain_index as u32));
                if digit == 0 {
                    start
                } else {
                    P::from_hash(hash_chain::<H>(H::hash_parts(&[start.as_ref()]), digit - 1))
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        FastSignature {
            chain_values,
            digits: digits.into_boxed_slice(),
        }
    }

    /// Builds the speed-optimized verifier and leaves authenticated message
    /// nibbles on the main stack in high/low order.
    ///
    /// Every message chain performs exactly `15 - digit` native hash calls;
    /// checksum chains use their mixed-radix maximum. The checksum and all
    /// chain values are consumed. The caller must consume the message and
    /// leave a terminal truthy predicate for a complete tapscript leaf.
    pub fn checksig_verify(public_key: &FastPublicKey<MESSAGE_BYTES, H, P>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_exact::<H, P>(
                    public_key.chain_ends[chain_index],
                    Self::chain_digit_bits(chain_index),
                    false,
                ) }
            }
            { recover_message_and_verify_checksum::<MESSAGE_BYTES>() }
        }
    }

    /// Builds a speed-optimized terminal verifier that consumes the entire
    /// signature and recovered message.
    ///
    /// Verified digits are collected on altstack before the checksum reduction.
    /// This avoids moving a running accumulator around every chain verifier.
    /// The fragment leaves an empty stack; append a terminal predicate.
    pub fn checksig_verify_and_clear(public_key: &FastPublicKey<MESSAGE_BYTES, H, P>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_exact::<H, P>(
                    public_key.chain_ends[chain_index],
                    Self::chain_digit_bits(chain_index),
                    false,
                ) }
            }
            OP_FROMALTSTACK
            for _ in 1..Self::MESSAGE_DIGITS {
                OP_FROMALTSTACK OP_ADD
            }
            { verify_checksum_from_altstack::<MESSAGE_BYTES>() }
        }
    }

    /// Builds the script-size-oriented verifier and leaves authenticated
    /// message nibbles on the main stack.
    ///
    /// The message-chain lookup has eight entries and executes 15 hashes for
    /// digits below 8 and seven otherwise; checksum lists are radix-specific. Use
    /// [`Self::checksig_verify`] when verification latency is the objective.
    pub fn checksig_verify_minimal(public_key: &FastPublicKey<MESSAGE_BYTES, H, P>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_minimal::<H, P>(
                    public_key.chain_ends[chain_index],
                    Self::chain_digit_bits(chain_index),
                    false,
                ) }
            }
            { recover_message_and_verify_checksum::<MESSAGE_BYTES>() }
        }
    }

    /// Builds the smallest strict numeric verifier and recovers the message.
    ///
    /// This profile expects [`FastSignature::to_size_optimized_witness`]. It
    /// rejects digits outside each chain's radix, uses full tables up to three bits
    /// and half tables for four-bit digits,
    /// and leaves the authenticated message nibbles on the main stack. It omits
    /// the explicit chain-item width guard, saving four bytes per chain for
    /// FullWidth or eleven for Preimage16. The accepted raw-width relation is
    /// documented on the internal chain verifier below.
    pub fn checksig_verify_size_optimized(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::checksig_verify_numeric_size(public_key, false, false)
    }

    /// Builds the terminal version of the strict numeric size verifier.
    ///
    /// The fragment leaves an empty stack after successful verification. The
    /// caller must append the surrounding protocol's terminal predicate.
    pub fn checksig_verify_size_optimized_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::checksig_verify_numeric_size(public_key, false, true)
    }

    /// Recovers the authenticated message using upper-clamped numeric digits.
    ///
    /// Accepts [`FastSignature::to_size_optimized_witness`]. Each supplied
    /// digit is replaced by `min(digit, chain_max)` before chain verification,
    /// message recovery, and checksum verification. The authenticated message
    /// is therefore the clamped value, exactly as with the legacy list-pick
    /// verifier. Raw digit encodings above the maximum are intentionally
    /// malleable; callers needing rejection use [`Self::checksig_verify_size_optimized`].
    /// Negative digits and oversized ScriptNums fail. Like the strict numeric
    /// size profile, this profile admits arbitrary-length chain preimages
    /// below the maximum digit rather than checking raw chain-item length.
    /// With Sha256Hash160, the commitment hash also permits arbitrary raw
    /// lengths at the maximum digit.
    pub fn checksig_verify_clamped(public_key: &FastPublicKey<MESSAGE_BYTES, H, P>) -> Script {
        Self::checksig_verify_numeric_size(public_key, true, false)
    }

    /// Verifies upper-clamped numeric digits and consumes the message.
    ///
    /// Uses the same witness and clamped-message contract as
    /// [`Self::checksig_verify_clamped`]. The successful fragment leaves an
    /// empty stack; append the surrounding protocol's terminal predicate.
    pub fn checksig_verify_clamped_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::checksig_verify_numeric_size(public_key, true, true)
    }

    fn checksig_verify_numeric_size(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
        clamp: bool,
        clear: bool,
    ) -> Script {
        Self::assert_public_key(public_key);
        script! {
            // Checksum chain 0 is on top, then the remaining checksum
            // chains and message chains in reverse order.
            for checksum_index in 0..Self::CHECKSUM_DIGITS {
                { verify_chain_size_optimized::<H>(
                    public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index],
                    Self::checksum_digit_bits(checksum_index),
                    clamp,
                ) }
            }
            for message_index in (0..Self::MESSAGE_DIGITS).rev() {
                { verify_chain_size_optimized::<H>(public_key.chain_ends[message_index], 4, clamp) }
            }
            if clear {
                { verify_checksum_and_clear_horner::<MESSAGE_BYTES>() }
            } else {
                { recover_message_and_verify_checksum_horner::<MESSAGE_BYTES>() }
            }
        }
    }

    /// Builds the smallest locking fragment for recovery and returns 64 authenticated
    /// message nibbles for `FastWots32`.
    ///
    /// Canonical witness bits drive exact conditional hash blocks. Checksum
    /// bits are fused directly into a mixed-radix Horner accumulator before
    /// the message chains are checked, avoiding per-checksum-digit stack
    /// storage and reconstruction.
    pub fn checksig_verify_bitwise_size_optimized(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for checksum_index in (0..Self::CHECKSUM_DIGITS).rev() {
                if checksum_index == Self::CHECKSUM_DIGITS - 1 {
                    { verify_chain_bitwise_and_recover::<H>(
                        public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index],
                        Self::checksum_digit_bits(checksum_index),
                    ) }
                } else {
                    { verify_chain_bitwise_and_fuse_horner::<H>(
                        public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index],
                        Self::checksum_digit_bits(checksum_index),
                    ) }
                }
            }
            for message_index in (0..Self::MESSAGE_DIGITS).rev() {
                { verify_chain_bitwise_and_recover::<H>(public_key.chain_ends[message_index], 4) }
            }
            { recover_message_and_verify_fused_checksum::<MESSAGE_BYTES>() }
        }
    }

    /// Builds a smaller terminal verifier using a canonical bitwise witness.
    ///
    /// The witness bits encode `chain_max - digit`. Tapscript `MINIMALIF`
    /// rejects every encoding except canonical false and true, the selected
    /// bit branches perform exactly the remaining chain hashes, and the same
    /// branches accumulate the Winternitz checksum relation. The fragment
    /// leaves an empty stack; append the surrounding protocol's predicate.
    pub fn checksig_verify_bitwise_size_optimized_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                if chain_index < Self::MESSAGE_DIGITS {
                    { verify_chain_bitwise_and_accumulate::<H>(
                        public_key.chain_ends[chain_index],
                        4,
                        1,
                        false,
                    ) }
                } else {
                    { verify_chain_bitwise_and_accumulate::<H>(
                        public_key.chain_ends[chain_index],
                        Self::checksum_digit_bits(chain_index - Self::MESSAGE_DIGITS),
                        Self::checksum_digit_place(chain_index - Self::MESSAGE_DIGITS),
                        chain_index == Self::TOTAL_DIGITS - 1,
                    ) }
                }
            }
            OP_FROMALTSTACK
            { (1usize << Self::CHECKSUM_BITS) - 1 }
            OP_EQUALVERIFY
        }
    }

    fn assert_public_key(public_key: &FastPublicKey<MESSAGE_BYTES, H, P>) {
        Self::assert_parameters();
        assert_eq!(
            public_key.chain_ends.len(),
            Self::TOTAL_DIGITS,
            "wrong Fast Winternitz public-key length"
        );
    }
}

const fn binary_digits(mut maximum: usize) -> usize {
    let mut digits = 1;
    while maximum >= 2 {
        maximum /= 2;
        digits += 1;
    }
    digits
}

#[cfg(test)]
fn derive_chain_namespace<const MESSAGE_BYTES: usize, H: ChainHash>(
    seed: &[u8; 32],
) -> FastChainValue<H> {
    H::hash_parts(&[H::DOMAIN, seed, &(MESSAGE_BYTES as u64).to_be_bytes()])
}

fn derive_preimage_namespace<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>(
    seed: &[u8; 32],
) -> FastChainValue<H> {
    H::hash_parts(&[
        P::DOMAIN_PREFIX,
        H::DOMAIN,
        seed,
        &(MESSAGE_BYTES as u64).to_be_bytes(),
    ])
}

fn derive_chain_start<H: ChainHash>(
    namespace: &FastChainValue<H>,
    chain_index: u32,
) -> FastChainValue<H> {
    H::hash_parts(&[namespace.as_ref(), &chain_index.to_be_bytes()])
}

fn hash_chain<H: ChainHash>(mut value: FastChainValue<H>, steps: u8) -> FastChainValue<H> {
    for _ in 0..steps {
        value = H::hash_parts(&[value.as_ref()]);
    }
    value
}

fn push_digit(witness: &mut Witness, digit: u8) {
    if digit == 0 {
        witness.push([]);
    } else {
        witness.push([digit]);
    }
}

fn message_and_checksum_digits<const MESSAGE_BYTES: usize>(
    message: &[u8; MESSAGE_BYTES],
) -> Vec<u8> {
    let mut digits = Vec::with_capacity(FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS);
    for &byte in message {
        digits.push(byte >> 4);
        digits.push(byte & 0x0f);
    }

    let checksum = digits
        .iter()
        .fold(0usize, |sum, &digit| sum + usize::from(MAX_DIGIT - digit));
    digits.extend(mixed_checksum_digits::<MESSAGE_BYTES>(checksum));
    digits
}

fn mixed_checksum_digits<const MESSAGE_BYTES: usize>(checksum: usize) -> Vec<u8> {
    debug_assert!(checksum <= FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize);
    let mut digits = Vec::with_capacity(FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS);
    let mut shift = 0;
    for checksum_index in 0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
        let digit_bits = FastWinternitz::<MESSAGE_BYTES>::checksum_digit_bits(checksum_index);
        digits.push(((checksum >> shift) & ((1usize << digit_bits) - 1)) as u8);
        shift += digit_bits;
    }
    digits
}

/// Strict relation: an un-hashed digit-zero secret has the initial width;
/// every later chain node has the native hash width. Input: [... digit, node].
fn verify_chain_input_size<H: ChainHash, P: PreimageSize<H>>() -> Script {
    script! {
        if P::START_BYTES == H::VALUE_BYTES {
            OP_SIZE { H::VALUE_BYTES } OP_EQUALVERIFY
        } else {
            OP_OVER OP_0NOTEQUAL
            OP_IF
                OP_SIZE { H::VALUE_BYTES } OP_EQUALVERIFY
            OP_ELSE
                OP_SIZE { P::START_BYTES } OP_EQUALVERIFY
            OP_ENDIF
        }
    }
}

/// Verifies one chain with the minimum possible number of executed hashes for
/// the supplied digit. Precondition: `[... digit, chain_value]`.
/// Postcondition: `[... digit]`.
fn verify_chain_exact<H: ChainHash, P: PreimageSize<H>>(
    expected: FastCommitment<H>,
    digit_bits: usize,
    return_digit: bool,
) -> Script {
    script! {
        { verify_chain_input_size::<H, P>() }
        OP_SWAP
        OP_DUP OP_TOALTSTACK

        // Keep [chain_value, residual_digit]. A set digit bit skips that
        // block of hashes; an unset bit executes it. Working directly with
        // the digit avoids constructing its complement and moving the chain
        // through the final condition. Out-of-range inputs leave a residual
        // other than canonical false or true at the final OP_NOTIF, so
        // tapscript MINIMALIF still enforces the complete digit range.
        for step in (1..digit_bits).rev().map(|bit_index| 1usize << bit_index) {
            OP_DUP { step } OP_GREATERTHANOREQUAL
            OP_IF
                { step } OP_SUB
            OP_ELSE
                OP_SWAP
                for _ in 0..step {
                    { H::hash_script() }
                }
                OP_SWAP
            OP_ENDIF
        }
        OP_NOTIF
            { H::hash_script() }
        OP_ENDIF

        { H::commit_script() }
        { expected.as_ref().to_vec() }
        OP_EQUALVERIFY
        if return_digit {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
#[path = "tests/exact_chain.rs"]
mod exact_chain_tests;

/// Verifies one chain using a full lookup for narrow checksum digits and a
/// symmetric half-radix lookup for four-bit message/checksum digits.
fn verify_chain_minimal<H: ChainHash, P: PreimageSize<H>>(
    expected: FastCommitment<H>,
    digit_bits: usize,
    return_digit: bool,
) -> Script {
    let radix = 1usize << digit_bits;
    let half = radix / 2;
    let table_len = if digit_bits <= 3 { radix } else { half };
    script! {
        { verify_chain_input_size::<H, P>() }
        OP_SWAP
        // OP_PICK rejects negative indices; the explicit upper bound keeps
        // every index inside this chain's own table.
        OP_DUP { radix } OP_LESSTHAN OP_VERIFY
        OP_DUP OP_TOALTSTACK

        if digit_bits <= 3 {
            // At radix 2/4/8 the extra table entries cost less than the
            // half-selector branch. The witness and returned digit agree
            // with the half-table implementation.
            OP_TOALTSTACK
        } else {
            { half }
            OP_2DUP OP_LESSTHAN
            OP_IF
                OP_DROP OP_TOALTSTACK
                for _ in 0..half {
                    { H::hash_script() }
                }
            OP_ELSE
                OP_SUB OP_TOALTSTACK
            OP_ENDIF
        }
        for _ in 1..table_len {
            OP_DUP { H::hash_script() }
        }
        OP_FROMALTSTACK
        OP_PICK
        { H::commit_script() }
        { expected.as_ref().to_vec() }
        OP_EQUALVERIFY
        for _ in 0..(table_len / 2) {
            OP_2DROP
        }
        if return_digit {
            OP_FROMALTSTACK
        }
    }
}

/// Verifies one chain with a strict or upper-clamped numeric lookup.
///
/// Precondition: `[... chain_value, digit]`. Postcondition: the digit is on
/// the altstack. In the clamped mode, both chain verification and the saved
/// digit use `min(digit, radix-1)`. Otherwise digits at or above the radix fail
/// the explicit upper bound. In both modes, negative digits fail at `OP_PICK`
/// and oversized ScriptNums fail numeric decoding.
///
/// This fragment omits strict initial/intermediate width checks. With identity
/// commitments, a maximum digit directly compares a native-width node; below
/// the maximum at least one chain hash normalizes any input length. With
/// Sha256Hash160, the final commitment hash also normalizes maximum-digit
/// inputs, so every digit admits arbitrary-length raw openings if they satisfy
/// the hash relation. Signers emit native-width nodes except for digit-zero
/// Preimage16 starts. Strict profiles enforce those signer widths explicitly.
fn verify_chain_size_optimized<H: ChainHash>(
    expected: FastCommitment<H>,
    digit_bits: usize,
    clamp: bool,
) -> Script {
    let radix = 1usize << digit_bits;
    let half = radix / 2;
    let table_len = if digit_bits <= 3 { radix } else { half };
    script! {
        if clamp {
            { radix - 1 } OP_MIN
        } else {
            OP_DUP { radix } OP_LESSTHAN OP_VERIFY
        }
        OP_DUP OP_TOALTSTACK

        if digit_bits <= 3 {
            OP_TOALTSTACK
        } else {
            { half }
            OP_2DUP OP_LESSTHAN
            OP_IF
                OP_DROP OP_TOALTSTACK
                for _ in 0..half {
                    { H::hash_script() }
                }
            OP_ELSE
                OP_SUB OP_TOALTSTACK
            OP_ENDIF
        }
        for _ in 1..table_len {
            OP_DUP { H::hash_script() }
        }
        OP_FROMALTSTACK OP_PICK
        { H::commit_script() }
        { expected.as_ref().to_vec() }
        OP_EQUALVERIFY
        for _ in 0..(table_len / 2) {
            OP_2DROP
        }
    }
}

#[cfg(test)]
#[path = "tests/numeric_lookup.rs"]
mod numeric_lookup_tests;

#[cfg(test)]
#[path = "tests/clamped_chain.rs"]
mod clamped_chain_tests;

/// Verifies one chain from canonical digit bits, leaving the bits on main.
fn verify_chain_bitwise<H: ChainHash>(expected: FastCommitment<H>, digit_bits: usize) -> Script {
    script! {
        OP_OVER
        OP_NOTIF
            for _ in 0..(1usize << (digit_bits - 1)) {
                { H::hash_script() }
            }
        OP_ENDIF
        for offset in 1..digit_bits {
            { offset + 1 } OP_PICK
            OP_NOTIF
                for _ in 0..(1usize << (digit_bits - 1 - offset)) {
                    { H::hash_script() }
                }
            OP_ENDIF
        }
        { H::commit_script() }
        { expected.as_ref().to_vec() }
        OP_EQUALVERIFY
    }
}

/// Verifies one chain and stores its reconstructed digit on altstack.
fn verify_chain_bitwise_and_recover<H: ChainHash>(
    expected: FastCommitment<H>,
    digit_bits: usize,
) -> Script {
    script! {
        { verify_chain_bitwise::<H>(expected, digit_bits) }
        for _ in 1..digit_bits {
            OP_DUP OP_ADD OP_ADD
        }
        OP_TOALTSTACK
    }
}

/// Verifies one checksum chain and fuses its bits into the Horner state.
fn verify_chain_bitwise_and_fuse_horner<H: ChainHash>(
    expected: FastCommitment<H>,
    digit_bits: usize,
) -> Script {
    script! {
        { verify_chain_bitwise::<H>(expected, digit_bits) }
        OP_FROMALTSTACK
        for _ in 0..digit_bits {
            OP_DUP OP_ADD OP_ADD
        }
        OP_TOALTSTACK
    }
}

/// Verifies one chain from canonical remaining-distance bits and adds
/// their weighted value to the accumulator on the altstack.
///
/// Precondition: `[... bit_8, bit_4, bit_2, chain_value, bit_1]` with the
/// accumulator on top of the altstack, unless `initialize` creates it instead.
/// Postcondition: the five main stack items are consumed and the updated
/// accumulator remains on altstack.
fn verify_chain_bitwise_and_accumulate<H: ChainHash>(
    expected: FastCommitment<H>,
    digit_bits: usize,
    place: usize,
    initialize: bool,
) -> Script {
    script! {
        if initialize {
            // The first authenticated bit supplies the initial weighted sum.
            // This avoids materializing a zero accumulator before consuming
            // any witness item, saving both locking bytes and one peak item.
            OP_IF
                { H::hash_script() }
                { place }
            OP_ELSE
                OP_0
            OP_ENDIF
            OP_TOALTSTACK
        } else {
            OP_IF
                { H::hash_script() }
                { add_weight_to_altstack(place) }
            OP_ENDIF
        }
        for bit_index in 1..digit_bits {
            OP_SWAP
            OP_IF
                for _ in 0..(1usize << bit_index) {
                    { H::hash_script() }
                }
                { add_weight_to_altstack((1usize << bit_index) * place) }
            OP_ENDIF
        }

        { H::commit_script() }
        { expected.as_ref().to_vec() }
        OP_EQUALVERIFY
    }
}

fn add_weight_to_altstack(weight: usize) -> Script {
    if weight == 1 {
        script! { OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK }
    } else {
        script! { OP_FROMALTSTACK { weight } OP_ADD OP_TOALTSTACK }
    }
}

fn recover_message_and_verify_checksum<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        { preserve_message_and_sum::<MESSAGE_BYTES>() }
        { verify_checksum_from_altstack::<MESSAGE_BYTES>() }
    }
}

/// Consumes the message sum on main and little-endian checksum digits on alt.
fn verify_checksum_from_altstack<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        // Stage little-endian digits together: each Horner addition then
        // consumes the next lower digit directly from beneath the accumulator.
        for _ in 0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
            OP_FROMALTSTACK
        }
        for checksum_index in (0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS - 1).rev() {
            for _ in 0..FastWinternitz::<MESSAGE_BYTES>::checksum_digit_bits(checksum_index) {
                OP_DUP OP_ADD
            }
            OP_ADD
        }
        OP_ADD
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_EQUALVERIFY
    }
}

fn recover_message_and_verify_checksum_horner<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        { preserve_message_and_sum::<MESSAGE_BYTES>() }

        // The custom witness order exposes checksum digits most-significant
        // first, so one mixed-radix Horner pass is smallest.
        OP_FROMALTSTACK
        for checksum_index in (0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS - 1).rev() {
            for _ in 0..FastWinternitz::<MESSAGE_BYTES>::checksum_digit_bits(checksum_index) {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK OP_ADD
        }
        OP_ADD
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_EQUALVERIFY
    }
}

fn recover_message_and_verify_fused_checksum<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        { preserve_message_and_sum::<MESSAGE_BYTES>() }
        OP_FROMALTSTACK OP_ADD
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_EQUALVERIFY
    }
}

fn preserve_message_and_sum<const MESSAGE_BYTES: usize>() -> Script {
    if FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS >= 3 {
        script! {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            OP_3DUP OP_ADD OP_ADD
            for _ in 3..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
                OP_FROMALTSTACK OP_TUCK OP_ADD
            }
        }
    } else {
        script! {
            OP_FROMALTSTACK OP_DUP
            for _ in 1..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
                OP_FROMALTSTACK OP_TUCK OP_ADD
            }
        }
    }
}

fn verify_checksum_and_clear_horner<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            OP_FROMALTSTACK OP_ADD
        }

        OP_FROMALTSTACK
        for checksum_index in (0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS - 1).rev() {
            for _ in 0..FastWinternitz::<MESSAGE_BYTES>::checksum_digit_bits(checksum_index) {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK OP_ADD
        }
        OP_ADD
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_EQUALVERIFY
    }
}

#[cfg(test)]
#[path = "tests/signature.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/hash_choice.rs"]
mod hash_choice_tests;

#[cfg(test)]
#[path = "tests/preimages.rs"]
mod preimage_tests;
