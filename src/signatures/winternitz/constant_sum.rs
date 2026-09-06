//! Lossless 160-bit encoding into a mixed-radix, constant-sum Winternitz code.
use super::{
    sum_chain::{verify_sum_chain, SumChainStyle},
    ChainHash, Hash160, Preimage16, PreimageSize,
};
use crate::support::script::{script, Script};
use bitcoin::{
    key::rand::{thread_rng, RngCore},
    Witness,
};
use core::{fmt, marker::PhantomData};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::sync::OnceLock;

const CHAINS: usize = 41;
const SUM: usize = 321;
const RADICES: [u8; CHAINS] = {
    let mut result = [20; CHAINS];
    let mut i = 0;
    while i < 32 {
        result[i] = 16;
        i += 1;
    }
    while i < 36 {
        result[i] = 18;
        i += 1;
    }
    result
};
const DOMAIN: &[u8] = b"bitcoin-lab/winternitz20-constant-sum/v1";

/// Terminal-only Winternitz for an unchanged 20-byte message.
///
/// A reversible enumerative encoder maps all 160-bit messages to 41 digits:
/// 32 radix-16 digits, four radix-18 digits, and five radix-20 digits, with sum 321.
/// There are no checksum chains. The default uses HASH160 and 16-byte initial
/// secrets; later chain nodes remain native width.
///
/// Verification authenticates the complete fixed-sum vector. It deliberately
/// omits individual upper bounds: an overflow digit can escape its own lookup
/// table, but is larger than every honest digit for that chain. Any distinct
/// vector with the same sum must decrease another coordinate, requiring chain
/// inversion/collision under the same honest-key assumptions as classic WOTS.
/// This relation must not be used as a locally range-checked digit fragment or
/// as message recovery. Use the bounded verifier for explicit radix checks.
///
/// ```
/// use bitcoin_lab::signatures::winternitz::ConstantSumWinternitz20;
/// type Wots = ConstantSumWinternitz20;
/// let key = Wots::generate_signing_key();
/// let public_key = Wots::public_key(&key);
/// let message = [0x42; 20];
/// let signature = Wots::sign(key, &message);
/// assert_eq!(Wots::decode_message(signature.digits()).unwrap(), message);
/// let verifier = Wots::checksig_verify_and_clear(&public_key);
/// let witness = signature.to_witness();
/// assert_eq!(witness.len(), 82);
/// // Append the surrounding protocol's terminal predicate to the fragment.
/// ```
#[derive(Debug)]
pub struct ConstantSumWinternitz20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16>(
    PhantomData<(H, P)>,
);

/// Consumed by signing; callers must also prevent reuse of its source seed.
pub struct ConstantSumSigningKey20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16> {
    seed: [u8; 32],
    marker: PhantomData<(H, P)>,
}
impl<H: ChainHash, P: PreimageSize<H>> fmt::Debug for ConstantSumSigningKey20<H, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConstantSumSigningKey20([redacted])")
    }
}

/// Forty-one independent endpoint commitments, in encoded-digit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantSumPublicKey20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16> {
    commitments: [H::Commitment; CHAINS],
    marker: PhantomData<P>,
}
impl<H: ChainHash, P: PreimageSize<H>> ConstantSumPublicKey20<H, P> {
    /// Restores commitments for this exact hash, preimage mode, and encoding.
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

/// An opening and encoded digit for each chain; digits are not message nibbles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstantSumSignature20<H: ChainHash = Hash160, P: PreimageSize<H> = Preimage16> {
    nodes: [P::Value; CHAINS],
    digits: [u8; CHAINS],
    marker: PhantomData<H>,
}
impl<H: ChainHash, P: PreimageSize<H>> ConstantSumSignature20<H, P> {
    pub fn digits(&self) -> &[u8; CHAINS] {
        &self.digits
    }
    pub fn chain_values(&self) -> &[P::Value; CHAINS] {
        &self.nodes
    }
    /// HASH160 uses 82 data items `[node_0, digit_0, ...]`; SHA-256 profiles
    /// use 123 items `[digit_0 / 2, node_0, 1 - digit_0 % 2, ...]`. Zero hints.
    /// All items coexist at entry; every number uses minimal ScriptNum encoding.
    pub fn to_witness(&self) -> Witness {
        let mut witness = Witness::new();
        for (node, &digit) in self.nodes.iter().zip(&self.digits) {
            if H::VALUE_BYTES == 20 {
                witness.push(node.as_ref());
                push_digit(&mut witness, digit);
            } else {
                push_digit(&mut witness, digit / 2);
                witness.push(node.as_ref());
                push_digit(&mut witness, 1 - digit % 2);
            }
        }
        witness
    }
}

/// Wrong digit count, range, sum, or a codeword outside the 160-bit encoder image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidConstantSumEncoding;
impl fmt::Display for InvalidConstantSumEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid constant-sum 20-byte message encoding")
    }
}
impl std::error::Error for InvalidConstantSumEncoding {}

impl<H: ChainHash, P: PreimageSize<H>> ConstantSumWinternitz20<H, P> {
    pub const MESSAGE_BYTES: usize = 20;
    pub const TOTAL_DIGITS: usize = CHAINS;
    pub const DIGIT_SUM: usize = SUM;
    pub const RADICES: [u8; CHAINS] = RADICES;
    pub const HASH_BYTES: usize = H::VALUE_BYTES;
    pub const COMMITMENT_BYTES: usize = H::COMMITMENT_BYTES;
    pub const PREIMAGE_BYTES: usize = P::START_BYTES;
    pub const WITNESS_DATA_ITEMS: usize = CHAINS * if H::VALUE_BYTES == 20 { 2 } else { 3 };

    pub fn signing_key_from_seed(seed: [u8; 32]) -> ConstantSumSigningKey20<H, P> {
        ConstantSumSigningKey20 {
            seed,
            marker: PhantomData,
        }
    }
    pub fn generate_signing_key() -> ConstantSumSigningKey20<H, P> {
        let mut seed = [0; 32];
        thread_rng().fill_bytes(&mut seed);
        Self::signing_key_from_seed(seed)
    }
    pub fn public_key(key: &ConstantSumSigningKey20<H, P>) -> ConstantSumPublicKey20<H, P> {
        let namespace = namespace::<H, P>(&key.seed);
        ConstantSumPublicKey20::from_commitments(core::array::from_fn(|i| {
            let start = chain_start::<H, P>(&namespace, i);
            H::commit(chain_hash::<H>(start.as_ref(), RADICES[i] as usize - 1))
        }))
    }
    /// Signs exactly these 20 bytes; no padding search or message modification.
    pub fn sign(
        key: ConstantSumSigningKey20<H, P>,
        message: &[u8; 20],
    ) -> ConstantSumSignature20<H, P> {
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
        ConstantSumSignature20 {
            nodes,
            digits,
            marker: PhantomData,
        }
    }
    pub fn encode_message(message: &[u8; 20]) -> [u8; CHAINS] {
        encoding().unrank(BigUint::from_bytes_be(message))
    }
    pub fn decode_message(digits: &[u8]) -> Result<[u8; 20], InvalidConstantSumEncoding> {
        let rank = encoding().rank(digits)?;
        if rank >= (BigUint::one() << 160usize) {
            return Err(InvalidConstantSumEncoding);
        }
        let bytes = rank.to_bytes_be();
        let mut message = [0; 20];
        message[20 - bytes.len()..].copy_from_slice(&bytes);
        Ok(message)
    }
    /// Exact size of the fixed-sum code, which is at least 2^160.
    pub fn codeword_count() -> BigUint {
        encoding().counts[0][SUM].clone()
    }

    /// Consumes the signature using the whole-vector fixed-sum security relation.
    /// Preserves unrelated main/altstack state; leaves no result. The surrounding
    /// protocol must append its terminal predicate. See the type's security contract.
    pub fn checksig_verify_and_clear(public_key: &ConstantSumPublicKey20<H, P>) -> Script {
        Self::verifier(public_key, false)
    }
    /// Adds explicit per-digit radix bounds, at additional script cost.
    /// This still does not check the offchain encoder's rank < 2^160 condition.
    pub fn checksig_verify_bounded_and_clear(public_key: &ConstantSumPublicKey20<H, P>) -> Script {
        Self::verifier(public_key, true)
    }
    fn verifier(public_key: &ConstantSumPublicKey20<H, P>, bounded: bool) -> Script {
        let strided = H::VALUE_BYTES == 32;
        script! {
            { if strided { CHAINS as i64 - SUM as i64 } else { -(SUM as i64) } } OP_TOALTSTACK
            for i in (0..CHAINS).rev() {
                if bounded {
                    if strided {
                        // Before consuming the bit, quotient is two items deep.
                        OP_2 OP_PICK { RADICES[i] as usize / 2 } OP_LESSTHAN OP_VERIFY
                    } else {
                        OP_DUP { RADICES[i] as usize } OP_LESSTHAN OP_VERIFY
                    }
                }
                { verify_sum_chain::<H>(public_key.commitments[i], RADICES[i] as usize,
                    if strided { SumChainStyle::Strided { split: 0 } }
                    else { SumChainStyle::Numeric { split: RADICES[i] as usize / 2 } }, false) }
            }
            OP_FROMALTSTACK OP_0 OP_NUMEQUALVERIFY
        }
    }
}

fn push_digit(witness: &mut Witness, digit: u8) {
    if digit == 0 {
        witness.push([]);
    } else {
        witness.push([digit]);
    }
}

fn namespace<H: ChainHash, P: PreimageSize<H>>(seed: &[u8; 32]) -> H::Value {
    H::hash_parts(&[
        DOMAIN,
        H::DOMAIN,
        P::DOMAIN_PREFIX,
        &RADICES,
        &(SUM as u16).to_be_bytes(),
        seed,
    ])
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

// counts[i][s] counts suffixes starting at i with sum s. All arithmetic is
// exact; no floating-point approximation participates in encoding or capacity.
struct Encoding {
    counts: Vec<Vec<BigUint>>,
}
fn encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut counts = vec![vec![BigUint::zero(); SUM + 1]; CHAINS + 1];
        counts[CHAINS][0] = BigUint::one();
        for i in (0..CHAINS).rev() {
            for s in 0..=SUM {
                for d in 0..(RADICES[i] as usize).min(s + 1) {
                    let suffix = counts[i + 1][s - d].clone();
                    counts[i][s] += suffix;
                }
            }
        }
        assert!(counts[0][SUM] >= (BigUint::one() << 160usize));
        Encoding { counts }
    })
}
impl Encoding {
    fn unrank(&self, mut rank: BigUint) -> [u8; CHAINS] {
        assert!(rank < self.counts[0][SUM]);
        let mut sum = SUM;
        let digits = core::array::from_fn(|i| {
            for d in 0..(RADICES[i] as usize).min(sum + 1) {
                let count = &self.counts[i + 1][sum - d];
                if &rank < count {
                    sum -= d;
                    return d as u8;
                }
                rank -= count;
            }
            unreachable!("rank is within the suffix count")
        });
        assert_eq!(sum, 0);
        assert!(rank.is_zero());
        digits
    }
    fn rank(&self, digits: &[u8]) -> Result<BigUint, InvalidConstantSumEncoding> {
        if digits.len() != CHAINS {
            return Err(InvalidConstantSumEncoding);
        }
        let mut sum = SUM;
        let mut rank = BigUint::zero();
        for (i, &d) in digits.iter().enumerate() {
            if d >= RADICES[i] || d as usize > sum {
                return Err(InvalidConstantSumEncoding);
            }
            for smaller in 0..d as usize {
                rank += &self.counts[i + 1][sum - smaller];
            }
            sum -= d as usize;
        }
        if sum != 0 {
            return Err(InvalidConstantSumEncoding);
        }
        Ok(rank)
    }
}

#[cfg(test)]
#[path = "constant_sum_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "constant_sum_overflow_tests.rs"]
mod overflow_tests;
