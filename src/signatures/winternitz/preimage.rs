//! Initial secret widths; subsequent nodes always use the native hash width.
use super::chain_hash::ChainHash;

mod private {
    pub trait Sealed {}
}

/// Supported initial secret widths for a native chain hash.
///
/// The choice is part of key and signature types. It changes deterministic
/// derivation and must be persisted alongside the seed and hash choice.
pub trait PreimageSize<H: ChainHash>: private::Sealed + Copy + core::fmt::Debug + Eq {
    /// A selected signature node, which may be the initial secret.
    type Value: AsRef<[u8]> + Copy + core::fmt::Debug + Eq;
    /// Width of the initial secret. Subsequent nodes have `H::VALUE_BYTES`.
    const START_BYTES: usize;
    /// Additional derivation domain; empty for the original full-width scheme.
    const DOMAIN_PREFIX: &'static [u8];
    /// Converts derived secret material into an initial chain value.
    fn from_start(material: H::Value) -> Self::Value;
    /// Wraps a native hash output without truncating it.
    fn from_hash(value: H::Value) -> Self::Value;
}

/// Original full-width initial secrets; preserves existing keys and vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullWidth;

/// 16-byte initial secret preimages; native hash outputs remain untruncated.
///
/// This limits exhaustive initial-secret search to at most 128 classical bits
/// before multi-target losses. It does not increase HASH160 collision strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preimage16;

/// A signature opening under [`Preimage16`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortChainValue<H: ChainHash> {
    /// Revealed only for digit zero.
    Secret([u8; 16]),
    /// Revealed after one or more native hash steps.
    Hashed(H::Value),
}

impl<H: ChainHash> AsRef<[u8]> for ShortChainValue<H> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Secret(value) => value,
            Self::Hashed(value) => value.as_ref(),
        }
    }
}

impl private::Sealed for FullWidth {}
impl private::Sealed for Preimage16 {}

impl<H: ChainHash> PreimageSize<H> for FullWidth {
    type Value = H::Value;
    const START_BYTES: usize = H::VALUE_BYTES;
    const DOMAIN_PREFIX: &'static [u8] = b"";
    fn from_start(material: H::Value) -> Self::Value {
        material
    }
    fn from_hash(value: H::Value) -> Self::Value {
        value
    }
}

impl<H: ChainHash> PreimageSize<H> for Preimage16 {
    type Value = ShortChainValue<H>;
    const START_BYTES: usize = 16;
    const DOMAIN_PREFIX: &'static [u8] = b"bitcoin-lab/winternitz-preimage16/v1";
    fn from_start(material: H::Value) -> Self::Value {
        Self::Value::Secret(
            material.as_ref()[..16]
                .try_into()
                .expect("native hash width is at least 16"),
        )
    }
    fn from_hash(value: H::Value) -> Self::Value {
        Self::Value::Hashed(value)
    }
}
