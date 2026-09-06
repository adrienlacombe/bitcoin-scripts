//! Native Bitcoin hash choices for the typed Winternitz implementation.

use crate::support::script::{script, Script};
use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};

mod private {
    pub trait Sealed {}
}

/// A supported chain hash, selected when the key and verifier are created.
///
/// Sealed to native HASH160 and SHA-256 so host hashing, Script hashing,
/// endpoint width, and key derivation cannot disagree.
pub trait ChainHash: private::Sealed + Copy + core::fmt::Debug + Eq {
    /// Fixed-size intermediate chain node.
    type Value: AsRef<[u8]> + Copy + core::fmt::Debug + Eq;
    /// Public commitment to a completed chain.
    type Commitment: AsRef<[u8]> + Copy + core::fmt::Debug + Eq;
    /// Intermediate chain node width in bytes.
    const VALUE_BYTES: usize;
    /// Public commitment width in bytes.
    const COMMITMENT_BYTES: usize;
    /// Domain separating this hash choice in deterministic key derivation.
    const DOMAIN: &'static [u8];
    /// Hashes concatenated byte slices without allocating a concatenation.
    fn hash_parts(parts: &[&[u8]]) -> Self::Value;
    /// The native one-opcode chain step.
    fn hash_script() -> Script;
    /// Commits to a completed chain; identity for the original hash profiles.
    fn commit(value: Self::Value) -> Self::Commitment;
    /// Converts the computed endpoint to its committed representation.
    fn commit_script() -> Script;
}

/// HASH160 = RIPEMD-160(SHA-256(input)), with 20-byte nodes and commitments.
/// This is the compatible default with 20-byte witness nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hash160;

/// SHA-256 (SHA-2), with 32-byte nodes and commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256;

macro_rules! chain_hash {
    ($name:ident, $hash:ty, $bytes:literal, $domain:literal, $opcode:ident) => {
        impl private::Sealed for $name {}
        impl ChainHash for $name {
            type Value = [u8; $bytes];
            type Commitment = Self::Value;
            const VALUE_BYTES: usize = $bytes;
            const COMMITMENT_BYTES: usize = $bytes;
            const DOMAIN: &'static [u8] = $domain;

            fn hash_parts(parts: &[&[u8]]) -> Self::Value {
                let mut engine = <$hash>::engine();
                for part in parts {
                    engine.input(part);
                }
                *<$hash>::from_engine(engine).as_byte_array()
            }

            fn hash_script() -> Script {
                script! { $opcode }
            }
            fn commit(value: Self::Value) -> Self::Commitment {
                value
            }
            fn commit_script() -> Script {
                script! {}
            }
        }
    };
}

chain_hash!(
    Hash160,
    hash160::Hash,
    20,
    b"bitcoin-lab/winternitz-hash160/v1",
    OP_HASH160
);
chain_hash!(
    Sha256,
    sha256::Hash,
    32,
    b"bitcoin-lab/winternitz-sha256/v1",
    OP_SHA256
);

/// SHA-256 chains with HASH160 commitments to their completed endpoints.
///
/// Intermediate nodes are 32 bytes; public commitments are 20 bytes. Native
/// SHA256 pairs fuse to HASH256, reducing script size. The commitment retains
/// HASH160's 160-bit output width, not SHA-256's collision-security bound.
/// Size-oriented verifiers accept arbitrary raw node lengths even at the
/// maximum digit because the final commitment hash normalizes the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Hash160;

impl private::Sealed for Sha256Hash160 {}
impl ChainHash for Sha256Hash160 {
    type Value = [u8; 32];
    type Commitment = [u8; 20];
    const VALUE_BYTES: usize = 32;
    const COMMITMENT_BYTES: usize = 20;
    const DOMAIN: &'static [u8] = b"bitcoin-lab/winternitz-sha256-hash160/v1";
    fn hash_parts(parts: &[&[u8]]) -> Self::Value {
        Sha256::hash_parts(parts)
    }
    fn hash_script() -> Script {
        script! { OP_SHA256 }
    }
    fn commit(value: Self::Value) -> Self::Commitment {
        *hash160::Hash::hash(&value).as_byte_array()
    }
    fn commit_script() -> Script {
        script! { OP_HASH160 }
    }
}
