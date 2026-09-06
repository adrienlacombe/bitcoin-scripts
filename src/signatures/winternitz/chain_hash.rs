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
    /// Fixed-size chain node and public endpoint.
    type Value: AsRef<[u8]> + Copy + core::fmt::Debug + Eq;
    /// Chain node and commitment width in bytes.
    const VALUE_BYTES: usize;
    /// Domain separating this hash choice in deterministic key derivation.
    const DOMAIN: &'static [u8];
    /// Hashes concatenated byte slices without allocating a concatenation.
    fn hash_parts(parts: &[&[u8]]) -> Self::Value;
    /// The native one-opcode chain step.
    fn hash_script() -> Script;
}

/// HASH160 = RIPEMD-160(SHA-256(input)), with 20-byte nodes and commitments.
/// This is the default and has the lower onchain byte cost.
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
            const VALUE_BYTES: usize = $bytes;
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
