//! Winternitz constructions: direct base-16, constant-sum, and the original API.
pub mod base16;
pub mod constant_sum;
pub mod legacy;
pub mod shared;

pub use base16::{
    FastChainValue, FastCommitment, FastPublicKey, FastSignature, FastSigningKey, FastWinternitz,
    FastWots16, FastWots32, FastWots4, FastWots64, FastWots80, InvalidFastPublicKeyLength,
};
pub use constant_sum::{
    ConstantSumPublicKey20, ConstantSumSignature20, ConstantSumSigningKey20,
    ConstantSumWinternitz20, InvalidConstantSumEncoding,
};
pub use legacy::verification::*;
pub use legacy::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80, LOG2_BASE,
};
pub use shared::{
    ChainHash, FullWidth, Hash160, Preimage16, PreimageSize, Sha256, Sha256Hash160, ShortChainValue,
};
