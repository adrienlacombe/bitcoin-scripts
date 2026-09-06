//! Winternitz signing, verification, and high-level typed APIs.

mod api;
mod chain_hash;
mod fast;
mod preimage;
pub mod signing;
pub mod utils;
pub mod verification;

pub use api::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80, LOG2_BASE,
};
pub use chain_hash::{ChainHash, Hash160, Sha256};
pub use fast::{
    FastChainValue, FastPublicKey, FastSignature, FastSigningKey, FastWinternitz, FastWots16,
    FastWots32, FastWots4, FastWots64, FastWots80, InvalidFastPublicKeyLength,
};
pub use verification::*;

pub use preimage::{FullWidth, Preimage16, PreimageSize, ShortChainValue};
