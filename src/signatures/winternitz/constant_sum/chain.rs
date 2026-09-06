//! Chain fragments for a terminal fixed-sum Winternitz verifier.
//!
//! The unbounded profiles deliberately rely on the complete verifier's exact
//! fixed-sum relation. They do not validate individual upper digit bounds.
use crate::{
    signatures::winternitz::shared::ChainHash,
    support::script::{script, Script},
};

/// Table representation. A zero split builds the full table; a positive split
/// conditionally advances the chain and removes that many table entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SumChainStyle {
    /// Input `[node, digit]`; adds `digit` to the altstack accumulator.
    Numeric { split: usize },
    /// Input `[quotient, node, bit]`; adds `2 * quotient - bit` to the
    /// accumulator. The digit is that value plus `(radix - 1) % 2`.
    Strided { split: usize },
}

/// Authenticate one fixed-sum chain and update the accumulator on the altstack.
///
/// `bounded` upper-clamps the selector for reference comparisons. Without it,
/// a selector beyond the radix may escape the local table; its claimed digit
/// then exceeds every canonical signer digit for this chain. For a signature
/// of a canonical vector, decreasing any component still requires a chain
/// inversion, whereas increasing components cannot preserve the complete
/// vector's exact fixed sum. This argument requires the surrounding verifier
/// to check that sum and the signer to emit canonical in-range vectors.
///
/// Negative selectors and oversized ScriptNums fail. `MINIMALIF` checks the
/// strided bit. At odd radices, `quotient = 0, bit = 1` is explicitly rejected
/// because it would represent digit -1 while selecting table index zero.
/// Unrelated main/altstack state is preserved; raw node widths are relaxed.
/// Every table and temporary item is removed. The accumulator remains on top
/// of the altstack, updated by the quantity documented on `SumChainStyle`.
pub(super) fn verify_sum_chain<H: ChainHash>(
    endpoint: H::Commitment,
    radix: usize,
    style: SumChainStyle,
    bounded: bool,
) -> Script {
    assert!(radix >= 2, "a sum chain requires at least two digits");
    let maximum = radix - 1;
    let (stride, selector_radix, split) = match style {
        SumChainStyle::Numeric { split } => (1, radix, split),
        SumChainStyle::Strided { split } => (2, maximum / 2 + 1, split),
    };
    assert!(
        split <= selector_radix / 2,
        "split exceeds the table's lower half"
    );
    let table_len = selector_radix - split;
    script! {
        if stride == 2 {
            OP_IF
                if maximum % 2 == 0 {
                    OP_OVER OP_0NOTEQUAL OP_VERIFY
                }
                { H::hash_script() }
                OP_FROMALTSTACK OP_1SUB OP_TOALTSTACK
            OP_ENDIF
            OP_SWAP
        }
        if bounded {
            { selector_radix - 1 } OP_MIN
        }
        OP_DUP
        if stride == 2 {
            OP_DUP OP_ADD
        }
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        if split == 0 {
            OP_TOALTSTACK
        } else {
            { split } OP_2DUP OP_LESSTHAN
            OP_IF
                OP_DROP OP_TOALTSTACK
                for _ in 0..stride * split {
                    { H::hash_script() }
                }
            OP_ELSE
                OP_SUB OP_TOALTSTACK
            OP_ENDIF
        }
        for _ in 1..table_len {
            OP_DUP
            for _ in 0..stride {
                { H::hash_script() }
            }
        }
        OP_FROMALTSTACK OP_PICK
        { H::commit_script() }
        { endpoint.as_ref().to_vec() } OP_EQUALVERIFY
        for _ in 0..table_len / 2 {
            OP_2DROP
        }
        if table_len % 2 != 0 {
            OP_DROP
        }
    }
}

#[cfg(test)]
#[path = "tests/chain.rs"]
mod tests;
