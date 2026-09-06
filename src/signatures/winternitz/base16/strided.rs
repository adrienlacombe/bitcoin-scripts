//! Terminal verifier combining one canonical bit with a numeric stride-two lookup.
use super::{
    push_digit, ChainHash, FastCommitment, FastPublicKey, FastSignature, FastWinternitz,
    PreimageSize,
};
use crate::support::script::{script, Script};
use bitcoin::Witness;

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastSignature<MESSAGE_BYTES, H, P>
{
    /// Serializes each chain as `[digit / 2, node, 1 - (digit % 2)]`.
    ///
    /// The canonical bit selects an optional first hash; the quotient selects
    /// from every second subsequent chain node. The terminal verifier clamps
    /// the quotient to the chain's maximum quotient before authentication and
    /// checksum accumulation. There are three data items per chain and no
    /// auxiliary hints; all items coexist at script entry.
    pub fn to_strided_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (&digit, node) in self.digits.iter().zip(self.chain_values.iter()) {
            push_digit(&mut witness, digit >> 1);
            witness.push(node.as_ref());
            push_digit(&mut witness, 1 - (digit & 1));
        }
        witness
    }
}

impl<const MESSAGE_BYTES: usize, H: ChainHash, P: PreimageSize<H>>
    FastWinternitz<MESSAGE_BYTES, H, P>
{
    /// Verifies a stride-two numeric/bit witness and consumes the message.
    ///
    /// Accepts [`FastSignature::to_strided_witness`]. Tapscript `MINIMALIF`
    /// authenticates the low bit. The quotient is upper-clamped before both
    /// table selection and checksum accumulation; negative quotients and
    /// oversized ScriptNum encodings fail. Each authenticated digit is `2 * min(quotient, max / 2)
    /// + 1 - bit`. As with the numeric size profiles, raw chain widths are
    /// relaxed. The successful fragment preserves unrelated stack state and
    /// leaves no result; append the surrounding protocol's terminal predicate.
    ///
    /// SHA-256's pairs of native hashes compile to `OP_HASH256`, making this
    /// profile a useful script/witness tradeoff between numeric and bitwise
    /// witnesses. It uses three signature data items per chain, with no
    /// auxiliary hints.
    pub fn checksig_verify_strided_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES, H, P>,
    ) -> Script {
        Self::assert_public_key(public_key);
        let checksum_places: usize = (0..Self::CHECKSUM_DIGITS)
            .map(Self::checksum_digit_place)
            .sum();
        // Each chain contributes weight * (digit - 1). The checksum relation
        // is sum(message digits) + sum(weighted checksum digits) = 15 * n.
        let initial_sum = checksum_places as i64 - 14 * Self::MESSAGE_DIGITS as i64;
        script! {
            { initial_sum } OP_TOALTSTACK
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_strided::<H>(
                    public_key.chain_ends[chain_index],
                    Self::chain_digit_bits(chain_index),
                    if chain_index < Self::MESSAGE_DIGITS {
                        1
                    } else {
                        Self::checksum_digit_place(chain_index - Self::MESSAGE_DIGITS)
                    },
                ) }
            }
            OP_FROMALTSTACK OP_0 OP_NUMEQUALVERIFY
        }
    }
}

/// Consumes `[... quotient, node, bit]`, adds `weight * (digit - 1)` to the
/// altstack accumulator, and authenticates the same digit against `endpoint`.
fn verify_chain_strided<H: ChainHash>(
    endpoint: FastCommitment<H>,
    digit_bits: usize,
    weight: usize,
) -> Script {
    debug_assert!(digit_bits > 0);
    debug_assert!(weight.is_power_of_two());
    let table_len = 1usize << (digit_bits - 1);
    script! {
        OP_IF
            { H::hash_script() }
            OP_FROMALTSTACK { weight } OP_SUB OP_TOALTSTACK
        OP_ENDIF
        OP_SWAP { table_len - 1 } OP_MIN
        OP_DUP
        for _ in 0..=weight.trailing_zeros() {
            OP_DUP OP_ADD
        }
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_TOALTSTACK
        for _ in 1..table_len {
            OP_DUP { H::hash_script() } { H::hash_script() }
        }
        OP_FROMALTSTACK OP_PICK
        { H::commit_script() }
        { endpoint.as_ref().to_vec() } OP_EQUALVERIFY
        for _ in 0..table_len / 2 {
            OP_2DROP
        }
        if table_len == 1 {
            OP_DROP
        }
    }
}

#[cfg(test)]
#[path = "tests/strided.rs"]
mod tests;
