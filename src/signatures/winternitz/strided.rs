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
mod tests {
    use super::*;
    use crate::{
        signatures::winternitz::{FullWidth, Hash160, Preimage16, Sha256, Sha256Hash160},
        support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
    };

    fn integer(value: i64) -> Vec<u8> {
        let mut bytes = [0; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn exhaustive_chain<H: ChainHash, P: PreimageSize<H>>() {
        for bits in 1..=4 {
            let maximum = (1usize << bits) - 1;
            let mut native = H::hash_parts(&[b"strided-chain-tests/v1"]);
            let mut selected = P::from_start(native);
            let mut nodes = vec![selected.as_ref().to_vec()];
            for _ in 0..maximum {
                native = H::hash_parts(&[selected.as_ref()]);
                selected = P::from_hash(native);
                nodes.push(selected.as_ref().to_vec());
            }
            let endpoint = H::commit(native);
            for actual in 0..=maximum {
                for weight in [1, 8, 64] {
                    let expected_sum = weight as i64 * (actual as i64 - 1);
                    let complete = script! {
                        OP_7 OP_TOALTSTACK OP_0 OP_TOALTSTACK
                        { verify_chain_strided::<H>(endpoint, bits, weight) }
                        OP_FROMALTSTACK { expected_sum } OP_NUMEQUALVERIFY
                        { native.as_ref().to_vec() } OP_EQUALVERIFY
                        OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
                    }
                    .compile_with_policy();
                    for quotient in (-1..=maximum as i64 / 2 + 2).chain([127, 128, i32::MAX as i64])
                    {
                        for bit in [0, 1] {
                            let result = execute_raw_script_with_inputs_strict(
                                complete.to_bytes(),
                                vec![
                                    native.as_ref().to_vec(),
                                    integer(quotient),
                                    nodes[actual].clone(),
                                    integer(bit),
                                ],
                            );
                            let recovered = 2 * quotient.min(maximum as i64 / 2) + 1 - bit;
                            assert_eq!(result.success, recovered == actual as i64,
                                "bits={bits}, weight={weight}, actual={actual}, q={quotient}, bit={bit}: {result}");
                        }
                    }
                    for invalid in [integer(i32::MIN as i64), integer(1i64 << 31), vec![0; 5]] {
                        let result = execute_raw_script_with_inputs_strict(
                            complete.to_bytes(),
                            vec![
                                native.as_ref().to_vec(),
                                invalid,
                                nodes[actual].clone(),
                                integer(1 - (actual as i64 & 1)),
                            ],
                        );
                        assert!(!result.success, "invalid quotient: {result}");
                    }
                    for invalid in [vec![0], vec![2], vec![0x81], vec![0x80], vec![1, 0]] {
                        let result = execute_raw_script_with_inputs_strict(
                            complete.to_bytes(),
                            vec![
                                native.as_ref().to_vec(),
                                integer(actual as i64 / 2),
                                nodes[actual].clone(),
                                invalid,
                            ],
                        );
                        assert!(!result.success, "noncanonical branch bit: {result}");
                    }
                }
            }
        }
    }

    #[test]
    fn strided_tables_authenticate_the_same_digit_used_by_the_checksum() {
        exhaustive_chain::<Hash160, FullWidth>();
        exhaustive_chain::<Hash160, Preimage16>();
        exhaustive_chain::<Sha256, FullWidth>();
        exhaustive_chain::<Sha256, Preimage16>();
        exhaustive_chain::<Sha256Hash160, FullWidth>();
        exhaustive_chain::<Sha256Hash160, Preimage16>();
    }

    fn roundtrip_and_attacks<const N: usize, H: ChainHash, P: PreimageSize<H>>() {
        type ScriptBytes = Vec<u8>;
        let seed = [0x4d; 32];
        let key = FastWinternitz::<N, H, P>::signing_key_from_seed(seed);
        let public_key = FastWinternitz::<N, H, P>::public_key(&key);
        let complete: ScriptBytes = script! {
            OP_7 OP_TOALTSTACK
            { FastWinternitz::<N, H, P>::checksig_verify_strided_and_clear(&public_key) }
            OP_9 OP_EQUALVERIFY OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for message in [
            [0; N],
            [0xff; N],
            std::array::from_fn(|i| (i * 37 + 15) as u8),
        ] {
            let signature = FastWinternitz::<N, H, P>::sign(
                FastWinternitz::<N, H, P>::signing_key_from_seed(seed),
                &message,
            );
            let signature_witness = signature.to_strided_witness();
            assert_eq!(
                signature_witness.len(),
                3 * FastWinternitz::<N, H, P>::TOTAL_DIGITS
            );
            let witness = [vec![integer(9)], signature_witness.to_vec()].concat();
            let execute = |items| execute_raw_script_with_inputs_strict(complete.clone(), items);
            let result = execute(witness.clone());
            assert!(result.success, "roundtrip N={N}: {result}");
            assert!(result.stats.max_nb_stack_items <= 1000);
            let mut missing = witness.clone();
            missing.pop();
            assert!(!execute(missing).success);
            let mut extra = witness.clone();
            extra.insert(0, integer(9));
            assert!(!execute(extra).success);
            for index in 0..FastWinternitz::<N, H, P>::TOTAL_DIGITS {
                let maximum = FastWinternitz::<N, H, P>::chain_max_digit(index);
                let digit = signature.digits()[index];
                if digit < maximum {
                    // Forwarding needs no secret. The chain verifies after
                    // this adjustment, so only checksum binding can reject it.
                    let mut forged = witness.clone();
                    let offset = 1 + 3 * index;
                    forged[offset] = integer((digit as i64 + 1) / 2);
                    forged[offset + 1] = H::hash_parts(&[&forged[offset + 1]]).as_ref().to_vec();
                    forged[offset + 2] = integer(1 - ((digit as i64 + 1) & 1));
                    assert!(!execute(forged).success, "forwarded chain {index}, N={N}");
                }
                if digit / 2 == maximum / 2 {
                    let mut alias = witness.clone();
                    alias[1 + 3 * index] = integer(i32::MAX as i64);
                    assert!(
                        execute(alias).success,
                        "clamped quotient alias chain {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn strided_terminal_roundtrips_and_rejects_forwarding_and_malformed_shapes() {
        roundtrip_and_attacks::<1, Hash160, FullWidth>();
        roundtrip_and_attacks::<4, Hash160, Preimage16>();
        roundtrip_and_attacks::<16, Sha256, FullWidth>();
        roundtrip_and_attacks::<32, Sha256, Preimage16>();
        roundtrip_and_attacks::<64, Sha256Hash160, FullWidth>();
        roundtrip_and_attacks::<80, Sha256Hash160, Preimage16>();
    }
}
