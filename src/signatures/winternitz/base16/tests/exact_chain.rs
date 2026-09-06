use super::{hash_chain, verify_chain_exact, FullWidth, Hash160, HASH_BYTES};
use crate::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, ScriptCompilation},
};

#[test]
fn exact_chain_binds_every_digit_and_rejects_malformed_residuals() {
    for digit_bits in 1..=4 {
        let maximum = (1u8 << digit_bits) - 1;
        let start = [0x42; HASH_BYTES];
        let endpoint = hash_chain::<Hash160>(start, maximum);
        let verifier = script! {
            { verify_chain_exact::<Hash160, FullWidth>(endpoint, digit_bits, true) }
            OP_DROP OP_TRUE
        }
        .compile_with_policy();

        for actual_digit in 0..=maximum {
            let node = hash_chain::<Hash160>(start, actual_digit);
            for claimed_digit in 0..=maximum {
                let digit_item = if claimed_digit == 0 {
                    Vec::new()
                } else {
                    vec![claimed_digit]
                };
                let result = execute_raw_script_with_inputs_strict(
                    verifier.to_bytes(),
                    vec![digit_item, node.to_vec()],
                );
                assert_eq!(
                    result.success,
                    actual_digit == claimed_digit,
                    "width {digit_bits}, actual {actual_digit}, claimed {claimed_digit}: {result}"
                );
            }
        }

        for invalid in [
            vec![0x81],
            vec![maximum + 1],
            vec![0x7f],
            vec![0xff, 0xff, 0xff, 0x7f],
            vec![0xff, 0xff, 0xff, 0xff, 0],
        ] {
            let result = execute_raw_script_with_inputs_strict(
                verifier.to_bytes(),
                vec![invalid.clone(), endpoint.to_vec()],
            );
            assert!(
                !result.success,
                "width {digit_bits} accepted malformed digit {invalid:?}: {result}"
            );
        }

        // Direct equality and every hashed path retain the strict raw
        // chain-length contract, independent of the digit relation.
        for length in [0, HASH_BYTES - 1, HASH_BYTES + 1] {
            for digit_item in [Vec::new(), vec![maximum]] {
                let result = execute_raw_script_with_inputs_strict(
                    verifier.to_bytes(),
                    vec![digit_item, vec![0x42; length]],
                );
                assert!(
                    !result.success,
                    "width {digit_bits}, length {length}: {result}"
                );
            }
        }
    }
}
