// Preserve the historical native-width regression vectors explicitly.
type FullWidthWots32 = FastWinternitz<32, Hash160, FullWidth>;

use super::{
    hash_chain, verify_chain_size_optimized, FastWinternitz, FullWidth, Hash160, HASH_BYTES,
};
use crate::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};

fn integer(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

#[test]
fn clamped_chains_bind_the_recovered_digit_and_reject_malformed_numbers() {
    // The supported message/checksum partitions use widths 2 through 4.
    for width in 2..=4 {
        let maximum = (1u8 << width) - 1;
        let start = [0x35; HASH_BYTES];
        let endpoint = hash_chain::<Hash160>(start, maximum);
        for actual_digit in 0..=maximum {
            let verifier = script! {
                { verify_chain_size_optimized::<Hash160>(endpoint, width, true) }
                OP_FROMALTSTACK { actual_digit } OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy();
            let node = hash_chain::<Hash160>(start, actual_digit);
            for claimed in (0..=i64::from(maximum) + 2).chain([127, 128, i64::from(i32::MAX)]) {
                let result = execute_raw_script_with_inputs_strict(
                    verifier.to_bytes(),
                    vec![node.to_vec(), integer(claimed)],
                );
                assert_eq!(
                    result.success,
                    claimed.min(i64::from(maximum)) == i64::from(actual_digit),
                    "width={width}, actual={actual_digit}, claimed={claimed}: {result}",
                );
            }
            for invalid in [
                integer(-1),
                integer(i64::from(i32::MIN)),
                integer(1i64 << 31),
                vec![0; 5],
            ] {
                let result = execute_raw_script_with_inputs_strict(
                    verifier.to_bytes(),
                    vec![node.to_vec(), invalid.clone()],
                );
                assert!(
                    !result.success,
                    "width={width}, invalid={invalid:?}: {result}"
                );
            }
        }
    }
}

fn recover_and_check<const N: usize>(verifier: Script, message: &[u8; N]) -> Script {
    let digits: Vec<_> = message
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 15])
        .collect();
    script! {
        { verifier }
        for digit in digits.into_iter().rev() {
            { digit } OP_EQUALVERIFY
        }
        OP_TRUE
    }
}

fn check_message_sizes<const N: usize>() {
    let key = FastWinternitz::<N, Hash160, FullWidth>::signing_key_from_seed([0x62; 32]);
    let public_key = FastWinternitz::<N, Hash160, FullWidth>::public_key(&key);
    for message in [[0; N], [0xff; N], std::array::from_fn(|i| (i * 37) as u8)] {
        let signature = FastWinternitz::<N, Hash160, FullWidth>::sign(
            FastWinternitz::<N, Hash160, FullWidth>::signing_key_from_seed([0x62; 32]),
            &message,
        );
        for verifier in [
            recover_and_check(
                FastWinternitz::<N, Hash160, FullWidth>::checksig_verify_clamped(&public_key),
                &message,
            ),
            script! { { FastWinternitz::<N, Hash160, FullWidth>::checksig_verify_clamped_and_clear(&public_key) } OP_TRUE },
        ] {
            let result = execute_raw_script_with_inputs_strict(
                verifier.compile_with_policy().to_bytes(),
                signature.to_size_optimized_witness().to_vec(),
            );
            assert!(result.success, "N={N}, message={message:?}: {result}");
            assert_eq!(result.final_stack.len(), 1);
        }
    }
}

#[test]
fn clamped_profiles_roundtrip_supported_message_boundaries() {
    check_message_sizes::<1>();
    check_message_sizes::<4>();
    check_message_sizes::<16>();
    check_message_sizes::<32>();
    check_message_sizes::<64>();
    check_message_sizes::<80>();
}

#[test]
fn clamped_checksum_binds_forwardable_chain_nodes_and_normalizes_raw_maxima() {
    let message = std::array::from_fn(|i| (i * 37) as u8);
    let key = FullWidthWots32::signing_key_from_seed([0x42; 32]);
    let public_key = FullWidthWots32::public_key(&key);
    let signature = FullWidthWots32::sign(key, &message);
    let witness = signature.to_size_optimized_witness().to_vec();
    let recovery = recover_and_check(
        FullWidthWots32::checksig_verify_clamped(&public_key),
        &message,
    )
    .compile_with_policy();
    let terminal =
        script! { { FullWidthWots32::checksig_verify_clamped_and_clear(&public_key) } OP_TRUE }
            .compile_with_policy();
    for index in 0..FullWidthWots32::TOTAL_DIGITS {
        let pair = 2 * if index < FullWidthWots32::MESSAGE_DIGITS {
            index
        } else {
            FullWidthWots32::MESSAGE_DIGITS + FullWidthWots32::TOTAL_DIGITS - 1 - index
        };
        let mut changed = witness.clone();
        changed[pair] = public_key.chain_ends[index].to_vec();
        changed[pair + 1] = integer(127);
        let already_maximum = signature.digits[index] == FullWidthWots32::chain_max_digit(index);
        for leaf in [&recovery, &terminal] {
            let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), changed.clone());
            assert_eq!(result.success, already_maximum, "chain={index}: {result}");
        }
    }
    for missing_items in 1..=2 {
        let mut malformed = witness.clone();
        malformed.truncate(malformed.len() - missing_items);
        let result = execute_raw_script_with_inputs_strict(terminal.to_bytes(), malformed);
        assert!(!result.success);
    }
    let mut extra = witness;
    extra.insert(0, Vec::new());
    let result = execute_raw_script_with_inputs_strict(terminal.to_bytes(), extra);
    assert!(!result.success);
}
