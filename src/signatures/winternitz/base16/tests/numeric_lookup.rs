//! Exhaustive lookup-selector checks, including access to unrelated stack items.
use super::{verify_chain_minimal, verify_chain_size_optimized};
use crate::{
    signatures::winternitz::{
        ChainHash, FullWidth, Hash160, Preimage16, PreimageSize, Sha256, Sha256Hash160,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, ScriptCompilation},
    },
};

fn integer(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn exhaustive<H: ChainHash, P: PreimageSize<H>>() {
    for bits in 1..=4 {
        let maximum = (1usize << bits) - 1;
        let mut native = H::hash_parts(&[b"numeric-lookup-exhaustive/v1"]);
        let mut selected = P::from_start(native);
        let mut nodes = vec![selected.as_ref().to_vec()];
        for _ in 0..maximum {
            native = H::hash_parts(&[selected.as_ref()]);
            selected = P::from_hash(native);
            nodes.push(selected.as_ref().to_vec());
        }
        let endpoint = H::commit(native);
        for actual in 0..=maximum {
            for profile in 0..3 {
                let fragment = if profile == 0 {
                    verify_chain_minimal::<H, P>(endpoint, bits, true)
                } else {
                    script! {
                        { verify_chain_size_optimized::<H>(endpoint, bits, profile == 2) }
                        OP_FROMALTSTACK
                    }
                };
                let complete = script! {
                    OP_7 OP_TOALTSTACK
                    { fragment }
                    { actual } OP_EQUALVERIFY
                    { native.as_ref().to_vec() } OP_EQUALVERIFY
                    OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy();
                for claimed in (-2..=maximum as i64 + 3).chain([127, 128, i32::MAX as i64]) {
                    let pair = if profile == 0 {
                        vec![integer(claimed), nodes[actual].clone()]
                    } else {
                        vec![nodes[actual].clone(), integer(claimed)]
                    };
                    // A table selector must never escape into this preceding,
                    // deliberately endpoint-valued witness item.
                    let witness = [vec![native.as_ref().to_vec()], pair].concat();
                    let result =
                        execute_raw_script_with_inputs_strict(complete.to_bytes(), witness);
                    let accepted = if profile == 2 {
                        claimed.min(maximum as i64) == actual as i64
                    } else {
                        claimed == actual as i64
                    };
                    assert_eq!(result.success, accepted,
                        "bits={bits}, profile={profile}, actual={actual}, claimed={claimed}: {result}");
                }
                for invalid in [integer(i32::MIN as i64), integer(1i64 << 31), vec![0; 5]] {
                    let pair = if profile == 0 {
                        vec![invalid, nodes[actual].clone()]
                    } else {
                        vec![nodes[actual].clone(), invalid]
                    };
                    let witness = [vec![native.as_ref().to_vec()], pair].concat();
                    let result =
                        execute_raw_script_with_inputs_strict(complete.to_bytes(), witness);
                    assert!(!result.success, "oversized selector: {result}");
                }
            }
        }
    }
}

#[test]
fn numeric_lookup_tables_bind_all_digits_for_both_hashes_and_preimage_widths() {
    exhaustive::<Hash160, FullWidth>();
    exhaustive::<Hash160, Preimage16>();
    exhaustive::<Sha256, FullWidth>();
    exhaustive::<Sha256, Preimage16>();
    exhaustive::<Sha256Hash160, FullWidth>();
    exhaustive::<Sha256Hash160, Preimage16>();
}

fn check_raw_width<H: ChainHash, P: PreimageSize<H>>() {
    for bits in 2..=4 {
        let maximum = (1usize << bits) - 1;
        for digit in [0, 1] {
            for length in [0, 15, 16, 17, 20, 32, 33] {
                let node = vec![0x53; length];
                let mut endpoint = H::hash_parts(&[&node]);
                for _ in 1..maximum - digit {
                    endpoint = H::hash_parts(&[endpoint.as_ref()]);
                }
                let endpoint = H::commit(endpoint);
                let complete = script! {
                    { verify_chain_minimal::<H, P>(endpoint, bits, true) }
                    { digit } OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy();
                let result = execute_raw_script_with_inputs_strict(
                    complete.to_bytes(),
                    vec![integer(digit as i64), node],
                );
                let required = if digit == 0 {
                    P::START_BYTES
                } else {
                    H::VALUE_BYTES
                };
                assert_eq!(
                    result.success,
                    length == required,
                    "bits={bits}, digit={digit}, length={length}, required={required}: {result}"
                );
            }
        }
    }
}

#[test]
fn strict_lookup_tables_preserve_digit_dependent_raw_width_checks() {
    check_raw_width::<Hash160, FullWidth>();
    check_raw_width::<Hash160, Preimage16>();
    check_raw_width::<Sha256, FullWidth>();
    check_raw_width::<Sha256, Preimage16>();
    check_raw_width::<Sha256Hash160, FullWidth>();
    check_raw_width::<Sha256Hash160, Preimage16>();
}

#[test]
fn hybrid_terminal_commitment_preserves_the_explicit_relaxed_width_relation() {
    use bitcoin::hashes::{hash160, Hash};
    for length in [0, 16, 20, 31, 32, 33] {
        let raw = vec![0x61; length];
        let endpoint = *hash160::Hash::hash(&raw).as_byte_array();
        for bits in 2..=4 {
            let maximum = (1usize << bits) - 1;
            let strict = script! {
                { verify_chain_minimal::<Sha256Hash160, Preimage16>(endpoint, bits, true) }
                { maximum } OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy();
            let result = execute_raw_script_with_inputs_strict(
                strict.to_bytes(),
                vec![integer(maximum as i64), raw.clone()],
            );
            assert_eq!(
                result.success,
                length == 32,
                "strict length={length}: {result}"
            );
            for clamp in [false, true] {
                let relaxed = script! {
                    { verify_chain_size_optimized::<Sha256Hash160>(endpoint, bits, clamp) }
                    OP_FROMALTSTACK { maximum } OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy();
                let result = execute_raw_script_with_inputs_strict(
                    relaxed.to_bytes(),
                    vec![raw.clone(), integer(maximum as i64)],
                );
                assert!(
                    result.success,
                    "relaxed length={length}, clamp={clamp}: {result}"
                );
            }
        }
    }
}
