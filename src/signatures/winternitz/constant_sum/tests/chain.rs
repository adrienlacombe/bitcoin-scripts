use super::*;
use crate::{
    signatures::winternitz::{Hash160, Sha256Hash160},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn integer(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn nodes<H: ChainHash>(radix: usize, domain: u8) -> (Vec<Vec<u8>>, H::Commitment) {
    let mut values = vec![vec![domain; 16]];
    let mut native = H::hash_parts(&[&values[0]]);
    for index in 1..radix {
        native = H::hash_parts(&[&values[index - 1]]);
        values.push(native.as_ref().to_vec());
    }
    (values, H::commit(native))
}

fn witness(node: &[u8], digit: usize, radix: usize, style: SumChainStyle) -> Vec<Vec<u8>> {
    match style {
        SumChainStyle::Numeric { .. } => vec![node.to_vec(), integer(digit as i64)],
        SumChainStyle::Strided { .. } => {
            let bit = (radix - 1 - digit) % 2;
            let quotient = (digit + bit - (radix - 1) % 2) / 2;
            vec![integer(quotient as i64), node.to_vec(), integer(bit as i64)]
        }
    }
}

fn exhaustive<H: ChainHash>() {
    for radix in [
        2, 3, 6, 7, 8, 11, 12, 15, 16, 17, 18, 20, 23, 24, 28, 32, 48, 64,
    ] {
        let (values, endpoint) = nodes::<H>(radix, 0x64);
        for style in [
            SumChainStyle::Numeric { split: 0 },
            SumChainStyle::Numeric { split: radix / 2 },
            SumChainStyle::Strided { split: 0 },
            SumChainStyle::Strided {
                split: (radix + 1) / 4,
            },
        ] {
            let strided = matches!(style, SumChainStyle::Strided { .. });
            let selector_max = if strided { (radix - 1) / 2 } else { radix - 1 };
            for bounded in [false, true] {
                for actual in 0..radix {
                    let expected = actual as i64 - if strided { (radix - 1) as i64 % 2 } else { 0 };
                    let complete = script! {
                        OP_7 OP_TOALTSTACK OP_0 OP_TOALTSTACK
                        { verify_sum_chain::<H>(endpoint, radix, style, bounded) }
                        OP_FROMALTSTACK { expected } OP_NUMEQUALVERIFY
                        for _ in 0..3 { { values[radix - 1].clone() } OP_EQUALVERIFY }
                        OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
                    }
                    .compile_with_policy();
                    for claimed in -1..=selector_max as i64 + 2 {
                        for bit in 0..=usize::from(strided) {
                            let pair = if strided {
                                vec![
                                    integer(claimed),
                                    values[actual].clone(),
                                    integer(bit as i64),
                                ]
                            } else {
                                vec![values[actual].clone(), integer(claimed)]
                            };
                            let result = execute_raw_script_with_inputs_strict(
                                complete.to_bytes(),
                                [vec![values[radix - 1].clone(); 3], pair].concat(),
                            );
                            let q = if bounded {
                                claimed.min(selector_max as i64)
                            } else {
                                claimed
                            };
                            let recovered = if strided {
                                2 * q + (radix - 1) as i64 % 2 - bit as i64
                            } else {
                                q
                            };
                            assert_eq!(result.success, recovered == actual as i64,
                                "radix={radix}, {style:?}, bounded={bounded}, actual={actual}, selector={claimed}, bit={bit}: {result}");
                        }
                    }
                    for malformed in [integer(i32::MIN as i64), integer(1i64 << 31), vec![0; 5]] {
                        let mut items = witness(&values[actual], actual, radix, style);
                        items[if strided { 0 } else { 1 }] = malformed;
                        let result = execute_raw_script_with_inputs_strict(
                            complete.to_bytes(),
                            [vec![values[radix - 1].clone(); 3], items].concat(),
                        );
                        assert!(!result.success, "oversized selector: {result}");
                    }
                    if strided {
                        for malformed in [vec![0], vec![2], vec![0x80], vec![0x81], vec![1, 0]] {
                            let mut items = witness(&values[actual], actual, radix, style);
                            items[2] = malformed;
                            let result = execute_raw_script_with_inputs_strict(
                                complete.to_bytes(),
                                [vec![values[radix - 1].clone(); 3], items].concat(),
                            );
                            assert!(!result.success, "noncanonical branch bit: {result}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn sum_chain_selectors_preserve_in_range_authentication_and_numeric_boundaries() {
    exhaustive::<Hash160>();
    exhaustive::<Sha256Hash160>();
}

fn table_escape<H: ChainHash>() {
    for (radix, style, overflow, original_digit, bit) in [
        (16, SumChainStyle::Numeric { split: 8 }, 16, 15, 0),
        (18, SumChainStyle::Strided { split: 0 }, 9, 8, 0),
    ] {
        let (first, first_endpoint) = nodes::<H>(radix, 0x31);
        let (second, second_endpoint) = nodes::<H>(16, 0x72);
        let raw_digit = if matches!(style, SumChainStyle::Strided { .. }) {
            2 * overflow + (radix - 1) % 2 - bit
        } else {
            overflow
        };
        let original_second = 12;
        let deficit = raw_digit - original_digit;
        let claimed_second = original_second - deficit;
        let escaped_witness = if matches!(style, SumChainStyle::Strided { .. }) {
            vec![
                first[radix - 1].clone(),
                integer(overflow as i64),
                first[original_digit].clone(),
                integer(bit as i64),
            ]
        } else {
            vec![
                first[radix - 1].clone(),
                first[original_digit].clone(),
                integer(overflow as i64),
            ]
        };
        // An endpoint-valued item immediately below the fragment's data
        // proves that the unbounded selector really can escape its table.
        let isolated = script! {
            OP_0 OP_TOALTSTACK
            { verify_sum_chain::<H>(first_endpoint, radix, style, false) }
            OP_FROMALTSTACK OP_DROP OP_DROP OP_TRUE
        }
        .compile_with_policy();
        assert!(
            execute_raw_script_with_inputs_strict(isolated.to_bytes(), escaped_witness.clone())
                .success
        );

        let offset =
            usize::from(matches!(style, SumChainStyle::Strided { .. })) * ((radix - 1) % 2);
        let complete = script! {
            { offset as i64 - (original_digit + original_second) as i64 } OP_TOALTSTACK
            { verify_sum_chain::<H>(first_endpoint, radix, style, false) }
            OP_DROP
            { verify_sum_chain::<H>(second_endpoint, 16, SumChainStyle::Numeric { split: 8 }, false) }
            OP_FROMALTSTACK OP_0 OP_NUMEQUALVERIFY OP_TRUE
        }.compile_with_policy();
        let canonical = [
            vec![
                second[original_second].clone(),
                integer(original_second as i64),
            ],
            vec![first[radix - 1].clone()],
            witness(&first[original_digit], original_digit, radix, style),
        ]
        .concat();
        assert!(execute_raw_script_with_inputs_strict(complete.to_bytes(), canonical).success);

        // Compensating the overflow requires decreasing another signed
        // digit. Every node available by forwarding that signature fails.
        for forwarded in original_second..16 {
            let forged = [
                vec![second[forwarded].clone(), integer(claimed_second as i64)],
                escaped_witness.clone(),
            ]
            .concat();
            assert!(!execute_raw_script_with_inputs_strict(complete.to_bytes(), forged).success);
        }
    }
}

#[test]
fn fixed_sum_rejects_table_escape_with_compensating_digit_decrease() {
    table_escape::<Hash160>();
    table_escape::<Sha256Hash160>();
}
