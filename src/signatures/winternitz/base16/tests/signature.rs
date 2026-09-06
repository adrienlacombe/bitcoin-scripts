// Preserve the historical native-width regression vectors explicitly.
type FullWidthWots32 = FastWinternitz<32, Hash160, FullWidth>;

use super::*;
use crate::{
    signatures::winternitz::{
        BinarysearchVerifier, BruteforceVerifier, CompactWots, ListpickVerifier, Parameters,
        VoidConverter, Winternitz, Wots, Wots32,
    },
    support::{
        execution::{execute_script, execute_script_with_inputs},
        script::ScriptCompilation,
    },
};
use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex;

const SEED: [u8; 32] = [0x42; 32];
const MESSAGE: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn fixture() -> (
    FastPublicKey<32, Hash160, FullWidth>,
    FastSignature<32, Hash160, FullWidth>,
) {
    let key = FullWidthWots32::signing_key_from_seed(SEED);
    let public_key = FullWidthWots32::public_key(&key);
    let signature = FullWidthWots32::sign(key, &MESSAGE);
    (public_key, signature)
}

fn search_checksum_partitions(widths: &mut Vec<usize>, remaining_slots: usize, best: &mut usize) {
    if remaining_slots == 0 {
        if widths.iter().sum::<usize>() < FullWidthWots32::CHECKSUM_BITS {
            return;
        }
        let mut place = 1usize;
        let size = widths
            .iter()
            .map(|&digit_bits| {
                let fragment = verify_chain_bitwise_and_accumulate::<Hash160>(
                    [0; HASH_BYTES],
                    digit_bits,
                    place,
                    false,
                );
                place <<= digit_bits;
                fragment.clone().compile_with_policy().len()
            })
            .sum::<usize>();
        *best = (*best).min(size);
        return;
    }

    for digit_bits in 1..=6 {
        widths.push(digit_bits);
        search_checksum_partitions(widths, remaining_slots - 1, best);
        widths.pop();
    }
}

fn assert_terminal_round_trip<const MESSAGE_BYTES: usize>(message: [u8; MESSAGE_BYTES]) {
    let seed = [MESSAGE_BYTES as u8; 32];
    let key = FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::signing_key_from_seed(seed);
    let public_key = FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::public_key(&key);
    let signature = FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::sign(key, &message);
    let result = execute_script(script! {
        { signature.to_witness() }
        { FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(result.success, "length {MESSAGE_BYTES}: {result}");
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);

    let bitwise_signature = FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::sign(
        FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::signing_key_from_seed(seed),
        &message,
    );
    let result = execute_script(script! {
        { bitwise_signature.to_bitwise_size_optimized_witness() }
        { FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::checksig_verify_bitwise_size_optimized(&public_key) }
        for _ in 0..FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::MESSAGE_DIGITS {
            OP_DROP
        }
        OP_TRUE
    });
    assert!(
        result.success,
        "bitwise recovery profile, length {MESSAGE_BYTES}: {result}"
    );
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);

    let result = execute_script(script! {
        { bitwise_signature.to_bitwise_terminal_witness() }
        { FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(
        result.success,
        "bitwise size profile, length {MESSAGE_BYTES}: {result}"
    );
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);

    let size_signature = FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::sign(
        FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::signing_key_from_seed(seed),
        &message,
    );
    let result = execute_script(script! {
        { size_signature.to_size_optimized_witness() }
        { FastWinternitz::<MESSAGE_BYTES, Hash160, FullWidth>::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(
        result.success,
        "size profile, length {MESSAGE_BYTES}: {result}"
    );
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);
}

fn assert_message_output(verifier: Script, witness: Witness) {
    let expected = MESSAGE
        .into_iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    let result = execute_script(script! {
        { witness }
        { verifier }
        for digit in expected.into_iter().rev() {
            { digit } OP_NUMEQUALVERIFY
        }
        OP_TRUE
    });
    assert!(result.success, "{result}");
    assert!(result.stats.max_nb_stack_items <= 1000);
}

#[test]
fn parameters_match_wots16_profile() {
    assert_eq!(FullWidthWots32::MESSAGE_DIGITS, 64);
    assert_eq!(FullWidthWots32::CHECKSUM_BITS, 10);
    assert_eq!(FullWidthWots32::CHECKSUM_DIGITS, 3);
    assert_eq!(FullWidthWots32::TOTAL_DIGITS, 67);
    assert_eq!(
        (0..FullWidthWots32::CHECKSUM_DIGITS)
            .map(FullWidthWots32::checksum_digit_bits)
            .collect::<Vec<_>>(),
        [3, 3, 4]
    );
    assert_eq!(
        (0..FullWidthWots32::CHECKSUM_DIGITS)
            .map(FullWidthWots32::checksum_digit_place)
            .collect::<Vec<_>>(),
        [1, 8, 64]
    );
}

#[test]
fn mixed_checksum_encoding_is_exhaustive_and_canonical() {
    for checksum in 0..=FullWidthWots32::MESSAGE_DIGITS * MAX_DIGIT as usize {
        let digits = mixed_checksum_digits::<32>(checksum);
        assert_eq!(digits.len(), FullWidthWots32::CHECKSUM_DIGITS);
        let decoded = digits
            .iter()
            .enumerate()
            .map(|(index, &digit)| {
                assert!(digit <= (1u8 << FullWidthWots32::checksum_digit_bits(index)) - 1);
                usize::from(digit) * FullWidthWots32::checksum_digit_place(index)
            })
            .sum::<usize>();
        assert_eq!(decoded, checksum);
    }

    for boundary in [7, 8, 63, 64, 959, 960] {
        let digits = mixed_checksum_digits::<32>(boundary);
        assert_eq!(
            digits
                .iter()
                .enumerate()
                .map(|(index, &digit)| {
                    usize::from(digit) * FullWidthWots32::checksum_digit_place(index)
                })
                .sum::<usize>(),
            boundary
        );
    }
}

#[test]
fn bitwise_checksum_partition_search_selects_three_three_four() {
    let mut best = usize::MAX;
    for digits in 1..=5 {
        search_checksum_partitions(&mut Vec::new(), digits, &mut best);
    }

    let mut place = 1usize;
    let selected = [3usize, 3, 4]
        .into_iter()
        .map(|digit_bits| {
            let fragment = verify_chain_bitwise_and_accumulate::<Hash160>(
                [0; HASH_BYTES],
                digit_bits,
                place,
                false,
            );
            place <<= digit_bits;
            fragment.clone().compile_with_policy().len()
        })
        .sum::<usize>();
    assert_eq!(selected, 169);
    assert_eq!(selected, best);
}

#[test]
fn bitwise_first_chain_initializes_exact_weighted_distance() {
    use crate::support::execution::execute_raw_script_with_inputs_strict;

    let start = [0x35; HASH_BYTES];
    let endpoint = hash_chain::<Hash160>(start, 15);
    let initialized = verify_chain_bitwise_and_accumulate::<Hash160>(endpoint, 4, 64, true);
    let separate_zero = script! {
        OP_0 OP_TOALTSTACK
        { verify_chain_bitwise_and_accumulate::<Hash160>(endpoint, 4, 64, false) }
    };
    // ALL does not already fuse initialization across conditional updates.
    assert_eq!(
        initialized.clone().compile_with_policy().len() + 2,
        separate_zero.compile_with_policy().len(),
    );

    for remaining in 0u8..=15 {
        let mut witness = Vec::new();
        for bit in (1..4).rev() {
            witness.push(if (remaining >> bit) & 1 == 0 {
                Vec::new()
            } else {
                vec![1]
            });
        }
        witness.push(hash_chain::<Hash160>(start, 15 - remaining).to_vec());
        witness.push(if remaining & 1 == 0 {
            Vec::new()
        } else {
            vec![1]
        });
        let leaf = script! {
            { initialized.clone() }
            OP_FROMALTSTACK { usize::from(remaining) * 64 } OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy();
        let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness);
        assert!(result.success, "remaining {remaining}: {result}");
        assert_eq!(result.final_stack.len(), 1);
    }
}

#[test]
fn supported_radix_list_sweep_selects_base16_for_script_size() {
    let secret = vec![0x42; 32];
    let measured = (4..=8)
        .map(|log2_base| {
            let parameters = Parameters::new_by_bit_length(256, log2_base);
            let public_key = super::super::generate_public_key(&parameters, &secret);
            Winternitz::<ListpickVerifier, VoidConverter>::new()
                .checksig_verify(&parameters, &public_key)
                .compile_with_policy()
                .len()
        })
        .collect::<Vec<_>>();
    assert_eq!(measured, [4_908, 5_631, 7_169, 10_585, 16_916]);
    assert_eq!(measured.iter().min(), measured.first());
}

#[test]
fn host_derivation_matches_independent_python_vector() {
    let (public_key, signature) = fixture();
    assert_eq!(
        public_key.chain_ends()[0].to_lower_hex_string(),
        "e7cba209d0f5143ec68a0047fdda4e56ce24a593"
    );
    assert_eq!(
        signature.chain_values()[0].to_lower_hex_string(),
        "fe39bed9c9449e7c5ee3df13b048b2e6168baef4"
    );
    assert_eq!(signature.digits()[..4], [0, 0, 1, 1]);
    assert_eq!(
        signature.digits()[FullWidthWots32::MESSAGE_DIGITS..],
        [0, 4, 7]
    );
    assert_eq!(
        public_key.chain_ends()[FullWidthWots32::MESSAGE_DIGITS].to_lower_hex_string(),
        "0ed29109fb0a775c1661d461cb6dad3310c1a445"
    );
    assert_eq!(
        signature.chain_values()[FullWidthWots32::MESSAGE_DIGITS].to_lower_hex_string(),
        "a86d4917608f262f138b776b30e87028659b96a1"
    );
}

#[test]
fn all_typed_lengths_and_checksum_boundaries_verify() {
    assert_terminal_round_trip([0x00; 4]);
    assert_terminal_round_trip([0xff; 4]);
    assert_terminal_round_trip([0x00; 16]);
    assert_terminal_round_trip([0xff; 16]);
    assert_terminal_round_trip([0x00; 32]);
    assert_terminal_round_trip([0xff; 32]);
    assert_terminal_round_trip([0x00; 64]);
    assert_terminal_round_trip([0xff; 64]);
    assert_terminal_round_trip([0x00; 80]);
    assert_terminal_round_trip([0xff; 80]);
}

#[test]
fn public_key_round_trips_and_rejects_wrong_endpoint_count() {
    let (public_key, _) = fixture();
    let restored =
        FastPublicKey::<32, Hash160, FullWidth>::from_chain_ends(public_key.chain_ends().to_vec())
            .expect("valid endpoint count");
    assert_eq!(restored, public_key);

    let error = FastPublicKey::<32, Hash160, FullWidth>::from_chain_ends(vec![[0; HASH_BYTES]; 66])
        .expect_err("short public key must fail");
    assert_eq!(error.expected, FullWidthWots32::TOTAL_DIGITS);
    assert_eq!(error.actual, 66);
}

#[test]
fn exact_and_minimal_verifiers_recover_message() {
    let (public_key, signature) = fixture();
    let witness = signature.to_witness();
    assert_message_output(
        FullWidthWots32::checksig_verify(&public_key),
        witness.clone(),
    );
    assert_message_output(
        FullWidthWots32::checksig_verify_minimal(&public_key),
        witness,
    );
    assert_message_output(
        FullWidthWots32::checksig_verify_size_optimized(&public_key),
        signature.to_size_optimized_witness(),
    );
    assert_message_output(
        FullWidthWots32::checksig_verify_bitwise_size_optimized(&public_key),
        signature.to_bitwise_size_optimized_witness(),
    );
}

#[test]
fn fused_terminal_verifier_is_clean() {
    let (public_key, signature) = fixture();
    let result = execute_script(script! {
        { signature.to_witness() }
        { FullWidthWots32::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(result.success, "{result}");
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);

    let result = execute_script(script! {
        { signature.to_size_optimized_witness() }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(result.success, "size profile: {result}");
    assert_eq!(result.final_stack.len(), 1);
    assert!(result.stats.max_nb_stack_items <= 1000);
}

#[test]
fn rejects_wrong_chain_value_and_public_key() {
    let (public_key, signature) = fixture();
    let mut bad_witness = signature.to_witness().to_vec();
    bad_witness[1][0] ^= 1;
    let result = execute_script(script! {
        { bad_witness }
        { FullWidthWots32::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut bad_size_witness = signature.to_size_optimized_witness().to_vec();
    bad_size_witness[0][0] ^= 1;
    let result = execute_script(script! {
        { bad_size_witness }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut wrong_public_key = public_key.clone();
    wrong_public_key.chain_ends[0][0] ^= 1;
    let result = execute_script(script! {
        { signature.to_witness() }
        { FullWidthWots32::checksig_verify_and_clear(&wrong_public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let result = execute_script(script! {
        { signature.to_size_optimized_witness() }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&wrong_public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut bad_bitwise_witness = signature.to_bitwise_size_optimized_witness().to_vec();
    bad_bitwise_witness[4][0] ^= 1;
    let result = execute_script(script! {
        { bad_bitwise_witness }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized(&public_key) }
        for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
            OP_DROP
        }
        OP_TRUE
    });
    assert!(!result.success);

    let result = execute_script(script! {
        { signature.to_bitwise_terminal_witness() }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&wrong_public_key) }
        OP_TRUE
    });
    assert!(!result.success);
}

#[test]
fn rejects_out_of_range_and_malformed_digits() {
    let (public_key, signature) = fixture();
    for invalid in [vec![16], vec![0x81], vec![1, 0, 0, 0, 0]] {
        let mut witness = signature.to_witness().to_vec();
        witness[0] = invalid.clone();
        let result = execute_script(script! {
            { witness }
            { FullWidthWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let mut size_witness = signature.to_size_optimized_witness().to_vec();
        size_witness[1] = invalid;
        let result = execute_script(script! {
            { size_witness }
            { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);
    }
}

#[test]
fn bitwise_profiles_reject_noncanonical_bits_and_wrong_item_counts() {
    let (public_key, signature) = fixture();
    for invalid in [vec![2], vec![0x81], vec![1, 0]] {
        let mut recovery_witness = signature.to_bitwise_size_optimized_witness().to_vec();
        recovery_witness[0] = invalid.clone();
        let result = execute_script(script! {
            { recovery_witness }
            { FullWidthWots32::checksig_verify_bitwise_size_optimized(&public_key) }
            for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
                OP_DROP
            }
            OP_TRUE
        });
        assert!(!result.success);

        let mut terminal_witness = signature.to_bitwise_terminal_witness().to_vec();
        terminal_witness[0] = invalid;
        let result = execute_script(script! {
            { terminal_witness }
            { FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);
    }

    let mut missing = signature.to_bitwise_terminal_witness().to_vec();
    missing.pop();
    let result = execute_script(script! {
        { missing }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut extra = signature.to_bitwise_terminal_witness().to_vec();
    extra.insert(0, Vec::new());
    let result = execute_script(script! {
        { extra }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(
        !result.success,
        "cleanstack must reject extra bitwise input"
    );
}

#[test]
fn rejects_wrong_chain_lengths_and_witness_item_counts() {
    let (public_key, signature) = fixture();
    for invalid_length in [19, 21] {
        let mut witness = signature.to_witness().to_vec();
        witness[1] = vec![0; invalid_length];
        let result = execute_script(script! {
            { witness }
            { FullWidthWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);
    }

    let mut missing = signature.to_witness().to_vec();
    missing.pop();
    let result = execute_script(script! {
        { missing }
        { FullWidthWots32::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut extra = signature.to_witness().to_vec();
    extra.insert(0, Vec::new());
    let result = execute_script(script! {
        { extra }
        { FullWidthWots32::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(
        !result.success,
        "tapscript cleanstack must reject extra input"
    );

    let mut size_missing = signature.to_size_optimized_witness().to_vec();
    size_missing.pop();
    let result = execute_script(script! {
        { size_missing }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let mut size_extra = signature.to_size_optimized_witness().to_vec();
    size_extra.insert(0, Vec::new());
    let result = execute_script(script! {
        { size_extra }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(
        !result.success,
        "tapscript cleanstack must reject extra input"
    );
}

#[test]
fn rejects_wrong_checksum_even_with_valid_chains() {
    let key = FullWidthWots32::signing_key_from_seed(SEED);
    let public_key = FullWidthWots32::public_key(&key);
    let mut signature = FullWidthWots32::sign(key, &MESSAGE);
    let checksum_index = FullWidthWots32::MESSAGE_DIGITS;
    signature.digits[checksum_index] ^= 1;
    let namespace = derive_chain_namespace::<32, Hash160>(&SEED);
    signature.chain_values[checksum_index] = hash_chain::<Hash160>(
        derive_chain_start::<Hash160>(&namespace, checksum_index as u32),
        signature.digits[checksum_index],
    );

    let result = execute_script(script! {
        { signature.to_witness() }
        { FullWidthWots32::checksig_verify_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let result = execute_script(script! {
        { signature.to_size_optimized_witness() }
        { FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let result = execute_script(script! {
        { signature.to_bitwise_terminal_witness() }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
        OP_TRUE
    });
    assert!(!result.success);

    let result = execute_script(script! {
        { signature.to_bitwise_size_optimized_witness() }
        { FullWidthWots32::checksig_verify_bitwise_size_optimized(&public_key) }
        for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
            OP_DROP
        }
        OP_TRUE
    });
    assert!(!result.success);
}

#[test]
fn performance_profiles_are_measurably_distinct() {
    let (public_key, signature) = fixture();
    let witness = signature.to_witness();
    let exact = FullWidthWots32::checksig_verify(&public_key);
    let minimal = FullWidthWots32::checksig_verify_minimal(&public_key);
    let clear = FullWidthWots32::checksig_verify_and_clear(&public_key);
    let size = FullWidthWots32::checksig_verify_size_optimized(&public_key);
    let size_clear = FullWidthWots32::checksig_verify_size_optimized_and_clear(&public_key);
    let size_witness = signature.to_size_optimized_witness();
    let bitwise = FullWidthWots32::checksig_verify_bitwise_size_optimized(&public_key);
    let bitwise_clear =
        FullWidthWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key);
    let bitwise_witness = signature.to_bitwise_size_optimized_witness();
    let bitwise_terminal_witness = signature.to_bitwise_terminal_witness();
    let exact_result = execute_script_with_inputs(
        script! {
            { exact.clone() }
            for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
                OP_DROP
            }
            OP_TRUE
        },
        witness.to_vec(),
    );
    let minimal_result = execute_script_with_inputs(
        script! {
            { minimal.clone() }
            for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
                OP_DROP
            }
            OP_TRUE
        },
        witness.to_vec(),
    );
    let clear_result =
        execute_script_with_inputs(script! {{ clear.clone() } OP_TRUE}, witness.to_vec());
    let size_result = execute_script_with_inputs(
        script! {
            { size.clone() }
            for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
                OP_DROP
            }
            OP_TRUE
        },
        size_witness.to_vec(),
    );
    let size_clear_result = execute_script_with_inputs(
        script! {{ size_clear.clone() } OP_TRUE},
        size_witness.to_vec(),
    );
    let bitwise_clear_result = execute_script_with_inputs(
        script! {{ bitwise_clear.clone() } OP_TRUE},
        bitwise_terminal_witness.to_vec(),
    );
    let bitwise_result = execute_script_with_inputs(
        script! {
            { bitwise.clone() }
            for _ in 0..FullWidthWots32::MESSAGE_DIGITS {
                OP_DROP
            }
            OP_TRUE
        },
        bitwise_witness.to_vec(),
    );
    assert!(exact_result.success, "{exact_result}");
    assert!(minimal_result.success, "{minimal_result}");
    assert!(clear_result.success, "{clear_result}");
    assert!(size_result.success, "{size_result}");
    assert!(size_clear_result.success, "{size_clear_result}");
    assert!(bitwise_result.success, "{bitwise_result}");
    assert!(bitwise_clear_result.success, "{bitwise_clear_result}");
    let exact_hashes = signature
        .digits()
        .iter()
        .enumerate()
        .map(|(index, &digit)| usize::from(FullWidthWots32::chain_max_digit(index) - digit))
        .sum::<usize>();
    let minimal_hashes = signature
        .digits()
        .iter()
        .enumerate()
        .map(|(index, &digit)| {
            let half = 1u8 << (FullWidthWots32::chain_digit_bits(index) - 1);
            if FullWidthWots32::chain_digit_bits(index) <= 3 || digit < half {
                usize::from(2 * half - 1)
            } else {
                usize::from(half - 1)
            }
        })
        .sum::<usize>();
    assert!(exact_hashes < minimal_hashes);
    assert!(
        minimal.clone().compile_with_policy().len() < exact.clone().compile_with_policy().len()
    );
    assert!(size.clone().compile_with_policy().len() < minimal.clone().compile_with_policy().len());
    assert!(
        size_clear.clone().compile_with_policy().len() < size.clone().compile_with_policy().len()
    );
    assert!(bitwise.clone().compile_with_policy().len() < size.clone().compile_with_policy().len());
    assert!(
        bitwise_clear.clone().compile_with_policy().len()
            < size_clear.clone().compile_with_policy().len()
    );

    let legacy_parameters = Parameters::new_by_bit_length(256, 4);
    let legacy_secret = vec![0x42; 20];
    let legacy_public_key = super::super::generate_public_key(&legacy_parameters, &legacy_secret);
    let legacy_list = Winternitz::<ListpickVerifier, VoidConverter>::new()
        .checksig_verify(&legacy_parameters, &legacy_public_key);
    let legacy_binary = Winternitz::<BinarysearchVerifier, VoidConverter>::new()
        .checksig_verify(&legacy_parameters, &legacy_public_key);
    let legacy_bruteforce = Winternitz::<BruteforceVerifier, VoidConverter>::new()
        .checksig_verify(&legacy_parameters, &legacy_public_key);
    let legacy_standard_witness = Wots32::sign_to_raw_witness(&legacy_secret, &[0; 32]);
    let legacy_compact_witness = Wots32::compact_sign_to_raw_witness(&legacy_secret, &[0; 32]);

    eprintln!(
        "fast-wots32 exact={} minimal={} clear={} size={} size_clear={} bitwise={} bitwise_clear={} witness={} bitwise_witness={} bitwise_terminal_witness={} exact_hashes={} minimal_hashes={} exact_ops={} minimal_ops={} clear_ops={} size_ops={} size_clear_ops={} bitwise_ops={} bitwise_clear_ops={} exact_stack={} minimal_stack={} clear_stack={} size_stack={} size_clear_stack={} bitwise_stack={} bitwise_clear_stack={} legacy_list={} legacy_binary={} legacy_bruteforce={} legacy_witness={} legacy_compact_witness={}",
        exact.clone().compile_with_policy().len(),
        minimal.clone().compile_with_policy().len(),
        clear.clone().compile_with_policy().len(),
        size.clone().compile_with_policy().len(),
        size_clear.clone().compile_with_policy().len(),
        bitwise.clone().compile_with_policy().len(),
        bitwise_clear.clone().compile_with_policy().len(),
        serialize(&witness).len(),
        serialize(&bitwise_witness).len(),
        serialize(&bitwise_terminal_witness).len(),
        exact_hashes,
        minimal_hashes,
        exact_result.stats.opcode_count,
        minimal_result.stats.opcode_count,
        clear_result.stats.opcode_count,
        size_result.stats.opcode_count,
        size_clear_result.stats.opcode_count,
        bitwise_result.stats.opcode_count,
        bitwise_clear_result.stats.opcode_count,
        exact_result.stats.max_nb_stack_items,
        minimal_result.stats.max_nb_stack_items,
        clear_result.stats.max_nb_stack_items,
        size_result.stats.max_nb_stack_items,
        size_clear_result.stats.max_nb_stack_items,
        bitwise_result.stats.max_nb_stack_items,
        bitwise_clear_result.stats.max_nb_stack_items,
        legacy_list.clone().compile_with_policy().len(),
        legacy_binary.clone().compile_with_policy().len(),
        legacy_bruteforce.clone().compile_with_policy().len(),
        serialize(&legacy_standard_witness).len(),
        serialize(&legacy_compact_witness).len(),
    );
}
