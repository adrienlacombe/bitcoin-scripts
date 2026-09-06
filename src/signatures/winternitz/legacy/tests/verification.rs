use super::*;
use crate::support::execution::{execute_script, run};
use bitcoin::hex::FromHex;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{LazyLock, Mutex};

static MALICIOUS_RNG: LazyLock<Mutex<ChaCha20Rng>> =
    LazyLock::new(|| Mutex::new(ChaCha20Rng::seed_from_u64(337)));

const SAMPLE_SECRET_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
const TEST_COUNT: u32 = 20;

#[test]
fn terminal_preserves_single_checksum_encoding_and_surrounding_stacks() {
    use bitcoin::{TapLeafHash, Transaction};
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    let parameters = Parameters::new(1, 4);
    let secret = vec![0x42; 20];
    let public_key = generate_public_key(&parameters, &secret);
    let wots = Winternitz::<BinarysearchVerifier, VoidConverter>::new();
    let signature = wots.sign_digits(&parameters, &secret, vec![5]);
    let leaf = script! {
        99 OP_TOALTSTACK
        { wots.checksig_verify_and_clear_stack(&parameters, &public_key) }
        33 OP_EQUALVERIFY
        OP_FROMALTSTACK 99 OP_EQUALVERIFY
        OP_TRUE
    }
    .compile_with_policy();

    for checksum_item in [vec![10], vec![10, 0], vec![10, 0, 0]] {
        let canonical = checksum_item.len() == 1;
        let mut witness = signature.to_vec();
        witness[3] = checksum_item;
        witness.insert(0, vec![33]);
        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options {
                require_minimal: false,
                ..Default::default()
            },
            TxTemplate {
                tx: Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
            },
            leaf.clone(),
            witness,
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        assert_eq!(exec.result().unwrap().success, canonical);
    }
}

fn get_type_name<T>() -> String {
    let full_type_name = std::any::type_name::<T>();
    let res = full_type_name.split("::").last().unwrap_or(full_type_name);
    res.to_string()
}

// This test is not extensive and definitely misses corner cases
fn try_malicious(ps: &Parameters, _message: &[u8], verifier: &str) -> Script {
    let mut rng = MALICIOUS_RNG.lock().unwrap();
    let ind = rng.gen_range(0..ps.total_digit_len());
    if verifier == get_type_name::<BruteforceVerifier>() {
        script! {
            for _ in 0..ind {
                OP_TOALTSTACK
            }
            for _ in 0..(rng.gen_range(1..20)) {
                OP_HASH160
            }                for _ in 0..ind {
                OP_FROMALTSTACK
            }
        }
    } else {
        let type_of_action = rng.gen_range(0..2);
        script! {
            for _ in 0..ind {
                OP_TOALTSTACK OP_TOALTSTACK
            }
            if type_of_action == 0 {
                OP_DROP {-1}
            } else {
                OP_TOALTSTACK
                for _ in 0..(rng.gen_range(1..20)) {
                    OP_HASH160
                }
                OP_FROMALTSTACK
            }
            for _ in 0..ind {
                OP_FROMALTSTACK OP_FROMALTSTACK
            }
        }
    }
}

fn test_script(
    ps: &Parameters,
    standard_script: Script,
    message_checker: Script,
    desired_outcome: bool,
) {
    println!(
        "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit\n",
        standard_script.len(),
        ps.message_digit_len * ps.log2_base,
        standard_script.len() as f64 / (ps.message_digit_len * ps.log2_base) as f64
    );
    if desired_outcome == true {
        assert!(
            execute_script(
                standard_script.push_script(message_checker.clone().compile_with_policy())
            )
            .success
                == true
        );
    } else {
        assert!(
            execute_script(standard_script.clone()).success == false
                || execute_script(
                    standard_script.push_script(message_checker.compile_with_policy())
                )
                .success
                    == true
        );
    }
}

fn run_winternitz_test<VERIFIER: Verifier, CONVERTER: Converter>(
    ps: &Parameters,
    secret_key: &SecretKey,
    public_key: &PublicKey,
    message: &[u8],
    message_checker: Script,
    desired_outcome: bool,
) {
    let o = Winternitz::<VERIFIER, CONVERTER>::new();
    let standard_script = script! {
        { o.sign(ps, secret_key, message) }
        if desired_outcome == false {
             { try_malicious(ps, message, &get_type_name::<VERIFIER>()) }
        }
        { o.checksig_verify(ps, &public_key) }
    };

    println!(
        "For message_digit_len: {} and log2_base: {} {} with {} =>",
        ps.message_digit_len,
        ps.log2_base,
        get_type_name::<VERIFIER>(),
        get_type_name::<CONVERTER>()
    );
    test_script(ps, standard_script, message_checker, desired_outcome);
    if desired_outcome == true {
        let message_remove_script = script! {
            { o.sign(ps, secret_key, message) }
            { o.checksig_verify_and_clear_stack(ps, public_key) }
            OP_TRUE
        };
        assert!(execute_script(message_remove_script).success == true);
    }
}

#[test]
fn test_winternitz_with_actual_message_success() {
    let secret_key = match Vec::<u8>::from_hex(SAMPLE_SECRET_KEY) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    let ps = Parameters::new_by_bit_length(32, 4);
    let public_key = generate_public_key(&ps, &secret_key);

    let message = 860033_u32;
    let message_bytes = &message.to_le_bytes();

    let winternitz_verifier = Winternitz::<ListpickVerifier, VoidConverter>::new();

    let s = script! {
        // sign
        { winternitz_verifier.sign(&ps, &secret_key, message_bytes.as_ref()) }

        // check signature
        { winternitz_verifier.checksig_verify(&ps, &public_key) }

        // convert to number
        { digits_to_number::<8, 4>() }

        { message }

        OP_EQUAL

    };
    run(s);
}

#[test]
fn test_winternitz_success() {
    let secret_key = match Vec::<u8>::from_hex(SAMPLE_SECRET_KEY) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    let mut prng = ChaCha20Rng::seed_from_u64(37);
    for _ in 0..TEST_COUNT {
        let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
        let message_byte_size = ps.message_digit_len * ps.log2_base / 8;
        let mut message = vec![0u8; message_byte_size as usize];
        let mut return_message = vec![0; ps.message_byte_len() as usize];
        for i in 0..message_byte_size {
            message[i as usize] = prng.gen_range(0u8..=255);
            return_message[i as usize] = message[i as usize];
        }
        let public_key = generate_public_key(&ps, &secret_key);
        let message_checker = script! {
            for i in 0..ps.message_byte_len() {
                {return_message[i as usize]}
                if i == ps.message_byte_len() - 1 {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        };

        run_winternitz_test::<ListpickVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker.clone(),
            true,
        );
        run_winternitz_test::<BruteforceVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker.clone(),
            true,
        );
        run_winternitz_test::<BinarysearchVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker,
            true,
        );

        let message_digits = message_to_digits(ps.message_digit_len, ps.log2_base, &message);
        let void_message_checker = script! {
            for i in (0..ps.message_digit_len).rev() {
                { message_digits[i as usize] }
                if i == 0 {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        };

        run_winternitz_test::<ListpickVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker.clone(),
            true,
        );
        run_winternitz_test::<BruteforceVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker.clone(),
            true,
        );
        run_winternitz_test::<BinarysearchVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker,
            true,
        );
    }
}

#[test]
fn test_winternitz_fail() {
    let secret_key = match Vec::<u8>::from_hex(SAMPLE_SECRET_KEY) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    let mut prng = ChaCha20Rng::seed_from_u64(37);
    for _ in 0..TEST_COUNT {
        let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
        let message_byte_size = ps.message_digit_len * ps.log2_base / 8;
        let mut message = vec![0u8; message_byte_size as usize];
        let mut return_message = vec![0; ps.message_byte_len() as usize];
        for i in 0..message_byte_size {
            message[i as usize] = prng.gen_range(0u8..=255);
            return_message[i as usize] = message[i as usize];
        }
        let public_key = generate_public_key(&ps, &secret_key);
        let message_checker = script! {
            for i in 0..ps.message_byte_len() {
                {return_message[i as usize]}
                if i == ps.message_byte_len() - 1 {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        };

        run_winternitz_test::<ListpickVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker.clone(),
            false,
        );
        run_winternitz_test::<BruteforceVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker.clone(),
            false,
        );
        run_winternitz_test::<BinarysearchVerifier, ToBytesConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            message_checker,
            false,
        );

        let message_digits = message_to_digits(ps.message_digit_len, ps.log2_base, &message);
        let void_message_checker = script! {
            for i in (0..ps.message_digit_len).rev() {
                { message_digits[i as usize] }
                if i == 0 {
                    OP_EQUAL
                } else {
                    OP_EQUALVERIFY
                }
            }
        };

        run_winternitz_test::<ListpickVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker.clone(),
            false,
        );
        run_winternitz_test::<BruteforceVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker.clone(),
            false,
        );
        run_winternitz_test::<BinarysearchVerifier, VoidConverter>(
            &ps,
            &secret_key,
            &public_key,
            &message,
            void_message_checker,
            false,
        );
    }
}

#[test]
fn test_if_binary_search_verifier_allows_out_of_range_digits() {
    let secret_key = match Vec::<u8>::from_hex(SAMPLE_SECRET_KEY) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    let o = Winternitz::<BinarysearchVerifier, VoidConverter>::new();
    let ps = Parameters::new_by_bit_length(8, 4); //changing log2_base will break this test
    let public_key = generate_public_key(&ps, &secret_key);
    assert_eq!(ps.checksum_digit_len, 2);

    fn signed_checksum(ps: &Parameters, message_digits: &[i32]) -> u32 {
        debug_assert_eq!(message_digits.len(), ps.message_digit_len as usize);

        let sum: i32 = message_digits.iter().sum();
        assert!(sum >= 0);
        ps.max_digit() * ps.message_digit_len - sum as u32
    }

    fn add_message_signed_checksum(ps: &Parameters, mut message_digits: Vec<i32>) -> Vec<i32> {
        debug_assert_eq!(message_digits.len(), ps.message_digit_len as usize);
        let checksum_digits = checksum_to_digits(
            signed_checksum(ps, &message_digits),
            ps.max_digit() + 1,
            ps.checksum_digit_len,
        );
        message_digits.extend(checksum_digits.iter().map(|&x| x as i32));
        message_digits
    }

    fn sign_signed_digits(
        ps: &Parameters,
        secret_key: &SecretKey,
        message_digits: Vec<i32>,
    ) -> Witness {
        let digits = add_message_signed_checksum(ps, message_digits);
        let mut result = Witness::new();
        for i in 0..ps.total_digit_len() {
            let mut impersonator_digit = digits[i as usize];
            impersonator_digit = impersonator_digit.max(0);
            impersonator_digit = impersonator_digit.min(ps.max_digit() as i32);
            let sig = digit_signature(secret_key, i, impersonator_digit as u32);
            // FIXME: Do trailing zeroes violate Bitcoin Script's minimum data push requirement?
            //        Maybe the script! macro removes the zeroes.
            //        There is a 1/256 chance that a signature contains a trailing zero.
            result.push(sig);
            result.push(bitcoin_representation(digits[i as usize]));
        }
        result
    }

    assert!(
        execute_script(script! {
            { sign_signed_digits(&ps, &secret_key, vec![2, 3]) }
            { o.checksig_verify_and_clear_stack(&ps, &public_key) }
            OP_TRUE
        })
        .success
    );

    assert!(
        !execute_script(script! {
            { sign_signed_digits(&ps, &secret_key, vec![-1, 1]) }
            { o.checksig_verify_and_clear_stack(&ps, &public_key) }
            OP_TRUE
        })
        .success
    );

    assert!(
        !execute_script(script! {
            { sign_signed_digits(&ps, &secret_key, vec![20, 0]) }
            { o.checksig_verify_and_clear_stack(&ps, &public_key) }
            OP_TRUE
        })
        .success
    );
}
