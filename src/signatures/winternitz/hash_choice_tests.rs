//! Hash-choice regression tests; all execution here enforces the stack limit.
use super::*;
use crate::signatures::winternitz::Sha256;
use crate::support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation};
use bitcoin::{
    hashes::{sha256, Hash},
    script::Instruction,
};

fn profiles<const N: usize, H: ChainHash>(
    pk: &FastPublicKey<N, H>,
    sig: &FastSignature<N, H>,
) -> Vec<(Script, Witness, bool)> {
    vec![
        (
            FastWinternitz::<N, H>::checksig_verify(pk),
            sig.to_witness(),
            true,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_and_clear(pk),
            sig.to_witness(),
            false,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_minimal(pk),
            sig.to_witness(),
            true,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_size_optimized(pk),
            sig.to_size_optimized_witness(),
            true,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_size_optimized_and_clear(pk),
            sig.to_size_optimized_witness(),
            false,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_clamped(pk),
            sig.to_size_optimized_witness(),
            true,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_clamped_and_clear(pk),
            sig.to_size_optimized_witness(),
            false,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_bitwise_size_optimized(pk),
            sig.to_bitwise_size_optimized_witness(),
            true,
        ),
        (
            FastWinternitz::<N, H>::checksig_verify_bitwise_size_optimized_and_clear(pk),
            sig.to_bitwise_terminal_witness(),
            false,
        ),
    ]
}

fn roundtrip<const N: usize, H: ChainHash>() {
    let key = FastWinternitz::<N, H>::signing_key_from_seed([0x42; 32]);
    let pk = FastWinternitz::<N, H>::public_key(&key);
    assert_eq!(
        FastPublicKey::<N, H>::from_chain_ends(pk.chain_ends().to_vec()).unwrap(),
        pk
    );
    assert!(FastPublicKey::<N, H>::from_chain_ends(pk.chain_ends()[1..].to_vec()).is_err());
    for message in [[0; N], [0xff; N], core::array::from_fn(|i| (i * 37) as u8)] {
        let sig = FastWinternitz::<N, H>::sign(
            FastWinternitz::<N, H>::signing_key_from_seed([0x42; 32]),
            &message,
        );
        assert!(sig
            .chain_values()
            .iter()
            .all(|v| v.as_ref().len() == H::VALUE_BYTES));
        for (profile, (fragment, witness, recover)) in profiles(&pk, &sig).into_iter().enumerate() {
            let leaf = script! {
                { fragment }
                if recover {
                    for digit in sig.digits()[..N * 2].iter().rev() {
                        { *digit as usize } OP_EQUALVERIFY
                    }
                }
                OP_TRUE
            }
            .compile_with_policy();
            let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness.to_vec());
            assert!(
                result.success,
                "N={N}, hash={}, profile={profile}: {result}",
                H::VALUE_BYTES
            );
        }
    }
}

#[test]
fn both_hashes_roundtrip_all_profiles_and_message_boundaries() {
    // Repeated seeds are deterministic test fixtures, never production key reuse.
    roundtrip::<1, Hash160>();
    roundtrip::<1, Sha256>();
    roundtrip::<4, Sha256>();
    roundtrip::<16, Sha256>();
    roundtrip::<32, Hash160>();
    roundtrip::<32, Sha256>();
    roundtrip::<64, Sha256>();
    roundtrip::<80, Sha256>();
}

#[test]
fn both_hashes_match_independent_python_vectors() {
    // Reproduce with: python3 tools/winternitz_hash_vectors.py
    fn check<H: ChainHash>(public_digest: &str, signature_digest: &str) {
        let key = FastWinternitz::<32, H>::signing_key_from_seed([0x42; 32]);
        let pk = FastWinternitz::<32, H>::public_key(&key);
        let sig = FastWinternitz::<32, H>::sign(key, &core::array::from_fn(|i| i as u8));
        let public_bytes: Vec<_> = pk
            .chain_ends()
            .iter()
            .flat_map(|v| v.as_ref().iter().copied())
            .collect();
        let signature_bytes: Vec<_> = sig
            .chain_values()
            .iter()
            .flat_map(|v| v.as_ref().iter().copied())
            .collect();
        assert_eq!(sha256::Hash::hash(&public_bytes).to_string(), public_digest);
        assert_eq!(
            sha256::Hash::hash(&signature_bytes).to_string(),
            signature_digest
        );
    }
    check::<Hash160>(
        "2af2fe53498dfaeba490d99a5be4057a7d0369abb6dd7968dcc3584f5f86a414",
        "bbf46492515d58525bbf57ba3b1d75b26a92416fbadbf5b4ce19fa3cee069fd7",
    );
    check::<Sha256>(
        "b3adc3efa9a36dc3d0dc9a545ba390fa39131315d20b0bef27aba88a4f412ff5",
        "6850a0b422d98944a6596bbfd4865ca32dbb08178e6a8247ced71053ebd1e19e",
    );
}

#[test]
fn sha256_chain_binds_all_digits_and_rejects_wrong_widths() {
    for width in 1..=4 {
        let max = (1 << width) - 1;
        let start = [0x42; 32];
        let end = hash_chain::<Sha256>(start, max);
        let leaves = [
            verify_chain_exact::<Sha256, FullWidth>(end, width, true),
            verify_chain_minimal::<Sha256, FullWidth>(end, width, true),
            script! { { verify_chain_size_optimized::<Sha256>(end, width, false) } OP_FROMALTSTACK },
            script! { { verify_chain_size_optimized::<Sha256>(end, width, true) } OP_FROMALTSTACK },
        ];
        for (profile, leaf) in leaves.into_iter().enumerate() {
            // Lookup tables are used only for widths 2..=4 by public parameters.
            if width == 1 && profile != 0 {
                continue;
            }
            let leaf = script! { { leaf } OP_DROP OP_TRUE }.compile_with_policy();
            let accepts = |digit: Vec<u8>, node: Vec<u8>| {
                let witness = if profile < 2 {
                    vec![digit, node]
                } else {
                    vec![node, digit]
                };
                execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness).success
            };
            for actual in 0..=max {
                let node = hash_chain::<Sha256>(start, actual).to_vec();
                for claimed in 0..=max {
                    let digit = if claimed == 0 { vec![] } else { vec![claimed] };
                    assert_eq!(
                        accepts(digit, node.clone()),
                        actual == claimed,
                        "width={width}, profile={profile}, actual={actual}, claimed={claimed}"
                    );
                }
            }
            for bad in [vec![0x81], vec![0x80], vec![0], vec![1, 0], vec![0xff; 5]] {
                assert!(!accepts(bad, end.to_vec()));
            }
            assert_eq!(accepts(vec![max + 1], end.to_vec()), profile == 3);
            for len in [0, 16, 20, 31, 33] {
                assert!(!accepts(vec![max], vec![0x42; len]));
            }
        }
    }
}

#[test]
fn sha256_profiles_reject_tampering_and_mismatched_hash_witnesses() {
    let key = FastWinternitz::<4, Sha256>::signing_key_from_seed([0x42; 32]);
    let pk = FastWinternitz::<4, Sha256>::public_key(&key);
    let message = [0x12, 0x34, 0x56, 0x78];
    let sig = FastWinternitz::<4, Sha256>::sign(key, &message);
    let old_key = FastWots4::signing_key_from_seed([0x42; 32]);
    let old_pk = FastWots4::public_key(&old_key);
    let old_sig = FastWots4::sign(old_key, &message);
    let old_profiles = profiles(&old_pk, &old_sig);
    for (index, (fragment, witness, recover)) in profiles(&pk, &sig).into_iter().enumerate() {
        let leaf = script! {
            { fragment }
            if recover { for _ in 0..8 { OP_DROP } }
            OP_TRUE
        }
        .compile_with_policy();
        let rejects = |items| {
            assert!(
                !execute_raw_script_with_inputs_strict(leaf.to_bytes(), items).success,
                "profile={index}"
            )
        };
        rejects(old_profiles[index].1.to_vec());
        let mut missing = witness.to_vec();
        missing.pop();
        rejects(missing);
        let mut extra = witness.to_vec();
        extra.insert(0, vec![1]);
        rejects(extra);
        // Every message/checksum chain commitment must bind its witness node.
        for i in 0..witness.len() {
            let mut changed = witness.to_vec();
            if changed[i].len() == 32 {
                changed[i][0] ^= 1;
            } else {
                changed[i] = vec![2];
            }
            // Numeric 2 may equal the original digit. Mutate those to 3 instead.
            if changed[i] == witness.to_vec()[i] {
                changed[i] = vec![3];
            }
            rejects(changed);
        }
    }
    // Forwarding a message chain yields a valid chain but the old checksum fails.
    let mut forged = sig.clone();
    forged.chain_values[0] = Sha256::hash_parts(&[forged.chain_values[0].as_ref()]);
    forged.digits[0] += 1;
    for (fragment, witness, recover) in profiles(&pk, &forged) {
        let leaf = script! { { fragment } if recover { for _ in 0..8 { OP_DROP } } OP_TRUE }
            .compile_with_policy();
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness.to_vec()).success);
    }
}

#[test]
fn hash_choice_accounts_for_width_and_sha256_pair_fusion() {
    let key160 = FastWots32::signing_key_from_seed([0x42; 32]);
    let pk160 = FastWots32::public_key(&key160);
    let sig160 = FastWots32::sign(key160, &[0; 32]);
    let key256 = FastWinternitz::<32, Sha256>::signing_key_from_seed([0x42; 32]);
    let pk256 = FastWinternitz::<32, Sha256>::public_key(&key256);
    let sig256 = FastWinternitz::<32, Sha256>::sign(key256, &[0; 32]);
    for ((s160, w160, _), (s256, w256, _)) in profiles(&pk160, &sig160)
        .into_iter()
        .zip(profiles(&pk256, &sig256))
    {
        let s160 = s160.compile_with_policy();
        let s256 = s256.compile_with_policy();
        let hash256_pairs = s256
            .instructions()
            .filter(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8() == 0xaa))
            .count();
        assert_eq!(s256.len() - s160.len(), 67 * 12 - hash256_pairs);
        eprintln!(
            "HASH160={} SHA256={} fused_pairs={} witness160={} witness256={}",
            s160.len(),
            s256.len(),
            hash256_pairs,
            bitcoin::consensus::serialize(&w160).len(),
            bitcoin::consensus::serialize(&w256).len()
        );
        assert_eq!(
            bitcoin::consensus::serialize(&w256).len() - bitcoin::consensus::serialize(&w160).len(),
            67 * 12
        );
        assert_eq!(w160.len(), w256.len());
        let ops160: Vec<_> = s160
            .instructions()
            .filter_map(|i| {
                if let Instruction::Op(op) = i.unwrap() {
                    Some(op.to_u8())
                } else {
                    None
                }
            })
            .collect();
        let ops256: Vec<_> = s256
            .instructions()
            .filter_map(|i| {
                if let Instruction::Op(op) = i.unwrap() {
                    Some(op.to_u8())
                } else {
                    None
                }
            })
            .collect();
        assert!(!ops160.contains(&0xa8)); // OP_SHA256
        assert!(!ops256.contains(&0xa9)); // OP_HASH160
        assert_eq!(
            ops160
                .iter()
                .map(|&op| if op == 0xa9 { 0xa8 } else { op })
                .collect::<Vec<_>>(),
            ops256
                .into_iter()
                .flat_map(|op| if op == 0xaa {
                    vec![0xa8, 0xa8]
                } else {
                    vec![op]
                })
                .collect::<Vec<_>>()
        );
    }
}
