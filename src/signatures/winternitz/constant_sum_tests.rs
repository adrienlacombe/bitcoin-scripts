use super::*;
use crate::{
    signatures::winternitz::{FullWidth, Sha256, Sha256Hash160},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin::hashes::{sha256, Hash};
use std::collections::HashSet;

type Wots = ConstantSumWinternitz20;

#[test]
fn lossless_encoding_covers_all_160_bit_boundaries_and_rejects_invalid_codewords() {
    assert_eq!(
        Wots::RADICES.iter().map(|&r| r as usize - 1).sum::<usize>() / 2,
        Wots::DIGIT_SUM
    );
    assert!(Wots::codeword_count() >= (BigUint::one() << 160usize));
    assert!(Wots::codeword_count() < (BigUint::one() << 161usize));
    let mut messages = vec![[0; 20], [0xff; 20]];
    for bit in 0usize..160 {
        let value = BigUint::one() << bit;
        for rank in [value.clone(), value - BigUint::one()] {
            let bytes = rank.to_bytes_be();
            let mut message = [0; 20];
            message[20 - bytes.len()..].copy_from_slice(&bytes);
            messages.push(message);
        }
    }
    for i in 0u32..256 {
        messages.push(
            sha256::Hash::hash(&i.to_be_bytes()).to_byte_array()[..20]
                .try_into()
                .unwrap(),
        );
    }
    let mut seen = HashSet::new();
    let mut unique = HashSet::new();
    for message in messages {
        let digits = Wots::encode_message(&message);
        assert_eq!(Wots::decode_message(&digits).unwrap(), message);
        assert_eq!(digits.iter().map(|&d| d as usize).sum::<usize>(), 321);
        assert!(digits.iter().zip(Wots::RADICES).all(|(&d, r)| d < r));
        if unique.insert(message) {
            assert!(seen.insert(digits));
        }
    }
    let valid = Wots::encode_message(&[0x42; 20]);
    assert!(Wots::decode_message(&valid[..40]).is_err());
    assert!(Wots::decode_message(&[valid.to_vec(), vec![0]].concat()).is_err());
    let mut bad = valid;
    bad[0] = Wots::RADICES[0];
    assert!(Wots::decode_message(&bad).is_err());
    let mut bad = valid;
    bad[0] ^= 1;
    assert!(Wots::decode_message(&bad).is_err());
    // Even bounded Script accepts the whole antichain. The host decoder rejects
    // its small unused suffix; it must never silently truncate a 161-bit rank.
    let unused = encoding().unrank(BigUint::one() << 160usize);
    assert!(Wots::decode_message(&unused).is_err());
}

fn roundtrips<H: ChainHash, P: PreimageSize<H>>() {
    let key = ConstantSumWinternitz20::<H, P>::signing_key_from_seed([0x42; 32]);
    assert_eq!(format!("{key:?}"), "ConstantSumSigningKey20([redacted])");
    let pk = ConstantSumWinternitz20::<H, P>::public_key(&key);
    assert_eq!(
        pk,
        ConstantSumPublicKey20::from_commitments(*pk.commitments())
    );
    let leaves = [false, true].map(|bounded| {
        let verifier = if bounded {
            ConstantSumWinternitz20::<H, P>::checksig_verify_bounded_and_clear(&pk)
        } else {
            ConstantSumWinternitz20::<H, P>::checksig_verify_and_clear(&pk)
        };
        script! {
            OP_7 OP_TOALTSTACK
            { verifier }
            OP_9 OP_EQUALVERIFY OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    });
    for message in [
        [0; 20],
        [0xff; 20],
        core::array::from_fn(|i| (i * 37) as u8),
        [0x42; 20],
    ] {
        let signature = ConstantSumWinternitz20::<H, P>::sign(
            ConstantSumWinternitz20::<H, P>::signing_key_from_seed([0x42; 32]),
            &message,
        );
        assert_eq!(
            signature.digits(),
            &ConstantSumWinternitz20::<H, P>::encode_message(&message)
        );
        let witness = signature.to_witness();
        assert_eq!(
            witness.len(),
            ConstantSumWinternitz20::<H, P>::WITNESS_DATA_ITEMS
        );
        for (i, node) in signature.chain_values().iter().enumerate() {
            assert_eq!(
                node.as_ref().len(),
                if signature.digits[i] == 0 {
                    P::START_BYTES
                } else {
                    H::VALUE_BYTES
                }
            );
        }
        for leaf in &leaves {
            let inputs = [vec![vec![9]], witness.to_vec()].concat();
            let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), inputs);
            assert!(result.success, "{result}");
            assert_eq!(result.final_stack.len(), 1);
            assert!(result.stats.max_nb_stack_items <= 1000);
        }
    }
}
#[test]
fn all_hash_and_initial_width_modes_roundtrip_with_exact_stack_cleanup() {
    roundtrips::<Hash160, Preimage16>();
    roundtrips::<Hash160, FullWidth>();
    roundtrips::<Sha256, Preimage16>();
    roundtrips::<Sha256, FullWidth>();
    roundtrips::<Sha256Hash160, Preimage16>();
    roundtrips::<Sha256Hash160, FullWidth>();
}

fn adversarial<H: ChainHash>() {
    let key = ConstantSumWinternitz20::<H>::signing_key_from_seed([0x42; 32]);
    let pk = ConstantSumWinternitz20::<H>::public_key(&key);
    let sig = ConstantSumWinternitz20::<H>::sign(key, &[0x42; 20]);
    let leaf = script! {{ConstantSumWinternitz20::<H>::checksig_verify_and_clear(&pk)}OP_TRUE}
        .compile_with_policy();
    let witness = sig.to_witness().to_vec();
    let stride = if H::VALUE_BYTES == 20 { 2 } else { 3 };
    let rejects =
        |items| assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), items).success);
    for i in 0..witness.len() {
        let mut bad = witness.clone();
        if bad[i].is_empty() {
            bad[i].push(1)
        } else {
            bad[i][0] ^= 1;
        }
        rejects(bad);
    }
    let mut missing = witness.clone();
    missing.pop();
    rejects(missing);
    let mut extra = witness.clone();
    extra.insert(0, vec![1]);
    rejects(extra);
    for i in 0..CHAINS {
        let selector = if stride == 2 { i * 2 + 1 } else { i * 3 };
        for raw in [vec![0x81], vec![0; 5], vec![0, 0, 0, 0x80, 0]] {
            let mut bad = witness.clone();
            bad[selector] = raw;
            rejects(bad);
        }
        if sig.digits[i] + 1 < RADICES[i] {
            let mut forged = sig.clone();
            forged.digits[i] += 1;
            forged.nodes[i] = Preimage16::from_hash(H::hash_parts(&[sig.nodes[i].as_ref()]));
            rejects(forged.to_witness().to_vec());
            // Retaining the sum demands another coordinate decrease. We give
            // the attacker every publicly forwardable node in that chain.
            if let Some(j) = (0..CHAINS).find(|&j| j != i && sig.digits[j] > 0) {
                forged.digits[j] -= 1;
                let mut node = sig.nodes[j];
                for _ in sig.digits[j]..RADICES[j] {
                    forged.nodes[j] = node;
                    rejects(forged.to_witness().to_vec());
                    node = Preimage16::from_hash(H::hash_parts(&[node.as_ref()]));
                }
            }
        }
    }
    let mut bad_pk = pk;
    bad_pk.commitments[0] = H::commit(H::hash_parts(&[b"wrong endpoint"]));
    let bad_leaf =
        script! {{ConstantSumWinternitz20::<H>::checksig_verify_and_clear(&bad_pk)}OP_TRUE}
            .compile_with_policy();
    assert!(!execute_raw_script_with_inputs_strict(bad_leaf.to_bytes(), witness).success);
}
#[test]
fn terminal_rejects_mutations_forwarding_and_compensated_decreases() {
    adversarial::<Hash160>();
    adversarial::<Sha256>();
    adversarial::<Sha256Hash160>();
}

#[test]
fn matches_independent_python_encoding_key_signature_and_witness_vectors() {
    // Reproduce with python3 tools/winternitz20_vectors.py; no Rust code is
    // imported by that independent stdlib implementation.
    fn check<H: ChainHash, P: PreimageSize<H>>(
        pk_digest: &str,
        signature_digest: &str,
        witness_digest: &str,
    ) {
        let key = ConstantSumWinternitz20::<H, P>::signing_key_from_seed([0x42; 32]);
        let pk = ConstantSumWinternitz20::<H, P>::public_key(&key);
        let sig =
            ConstantSumWinternitz20::<H, P>::sign(key, &core::array::from_fn(|i| (i * 37) as u8));
        let public_bytes: Vec<u8> = pk
            .commitments()
            .iter()
            .flat_map(|v| v.as_ref().iter().copied())
            .collect();
        let signature_bytes: Vec<u8> = sig
            .chain_values()
            .iter()
            .flat_map(|v| v.as_ref().iter().copied())
            .collect();
        assert_eq!(sha256::Hash::hash(&public_bytes).to_string(), pk_digest);
        assert_eq!(
            sha256::Hash::hash(&signature_bytes).to_string(),
            signature_digest
        );
        assert_eq!(
            sha256::Hash::hash(&bitcoin::consensus::serialize(&sig.to_witness())).to_string(),
            witness_digest
        );
        assert_eq!(
            sig.digits(),
            &[
                0, 0, 2, 14, 0, 14, 1, 15, 7, 15, 5, 1, 14, 6, 10, 8, 14, 2, 4, 13, 14, 6, 10, 4,
                3, 11, 10, 9, 1, 7, 13, 14, 12, 15, 2, 3, 5, 8, 19, 0, 10
            ]
        );
    }
    check::<Hash160, Preimage16>(
        "dbfd392a6fd029c722770b2a0a59011920b1e33616a5efd22d38d4526e71e125",
        "662afc7b868135bdc974927d34e409f31afeb7bf4c4233da96ab19ba0828a0ed",
        "525f48de3f39d2c2692b84e8c86142ce7d2cdfc3c53d4d4555c1ff4e9bb2e94a",
    );
    check::<Hash160, FullWidth>(
        "e0ec1a7c1d6432f9c559029ad2c189f9059c912caee2acf259a7ffa6d5158b11",
        "2f2925605df5998a6007c5088189f7a8e13aa60ebae006109a8b71b06425972d",
        "3578ed1cc0e04b7a4dfe550df9867c37e12a2417fe843bc693b1bff0721ca0fa",
    );
    check::<Sha256, Preimage16>(
        "e8bde35a8bc33f2e210d0047806ea70cbac1773430ec7ca1bba76275f104564d",
        "904caa8e48cd33156134bc0993c28c6809c963cb1111048bf5989968bf63449f",
        "0f550058b782394b42e4fce50843eee77f6575eeffc67abc5404cfbb3f05244e",
    );
    check::<Sha256, FullWidth>(
        "f15178e581a717e95e5cc474dbb47b1141fe9023f21247d6c5814fc8da631c45",
        "314cf05ef9cfba64529f66a82040f8a83bb72962ccfb2ffd1f0854fb5ede28a3",
        "f13b37037ce34d878115d43ee5a471a256adf204efda3bf179d828e3adad505d",
    );
    check::<Sha256Hash160, Preimage16>(
        "5502c4bcaacdc64d8b01b33069b5644c54536e2eb10e2a1209ca47c84f994249",
        "1e8b150e1cce2a29db871de28dee23199cd6eb67f485a3b9d1e7f5a7ef55f3fe",
        "99fa6c0edf93a1277c2f1a28de25a1161e391dcb21e838ba36296ac29a035115",
    );
    check::<Sha256Hash160, FullWidth>(
        "5fdd4a7f5ebcc0e613489044d3738ff42697987daf79cc3b5f1e55c9d4767b19",
        "b178df30e5e8b27a8b78dc4a81931e956e576cbd3cd3c3b900e83476bf22e1b7",
        "ddf746f066986d2626d51f433286da0bf9d560c513571f98642ad741bd94d342",
    );
    assert_eq!(
        Wots::codeword_count().to_string(),
        "1470691080098966924606702294670956744709470421906"
    );
}
