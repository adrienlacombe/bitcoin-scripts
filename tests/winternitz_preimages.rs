//! Short chain-start coverage with the local tapscript stack limit enabled.
//! These are local interpreter checks, not Bitcoin Core consensus/policy validation.

use bitcoin::{
    consensus::serialize,
    hashes::{sha256, Hash},
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    signatures::winternitz::{
        ChainHash, FastPublicKey, FastSignature, FastWinternitz, Hash160, Preimage16, Sha256,
    },
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin_script::{script, Script};

const SEED: [u8; 32] = [0x6d; 32];

#[derive(Clone, Copy, Debug)]
enum Profile {
    Exact,
    ExactTerminal,
    Lookup,
    Numeric,
    NumericTerminal,
    Clamped,
    ClampedTerminal,
    Bitwise,
    BitwiseTerminal,
}

const PROFILES: [Profile; 9] = [
    Profile::Exact,
    Profile::ExactTerminal,
    Profile::Lookup,
    Profile::Numeric,
    Profile::NumericTerminal,
    Profile::Clamped,
    Profile::ClampedTerminal,
    Profile::Bitwise,
    Profile::BitwiseTerminal,
];

impl Profile {
    fn recovers(self) -> bool {
        matches!(
            self,
            Self::Exact | Self::Lookup | Self::Numeric | Self::Clamped | Self::Bitwise
        )
    }

    fn fragment<const N: usize, H: ChainHash>(
        self,
        key: &FastPublicKey<N, H, Preimage16>,
    ) -> Script {
        match self {
            Self::Exact => FastWinternitz::<N, H, Preimage16>::checksig_verify(key),
            Self::ExactTerminal => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_and_clear(key)
            }
            Self::Lookup => FastWinternitz::<N, H, Preimage16>::checksig_verify_minimal(key),
            Self::Numeric => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_size_optimized(key)
            }
            Self::NumericTerminal => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_size_optimized_and_clear(key)
            }
            Self::Clamped => FastWinternitz::<N, H, Preimage16>::checksig_verify_clamped(key),
            Self::ClampedTerminal => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_clamped_and_clear(key)
            }
            Self::Bitwise => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_bitwise_size_optimized(key)
            }
            Self::BitwiseTerminal => {
                FastWinternitz::<N, H, Preimage16>::checksig_verify_bitwise_size_optimized_and_clear(
                    key,
                )
            }
        }
    }

    fn witness<const N: usize, H: ChainHash>(
        self,
        signature: &FastSignature<N, H, Preimage16>,
    ) -> Vec<Vec<u8>> {
        match self {
            Self::Exact | Self::ExactTerminal | Self::Lookup => signature.to_witness(),
            Self::Numeric | Self::NumericTerminal | Self::Clamped | Self::ClampedTerminal => {
                signature.to_size_optimized_witness()
            }
            Self::Bitwise => signature.to_bitwise_size_optimized_witness(),
            Self::BitwiseTerminal => signature.to_bitwise_terminal_witness(),
        }
        .to_vec()
    }

    fn leaf<const N: usize, H: ChainHash>(
        self,
        key: &FastPublicKey<N, H, Preimage16>,
    ) -> ScriptBuf {
        script! {
            { self.fragment(key) }
            if self.recovers() {
                for _ in 0..N * 2 { OP_DROP }
            }
            OP_TRUE
        }
        .compile_with_policy()
    }
}

fn run(leaf: &ScriptBuf, witness: Vec<Vec<u8>>, expected: bool, context: &str) {
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness);
    assert_eq!(result.success, expected, "{context}: {result}");
    if expected {
        assert_eq!(result.final_stack.len(), 1, "{context}");
        assert!(result.stats.max_nb_stack_items <= 1000, "{context}");
    }
}

fn chain_bits<const N: usize, H: ChainHash>(index: usize) -> usize {
    if index < N * 2 {
        return 4;
    }
    let bits = FastWinternitz::<N, H, Preimage16>::CHECKSUM_BITS;
    let digits = FastWinternitz::<N, H, Preimage16>::CHECKSUM_DIGITS;
    bits / digits + usize::from(index - N * 2 >= digits - bits % digits)
}

fn round_trips<const N: usize, H: ChainHash>() {
    let key = FastWinternitz::<N, H, Preimage16>::signing_key_from_seed(SEED);
    let public_key = FastWinternitz::<N, H, Preimage16>::public_key(&key);
    let native_key = FastWinternitz::<N, H>::signing_key_from_seed(SEED);
    let native_public_key = FastWinternitz::<N, H>::public_key(&native_key);
    assert_ne!(
        public_key.chain_ends(),
        native_public_key.chain_ends(),
        "preimage mode needs its own key namespace"
    );
    let leaves = PROFILES.map(|profile| (profile, profile.leaf(&public_key)));

    for message in [
        [0; N],
        [0xff; N],
        core::array::from_fn(|i| (i as u8).wrapping_mul(0x31).wrapping_add(0x17)),
    ] {
        // Seed restoration here is only for deterministic test vectors.
        let signature = FastWinternitz::<N, H, Preimage16>::sign(
            FastWinternitz::<N, H, Preimage16>::signing_key_from_seed(SEED),
            &message,
        );
        let native_signature = FastWinternitz::<N, H>::sign(
            FastWinternitz::<N, H>::signing_key_from_seed(SEED),
            &message,
        );
        assert_eq!(signature.digits(), native_signature.digits());
        let zero_digits = signature
            .digits()
            .iter()
            .filter(|&&digit| digit == 0)
            .count();

        for (index, (node, &digit)) in signature
            .chain_values()
            .iter()
            .zip(signature.digits())
            .enumerate()
        {
            assert_eq!(
                node.as_ref().len(),
                if digit == 0 { 16 } else { H::VALUE_BYTES }
            );
            let maximum = (1 << chain_bits::<N, H>(index)) - 1;
            let mut endpoint = node.as_ref().to_vec();
            for _ in digit..maximum {
                endpoint = H::hash_parts(&[&endpoint]).as_ref().to_vec();
            }
            assert_eq!(endpoint, public_key.chain_ends()[index].as_ref());
        }

        for (profile, leaf) in &leaves {
            let witness = profile.witness(&signature);
            let native_witness = match profile {
                Profile::Exact | Profile::ExactTerminal | Profile::Lookup => {
                    native_signature.to_witness()
                }
                Profile::Numeric
                | Profile::NumericTerminal
                | Profile::Clamped
                | Profile::ClampedTerminal => native_signature.to_size_optimized_witness(),
                Profile::Bitwise => native_signature.to_bitwise_size_optimized_witness(),
                Profile::BitwiseTerminal => native_signature.to_bitwise_terminal_witness(),
            };
            // There are no auxiliary hints: all entry items are chain nodes
            // and authenticated digits/bits. Shortening nodes adds no items.
            let expected_items = if matches!(profile, Profile::Bitwise | Profile::BitwiseTerminal) {
                FastWinternitz::<N, H, Preimage16>::TOTAL_DIGITS
                    + N * 8
                    + FastWinternitz::<N, H, Preimage16>::CHECKSUM_BITS
            } else {
                2 * FastWinternitz::<N, H, Preimage16>::TOTAL_DIGITS
            };
            assert_eq!(witness.len(), expected_items);
            assert_eq!(witness.len(), native_witness.len());
            assert_eq!(
                serialize(&native_witness).len() - serialize(&Witness::from_slice(&witness)).len(),
                zero_digits * (H::VALUE_BYTES - 16)
            );
            run(
                leaf,
                witness,
                true,
                &format!("{profile:?}, N={N}, hash width {}", H::VALUE_BYTES),
            );
        }
    }
}

#[test]
fn short_preimages_round_trip_all_profiles_and_preserve_exact_witness_savings() {
    round_trips::<1, Hash160>();
    round_trips::<4, Hash160>();
    round_trips::<32, Hash160>();
    round_trips::<80, Hash160>();
    round_trips::<1, Sha256>();
    round_trips::<4, Sha256>();
    round_trips::<32, Sha256>();
    round_trips::<80, Sha256>();
}

fn recover_message<H: ChainHash>() {
    let message = [0x01, 0x7f, 0x80, 0xee];
    let key = FastWinternitz::<4, H, Preimage16>::signing_key_from_seed(SEED);
    let public_key = FastWinternitz::<4, H, Preimage16>::public_key(&key);
    let signature = FastWinternitz::<4, H, Preimage16>::sign(key, &message);
    let expected = message
        .into_iter()
        .flat_map(|byte| [byte >> 4, byte & 15])
        .collect::<Vec<_>>();
    for profile in PROFILES.into_iter().filter(|profile| profile.recovers()) {
        let leaf = script! {
            { profile.fragment(&public_key) }
            for digit in expected.iter().rev() { { *digit as i64 } OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy();
        run(
            &leaf,
            profile.witness(&signature),
            true,
            &format!("{profile:?} recovered message"),
        );
    }
}

#[test]
fn short_preimages_recover_the_original_nibbles() {
    recover_message::<Hash160>();
    recover_message::<Sha256>();
}

fn malformed_inputs<H: ChainHash>() {
    let key = FastWinternitz::<1, H, Preimage16>::signing_key_from_seed(SEED);
    let public_key = FastWinternitz::<1, H, Preimage16>::public_key(&key);
    for profile in PROFILES {
        let leaf = profile.leaf(&public_key);
        for message in [[0x00], [0xff]] {
            let signature = FastWinternitz::<1, H, Preimage16>::sign(
                FastWinternitz::<1, H, Preimage16>::signing_key_from_seed(SEED),
                &message,
            );
            let witness = profile.witness(&signature);
            let chain_index = if message[0] == 0 { 0 } else { 2 };
            assert_eq!(signature.digits()[chain_index], 0);
            let node = signature.chain_values()[chain_index].as_ref();
            let node_index = witness
                .iter()
                .position(|item| item.as_slice() == node)
                .unwrap();
            let digit_index = match profile {
                Profile::Exact | Profile::ExactTerminal | Profile::Lookup => node_index - 1,
                Profile::Numeric
                | Profile::NumericTerminal
                | Profile::Clamped
                | Profile::ClampedTerminal => node_index + 1,
                Profile::Bitwise => node_index - chain_bits::<1, H>(chain_index),
                Profile::BitwiseTerminal => node_index + 1,
            };
            for invalid in [vec![0x81], vec![1; 5], vec![1, 0]] {
                let mut changed = witness.clone();
                changed[digit_index] = invalid;
                run(
                    &leaf,
                    changed,
                    false,
                    &format!("{profile:?} malformed digit/bit"),
                );
            }
            for length in [0, 15, 17, H::VALUE_BYTES] {
                let mut changed = witness.clone();
                changed[node_index].resize(length, 0x5a);
                run(
                    &leaf,
                    changed,
                    false,
                    &format!("{profile:?} malformed short node"),
                );
            }
            let mut changed = witness.clone();
            changed[node_index][0] ^= 1;
            run(&leaf, changed, false, &format!("{profile:?} tampered node"));

            // Forward a real chain node, while keeping every other chain
            // unchanged. Chain equality still holds; the checksum must fail.
            let mut changed = witness.clone();
            changed[node_index] = H::hash_parts(&[node]).as_ref().to_vec();
            changed[digit_index] = if matches!(profile, Profile::BitwiseTerminal) {
                vec![]
            } else {
                vec![1]
            };
            run(
                &leaf,
                changed,
                false,
                &format!("{profile:?} forwarded chain {chain_index}"),
            );

            let mut missing = witness.clone();
            missing.pop();
            run(&leaf, missing, false, &format!("{profile:?} missing item"));
            let mut extra = witness;
            extra.insert(0, vec![]);
            run(&leaf, extra, false, &format!("{profile:?} extra item"));
        }
    }
}

#[test]
fn short_preimages_reject_malformed_inputs_and_chain_forwarding() {
    malformed_inputs::<Hash160>();
    malformed_inputs::<Sha256>();
}

fn strict_widths<H: ChainHash>() {
    let key = FastWinternitz::<1, H, Preimage16>::signing_key_from_seed(SEED);
    let public_key = FastWinternitz::<1, H, Preimage16>::public_key(&key);
    for digit in [0u8, 1, 14, 15] {
        let signature = FastWinternitz::<1, H, Preimage16>::sign(
            FastWinternitz::<1, H, Preimage16>::signing_key_from_seed(SEED),
            &[digit << 4 | 7],
        );
        for length in [
            15,
            16,
            17,
            H::VALUE_BYTES - 1,
            H::VALUE_BYTES,
            H::VALUE_BYTES + 1,
        ] {
            let (node, endpoint) = if digit == 15 {
                // At the maximum digit no hash executes. Endpoint equality
                // itself enforces the full hash width.
                let mut node = signature.chain_values()[0].as_ref().to_vec();
                node.resize(length, 0x73);
                (node, public_key.chain_ends()[0])
            } else {
                let node = vec![0x73; length];
                let mut endpoint = H::hash_parts(&[&node]);
                for _ in digit + 1..15 {
                    endpoint = H::hash_parts(&[endpoint.as_ref()]);
                }
                (node, endpoint)
            };
            let mut ends = public_key.chain_ends().to_vec();
            ends[0] = endpoint;
            let changed_key = FastPublicKey::<1, H, Preimage16>::from_chain_ends(ends).unwrap();
            let mut witness = signature.to_witness().to_vec();
            witness[1] = node;
            for profile in [Profile::Exact, Profile::ExactTerminal, Profile::Lookup] {
                run(
                    &profile.leaf(&changed_key),
                    witness.clone(),
                    length == if digit == 0 { 16 } else { H::VALUE_BYTES },
                    &format!("{profile:?} independently committed width {length}, digit {digit}"),
                );
            }
        }
    }
}

#[test]
fn strict_profiles_bind_short_nodes_to_zero_digits() {
    strict_widths::<Hash160>();
    strict_widths::<Sha256>();
}

fn python_vector<H: ChainHash>(expected_public_digest: &str, expected_signature_digest: &str) {
    let key = FastWinternitz::<32, H, Preimage16>::signing_key_from_seed([0x42; 32]);
    let public_key = FastWinternitz::<32, H, Preimage16>::public_key(&key);
    let signature =
        FastWinternitz::<32, H, Preimage16>::sign(key, &core::array::from_fn(|i| i as u8));
    let public_bytes: Vec<_> = public_key
        .chain_ends()
        .iter()
        .flat_map(|node| node.as_ref().iter().copied())
        .collect();
    let signature_bytes: Vec<_> = signature
        .chain_values()
        .iter()
        .flat_map(|node| node.as_ref().iter().copied())
        .collect();
    assert_eq!(
        sha256::Hash::hash(&public_bytes).to_string(),
        expected_public_digest
    );
    assert_eq!(
        sha256::Hash::hash(&signature_bytes).to_string(),
        expected_signature_digest
    );
}

#[test]
fn short_preimages_match_independent_python_vectors() {
    // Generated by tools/winternitz_hash_vectors.py using Python hashlib,
    // seed 0x42 * 32, bytes(range(32)), and the explicit preimage16 domain.
    python_vector::<Hash160>(
        "64fab0fc46410aba9efce0c97c9887bc093bbdb52ea182336d06fa8cacff5010",
        "ceaaf95e1318077f3ea43eacc537e916b0f9a7ba66a9bdadd0744e52c934ead6",
    );
    python_vector::<Sha256>(
        "8ad51f6ea8e6aec8e9ad7e8566290080d04ac5e3535d4f32cbe6a226ddcfc18b",
        "96415f25dbcbc97147b90200b17ab2284f4e533003c239d76d4f5e0700fc772b",
    );
}
