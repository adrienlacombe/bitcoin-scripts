//! The isolated verifier makes the trusted pool the entire main stack.
use super::*;
use crate::{
    signatures::winternitz::{FullWidth, Sha256, Sha256Hash160},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn isolated<H: ChainHash, P: PreimageSize<H>>() {
    type Wots<H, P> = ConstantCompositionWinternitz20<H, P>;
    let key = Wots::<H, P>::signing_key_from_seed([0x64; 32]);
    let public_key = Wots::<H, P>::public_key(&key);
    let verifier = Wots::<H, P>::checksig_verify_isolated_and_clear(&public_key);
    let leaf = script! {
        OP_7 OP_TOALTSTACK
        { verifier }
        OP_DEPTH OP_0 OP_EQUALVERIFY
        OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
    }
    .compile_with_policy();
    for message in [
        [0; 20],
        [0xff; 20],
        core::array::from_fn(|i| (i * 37) as u8),
    ] {
        let signature =
            Wots::<H, P>::sign(Wots::<H, P>::signing_key_from_seed([0x64; 32]), &message);
        let witness = signature.to_witness().to_vec();
        let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness.clone());
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.stats.max_nb_stack_items, 120);

        let mut extra = witness.clone();
        extra.insert(0, vec![1]);
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), extra).success);
        let mut missing = witness.clone();
        missing.pop();
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), missing).success);

        for slot in 0..OPENINGS {
            // The pinned local interpreter has a ROLL bounds-check bug at
            // exactly the pool length: it panics after popping the selector.
            // Exercise an unambiguously invalid larger index here. Bitcoin's
            // intrinsic ROLL bound also rejects equality with the pool length.
            for selector in [vec![0x81], integer(CHAINS - slot + 1), vec![0; 5]] {
                let mut malformed = witness.clone();
                malformed[2 * slot] = selector;
                let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), malformed);
                assert!(!result.success, "slot {slot}: {result}");
            }
        }
    }
}

#[test]
fn isolated_pool_preserves_altstack_and_rejects_foreign_main_state() {
    isolated::<Hash160, Preimage16>();
    isolated::<Hash160, FullWidth>();
    isolated::<Sha256, Preimage16>();
    isolated::<Sha256, FullWidth>();
    isolated::<Sha256Hash160, Preimage16>();
    isolated::<Sha256Hash160, FullWidth>();
}
