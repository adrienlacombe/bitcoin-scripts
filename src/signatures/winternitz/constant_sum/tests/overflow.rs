//! The global one-time security argument is not an individual range check.
use super::*;
use crate::support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation};

#[test]
fn unbounded_complete_leaf_can_accept_a_noncanonical_vector_constructed_with_the_secret_key() {
    type Wots = ConstantSumWinternitz20<Hash160, Preimage16>;
    let seed = [0x7b; 32];
    let key = Wots::signing_key_from_seed(seed);
    let public_key = Wots::public_key(&key);
    let namespace = namespace::<Hash160, Preimage16>(&seed);

    let mut digits = [0u8; CHAINS];
    digits[CHAINS - 1] = 100;
    let mut remaining = SUM - 100;
    for i in 0..CHAINS - 1 {
        digits[i] = remaining.min(RADICES[i] as usize - 1) as u8;
        remaining -= digits[i] as usize;
    }
    assert_eq!(remaining, 0);
    assert_eq!(digits.iter().map(|&d| d as usize).sum::<usize>(), SUM);
    assert!(Wots::decode_message(&digits).is_err());

    // A legitimate protocol item below the complete signature is the last
    // public endpoint. This is unrelated stack state, not a signature hint.
    let trap = public_key.commitments[CHAINS - 1].to_vec();
    let mut witness = Witness::new();
    witness.push(&trap);
    for i in 0..CHAINS {
        let start = chain_start::<Hash160, Preimage16>(&namespace, i);
        if i == CHAINS - 1 || digits[i] == 0 {
            witness.push(start.as_ref());
        } else {
            witness.push(chain_hash::<Hash160>(start.as_ref(), digits[i] as usize));
        }
        push_digit(&mut witness, digits[i]);
    }
    assert_eq!(witness.len(), Wots::WITNESS_DATA_ITEMS + 1);

    // Index 40 is consumed first. Its raw selector 100 becomes 90 after the
    // half-table subtraction. OP_PICK therefore skips its 10 table entries
    // and the other 40 chains' 80 witness items, selecting the protocol item.
    // Every remaining opening is constructed from the actual secret key with
    // digit sum 221. This does not model an attacker given one valid signature.
    for bounded in [false, true] {
        let complete = script! {
            { if bounded {
                Wots::checksig_verify_bounded_and_clear(&public_key)
            } else {
                Wots::checksig_verify_and_clear(&public_key)
            } }
            { trap.clone() } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let result = execute_raw_script_with_inputs_strict(complete.to_bytes(), witness.to_vec());
        assert_eq!(result.success, !bounded, "bounded={bounded}: {result}");
        if result.success {
            assert_eq!(result.final_stack.len(), 1);
        }
    }
}
