use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch before accounting for unrelated live stack state.
pub const U4_EXACT_SUM_MAX_BATCH: u32 = 997;

/// Consume checked nibbles and return their exact arithmetic sum.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | sum`, where `sum` is in `0..=15*n`.
pub fn u4_nibbles_sum_exact(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "exact sum needs a nonempty vector");
    assert!(
        nibble_count <= U4_EXACT_SUM_MAX_BATCH,
        "exact-sum batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        0 OP_TOALTSTACK
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{execution::execute_script, script::script},
    };

    #[test]
    fn returns_exact_sum_not_modulo_sixteen() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("1234") }
            { u4_nibbles_sum_exact(4) }
            10 OP_EQUAL
        });
        assert!(result.success, "exact sum failed: {result}");

        let above_modulus = execute_script(script! {
            { u4_hex_to_nibbles("ffff") }
            { u4_nibbles_sum_exact(4) }
            60 OP_EQUAL
        });
        assert!(
            above_modulus.success,
            "sum was reduced modulo 16: {above_modulus}"
        );
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_sum_exact(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_sum_exact(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_sum_exact(U4_EXACT_SUM_MAX_BATCH + 1) })
                .is_err()
        );
    }

    #[test]
    fn preserves_surrounding_stack_items_and_singletons() {
        let singleton = execute_script(script! {
            7
            { u4_hex_to_nibbles("a") }
            { u4_nibbles_sum_exact(1) }
            10 OP_EQUALVERIFY
            7 OP_EQUAL
        });
        assert!(singleton.success, "singleton failed: {singleton}");

        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_nibbles_sum_exact(4) }
            6 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
