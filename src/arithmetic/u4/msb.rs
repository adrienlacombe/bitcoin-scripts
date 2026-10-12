//! Batched most-significant-bit projection for range-checked u4 limbs.

use crate::support::script::*;

/// Largest direct-threshold batch before unrelated stack state.
pub const U4_MSB_MAX_BATCH: u32 = 998;

/// Largest batch that uses three-wide range-check groups.
///
/// These batches peak at `batch + 3` combined items. Larger batches, up to
/// [`U4_MSB_MAX_BATCH`], use two-wide groups and peak at `batch + 2`, so the
/// frontier near the 1,000-item limit is unchanged.
pub const U4_MSB_WIDE_MAX_BATCH: u32 = U4_MSB_MAX_BATCH - 3;

/// Remaining batch depth from which `OP_PICK` can check a group minimum.
///
/// With at least 16 batch items still on the main stack, `OP_PICK` succeeds for
/// any index in `0..=15` whatever lies below the batch, and fails for a
/// negative index. It then checks the lower bound in two bytes instead of three.
const PICK_LOWER_BOUND_DEPTH: u32 = 16;

/// Bytes for one group of `width` nibbles when `remaining` batch items are
/// still on the main stack, including its share of `OP_FROMALTSTACK`s.
fn group_cost(width: u32, max_width: u32, remaining: u32) -> u32 {
    let pick = remaining >= PICK_LOWER_BOUND_DEPTH;
    // 8 OP_GREATERTHANOREQUAL OP_TOALTSTACK ... OP_FROMALTSTACK per nibble.
    let bits = 4 * width;
    match width {
        // OP_DUP 0 16 OP_WITHIN OP_VERIFY needs three scratch items.
        1 if max_width >= 3 => 5 + bits,
        // OP_DUP 16 OP_LESSTHAN OP_VERIFY, then OP_DUP OP_PICK OP_DROP or
        // OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY.
        1 => 4 + if pick { 3 } else { 4 } + bits,
        // copy, (width - 1) x OP_MAX, 16 OP_LESSTHAN OP_VERIFY, then
        // copy, (width - 1) x OP_MIN, OP_PICK OP_DROP or 0 OP_GTE OP_VERIFY.
        _ => 2 * width + 3 + if pick { 2 } else { 3 } + bits,
    }
}

/// Group widths from the top of the batch down, minimizing the script size.
fn group_schedule(nibble_count: u32, max_width: u32) -> Vec<u32> {
    let n = nibble_count as usize;
    // best[k] = (cost, top group width) for the bottom k nibbles of the batch.
    let mut best = vec![(0u32, 0u32); n + 1];
    for k in 1..=n {
        best[k] = (1..=max_width.min(k as u32))
            .map(|width| {
                let below = best[k - width as usize].0;
                (below + group_cost(width, max_width, k as u32), width)
            })
            .min_by_key(|&(cost, width)| (cost, core::cmp::Reverse(width)))
            .expect("width range is non-empty");
    }
    let mut schedule = Vec::new();
    let mut k = n;
    while k > 0 {
        let width = best[k].1;
        schedule.push(width);
        k -= width as usize;
    }
    schedule
}

/// Fail unless the top `width` items are all in `0..=15`; leave them in place.
///
/// `remaining` counts the batch items still on the main stack, these included.
fn verify_group(width: u32, max_width: u32, remaining: u32) -> Script {
    let pick = remaining >= PICK_LOWER_BOUND_DEPTH;
    if width == 1 {
        return if max_width >= 3 {
            script! { OP_DUP 0 16 OP_WITHIN OP_VERIFY }
        } else if pick {
            script! { OP_DUP 16 OP_LESSTHAN OP_VERIFY OP_DUP OP_PICK OP_DROP }
        } else {
            script! {
                OP_DUP 16 OP_LESSTHAN OP_VERIFY
                OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            }
        };
    }
    assert!(width <= 3, "range-check groups are at most three wide");
    let copy = || {
        if width == 3 {
            script! { OP_3DUP }
        } else {
            script! { OP_2DUP }
        }
    };
    script! {
        { copy() }
        for _ in 1..width { OP_MAX }
        16 OP_LESSTHAN OP_VERIFY
        { copy() }
        for _ in 1..width { OP_MIN }
        if pick {
            // A negative minimum is an invalid stack index; the picked item
            // itself is irrelevant.
            OP_PICK OP_DROP
        } else {
            0 OP_GREATERTHANOREQUAL OP_VERIFY
        }
    }
}

/// Consume range-checked nibbles and replace each with its most-significant bit.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | msb[0] | ... | msb[n-1]`, with the last output
/// on top. Every input must be a number in `0..=15`; anything else fails.
///
/// Nibbles are range-checked in groups: the group maximum must be below 16 and
/// the group minimum non-negative. Batches of up to [`U4_MSB_WIDE_MAX_BATCH`]
/// use three-wide groups and peak at `n + 3` combined items; larger batches use
/// two-wide groups and peak at `n + 2`.
pub fn u4_nibbles_to_msb(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_MSB_MAX_BATCH,
        "nibble-MSB batch exceeds Bitcoin Script's stack limit"
    );

    let max_width = if nibble_count <= U4_MSB_WIDE_MAX_BATCH {
        3
    } else {
        2
    };
    grouped_nibbles_to_msb(nibble_count, max_width)
}

fn grouped_nibbles_to_msb(nibble_count: u32, max_width: u32) -> Script {
    let mut groups = Vec::new();
    let mut remaining = nibble_count;
    for width in group_schedule(nibble_count, max_width) {
        let last_group = remaining == width;
        groups.push(script! {
            { verify_group(width, max_width, remaining) }
            for index in 0..width {
                8 OP_GREATERTHANOREQUAL
                // The bottom output can stay on the main stack.
                if !(last_group && index + 1 == width) {
                    OP_TOALTSTACK
                }
            }
        });
        remaining -= width;
    }

    script! {
        for group in groups { { group } }
        for _ in 1..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{
            execution::{execute_script, execute_script_with_inputs_strict, ExecuteInfo},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

    #[test]
    fn projects_asymmetric_boundary_values_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("78f") }
            { u4_nibbles_to_msb(3) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "MSB projection failed: {result}");
    }

    fn scriptnum(value: i64) -> Vec<u8> {
        script! { { value } }
            .compile()
            .instructions()
            .next()
            .map(|instruction| match instruction.unwrap() {
                bitcoin::script::Instruction::PushBytes(bytes) => bytes.as_bytes().to_vec(),
                bitcoin::script::Instruction::Op(op) => {
                    let code = op.to_u8();
                    if code == 0x4f {
                        vec![0x81]
                    } else {
                        vec![code - 0x50]
                    }
                }
            })
            .unwrap_or_default()
    }

    /// Run `fragment` on `preserved | nibbles` and check the projected bits and
    /// the untouched preserved items. Returns the execution result.
    fn run_batch(fragment: Script, preserved: &[i64], nibbles: &[Vec<u8>]) -> ExecuteInfo {
        let expected: Vec<i64> = nibbles
            .iter()
            .map(|bytes| {
                let value = bytes
                    .iter()
                    .rev()
                    .fold(0i64, |acc, byte| (acc << 8) | *byte as i64);
                (value >= 8) as i64
            })
            .collect();
        let mut witness: Vec<Vec<u8>> = preserved.iter().map(|value| scriptnum(*value)).collect();
        witness.extend(nibbles.iter().cloned());
        execute_script_with_inputs_strict(
            script! {
                { fragment }
                for bit in expected.iter().rev() {
                    { *bit } OP_EQUALVERIFY
                }
                for value in preserved.iter().rev() {
                    { *value } OP_EQUALVERIFY
                }
                OP_TRUE
            },
            witness,
        )
    }

    fn schedules(nibble_count: u32) -> Vec<(u32, Script)> {
        vec![
            (3, grouped_nibbles_to_msb(nibble_count, 3)),
            (2, grouped_nibbles_to_msb(nibble_count, 2)),
        ]
    }

    #[test]
    fn projects_every_value_at_every_position_for_all_schedules() {
        for nibble_count in [1u32, 2, 3, 4, 5, 16, 17, 18, 19, 20, 32, 33, 40] {
            for (width, fragment) in schedules(nibble_count) {
                for shift in 0..16 {
                    let nibbles: Vec<Vec<u8>> = (0..nibble_count)
                        .map(|index| scriptnum(((index * 7 + shift) % 16) as i64))
                        .collect();
                    for preserved in [&[][..], &[-5, 1_000_000][..]] {
                        let result = run_batch(fragment.clone(), preserved, &nibbles);
                        assert!(
                            result.success,
                            "width {width}, {nibble_count} nibbles, shift {shift}: {result}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_every_invalid_value_at_every_position_for_all_schedules() {
        let invalid: Vec<Vec<u8>> = [-1i64, -8, -15, -16, 16, 17, 24, 255, 1 << 20, -(1 << 30)]
            .iter()
            .map(|value| scriptnum(*value))
            .chain([vec![0, 0, 0, 0, 1], vec![0x10, 0x80], vec![0x01, 0x80]])
            .collect();
        for nibble_count in [1u32, 2, 3, 4, 17, 32] {
            for (width, fragment) in schedules(nibble_count) {
                for position in 0..nibble_count as usize {
                    for bad in &invalid {
                        let mut nibbles: Vec<Vec<u8>> = (0..nibble_count)
                            .map(|index| scriptnum((index % 16) as i64))
                            .collect();
                        nibbles[position] = bad.clone();
                        for preserved in [&[][..], &[3, 7, 15, 20][..]] {
                            let result = run_batch(fragment.clone(), preserved, &nibbles);
                            assert!(
                                !result.success,
                                "width {width}, {nibble_count} nibbles: accepted {bad:?} at {position}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn batch32_stays_within_three_scratch_items() {
        let fragment = u4_nibbles_to_msb(32);
        for value in [0, 7, 8, 15] {
            let result = execute_script_with_inputs_strict(
                script! {
                    { fragment.clone() }
                    { crate::arithmetic::u4::stack::u4_drop(32) }
                    OP_TRUE
                },
                vec![scriptnum(value); 32],
            );
            assert!(result.success, "{result}");
            assert!(result.stats.max_nb_stack_items <= 35, "{result}");
        }
    }

    #[test]
    fn rejects_invalid_nibbles_at_each_position() {
        for position in 0..3 {
            let mut input = vec![1; 3];
            input[position] = if position % 2 == 0 { -1 } else { 16 };
            let result = execute_script(script! {
                for nibble in input { { nibble } }
                { u4_nibbles_to_msb(3) }
                OP_2DROP OP_DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble at {position}");
        }

        for position in 0..3 {
            let mut witness = vec![vec![1]; 3];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_nibbles_to_msb(3) }
                    OP_2DROP OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized nibble at {position}");
        }
    }

    #[test]
    fn respects_direct_threshold_stack_frontier() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_msb(U4_MSB_MAX_BATCH) }
                { crate::arithmetic::u4::stack::u4_drop(U4_MSB_MAX_BATCH) }
                OP_TRUE
            },
            vec![Vec::new(); U4_MSB_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum MSB batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let mut preserved = vec![vec![7]];
        preserved.extend(vec![Vec::new(); 996]);
        let with_state = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_msb(996) }
                { crate::arithmetic::u4::stack::u4_drop(996) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved,
        );
        assert!(with_state.success, "preserved state failed: {with_state}");

        let mut over_budget = vec![vec![7]];
        over_budget.extend(vec![Vec::new(); 997]);
        let rejected = execute_script_with_inputs_strict(
            script! { OP_9 OP_TOALTSTACK { u4_nibbles_to_msb(997) } },
            over_budget,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    #[should_panic(expected = "nibble-MSB batch exceeds Bitcoin Script's stack limit")]
    fn rejects_batch_above_stack_limit() {
        let _ = u4_nibbles_to_msb(U4_MSB_MAX_BATCH + 1);
    }
}
