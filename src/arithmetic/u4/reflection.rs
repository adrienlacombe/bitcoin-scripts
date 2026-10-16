//! Canonical reflection-constrained u4 vector witnesses.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Conservative common bound: the raw verifier needs four temporary items.
pub const MAX_REFLECTION_WIDTH: u32 = 996;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reflection {
    /// Mirrored symbols are equal.
    Equal,
    /// Mirrored symbols sum to fifteen. Width must be even.
    Complement,
}

fn half_width(width: u32, reflection: Reflection) -> u32 {
    assert!(
        (1..=MAX_REFLECTION_WIDTH).contains(&width),
        "reflection width must be in 1..=996"
    );
    assert!(
        reflection != Reflection::Complement || width % 2 == 0,
        "odd complement reflection has no integer center"
    );
    width.div_ceil(2)
}

fn verify_vector(width: u32) -> Script {
    script! {
        for depth in 0..width {
            { depth } OP_PICK
            { verify_canonical_nibble() }
            OP_DROP
        }
    }
}

/// Expand `ceil(width/2)` canonical nibbles into a reflection-constrained vector.
///
/// `preserved | h[0] ... h[m-1] -> preserved | v[0] ... v[width-1]`.
/// The last item is on top. Odd equal reflection retains one central symbol;
/// complement reflection is even-only. No hints, tables, or altstack state.
pub fn expand_reflection(width: u32, reflection: Reflection) -> Script {
    let half = half_width(width, reflection);
    script! {
        { verify_vector(half) }
        for index in 0..width / 2 {
            { 2 * index + width % 2 } OP_PICK
            if reflection == Reflection::Complement {
                15 OP_SWAP OP_SUB
            }
        }
    }
}

/// Baseline: verify canonical encoding and reflection of a full witness vector.
///
/// Leaves all `width` nibbles in place, preserves unrelated main/alt state, and
/// rejects symmetry violations. The same output/terminal obligations apply.
pub fn verify_reflection(width: u32, reflection: Reflection) -> Script {
    half_width(width, reflection);
    script! {
        { verify_vector(width) }
        for index in 0..width / 2 {
            { width - 1 - index } OP_PICK
            { index + 1 } OP_PICK
            if reflection == Reflection::Equal {
                OP_EQUALVERIFY
            } else {
                OP_ADD 15 OP_NUMEQUALVERIFY
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };

    fn expected(half: &[u8], width: u32, reflection: Reflection) -> Vec<u8> {
        // Independent output-coordinate definition, rather than stack depths.
        (0..width as usize)
            .map(|i| {
                if i < half.len() {
                    half[i]
                } else {
                    let x = half[width as usize - 1 - i];
                    if reflection == Reflection::Equal {
                        x
                    } else {
                        15 - x
                    }
                }
            })
            .collect()
    }

    fn leaf(fragment: Script, values: &[u8]) -> bitcoin::ScriptBuf {
        script! {
            { fragment }
            for value in values.iter().rev() { { *value as u32 } OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn witness(values: &[u8]) -> Vec<Vec<u8>> {
        values.iter().map(|&x| scriptnum(i64::from(x))).collect()
    }

    #[test]
    fn exhausts_all_one_and_two_symbol_half_vectors() {
        for (width, reflection) in [
            (1, Reflection::Equal),
            (2, Reflection::Equal),
            (3, Reflection::Equal),
            (4, Reflection::Equal),
            (2, Reflection::Complement),
            (4, Reflection::Complement),
        ] {
            let half = half_width(width, reflection);
            for packed in 0..16u32.pow(half) {
                let source: Vec<_> = (0..half)
                    .map(|i| ((packed >> (4 * i)) & 15) as u8)
                    .collect();
                let values = expected(&source, width, reflection);
                assert_clean_true(&run_tapscript(
                    leaf(expand_reflection(width, reflection), &values),
                    witness(&source),
                    TapscriptProfile::Consensus,
                ));
                assert_clean_true(&run_tapscript(
                    leaf(verify_reflection(width, reflection), &values),
                    witness(&values),
                    TapscriptProfile::Consensus,
                ));
            }
        }
    }

    #[test]
    fn wider_asymmetric_halves_preserve_every_coordinate_and_surrounding_state() {
        for (width, reflection) in [
            (16, Reflection::Equal),
            (17, Reflection::Equal),
            (32, Reflection::Complement),
            (33, Reflection::Equal),
        ] {
            let source: Vec<_> = (0..half_width(width, reflection))
                .map(|i| ((i * 7 + 3) % 16) as u8)
                .collect();
            let values = expected(&source, width, reflection);
            for (fragment, data) in [
                (expand_reflection(width, reflection), source.clone()),
                (verify_reflection(width, reflection), values.clone()),
            ] {
                let compiled = script! {
                    { data.len() } OP_ROLL OP_TOALTSTACK
                    { fragment }
                    for value in values.iter().rev() { { *value as u32 } OP_EQUALVERIFY }
                    77 OP_EQUALVERIFY
                    OP_FROMALTSTACK 99 OP_EQUAL
                }
                .compile_with_policy();
                let mut data_witness = vec![scriptnum(77), scriptnum(99)];
                data_witness.extend(witness(&data));
                assert_clean_true(&run_tapscript(
                    compiled,
                    data_witness,
                    TapscriptProfile::Consensus,
                ));
            }
        }
    }

    #[test]
    fn rejects_hostile_raw_encodings_at_every_witness_position() {
        for reflection in [Reflection::Equal, Reflection::Complement] {
            let source = vec![3; 4];
            let values = expected(&source, 8, reflection);
            for (fragment, data) in [
                (expand_reflection(8, reflection), source.clone()),
                (verify_reflection(8, reflection), values.clone()),
            ] {
                // Cleanup makes rejection a property of the fragment itself,
                // rather than of byte-equality checks on aliased outputs.
                let compiled = script! {
                    { fragment }
                    for _ in 0..8 { OP_DROP }
                    OP_TRUE
                }
                .compile_with_policy();
                for i in 0..data.len() {
                    for bad in [
                        scriptnum(-1),
                        scriptnum(16),
                        vec![3, 0],
                        vec![0x80],
                        vec![0],
                        vec![0; 5],
                        vec![0; 521],
                    ] {
                        let mut raw = witness(&data);
                        raw[i] = bad;
                        assert!(
                            !run_tapscript(compiled.clone(), raw, TapscriptProfile::Consensus)
                                .success
                        );
                    }
                }
                let mut missing = witness(&data);
                missing.pop();
                assert!(
                    !run_tapscript(compiled.clone(), missing, TapscriptProfile::Consensus).success
                );
                let mut extra = witness(&data);
                extra.insert(0, vec![]);
                assert!(!run_tapscript(compiled, extra, TapscriptProfile::Consensus).success);
            }
        }
    }

    #[test]
    fn raw_aliases_cannot_hide_in_a_center_or_matching_mirrored_pair() {
        for width in [1, 7] {
            let compiled = script! {
                { verify_reflection(width,Reflection::Equal) }
                for _ in 0..width { OP_DROP }
                OP_TRUE
            }
            .compile_with_policy();
            let mut raw = vec![scriptnum(3); width as usize];
            raw[(width / 2) as usize] = vec![3, 0];
            assert!(!run_tapscript(compiled, raw, TapscriptProfile::Consensus).success);
        }
        let compiled=script! { { verify_reflection(8,Reflection::Equal) } for _ in 0..8 { OP_DROP } OP_TRUE }.compile_with_policy();
        assert!(!run_tapscript(compiled, vec![vec![3, 0]; 8], TapscriptProfile::Consensus).success);
    }

    #[test]
    fn full_vector_baseline_rejects_every_broken_pair() {
        for reflection in [Reflection::Equal, Reflection::Complement] {
            let values = expected(&[1, 5, 9, 13], 8, reflection);
            for position in 0..values.len() {
                let mut bad = values.clone();
                bad[position] = (bad[position] + 1) % 16;
                // Drop outputs, so rejection must come from the symmetry verifier.
                let compiled=script! { { verify_reflection(8,reflection) } for _ in 0..8 { OP_DROP } OP_TRUE }.compile_with_policy();
                assert!(
                    !run_tapscript(compiled, witness(&bad), TapscriptProfile::Consensus).success
                );
            }
        }
    }

    #[test]
    fn exact_combined_stack_frontiers_include_expanded_output_and_live_state() {
        for reflection in [Reflection::Equal, Reflection::Complement] {
            for expanded in [false, true] {
                let width = 32;
                let source = vec![3; 16];
                let values = expected(&source, width, reflection);
                let (fragment, data, peak) = if expanded {
                    // Complete leaf needs one item for its first output comparison.
                    (expand_reflection(width, reflection), source, 33)
                } else {
                    (verify_reflection(width, reflection), values.clone(), 36)
                };
                let preserved = 1000 - peak;
                let compiled = script! {
                    // Move a runtime witness item into the altstack; a known
                    // constant checked against itself could optimize away.
                    { data.len() } OP_ROLL OP_TOALTSTACK
                    { fragment.clone() }
                    for value in values.iter().rev() { { *value as u32 } OP_EQUALVERIFY }
                    for _ in 0..preserved-1 { 77 OP_EQUALVERIFY }
                    OP_FROMALTSTACK 99 OP_EQUAL
                }
                .compile_with_policy();
                let mut raw = vec![scriptnum(77); preserved - 1];
                raw.push(scriptnum(99));
                raw.extend(witness(&data));
                let result = run_tapscript(compiled, raw, TapscriptProfile::Consensus);
                assert_clean_true(&result);
                assert_eq!(result.stats.max_nb_stack_items, 1000);
                let compiled=script! { { data.len() } OP_ROLL OP_TOALTSTACK { fragment } for value in values.iter().rev() { { *value as u32 } OP_EQUALVERIFY } }.compile_with_policy();
                let mut raw = vec![scriptnum(77); preserved];
                raw.push(scriptnum(99));
                raw.extend(witness(&data));
                let result = run_tapscript(compiled, raw, TapscriptProfile::Consensus);
                assert!(matches!(
                    result.error,
                    Some(bitcoin_scriptexec::ExecError::StackSize)
                ));
                assert_eq!(result.stats.max_nb_stack_items, 1001);
            }
        }
    }

    #[test]
    fn accepts_the_maximum_common_width_with_checked_outputs() {
        let width = MAX_REFLECTION_WIDTH;
        for reflection in [Reflection::Equal, Reflection::Complement] {
            let source: Vec<_> = (0..width / 2).map(|i| ((i * 7 + 3) % 16) as u8).collect();
            let values = expected(&source, width, reflection);
            for (fragment, data) in [
                (expand_reflection(width, reflection), source.clone()),
                (verify_reflection(width, reflection), values.clone()),
            ] {
                let result = run_tapscript(
                    leaf(fragment, &values),
                    witness(&data),
                    TapscriptProfile::Consensus,
                );
                assert_clean_true(&result);
                assert!(result.stats.max_nb_stack_items <= 1000);
            }
        }
    }

    #[test]
    fn rejects_unsupported_widths_and_odd_complement_centers() {
        for width in [0, 997, u32::MAX] {
            assert!(
                std::panic::catch_unwind(|| expand_reflection(width, Reflection::Equal)).is_err()
            );
            assert!(
                std::panic::catch_unwind(|| verify_reflection(width, Reflection::Equal)).is_err()
            );
        }
        for width in [1, 3, 995] {
            assert!(
                std::panic::catch_unwind(|| expand_reflection(width, Reflection::Complement))
                    .is_err()
            );
            assert!(
                std::panic::catch_unwind(|| verify_reflection(width, Reflection::Complement))
                    .is_err()
            );
        }
    }
}
