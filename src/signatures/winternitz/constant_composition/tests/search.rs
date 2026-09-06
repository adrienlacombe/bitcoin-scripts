//! Bounded design search for constant-composition Winternitz verification.
//!
//! Run independently of Cargo (this file is not a Rust test module):
//! ```text
//! rustc -O src/signatures/winternitz/constant_composition/tests/search.rs -o /private/tmp/wots-composition-search
//! /private/tmp/wots-composition-search
//! ```
//!
//! All symbols have positive multiplicity; the highest symbol is implicit.
//! Bounds: 110 keys, 90 openings, maximum digit 48, 1,200 units of nonzero
//! fixed-hash cost. Digit-zero shortening is accounted for separately. Binary
//! alphabets cannot encode 160 bits within the 110-key bound, so start at radix 3.
//! Only candidates whose total witness bound plus script cost is below 3,000
//! bytes are reported; this is the explicit comparison objective.
//!
//! The DP minimizes the log-factorial denominator of the multinomial capacity
//! for each opening-count/cost pair. Capacity screening uses f64 log2 values
//! and a 1e-10 tolerance. This is a bounded candidate search, not a proof of a
//! global optimum or exact capacity. Independently confirm retained candidates
//! with the exact integer arithmetic in vectors.py and compiled whole scripts.
//!
//! Costs assume 16-byte starts, 20-byte public commitments, altstack staging,
//! and upper-clamped selectors. Every selector uses at most one payload byte
//! at these bounds; the count prefix uses one byte. The objective includes a
//! conservative all-nonzero-selector witness bound, which vectors.py proves
//! attainable for the selected default's 160-bit encoder image. Transaction
//! overhead and a terminal predicate are excluded. This program executes no
//! Bitcoin Script and establishes no consensus or relay-policy classification.

const MAX_OPENINGS: usize = 90;
const MAX_HASH_COST: usize = 1200;
const MAX_DIGIT: usize = 48;
const MAX_KEYS: usize = 110;
const COST_OFFSET: usize = 16 * MAX_OPENINGS;
const ADJUSTED_WIDTH: usize = MAX_HASH_COST + COST_OFFSET + 1;

fn state(openings: usize, cost: usize) -> usize {
    openings * (MAX_HASH_COST + 1) + cost
}

fn adjusted_state(openings: usize, cost: isize) -> usize {
    openings * ADJUSTED_WIDTH + (cost + COST_OFFSET as isize) as usize
}

fn push_bytes(value: usize) -> usize {
    if value <= 16 {
        1
    } else if value <= 127 {
        2
    } else {
        3
    }
}

#[derive(Clone, Copy, Debug)]
enum Profile {
    Hash160,
    Sha256Hash160,
}

impl Profile {
    fn hash_cost(self, distance: usize) -> usize {
        match self {
            Self::Hash160 => distance,
            // The centralized optimizer fuses pairs of SHA256 to HASH256.
            Self::Sha256Hash160 => (distance + 1) / 2,
        }
    }

    fn shortening_savings(self) -> usize {
        match self {
            Self::Hash160 => 4,
            Self::Sha256Hash160 => 16,
        }
    }

    fn opening_base_cost(self) -> usize {
        match self {
            // Node, selector, and both item-length prefixes.
            Self::Hash160 => 23,
            // 35 witness bytes plus one HASH160 endpoint commitment opcode.
            Self::Sha256Hash160 => 36,
        }
    }
}

fn search(profile: Profile) {
    let mut log_factorial = [0.0; MAX_KEYS + 1];
    for n in 1..=MAX_KEYS {
        log_factorial[n] = log_factorial[n - 1] + (n as f64).log2();
    }
    let states = (MAX_OPENINGS + 1) * (MAX_HASH_COST + 1);
    let mut previous = vec![f64::INFINITY; states];
    previous[0] = 0.0;
    let mut histories = vec![vec![0u8; states]];
    let mut best = 3000isize;
    let mut winner = None;

    // Add each nonzero, nonmaximum symbol by its distance from the endpoint.
    for distance in 1..MAX_DIGIT {
        let weight = profile.hash_cost(distance);
        let mut current = vec![f64::INFINITY; states];
        let mut history = vec![0u8; states];
        for openings in 0..=MAX_OPENINGS {
            for cost in 0..=MAX_HASH_COST {
                let old = previous[state(openings, cost)];
                if !old.is_finite() {
                    continue;
                }
                let count_bound = (MAX_OPENINGS - openings).min((MAX_HASH_COST - cost) / weight);
                for count in 1..=count_bound {
                    let index = state(openings + count, cost + count * weight);
                    let candidate = old + log_factorial[count];
                    if candidate < current[index] {
                        current[index] = candidate;
                        history[index] = count as u8;
                    }
                }
            }
        }
        histories.push(history);
        previous = current;
        let maximum_digit = distance + 1;
        let zero_weight =
            profile.hash_cost(maximum_digit) as isize - profile.shortening_savings() as isize;

        // Digit zero has a different cost because only its node is 16 bytes.
        let mut with_zero = vec![f64::INFINITY; (MAX_OPENINGS + 1) * ADJUSTED_WIDTH];
        let mut zero_counts = vec![0u8; with_zero.len()];
        for openings in 0..=MAX_OPENINGS {
            for cost in 0..=MAX_HASH_COST {
                let old = previous[state(openings, cost)];
                if !old.is_finite() {
                    continue;
                }
                for zero_count in 1..=MAX_OPENINGS - openings {
                    let adjusted_cost = cost as isize + zero_count as isize * zero_weight;
                    if adjusted_cost > MAX_HASH_COST as isize {
                        continue;
                    }
                    let index = adjusted_state(openings + zero_count, adjusted_cost);
                    let candidate = old + log_factorial[zero_count];
                    if candidate < with_zero[index] {
                        with_zero[index] = candidate;
                        zero_counts[index] = zero_count as u8;
                    }
                }
            }
        }

        for openings in maximum_digit..=MAX_OPENINGS {
            for implicit_count in 1..=MAX_KEYS - openings {
                let keys = openings + implicit_count;
                // Per opening: two initial TOALTSTACKs, two FROMALTSTACKs,
                // a bound push, MIN, ROLL, and EQUALVERIFY.
                let routing: usize = (implicit_count + 1..=keys)
                    .map(|remaining| push_bytes(remaining - 1) + 7)
                    .sum();
                let base = (21 * keys
                    + routing
                    + (implicit_count + 1) / 2
                    + 1
                    + profile.opening_base_cost() * openings) as isize;
                let allowed_cost = best - base;
                if allowed_cost < -(COST_OFFSET as isize) {
                    continue;
                }
                let allowed_denominator =
                    log_factorial[keys] - log_factorial[implicit_count] - 160.0;
                for cost in -(COST_OFFSET as isize)..=allowed_cost.min(MAX_HASH_COST as isize) {
                    let index = adjusted_state(openings, cost);
                    if with_zero[index] > allowed_denominator + 1e-10 {
                        continue;
                    }
                    let total = base + cost;
                    if total < best {
                        best = total;
                        let first = zero_counts[index] as usize;
                        let mut counts = vec![0usize; maximum_digit + 1];
                        counts[0] = first;
                        counts[maximum_digit] = implicit_count;
                        let mut left_openings = openings - first;
                        let mut left_cost = (cost - first as isize * zero_weight) as usize;
                        for r in (1..=distance).rev() {
                            let count = histories[r][state(left_openings, left_cost)] as usize;
                            counts[maximum_digit - r] = count;
                            left_openings -= count;
                            left_cost -= count * profile.hash_cost(r);
                        }
                        assert_eq!((left_openings, left_cost), (0, 0));
                        let entropy = log_factorial[keys]
                            - counts
                                .iter()
                                .map(|&count| log_factorial[count])
                                .sum::<f64>();
                        println!("profile={profile:?} total_bound={total} keys={keys} openings={openings} \
                            radix={} approx_log2_capacity={entropy:.12} counts={counts:?}", maximum_digit + 1);
                        winner = Some(counts);
                    }
                    // Every higher cost has the same fixed base and is worse.
                    break;
                }
            }
        }
    }
    println!("FINAL profile={profile:?} total_bound={best} counts={winner:?}");
}

fn main() {
    search(Profile::Hash160);
    search(Profile::Sha256Hash160);
}
