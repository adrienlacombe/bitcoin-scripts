//! Direct-u4 generator for the single-block BLAKE3 root compression of a
//! `1..=32`-byte witness message.
//!
//! The generator keeps an exact model of the main and alt stacks and emits
//! opcodes directly. Its lookup tables are placed so that, in the steady state
//! of the middle rounds, table indexes need no offset arithmetic:
//!
//! * Addition outputs (`A` words) store each nibble as `n + MU`. Such a value
//!   is directly the `OP_PICK` depth of the lut entry for `n`, which holds the
//!   depth of XOR row `n`; adding a plain nibble then addresses the row entry.
//! * XOR outputs and message nibbles (`X` words) are plain nibbles.
//! * Carries are stored as `c + KAPPA`, so `a + b (+m) + carry` is directly the
//!   depth of the modulo entry for the sum, and `sum - modulo` is directly the
//!   depth of the next carry. Results stay on the main stack.
//!
//! Every lookup derives any residual index adjustment from the modelled stack
//! (round zero, the finalization and constant operands). Constant words are
//! folded into lookup addresses at generation time; a variant that instead
//! pushes the initial state is also generated and the shorter script kept.
//! Witness nibbles are range-checked when they are first fetched, before any
//! use.
//!
//! While generating, the model also carries the concrete value of every item
//! for a fixed sample message. Each lookup asserts that it reaches the
//! intended table entry, each word operation is checked against host
//! arithmetic, and the final output is checked against a host compression.
//!
//! The construction comes from an agentic Claude Opus 5.5 run and was
//! generalized here to every short length, mode and output width.

use std::collections::{HashMap, HashSet};

use bitcoin::opcodes::all::*;
use bitcoin::opcodes::Opcode;
use bitcoin::script::PushBytesBuf;
use bitcoin::ScriptBuf;

use super::utils::{IV, MSG_PERMUTATION};

/// Items above the tables in the steady state: sixteen eight-nibble words.
const N_REF: i64 = 128;

// Table layout. Entries are counted downwards from the topmost table item.
//
//   0..16     left shift: (2z) mod 16
//   16..32    lut: depth of XOR row `y` for an `A` nibble
//   32, 48, 64  carry q + KAPPA for q = 0, 1, 2 (gaps are padding)
//   65..161   XOR rows 0..6
//   161..176  padding
//   176..224  modulo: (s mod 16) + MU at E_MOD + s
//   224..384  XOR rows 6..16
const E_LSH: usize = 0;
const E_LUT: usize = 16;
/// Bias of `A` nibbles: their value is directly the depth of their lut entry.
const MU: i64 = N_REF + E_LUT as i64;
/// Bias of carries. A split computes `t - (s mod 16 + MU) = 16 q + KAPPA`,
/// the depth of the carry entry for `q = s / 16`.
const KAPPA: i64 = 160;
const E_MOD: usize = (MU + KAPPA - N_REF) as usize;
const E_CARRY: usize = (KAPPA - N_REF) as usize;
const TABLE_ITEMS: usize = 384;

const COLUMNS: [(usize, usize, usize, usize); 4] =
    [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)];
const DIAGONALS: [(usize, usize, usize, usize); 4] =
    [(0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)];

fn e_lut(y: usize) -> usize {
    E_LUT + y
}

fn e_mod(s: usize) -> usize {
    E_MOD + s
}

fn e_carry(s: usize) -> usize {
    E_CARRY + 16 * (s / 16)
}

fn e_xor_row(y: usize) -> usize {
    if y < 6 {
        65 + 16 * y
    } else {
        224 + 16 * (y - 6)
    }
}

fn e_xor(y: usize, x: usize) -> usize {
    e_xor_row(y) + x
}

fn e_lsh(z: usize) -> usize {
    E_LSH + z
}

/// Value of every table entry, indexed by entry offset.
fn table_values() -> Vec<i64> {
    let mut values = vec![None; TABLE_ITEMS];
    let mut set = |entry: usize, value: i64| {
        assert!(
            values[entry].is_none(),
            "table entry {entry} assigned twice"
        );
        values[entry] = Some(value);
    };
    for y in 0..16 {
        set(e_lut(y), N_REF - 1 + e_xor_row(y) as i64);
        for x in 0..16 {
            set(e_xor(y, x), (y ^ x) as i64);
        }
        set(e_lsh(y), ((2 * y) % 16) as i64);
    }
    for s in 0..48 {
        set(e_mod(s), (s % 16) as i64 + MU);
    }
    for q in 0..3 {
        set(e_carry(16 * q), q as i64 + KAPPA);
    }
    // Padding repeats the entry below it so that it pushes with DUP.
    for entry in (0..TABLE_ITEMS).rev() {
        if values[entry].is_none() {
            values[entry] = values[entry + 1];
        }
    }
    values.into_iter().map(Option::unwrap).collect()
}

/// A generation-time description of one short root compression.
pub(super) struct ShortSpec<'a> {
    pub message_len: u32,
    /// Input chaining value: the IV, a key, or a derive-key context key.
    pub key: [u32; 8],
    /// Complete root flags, including the mode flag.
    pub flags: u32,
    /// Leading digest words to return (`1..=8`).
    pub output_words: usize,
    /// Also return `state[i + 8] ^ key[i]`, the second 32 output bytes.
    pub extended_output: bool,
    /// Semantic `(word, digit)` of each witness item, deepest first. Digit 0
    /// is the most significant nibble of the little-endian word.
    pub layout: &'a [(usize, usize)],
}

/// Generation choices that do not affect semantics.
#[derive(Clone, Copy, Debug)]
pub(super) struct Variant {
    /// Push the initial state instead of folding it as constants.
    pub materialize: bool,
    /// Pre-bias the low nibble of each message word by `KAPPA`.
    pub bias_message: bool,
}

pub(super) const VARIANTS: [Variant; 4] = [
    Variant {
        materialize: true,
        bias_message: true,
    },
    Variant {
        materialize: false,
        bias_message: true,
    },
    Variant {
        materialize: true,
        bias_message: false,
    },
    Variant {
        materialize: false,
        bias_message: false,
    },
];

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: u32,
    val: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Nibble stored as `n + MU`.
    A,
    /// Plain nibble.
    X,
}

impl Kind {
    fn bias(self) -> i64 {
        match self {
            Kind::A => MU,
            Kind::X => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Nib {
    Const(u8),
    Dyn(u32),
}

/// A 32-bit word; `nibs[0]` is the most significant nibble.
#[derive(Clone, Copy, Debug)]
struct Word {
    nibs: [Nib; 8],
    kind: Kind,
}

impl Word {
    fn constant(value: u32) -> Self {
        Word {
            nibs: std::array::from_fn(|n| Nib::Const(((value >> (28 - 4 * n)) & 15) as u8)),
            kind: Kind::X,
        }
    }

    fn const_value(&self) -> Option<u32> {
        let mut value = 0;
        for nib in self.nibs {
            match nib {
                Nib::Const(c) => value = (value << 4) | u32::from(c),
                Nib::Dyn(_) => return None,
            }
        }
        Some(value)
    }
}

#[derive(Clone)]
struct Gen {
    script: ScriptBuf,
    main: Vec<Slot>,
    alt: Vec<Slot>,
    next_id: u32,
    peak: usize,
    table_bottom: usize,
    unvalidated: HashSet<u32>,
    /// Items whose bias differs from their word's kind.
    slot_bias: HashMap<u32, i64>,
    /// Bytes of the final table and state cleanup.
    cleanup_bytes: usize,
}

impl Gen {
    fn new() -> Self {
        Gen {
            script: ScriptBuf::new(),
            main: Vec::new(),
            alt: Vec::new(),
            next_id: 0,
            peak: 0,
            table_bottom: 0,
            unvalidated: HashSet::new(),
            slot_bias: HashMap::new(),
            cleanup_bytes: 0,
        }
    }

    /// Runs the cheapest of `options` alternatives, judged by emitted bytes.
    fn best_of<T>(&mut self, options: usize, f: impl Fn(&mut Gen, usize) -> T) -> T {
        let mut best = (usize::MAX, 0);
        if options > 1 {
            for option in 0..options {
                let mut trial = self.clone();
                f(&mut trial, option);
                best = best.min((trial.script.len(), option));
            }
        }
        f(self, best.1)
    }

    fn fresh(&mut self, val: i64) -> Slot {
        self.next_id += 1;
        Slot {
            id: self.next_id,
            val,
        }
    }

    fn note_peak(&mut self) {
        self.note_transient(0);
    }

    /// Records `extra` items pushed above the modelled stack and consumed
    /// again within the same short opcode sequence.
    fn note_transient(&mut self, extra: usize) {
        self.peak = self.peak.max(self.main.len() + self.alt.len() + extra);
    }

    fn push_slot(&mut self, slot: Slot) {
        self.main.push(slot);
        self.note_peak();
    }

    fn op(&mut self, opcode: Opcode) {
        self.script.push_opcode(opcode);
    }

    fn emit_int(&mut self, value: i64) {
        match value {
            0 => self.op(OP_PUSHBYTES_0),
            -1 => self.op(OP_PUSHNUM_NEG1),
            1..=16 => self.op(Opcode::from(0x50 + value as u8)),
            _ => {
                let mut bytes = [0u8; 8];
                let len = bitcoin::script::write_scriptint(&mut bytes, value);
                let push = PushBytesBuf::try_from(bytes[..len].to_vec()).unwrap();
                self.script.push_slice(push);
            }
        }
    }

    fn top(&self) -> Slot {
        *self.main.last().unwrap()
    }

    fn val(&self, id: u32) -> i64 {
        self.main
            .iter()
            .rev()
            .find(|slot| slot.id == id)
            .unwrap()
            .val
    }

    fn position(&self, id: u32) -> usize {
        self.main
            .iter()
            .rposition(|slot| slot.id == id)
            .unwrap_or_else(|| panic!("item {id} is not on the main stack"))
    }

    fn depth(&self, id: u32) -> usize {
        self.main.len() - 1 - self.position(id)
    }

    fn push_int(&mut self, value: i64) -> u32 {
        self.emit_int(value);
        let slot = self.fresh(value);
        self.push_slot(slot);
        slot.id
    }

    /// Copies or moves an item to the top and returns its (new) id. A witness
    /// item is range-checked when it is first fetched, before any use.
    fn fetch(&mut self, id: u32, consume: bool) -> u32 {
        let validate = self.unvalidated.remove(&id);
        let result = self.fetch_inner(id, consume);
        if validate {
            let value = self.top().val;
            assert!((0..16).contains(&value));
            self.note_transient(3);
            self.op(OP_DUP);
            self.op(OP_PUSHBYTES_0);
            self.op(OP_PUSHNUM_16);
            self.op(OP_WITHIN);
            self.op(OP_VERIFY);
        }
        result
    }

    fn fetch_inner(&mut self, id: u32, consume: bool) -> u32 {
        let position = self.position(id);
        let depth = self.main.len() - 1 - position;
        if consume {
            match depth {
                0 => {}
                1 => self.op(OP_SWAP),
                2 => self.op(OP_ROT),
                _ => {
                    self.note_transient(1);
                    self.emit_int(depth as i64);
                    self.op(OP_ROLL);
                }
            }
            let slot = self.main.remove(position);
            self.main.push(slot);
            if position < self.table_bottom {
                self.table_bottom -= 1;
            }
            id
        } else {
            match depth {
                0 => self.op(OP_DUP),
                1 => self.op(OP_OVER),
                _ => {
                    self.emit_int(depth as i64);
                    self.op(OP_PICK);
                }
            }
            let slot = self.fresh(self.main[position].val);
            self.push_slot(slot);
            slot.id
        }
    }

    /// Bytes needed to fetch the given items in order, adding each fetched
    /// item to the previous one.
    fn fetch_and_add_cost(&self, items: &[(u32, bool)]) -> usize {
        let mut len = self.main.len();
        let mut positions: Vec<usize> = items.iter().map(|(id, _)| self.position(*id)).collect();
        let mut cost = 0;
        for k in 0..items.len() {
            let position = positions[k];
            let depth = len - 1 - position;
            cost += fetch_cost(depth, items[k].1);
            if items[k].1 {
                for other in positions.iter_mut().skip(k + 1) {
                    if *other > position {
                        *other -= 1;
                    }
                }
            } else {
                len += 1;
            }
            if k > 0 {
                len -= 1;
            }
        }
        cost
    }

    fn binary(&mut self, opcode: Opcode, f: impl Fn(i64, i64) -> i64) -> u32 {
        let b = self.main.pop().unwrap();
        let a = self.main.pop().unwrap();
        self.op(opcode);
        let slot = self.fresh(f(a.val, b.val));
        self.push_slot(slot);
        slot.id
    }

    fn op_add(&mut self) -> u32 {
        self.binary(OP_ADD, |a, b| a + b)
    }

    /// Replaces a plain nibble on top of the stack with its top bit.
    fn top_bit(&mut self) {
        self.push_int(8);
        self.binary(OP_GREATERTHANOREQUAL, |a, b| i64::from(a >= b));
    }

    fn op_dup(&mut self) {
        self.op(OP_DUP);
        let slot = self.fresh(self.top().val);
        self.push_slot(slot);
    }

    fn op_swap(&mut self) {
        self.op(OP_SWAP);
        let len = self.main.len();
        self.main.swap(len - 1, len - 2);
    }

    /// `[a b] -> [b a b]`; returns the id of the inserted copy of `b`.
    fn op_tuck(&mut self) -> u32 {
        self.op(OP_TUCK);
        let top = self.top();
        let copy = self.fresh(top.val);
        let len = self.main.len();
        self.main.insert(len - 2, copy);
        self.note_peak();
        copy.id
    }

    fn to_alt(&mut self) {
        self.op(OP_TOALTSTACK);
        let slot = self.main.pop().unwrap();
        self.alt.push(slot);
        self.note_peak();
    }

    fn from_alt(&mut self) -> u32 {
        self.op(OP_FROMALTSTACK);
        let slot = self.alt.pop().unwrap();
        self.main.push(slot);
        self.note_peak();
        slot.id
    }

    /// Adds a constant to the top item using the shortest encoding.
    fn add_const(&mut self, k: i64) {
        match k {
            0 => return,
            1 => self.op(OP_1ADD),
            -1 => self.op(OP_1SUB),
            k if k < 0 => {
                self.note_transient(1);
                self.emit_int(-k);
                self.op(OP_SUB);
            }
            k => {
                self.note_transient(1);
                self.emit_int(k);
                self.op(OP_ADD);
            }
        }
        self.main.last_mut().unwrap().val += k;
    }

    fn table_position(&self, entry: usize) -> usize {
        self.table_bottom + TABLE_ITEMS - 1 - entry
    }

    /// Replaces the index on top of the stack with a copy of the table entry
    /// at `entry`, first adjusting the index if necessary. The final query
    /// before cleanup moves the entry instead when that leaves an even number
    /// of items to drop once its result has gone to the altstack.
    fn lookup_with(&mut self, entry: usize, final_query: bool) -> u32 {
        let position = self.table_position(entry);
        let needed = self.main.len() as i64 - 2 - position as i64;
        let adj = needed - self.top().val;
        self.add_const(adj);
        let destructive = final_query && (self.main.len() - 1) % 2 == 1;
        let index = self.main.pop().unwrap();
        let picked = self.main.len() - 1 - index.val as usize;
        assert_eq!(picked, position, "lookup reached the wrong entry");
        if destructive {
            self.op(OP_ROLL);
            let slot = self.main.remove(position);
            self.main.push(slot);
            slot.id
        } else {
            self.op(OP_PICK);
            let slot = self.fresh(self.main[position].val);
            self.push_slot(slot);
            slot.id
        }
    }

    fn lookup(&mut self, entry: usize) -> u32 {
        self.lookup_with(entry, false)
    }

    /// Plain value of a dynamic nibble.
    fn plain(&self, id: u32, kind: Kind) -> i64 {
        let bias = self.slot_bias.get(&id).copied().unwrap_or(kind.bias());
        let value = self.val(id) - bias;
        assert!((0..16).contains(&value));
        value
    }

    fn word_value(&self, word: &Word) -> u32 {
        word.nibs.iter().fold(0, |acc, nib| {
            let nibble = match *nib {
                Nib::Const(c) => i64::from(c),
                Nib::Dyn(id) => self.plain(id, word.kind),
            };
            (acc << 4) | nibble as u32
        })
    }

    fn word_value_or_const(&self, word: &Word) -> u32 {
        word.const_value().unwrap_or_else(|| self.word_value(word))
    }

    fn push_tables(&mut self) {
        self.table_bottom = self.main.len();
        let values = table_values();
        // Push from the deepest entry upwards.
        let mut entry = TABLE_ITEMS;
        while entry > 0 {
            entry -= 1;
            let value = values[entry];
            if (e_mod(0)..e_mod(32)).contains(&entry) {
                // Repeat the previous sixteen-entry period.
                debug_assert_eq!(values[entry + 16], value);
                self.emit_int(15);
                self.op(OP_PICK);
                let slot = self.fresh(value);
                self.push_slot(slot);
                continue;
            }
            if (e_mod(32)..e_mod(47)).contains(&entry) {
                debug_assert_eq!(values[entry + 1], value + 1);
                self.op(OP_DUP);
                self.op(OP_1SUB);
                let slot = self.fresh(value);
                self.push_slot(slot);
                continue;
            }
            // Push a run of equal values with DUP/2DUP/3DUP.
            let mut run = 1;
            while entry >= run
                && values[entry - run] == value
                && !(e_mod(0)..e_mod(48)).contains(&(entry - run))
            {
                run += 1;
            }
            self.emit_int(value);
            let mut remaining = run - 1;
            let mut copies = Vec::new();
            if remaining >= 1 {
                copies.push(1);
                remaining -= 1;
            }
            if remaining >= 2 {
                copies.push(2);
                remaining -= 2;
            }
            while remaining >= 3 {
                copies.push(3);
                remaining -= 3;
            }
            if remaining > 0 {
                copies.push(remaining);
            }
            for copy in copies {
                self.op(match copy {
                    1 => OP_DUP,
                    2 => OP_2DUP,
                    _ => OP_3DUP,
                });
            }
            for _ in 0..run {
                let slot = self.fresh(value);
                self.push_slot(slot);
            }
            entry -= run - 1;
        }
        assert_eq!(self.main.len(), self.table_bottom + TABLE_ITEMS);
        for (entry, value) in values.iter().enumerate() {
            assert_eq!(self.main[self.table_position(entry)].val, *value);
        }
    }

    /// Adds words nibble by nibble from least to most significant.
    fn add(&mut self, operands: &[(Word, bool)]) -> Word {
        let constant_sum = operands
            .iter()
            .map(|(word, _)| word.const_value())
            .try_fold(0u32, |acc, value| value.map(|v| acc.wrapping_add(v)));
        if let Some(value) = constant_sum {
            return Word::constant(value);
        }
        let expected = operands.iter().fold(0u32, |acc, (word, _)| {
            acc.wrapping_add(self.word_value_or_const(word))
        });

        let mut out = [Nib::Const(0); 8];
        let mut const_carry = 0i64;
        let mut dyn_carry: Option<u32> = None;
        for i in (0..8).rev() {
            let mut const_sum = const_carry;
            let mut dynamic = Vec::new();
            for (word, consume) in operands {
                match word.nibs[i] {
                    Nib::Const(c) => const_sum += i64::from(c),
                    Nib::Dyn(id) => dynamic.push((id, *consume, word.kind)),
                }
            }
            if dynamic.is_empty() && dyn_carry.is_none() {
                out[i] = Nib::Const((const_sum % 16) as u8);
                const_carry = const_sum / 16;
                continue;
            }

            let dynamic = permutations(&dynamic)
                .into_iter()
                .min_by_key(|order| {
                    let items: Vec<(u32, bool)> = order
                        .iter()
                        .map(|(id, consume, _)| (*id, *consume))
                        .collect();
                    self.fetch_and_add_cost(&items)
                })
                .unwrap();
            let mut sum = const_sum;
            for (k, (id, consume, kind)) in dynamic.iter().enumerate() {
                sum += self.plain(*id, *kind);
                self.fetch(*id, *consume);
                if k > 0 {
                    self.op_add();
                }
            }
            if let Some(carry) = dyn_carry {
                sum += self.val(carry) - KAPPA;
                if !dynamic.is_empty() {
                    self.op_add();
                }
            }
            let s = sum as usize;
            assert!(s < 48, "nibble {i}: sum {s}");

            if i > 0 {
                // t -> [adj] DUP PICK -> [t mod] -> TUCK SUB PICK -> [mod carry]
                let position = self.table_position(e_mod(s));
                let needed = self.main.len() as i64 - 1 - position as i64;
                let adj = needed - self.top().val;
                self.add_const(adj);
                self.op_dup();
                self.lookup(e_mod(s));
                let modulo = self.op_tuck();
                self.binary(OP_SUB, |a, b| a - b);
                let carry = self.lookup(e_carry(s));
                out[i] = Nib::Dyn(modulo);
                dyn_carry = Some(carry);
            } else {
                let modulo = self.lookup(e_mod(s));
                out[i] = Nib::Dyn(modulo);
            }
        }
        let word = Word {
            nibs: out,
            kind: Kind::A,
        };
        assert_eq!(self.word_value(&word), expected);
        word
    }

    /// XORs one nibble pair and returns the plain result. At least one nibble
    /// is dynamic.
    fn xor_nibble(&mut self, x: (Nib, Kind, bool), y: (Nib, Kind, bool)) -> u32 {
        self.xor_nibble_with(x, y, false)
    }

    fn xor_nibble_with(
        &mut self,
        x: (Nib, Kind, bool),
        y: (Nib, Kind, bool),
        final_query: bool,
    ) -> u32 {
        let (lut, other) = match (x.0, y.0) {
            (Nib::Dyn(_), Nib::Dyn(_)) => {
                if x.1 == Kind::A && y.1 != Kind::A {
                    (x, y)
                } else {
                    (y, x)
                }
            }
            (Nib::Dyn(_), Nib::Const(_)) => (x, y),
            (Nib::Const(_), Nib::Dyn(_)) => (y, x),
            _ => unreachable!("constant nibble pairs are folded"),
        };
        let Nib::Dyn(lut_id) = lut.0 else {
            unreachable!()
        };
        let p = self.plain(lut_id, lut.1) as usize;
        match other.0 {
            Nib::Const(q) => {
                let q = usize::from(q);
                match (lut.1, q) {
                    // A plain nibble XOR zero is the nibble itself.
                    (Kind::X, 0) if !final_query => self.fetch(lut_id, lut.2),
                    (Kind::X, 15) if !final_query => {
                        self.push_int(15);
                        self.fetch(lut_id, lut.2);
                        self.binary(OP_SUB, |a, b| a - b)
                    }
                    _ => {
                        // Index row `q` directly by the dynamic nibble.
                        self.fetch(lut_id, lut.2);
                        self.lookup_with(e_xor(q, p), final_query)
                    }
                }
            }
            Nib::Dyn(id) => {
                self.fetch(lut_id, lut.2);
                self.lookup(e_lut(p));
                let q = self.plain(id, other.1) as usize;
                self.fetch(id, other.2);
                self.op_add();
                self.lookup_with(e_xor(p, q), final_query)
            }
        }
    }

    /// Computes `(x ^ y) >>> (4 * rot)`. `x` is consumed and `y` copied.
    fn xor_rotate(&mut self, x: Word, y: Word, rot: usize) -> Word {
        if let (Some(a), Some(b)) = (x.const_value(), y.const_value()) {
            return Word::constant((a ^ b).rotate_right(4 * rot as u32));
        }
        let orders = self.xor_orders(&x, &y);
        self.best_of(orders.len(), |gen, option| {
            gen.xor_rotate_in_order(x, y, rot, &orders[option])
        })
    }

    fn xor_rotate_in_order(&mut self, x: Word, y: Word, rot: usize, order: &[usize]) -> Word {
        let expected = (self.word_value_or_const(&x) ^ self.word_value_or_const(&y))
            .rotate_right(4 * rot as u32);
        let mut z = [Nib::Const(0); 8];
        for &k in order {
            z[k] = match (x.nibs[k], y.nibs[k]) {
                (Nib::Const(a), Nib::Const(b)) => Nib::Const(a ^ b),
                _ => {
                    Nib::Dyn(self.xor_nibble((x.nibs[k], x.kind, true), (y.nibs[k], y.kind, false)))
                }
            };
        }
        let word = Word {
            nibs: std::array::from_fn(|n| z[(n + 8 - rot) % 8]),
            kind: Kind::X,
        };
        assert_eq!(self.word_value(&word), expected);
        word
    }

    /// Candidate nibble orders for an XOR.
    fn xor_orders(&self, x: &Word, y: &Word) -> Vec<Vec<usize>> {
        let depth_of = |nib: Nib| match nib {
            Nib::Dyn(id) => self.depth(id),
            Nib::Const(_) => 0,
        };
        let mut orders = Vec::new();
        for key in [
            |dx: usize, _dy: usize| dx as i64,
            |dx: usize, _dy: usize| -(dx as i64),
            |_dx: usize, dy: usize| dy as i64,
            |_dx: usize, dy: usize| -(dy as i64),
        ] {
            let mut order: Vec<usize> = (0..8).collect();
            order.sort_by_key(|&k| key(depth_of(x.nibs[k]), depth_of(y.nibs[k])));
            if !orders.contains(&order) {
                orders.push(order);
            }
        }
        orders
    }

    /// Computes `(x ^ y) >>> 7`. `x` is consumed and `y` copied.
    ///
    /// With `z = x ^ y`, output nibble `n` is
    /// `((z[n-2] << 1) & 15) | (z[n-1] >> 3)` (indices modulo eight).
    fn xor_rotate_7(&mut self, x: Word, y: Word) -> Word {
        if let (Some(a), Some(b)) = (x.const_value(), y.const_value()) {
            return Word::constant((a ^ b).rotate_right(7));
        }
        self.best_of(8, |gen, k0| gen.xor_rotate_7_from(x, y, k0))
    }

    fn xor_rotate_7_from(&mut self, x: Word, y: Word, k0: usize) -> Word {
        let expected =
            (self.word_value_or_const(&x) ^ self.word_value_or_const(&y)).rotate_right(7);
        let mut w = [0u32; 8];
        for step in 0..8 {
            let k = (k0 + step) % 8;
            let z = match (x.nibs[k], y.nibs[k]) {
                (Nib::Const(a), Nib::Const(b)) => self.push_int(i64::from(a ^ b)),
                _ => self.xor_nibble((x.nibs[k], x.kind, true), (y.nibs[k], y.kind, false)),
            };
            let zv = self.val(z) as usize;
            if step == 0 {
                // Keep top(z[k0]) for the final output nibble.
                self.op_dup();
                self.top_bit();
                self.to_alt();
            } else {
                // [p z] -> [z p z] -> [z w] -> [w z]
                self.op_tuck();
                self.top_bit();
                w[(k + 1) % 8] = self.op_add();
                self.op_swap();
            }
            self.lookup(e_lsh(zv));
        }
        self.from_alt();
        w[(k0 + 1) % 8] = self.op_add();
        let word = Word {
            nibs: std::array::from_fn(|n| Nib::Dyn(w[n])),
            kind: Kind::X,
        };
        assert_eq!(self.word_value(&word), expected);
        word
    }

    /// Leaves exactly the requested output nibbles on the main stack, first
    /// output byte deepest and each byte's high nibble first.
    ///
    /// With `steady`, each output stays on the main stack while it is
    /// computed, `state[i]` is consumed and every other operand copied, which
    /// keeps lookup depths fixed; the outputs then move to the altstack
    /// together. Otherwise every operand is consumed at its last use and each
    /// output goes straight to the altstack, in reverse order.
    fn finalize(&mut self, state: &[Word; 16], spec: &ShortSpec, steady: bool) {
        const NIBBLE_ORDER: [usize; 8] = [6, 7, 4, 5, 2, 3, 0, 1];
        // (x, y) operand pairs in final output order.
        let mut outputs = Vec::new();
        for i in 0..spec.output_words {
            for n in NIBBLE_ORDER {
                outputs.push((
                    (state[i].nibs[n], state[i].kind),
                    (state[i + 8].nibs[n], state[i + 8].kind),
                ));
            }
        }
        if spec.extended_output {
            for i in 0..8 {
                let key = Word::constant(spec.key[i]);
                for n in NIBBLE_ORDER {
                    outputs.push((
                        (state[i + 8].nibs[n], state[i + 8].kind),
                        (key.nibs[n], Kind::X),
                    ));
                }
            }
        }
        if !steady {
            // The altstack reverses the order.
            outputs.reverse();
        }
        let mut uses: HashMap<u32, usize> = HashMap::new();
        for ((x, _), (y, _)) in &outputs {
            for nib in [x, y] {
                if let Nib::Dyn(id) = nib {
                    *uses.entry(*id).or_default() += 1;
                }
            }
        }
        let count = outputs.len();
        let mut consume = |nib: Nib, first: bool| -> bool {
            let Nib::Dyn(id) = nib else {
                return false;
            };
            let remaining = uses.get_mut(&id).unwrap();
            *remaining -= 1;
            if steady {
                first && *remaining == 0
            } else {
                *remaining == 0
            }
        };
        for (index, ((x, xk), (y, yk))) in outputs.into_iter().enumerate() {
            let cx = consume(x, true);
            let cy = consume(y, false);
            match (x, y) {
                (Nib::Const(a), Nib::Const(b)) => {
                    self.push_int(i64::from(a ^ b));
                }
                _ => {
                    let final_query = !steady && index + 1 == count;
                    self.xor_nibble_with((x, xk, cx), (y, yk, cy), final_query);
                }
            }
            if !steady {
                self.to_alt();
            }
        }
        if steady {
            for _ in 0..count {
                self.to_alt();
            }
        }
        let cleanup_start = self.script.len();
        while self.main.len() >= 2 {
            self.op(OP_2DROP);
            self.main.truncate(self.main.len() - 2);
        }
        if self.main.len() == 1 {
            self.op(OP_DROP);
            self.main.pop();
        }
        self.cleanup_bytes = self.script.len() - cleanup_start;
        for _ in 0..count {
            self.from_alt();
        }
    }

    fn g(
        &mut self,
        state: &mut [Word; 16],
        (a, b, c, d): (usize, usize, usize, usize),
        (m0, m1): (Option<Word>, Option<Word>),
        round: usize,
    ) {
        let consume_message = round == 6;
        let mut operands = vec![(state[a], true), (state[b], false)];
        operands.extend(m0.map(|m| (m, consume_message)));
        state[a] = self.add(&operands);
        state[d] = self.xor_rotate(state[d], state[a], 4);
        state[c] = self.add(&[(state[c], true), (state[d], false)]);
        state[b] = self.xor_rotate(state[b], state[c], 3);
        let mut operands = vec![(state[a], true), (state[b], false)];
        operands.extend(m1.map(|m| (m, consume_message)));
        state[a] = self.add(&operands);
        state[d] = self.xor_rotate(state[d], state[a], 2);
        state[c] = self.add(&[(state[c], true), (state[d], false)]);
        state[b] = self.xor_rotate_7(state[b], state[c]);
    }
}

fn int_cost(value: i64) -> usize {
    match value {
        -1..=16 => 1,
        -127..=127 => 2,
        -32767..=32767 => 3,
        _ => 4,
    }
}

fn fetch_cost(depth: usize, consume: bool) -> usize {
    match (depth, consume) {
        (0, true) => 0,
        (1 | 2, true) | (0 | 1, false) => 1,
        (depth, _) => int_cost(depth as i64) + 1,
    }
}

/// All orderings of a short list.
fn permutations<T: Copy>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut result = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, first);
            result.push(tail);
        }
    }
    result
}

/// A generated script with its modelled resources; tests read the resources.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct Generated {
    pub script: ScriptBuf,
    /// Modelled combined main/altstack peak, excluding any caller state.
    pub peak: usize,
    /// Bytes that push the lookup tables.
    pub setup_bytes: usize,
    /// Bytes that drop the tables and leftover state below the outputs.
    pub cleanup_bytes: usize,
}

/// Sample message used only for generation-time self checks.
fn sample_message(message_len: u32) -> Vec<u8> {
    (0..message_len)
        .map(|index| (index * 167 + 89) as u8)
        .collect()
}

fn word_from_le(message: &[u8], word: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = message.get(4 * word + index).copied().unwrap_or(0);
    }
    u32::from_le_bytes(bytes)
}

pub(super) fn generate(spec: &ShortSpec, variant: Variant) -> Generated {
    let message_len = spec.message_len;
    assert!((1..=32).contains(&message_len));
    assert!((1..=8).contains(&spec.output_words));
    assert!(!spec.extended_output || spec.output_words == 8);
    let word_count = message_len.div_ceil(4) as usize;
    assert_eq!(spec.layout.len(), 2 * message_len as usize);

    let sample = sample_message(message_len);
    let mut gen = Gen::new();

    // Message words. Word `w` holds its present bytes in the low nibbles;
    // absent high nibbles are constant zero padding.
    let mut message: Vec<Word> = (0..word_count)
        .map(|w| {
            let bytes = (message_len as usize - 4 * w).min(4);
            let first_present = 8 - 2 * bytes;
            Word {
                nibs: std::array::from_fn(|n| {
                    if n < first_present {
                        Nib::Const(0)
                    } else {
                        Nib::Dyn(0)
                    }
                }),
                kind: Kind::X,
            }
        })
        .collect();
    for &(w, d) in spec.layout {
        assert_eq!(
            message[w].nibs[d],
            Nib::Dyn(0),
            "invalid layout item ({w}, {d})"
        );
        let value = (word_from_le(&sample, w) >> (28 - 4 * d)) & 15;
        let slot = gen.fresh(i64::from(value));
        gen.push_slot(slot);
        gen.unvalidated.insert(slot.id);
        message[w].nibs[d] = Nib::Dyn(slot.id);
    }
    assert!(message.iter().all(|word| !word.nibs.contains(&Nib::Dyn(0))));
    let input_items = spec.layout.len();

    gen.op(OP_DEPTH);
    gen.emit_int(input_items as i64);
    gen.op(OP_EQUALVERIFY);
    if variant.bias_message {
        // Store the least significant nibble of each message word as
        // `m + KAPPA`, so a message-bearing addition needs no explicit carry
        // bias on its first nibble.
        let mut low: Vec<u32> = message
            .iter()
            .map(|word| match word.nibs[7] {
                Nib::Dyn(id) => id,
                Nib::Const(_) => unreachable!("the low nibble of a present word is supplied"),
            })
            .collect();
        // Roll from the top down so each move is shallow.
        low.sort_by_key(|id| gen.depth(*id));
        for id in low {
            gen.fetch(id, true);
            gen.add_const(KAPPA);
            gen.slot_bias.insert(id, KAPPA);
        }
    }
    let setup_start = gen.script.len();
    gen.push_tables();
    let setup_bytes = gen.script.len() - setup_start;

    let mut state: [Word; 16] = std::array::from_fn(|i| {
        Word::constant(match i {
            0..=7 => spec.key[i],
            8..=11 => IV[i - 8],
            12 | 13 => 0,
            14 => message_len,
            _ => spec.flags,
        })
    });
    if variant.materialize {
        // Push words in reverse order of first use so the first used word
        // ends on top.
        let mut first_use = Vec::new();
        for column in COLUMNS {
            let (a, b, c, d) = column;
            first_use.extend([a, b, c, d]);
        }
        let mut pushed: Vec<(u32, Kind, Word)> = Vec::new();
        for &index in first_use.iter().rev() {
            let value = state[index].const_value().unwrap();
            let kind = if index % 8 < 4 { Kind::A } else { Kind::X };
            // An identical word already on the stack can be copied.
            let twin = pushed
                .iter()
                .find(|(v, k, _)| *v == value && *k == kind)
                .map(|(_, _, word)| *word);
            let mut nibs = [Nib::Const(0); 8];
            for (n, nib) in nibs.iter_mut().enumerate() {
                let nibble = i64::from((value >> (28 - 4 * n)) & 15);
                let literal = nibble + kind.bias();
                let id = match twin.map(|word| word.nibs[n]) {
                    Some(Nib::Dyn(source))
                        if fetch_cost(gen.depth(source), false) < int_cost(literal) =>
                    {
                        gen.fetch(source, false)
                    }
                    _ => gen.push_int(literal),
                };
                *nib = Nib::Dyn(id);
            }
            let word = Word { nibs, kind };
            pushed.push((value, kind, word));
            state[index] = word;
        }
    }
    let mut schedule: Vec<Option<Word>> = (0..16).map(|i| message.get(i).copied()).collect();

    for round in 0..7 {
        for (column, &lanes) in COLUMNS.iter().enumerate() {
            gen.g(
                &mut state,
                lanes,
                (schedule[2 * column], schedule[2 * column + 1]),
                round,
            );
        }
        for (diagonal, &lanes) in DIAGONALS.iter().enumerate() {
            gen.g(
                &mut state,
                lanes,
                (schedule[8 + 2 * diagonal], schedule[8 + 2 * diagonal + 1]),
                round,
            );
        }
        schedule = (0..16)
            .map(|i| schedule[usize::from(MSG_PERMUTATION[i])])
            .collect();
    }
    assert!(
        gen.unvalidated.is_empty(),
        "every input nibble is validated"
    );

    // Host reference output for the sample message.
    let host = super::host_compress(&spec.key, &sample, message_len, spec.flags);
    let mut expected = Vec::new();
    let mut push_word = |word: u32| {
        for byte in word.to_le_bytes() {
            expected.push(i64::from(byte >> 4));
            expected.push(i64::from(byte & 15));
        }
    };
    for word in &host[..spec.output_words] {
        push_word(*word);
    }
    if spec.extended_output {
        for word in &host[8..] {
            push_word(*word);
        }
    }
    for i in 0..spec.output_words {
        assert_eq!(
            gen.word_value_or_const(&state[i]) ^ gen.word_value_or_const(&state[i + 8]),
            host[i]
        );
    }

    gen.best_of(2, |gen, mode| gen.finalize(&state, spec, mode == 1));

    let output: Vec<i64> = gen.main.iter().map(|slot| slot.val).collect();
    assert_eq!(
        output, expected,
        "generated output differs from host BLAKE3"
    );
    assert!(gen.alt.is_empty());

    Generated {
        script: gen.script,
        peak: gen.peak,
        setup_bytes,
        cleanup_bytes: gen.cleanup_bytes,
    }
}

/// The smallest generated script over all variants.
pub(super) fn short_compute_script(spec: &ShortSpec) -> Generated {
    VARIANTS
        .iter()
        .map(|variant| generate(spec, *variant))
        .min_by_key(|generated| generated.script.len())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_buf;

    #[test]
    fn pushed_tables_hold_every_entry() {
        let mut gen = Gen::new();
        gen.push_tables();
        // Entry 0 is on top.
        for value in table_values() {
            gen.emit_int(value);
            gen.op(OP_EQUALVERIFY);
        }
        gen.op(OP_PUSHNUM_1);
        let result = execute_script_buf(gen.script);
        assert!(result.success, "{result}");
        assert_eq!(result.stats.max_nb_stack_items, TABLE_ITEMS + 1);
    }

    #[test]
    fn every_sum_and_xor_has_a_table_entry() {
        let values = table_values();
        for s in 0..48 {
            assert_eq!(values[e_mod(s)], (s % 16) as i64 + MU);
            assert_eq!(values[e_carry(s)], (s / 16) as i64 + KAPPA);
        }
        for y in 0..16 {
            assert_eq!(values[e_lsh(y)], ((2 * y) % 16) as i64);
            for x in 0..16 {
                assert_eq!(values[e_xor(y, x)], (y ^ x) as i64);
            }
        }
    }
}
