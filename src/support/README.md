# Local execution support

All helpers in `execution.rs` use `ExecCtx::Tapscript` with the
`bitcoin-scriptexec` revision pinned in `Cargo.lock`:
`ba96bc2bd76774c9d1b011461cb79d983c2c43a1`. Generated scripts use
`ScriptCompilation::compile_with_policy()`; raw-byte helpers execute the exact
provided serialization.

## Resource checks

| Helpers | Combined main/alt-stack item limit | Initial witness element limit |
| --- | --- | --- |
| `execute_script`, `execute_script_buf` | 1,000, after every instruction | No witness |
| `execute_*_with_inputs_strict` | 1,000 at entry and after every instruction | 520 bytes |
| `dry_run_taproot_input` | 1,000 at leaf entry and after every instruction | 520 bytes for data items |
| `execute_*_without_stack_limit` | Disabled | No witness |
| `execute_script_with_inputs`, `execute_raw_script_with_inputs` | Disabled | 520 bytes |

`ExecuteInfo.stack_limit_enforced` exposes the choice. Display output labels
the count-disabled mode `research-unlimited`; count enforcement alone leaves
deployment `unclassified`. Disabling the item-count limit does not disable the
520-byte element limit. The upstream interpreter checks script pushes against
that element limit; this wrapper also checks witness elements before they can
be consumed.

The wrapper checks combined live depth after every instruction, including
direct data pushes and `OP_0`, even when the next instruction would drop the
extra item. Entry rejection leaves the witness intact. Stack statistics include
the initial witness and the failing instruction's live main-plus-alt stack.
All witness hints therefore coexist at entry; putting later inputs in script
constants does not reproduce an all-witness-at-entry schedule.

These checks repair gaps in the pinned upstream executor. See
[NR-043](../../knowledge/negative-results/index.md#nr-043-upstream-stack-limit-enforcement-misses-entry-and-data-pushes)
for the reproduced counterexamples.

## Evidence boundary

The resource tests are `locally-reproduced`, using exact bytecode so the
optimizer cannot erase a temporary overflow. They cover 1,000/1,001 entry
items, 520/521-byte witness elements, main/alt-stack coexistence, data and
numeric pushes, skipped branches, and the raw, compiled, and transaction dry-run
entry points:

```sh
cargo test --locked --test execution_limits
```

The applicable rules were `inspected` in Bitcoin Core **v30.0**, commit
`d0f6d9953a15d7c7111d46dcb76ab2bb18e5dee3`:
[`ExecuteWitnessScript`](https://github.com/bitcoin/bitcoin/blob/d0f6d9953a15d7c7111d46dcb76ab2bb18e5dee3/src/script/interpreter.cpp#L1684)
checks entry resources, while `EvalScript` checks live main-plus-alt depth.
Those source-inspection results are separate from the later
[pinned v30.3 harness](../../knowledge/core-validation.md), which checks complete
Taproot entry/push fixtures and a Winternitz spend against independent block
and policy acceptance. Its recorded outcomes are `differentially-validated`;
this wrapper alone still leaves deployment `unclassified`.

## Remaining limitations

These helpers are fragment executors, not complete consensus validators:

- The pinned interpreter does not implement the BIP342 `OP_SUCCESSx` scan and
  enables experimental `OP_CAT` in its default options. The wrapper retains
  these existing options. The resource results apply to ordinary tapscripts
  without `OP_SUCCESSx`; Core processes that upgrade hook before entry limits.
- Default options require minimal data, mixing policy restrictions into local
  execution. There is no explicit legacy/P2WSH consensus/policy matrix here.
- Except for `dry_run_taproot_input`, transaction context is a dummy template.
  The dry run extracts a leaf but does not validate its Taproot commitment or
  full transaction, and currently does not pass the annex into signature checks.
- Upstream validation weight is initialized from the data-item vector rather
  than the complete serialized Taproot witness. Its tapscript `opcode_count`
  does not count executed non-push instructions. Neither statistic establishes
  a complete transaction budget.
- Malformed script construction and some invalid `OP_PICK` indices can still
  panic in upstream code. These tests do not certify those paths.

OP-001 and OP-002 in [open problems](../../knowledge/open-problems.md) track
the remaining execution matrix and completed initial Core differential scope.
