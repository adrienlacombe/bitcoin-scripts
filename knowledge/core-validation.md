# Pinned Bitcoin Core differential validation

Question: do the local resource-boundary decisions and one complete
constant-composition Winternitz spend agree with Bitcoin consensus, and which
consensus-valid witnesses also satisfy relay policy? This experiment establishes
those outcomes for **24 deterministic fixtures**, including rejected inputs.
It does not generalize one successful profile to the entire primitive catalog.

## Reproduce

```sh
cargo test --locked --test execution_limits
cargo test --locked --example core_validation_fixtures
python3 -m unittest discover -s tools -p 'test_core_regtest.py'
python3 tools/core_regtest.py --download-core
python3 tools/kb.py best signature/winternitz-constant-composition20 script_bytes --execution policy-validated
```

The first run downloads an official Bitcoin Core archive into ignored
`target/core-regtest/`. Later runs omit `--download-core` and work offline once
Rust dependencies are available. The runner verifies the pinned archive SHA256
on every run and extracts only `bitcoind`. Supported archives cover macOS ARM64
and x86-64, Linux AArch64 and x86-64; this recorded run used macOS ARM64.
The manifest pins **v30.3**, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, to the
[official checksums](https://bitcoincore.org/bin/bitcoin-core-30.3/SHA256SUMS).
The executable SHA256 and version string are also recorded; this does not
rebuild Core from source or independently attest the release build.

Every run starts a fresh temporary regtest directory, disables wallets and
P2P connections, uses local cookie-authenticated RPC, and removes its node data
after stopping. It never uses an existing node or real funds. The public test
internal key is derived from `[0x01;32]`; these fixtures are not funding templates.
Block times, keys, messages, transaction amounts and fixture ordering are fixed.

- [Runner](../tools/core_regtest.py) and [release manifest](../tools/bitcoin_core_release.json).
- [Rust fixture generator](../examples/core_validation_fixtures.rs): full bytecode,
  data witnesses, Taproot commitments, local outcomes and explicit expectations.
- [Recorded report](../tests/data/core-validation-v30.3.json): source/binary pins,
  fixture SHA256, transaction identities/weights, raw Core results and local differences.
- Fresh output defaults to `target/core-validation.json`; `--output PATH` chooses
  another location. Do not overwrite the committed report without reviewing
  the intended experiment change.

## Independent acceptance checks

The runner mines 101 blocks to a deterministic P2WSH `OP_TRUE` output, spends a
mature coinbase to one Taproot output per fixture, and confirms that funding
transaction. Each fixture then spends its own output, paying 10,000 satoshis
and producing one P2WSH output. A real script/control-block commitment is checked.
SegWit and Taproot activation is asserted through `getdeploymentinfo`.

`testmempoolaccept` measures policy with **`-acceptnonstdtxn=0`** explicitly set
(regtest would otherwise accept nonstandard transactions). Other policy options
are the pinned release defaults. Separately, `generateblock` receives the raw
transaction directly, bypassing the mempool. Core's pinned
[`generateblock` implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/rpc/mining.cpp)
uses `TestBlockValidity` before generating and connecting the block. Successful
results are checked for the expected height and included transaction ID.

Only Core's script-validation error with RPC code -25 is treated as a
consensus rejection. Transport failures, decoding failures and missing inputs
fail the run. Expected rejection categories also match the pinned diagnostics;
an unrelated commitment failure cannot satisfy a stack-boundary test. Core
reports both oversized and nonminimal ScriptNums as `unknown error`, so their
finer labels describe the specific fixture mutations rather than distinct Core
error codes. All raw reasons are retained. `decoderawtransaction` independently
checks every transaction's txid, wtxid, serialized size, weight and vsize;
Rust and Python also agree on the complete serialized witness size.

## Results recorded 2026-09-10

All 24 consensus/policy expectations and rejection diagnostics pass; two fresh
runs on the recorded platform produce byte-identical reports. Evidence
is `differentially-validated` for these comparisons. A rejected fixture is
`consensus-incompatible`; successful ones are `consensus-validated` or
`policy-validated` according to the separately recorded policy result.

| Case | Core consensus | Core policy | Local stack-limited tapscript |
| --- | --- | --- | --- |
| 1,000 / 1,001 initial items | Accept / reject | Accept / reject | Agrees after wrapper repair |
| 80 / 81 / 520 / 521-byte data item | Accept / accept / accept / reject | Accept / reject / reject / reject | Agrees with consensus |
| Transient combined depth 1,000 / 1,001 | Accept / reject | Accept / reject | Agrees after wrapper repair |
| `OP_PICK` / `OP_ROLL` exact upper boundary | Reject | Reject | Panics |
| Valid Winternitz leaf | Accept | Accept | Accept |
| Winternitz control-block parity mutation | Reject | Reject | Accepts the leaf; does not validate its commitment |
| Winternitz exact-pool selector | Reject | Reject | Panics |
| Winternitz nonminimal numeric selector | Accept | Reject | Rejects under default minimal-number option |

Negative selectors, larger pool indices, oversized ScriptNums, mutated nodes,
and wrong signature-item counts are also rejected as expected.

The valid `ConstantCompositionWinternitz20<Hash160,Preimage16>` isolated leaf
uses seed `[0x42;32]`, message `00254a6f94b9de03284d7297bce1062b50759abf`, and
the verifier followed by terminal `OP_TRUE`. Whole-script repository policy
compilation produces **1,599 locking-script bytes**. Its serialized data witness
is **796 bytes**, and the full Taproot witness (data, script, 33-byte control
block and all count/length prefixes) is **2,432 bytes**. The spending transaction
has 94 base bytes, 2,528 total bytes, **2,810 weight units / 703 vbytes**.
The 1,599 script bytes are already inside the 2,432 witness bytes; do not add
them again when comparing complete transaction costs.

There are **70 signature data items, zero auxiliary hint items and zero hint
bytes per invocation**. All 70 data items coexist at entry; the complete witness
has 72 items including script/control block. The local combined main/alt peak is
**119**, including staged signature data and 49 embedded commitments. This is
one isolated invocation; no repeated configuration is measured. Surrounding
live state shares the 1,000-item limit, and the isolated verifier rejects extra
main-stack data. Static non-push count is 567; executed-opcode and validation
budget counters remain unavailable rather than being inferred from unreliable
local counters. The local run is stack-limited tapscript, deployment
`unclassified` on its own; Core supplies this fixture's `policy-validated` result.

The catalog's older fragment measurements remain `locally-reproduced` and
`research-unlimited`. A separate complete-leaf configuration records this
result with schema 1.1 configuration-level qualifiers; `best` filters use those
qualifiers while `list` retains the conservative record-level defaults. Other
hash profiles, composable variants, mainnet propagation and full
BitVM protocol transactions were not exercised. These fixtures contain no
`OP_SUCCESSx` or experimental `OP_CAT`; the local helper still does not implement
the full consensus or policy matrix. See [OP-001 and OP-002](open-problems.md)
and [NR-045](negative-results/index.md#nr-045-core-differentials-expose-local-executor-boundaries).

The interpreter corrections are submitted upstream as
[resource checks #18](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/18)
and [stack-index bounds #19](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/19).
The recorded comparison retains the original pinned dependency, with the local
resource wrapper repair; it does not assume either upstream PR has merged.
