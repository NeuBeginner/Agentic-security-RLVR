# Upstream Reconciliation — Change Impact Matrix

**Reconciliation:** the PR #12 branch `minimax/iteration-14-evidence-integrity` against the upstream integration branch `feat/empirical-benchmark-runner`
**Isolated branch:** `integration/reconcile-upstream-7876f6e-into-iteration-14`
**Merge commit:** `b0826f4b5d7c0451abbe0d3ebadfd63ef6a94b25`
**First parent (PR #12 head):** `d3201c9123d74483e4302802454c2d4dda18e61b`
**Second parent (upstream tip):** `7876f6e4e70e7001a24dbe73f94d5bb2349f6c02`
**PR base:** `736f11d5e8abac6e5b5bd3e37ba1487c75293ec8` — **merge base:** `47e49b9389753d6ce3a7075d0d1cef9cc2c5d5d7`
**Trigger:** review comment [`issuecomment-6777189536`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6777189536) (2026-11-10T19:31:30Z); the preceding question is [`issuecomment-6777143694`](https://github.com/NeuBeginner/Agentic-security-RLVR/pull/12#issuecomment-6777143694)
**Authorization:** no live Modal call, no deployment, no redeployment, no GPU (H100/T4), no paid computation, no merge of PR #12, no push to `minimax/iteration-14-evidence-integrity`, `integration/minimax-antigravity-reconciled`, `feat/empirical-benchmark-runner` or `main`, no change to PR #8, no rebase / squash / cherry-pick / history rewrite, no rewrite of published evidence, no weakening of any validator or test.

---

## 1. What was asked and what this document is

The maintainer asked for a reconciliation of the PR #12 branch with the upstream branch, prepared on an isolated branch, with every conflict resolved under a documented per-conflict rationale, and with the semantic decision left to him.

This document is that rationale. It records, for every conflict, what each side contained, why the iteration line was taken, and which published evidence depends on the choice. **The semantic decisions here are proposals; the maintainer owns the final call.** Nothing in this branch merges PR #12, and nothing in it regenerates published evidence.

---

## 2. Method

1. The branch was created at the **exact** PR head `d3201c9`, not at the PR base and not at a rebuilt head.
2. Upstream was merged with `git merge --no-ff --no-commit 7876f6e`. The merge direction is unchanged: upstream is absorbed by the iteration line, never the other way round.
3. The conflict inventory was predicted before touching anything, with
   `git merge-tree --write-tree --name-only 7876f6e d3201c9`, and the real merge produced **exactly** the same five files:

   ```
   benchmarks/adapters.py
   benchmarks/benchmark_runner.py
   benchmarks/evidence/modal_billing_join_table.json
   benchmarks/protocol.py
   tests/test_real_benchmark_execution.py
   ```

4. **Resolution rule applied to all five textual conflicts: the iteration line wins.** Two independent reasons support it:

   * the iteration line's validators are the **strictly stronger** ones — they recompute digests from stored bytes, require an `artifact_root`, bind the safe-control sentinel to a concrete target and harness, and accept provenance only as observed facts with a named source;
   * every published, SHA-bound evidence file in this repository was produced **against** those validators. Taking the upstream side of a conflict would invalidate the published evidence without regenerating it, which the maintainer forbade.

5. The merge was committed as a real merge commit with two parents. The diff against the first parent is the whole change of this branch:

   ```
   5 files changed, 91 insertions(+)
   benchmarks/artifacts/.../baseline_5/AC-01_replay_stderr.txt     |   0   (new, from upstream)
   benchmarks/artifacts/.../baseline_5/AC-01_replay_stdout.txt     |   1   (new, from upstream)
   benchmarks/artifacts/.../baseline_5/REENT-01_replay_stderr.txt  |   0   (new, from upstream)
   benchmarks/artifacts/.../baseline_5/REENT-01_replay_stdout.txt  |   1   (new, from upstream)
   tests/test_real_benchmark_execution.py                         |  89   (ported upstream test, §3.5)
   ```

---

## 3. Per-conflict rationale

### 3.1 `benchmarks/protocol.py`

| | Upstream `7876f6e` | Iteration line `d3201c9` |
|---|---|---|
| Validation home | validators inlined in `protocol.py` | validators delegated to `benchmarks/evidence_integrity.py` (`protocol.py` lines 397–517 import from it) |
| Replay envelope | digest checked only when an artifacts directory is handed in | `artifact_root` is mandatory; the digest is recomputed from the bytes that are actually stored |
| Safe-control sentinel | any target is accepted for a sentinel value | the sentinel is bound to a concrete target and harness, `harness_verdict == "BREACH"` is required |
| EVM provenance | flat strings | provenance is accepted only as observed facts with a named source; the legacy hardcoded constants are rejected |

**Decision: iteration line.** The upstream inline validators are a weaker re-implementation of exactly the checks the iteration line performs through `benchmarks/evidence_integrity.py`. The published Iteration 16–23 evidence — the per-stage evidence artifacts, the byte-verified envelopes, the strict observation side — was produced and validated against the delegated validators. Taking the upstream file would have silently downgraded every one of those checks while leaving the published evidence untouched, which is the classic "green because the check got weaker" failure the maintainer explicitly forbade.

### 3.2 `benchmarks/adapters.py`

| | Upstream `7876f6e` | Iteration line `d3201c9` |
|---|---|---|
| Producer | simplified producer, no per-stage evidence artifacts | full Iteration 14–21 producer: per-stage evidence artifacts, client-observed provenance, fail-closed on `validate_stage_capture` |

**Decision: iteration line.** The producer is not interchangeable with its evidence. The Iteration 16 rehearsal (`benchmarks/run_iteration16_producer_capture.py`) imports `benchmarks.adapters.FullAegisRLVRBaselineAdapter` and validates the artifacts that this producer wrote; the closure validator additionally requires that the producer source (`modal_app.py`) is unchanged between the capture SHA and the code SHA. Substituting the upstream producer would break the reproduction chain of the published per-stage evidence.

### 3.3 `benchmarks/benchmark_runner.py`

| | Upstream `7876f6e` | Iteration line `d3201c9` |
|---|---|---|
| `remote_evm_environment` | a constant environment is hardcoded into the run manifest | declared `NOT_AVAILABLE` with a reason: the environment is observed in the worker and is not knowable by the client in advance |

**Decision: iteration line.** The upstream version asserts a fact the client never observed. The iteration line reports the absence instead, with the reason, which is what `validate_remote_evm_toolchain_provenance` expects. This is a factual difference, not a stylistic one, and it is exactly the class of defect upstream's own commit message names ("eliminate fallbacks") — but in the upstream file it is introduced in the opposite direction.

### 3.4 `benchmarks/evidence/modal_billing_join_table.json`

| | Upstream `7876f6e` | Iteration line `d3201c9` |
|---|---|---|
| Schema | `2.0.0`, `app_sessions_reconciliation`, `attribution_status = UNATTRIBUTABLE_AGGREGATE` | `3.0.0`, 25 `app_session_level` rows + 16 `target_level` rows, `cost_usd: null`, `cost_reason_code: NO_JOIN_PROVIDED`, `attribution_policy.aggregate_bucket_allocation: FORBIDDEN`, `provider_join_fields` |
| Target cost rule | an aggregate session bucket may be allocated to a target | a target cost is published only for an exact, unique, provider-backed join (`invocation_id`, `function_call_id`, `task_id`) that resolves to exactly one raw line item |

**Decision: iteration line.** The upstream schema 2.0.0 is the aggregate-bucket shape that Iteration 15 forbade: an App/resource/interval bucket is an aggregate and must never be allocated to an individual target, and a target-level cost requires an exact provider-backed join. The published Iteration 15 evidence is bound to schema `3.0.0` and to `validate_billing_attribution`, which rejects a shared bucket, a missing join key, a fabricated invocation id, a duplicate line item and a cost mismatch. Taking the upstream file would have restored exactly the defect Iteration 15 closed.

### 3.5 `tests/test_real_benchmark_execution.py`

| | Upstream `7876f6e` | Iteration line `d3201c9` |
|---|---|---|
| Assertions | flattened provenance values | strict APIs: `artifact_root=`, `observed(...)`, `not_available(...)`, `SAFE_CONTROL_SENTINELS` |
| New test | `test_modal_billing_reconciliation_integrity` against `benchmarks.protocol.validate_billing_reconciliation` (the schema 2.0.0 validator of §3.4) | — |

**Decision: iteration line for the assertions, upstream coverage preserved by a port.** Dropping the upstream file would have dropped the upstream test with it, and that test encodes five real cheating scenarios that the iteration line must also reject. The upstream validator it exercises does not exist in the iteration line, and the upstream validator it needs is weaker than the iteration line's, so the port is written against the authoritative API:

* `benchmarks.evidence_integrity.validate_billing_attribution` for the attribution checks,
* `benchmarks.evidence_integrity.has_synthetic_modal_uri` for the pseudo-URI check.

The ported test keeps **all five** upstream cases and adds one more:

| # | Upstream case | Ported expression | Expected rejection |
|---|---|---|---|
| 1 | the published table validates | published schema 3.0.0 table against the raw export | accepted |
| 2 | a non-null target `cost_usd` is refused | target cost without a proven invocation-level join | `without a proven invocation-level join` |
| 3 | a duplicated `billing_line_item` is refused | one raw line item accounted for twice | `double-counts at least one raw billing line item` |
| 4 | a `modal-app://` pseudo-URI is refused | manufactured pseudo-URI in a target row | detected by `has_synthetic_modal_uri` |
| 5 | an omitted raw line item is refused | the attribution omits a raw line item | `omits … raw billing line item(s)` |
| 5b | — (added) | the attribution references a line item the export does not contain | `references unknown line item` |

Case 5b is not an upstream case; it is the other direction of the same invariant and it is the message the iteration line produces when the raw export is short.

---

## 4. The sixth conflict — the published run artifacts

This conflict is **not visible to git**. Upstream changed 21 published files that the iteration line never touched, so the merge took the upstream bytes automatically. Those bytes are the historical record of the run `run_1794209615_70f5d22`, and they are pinned by digest.

### 4.1 What upstream changed in the published artifacts

Upstream rewrote the provenance schema of all 16 target artifacts and of the run summaries:

| Field | Iteration line (published) | Upstream (proposed) |
|---|---|---|
| `modal_invocation_provenance.modal_app_id` | `ap-EDUitOwWeMrIdYbTh4kB63` | renamed to `app_session_id` |
| `remote_evm_provenance.image_tag` | `debian:12-slim-foundry` (asserted) | `image_digest: NOT_AVAILABLE` + reason |
| `stages.*.durable_log_ref` | `modal-app://ap-…/inference/…` (manufactured) | `NOT_AVAILABLE: …` |
| `stages.*.app_id` / `resource_interval` / `billing_line_item` | present | removed |
| `security_verdict` / `evm_outcome` (FLASH-01) | `SAFE_RUN` / `SAFE_CONTROL_HELD` | `RUNTIME_REVERT` / `RUNTIME_REVERT` |

### 4.2 Why the upstream bytes cannot be taken here

The published evidence pins those bytes by SHA-256, and the pins are real, not decorative:

* `benchmarks/evidence/iteration19_cpu_smoke/CPU-SMOKE-01_stage_evidence_cpu_smoke.json` — pinned `d797c328eea8950dfce56dd22255ad0793019d745c4a2f692a0e4df91b422e51` (6 129 bytes)
* `benchmarks/evidence/iteration20_producer_capture/ITER20-01_stage_evidence_evm_sandbox.json` — pinned `cdf0653f5f16a6e8174da65ac37073f7e5f8cf69dffdbffa3a742175f3934820` (6 337 bytes)
* `benchmarks/evidence/iteration21_producer_capture/ITER21-01_stage_evidence_evm_sandbox.json` — pinned `f877d58110a79c0461e353f5bc1a92fc9f5cabd2c0db406836939141f29f50de` (7 327 bytes)
* `benchmarks/evidence/modal_control_harness_validation.json` — pinned **17 times** across the published evidence, among them by the billing join table as `app_id_evidence_ref.sha256 = 7a56eadb65803946c0fb0d8afcf83f58c839638b79d83c11ac3d1d1c2c7468e5` (40 052 bytes); upstream's version of that file hashes to `4a06bbc4c2e4c28b067181751cce836842c6815fe798f81033afcf7c1533b173` (43 707 bytes)
* the 16 target artifacts and the run summaries are pinned by the Iteration 19–23 validation records

Measured on the merge as it stood with the upstream artifact bytes in place, this is what the validators said:

```
validate_iteration19_evidence --check  => exit 1
  FAILED: the digest of the artifact on disk (e86e8815…) differs from the digest the record claims (d797c328…)
  FAILED: the byte length of the artifact on disk (6260) differs from the length the record claims (6129)
validate_iteration20_evidence --check  => exit 1
  FAILED: the digest of the artifact on disk is 9e029cca…, not cdf0653f…
validate_iteration21_evidence --check  => exit 1
  FAILED: the digest of the artifact on disk is 7913a836…, not f877d581…
  FAILED: Modal provenance records 'modal_app_id' as NOT_AVAILABLE: …
validate_iteration22_evidence --check  => exit 1   (propagated)
validate_iteration23_evidence --check  => exit 1   (propagated)
validate_consolidated_closure_evidence --check => exit 1
  FAILED: the evidence of Iteration 19/20/21/22/23 is 'FAILED' instead of 'PASSED'   (15 checks)
```

The upstream artifacts are not only byte-different, they are **schema-incompatible**: `modal_app_id` does not exist in them any more, so the iteration line's strict provenance validator sees the App id as `NOT_AVAILABLE` and refuses the record.

### 4.3 Decision

**The published evidence tree stays byte-identical to `d3201c9`.** 21 files were restored to the PR head's bytes:

```
benchmarks/artifacts/latest_summary.json
benchmarks/artifacts/run_1794209615_70f5d22/summary.json
benchmarks/artifacts/run_1794209615_70f5d22/reproducibility_manifest.json
benchmarks/artifacts/run_1794209615_70f5d22/baseline_5/*.json      (16 target artifacts)
benchmarks/benchmark_results.json
benchmarks/evidence/modal_control_harness_validation.json
```

Regenerating the Iteration 19–23 evidence and the join table against the upstream schema would have been the alternative — and it is exactly what the maintainer forbade as a silent operation, and it is a separate, explicitly authorised iteration, not a merge side effect.

**Retained from upstream:** the four additive replay text artifacts of `AC-01` and `REENT-01` (`*_replay_stdout.txt`, `*_replay_stderr.txt`). They are new files, no published digest references them, and they break no binding. This is upstream's genuine contribution that survives the reconciliation as it stands.

---

## 5. Upstream work this branch does **not** take

Recorded explicitly, so that nothing is dropped silently. Each item needs a decision of the maintainer, and each one that touches published evidence needs an authorised regeneration iteration.

| # | Upstream item | What it would improve | What it would cost here |
|---|---|---|---|
| 1 | the published run artifacts rewritten in the upstream provenance schema (§4.1) | removes the **66** manufactured `modal-app://` pseudo-URIs that the iteration line's published artifacts still carry across all 16 target artifacts; replaces the asserted `image_tag`/`remote_os`/`forge_version`/`working_directory` constants — exactly the four entries of `LEGACY_HARDCODED_EVM_FACTS` that the current validator rejects — with honest `NOT_AVAILABLE` records; renames `modal_app_id` to the more precise `app_session_id` | invalidates the SHA-256 pins of the Iteration 19–23 evidence and of the join table's `app_id_evidence_ref` |
| 2 | `benchmarks/protocol.py::validate_billing_reconciliation` (schema 2.0.0) | an explicit reconciliation validator with a readable error message | the schema it validates is the aggregate-bucket shape Iteration 15 forbade; the iteration line's `validate_billing_attribution` is strictly stronger (exact `Decimal` reconciliation, double-count and omission detection, exact unique provider join) and its coverage was ported (§3.5) |
| 3 | `benchmarks/adapters.py` simplified producer | a smaller producer surface | breaks the Iteration 16 rehearsal chain and the producer-source immutability check of the closure validator (§3.2) |
| 4 | `benchmarks/benchmark_runner.py` hardcoded `remote_evm_environment` | — | asserts a fact the client never observed (§3.3) |
| 5 | upstream's flattened provenance assertions in the test file | — | weaker assertions than the iteration line's strict APIs (§3.5) |
| 6 | `benchmarks/evidence/modal_billing_join_table.json` schema 2.0.0 | — | restores the aggregate-bucket allocation that Iteration 15 closed (§3.4) |

Item 1 is the only one where upstream is strictly better than the iteration line *and* where the iteration line has a real residual gap. The reconciliation therefore **defers** it rather than pretending it does not exist: the published artifacts of this branch still carry pseudo-URIs and hardcoded legacy constants, and the current validator would refuse those same values if they were produced today. Closing that gap is the natural next iteration, and it needs the maintainer's authorisation for a regeneration that rewrites the SHA-bound Iteration 19–23 evidence.

---

## 6. Validation results

All runs below were executed against the merge commit `b0826f4` in a checkout with LF line endings (see §6.2).

### 6.1 Validators and tests

```
python -m benchmarks.regenerate_billing_join_table --check
  join table validation: PASSED (no error)                                     exit 0

python -m benchmarks.validate_iteration14_evidence --check
  validation report …iteration14_validation_evidence.json: FAILED (0/16 targets), bound to 43436b0266254d2504b2521f8499aa1604e11280   exit 0
python -m benchmarks.validate_iteration15_evidence --check
  … FAILED (0/16 targets), bound to cf2622362d5343ae70ecc1cf1622db9460f18a5b   exit 0
python -m benchmarks.validate_iteration16_evidence --check
  … FAILED (0/16 targets), bound to b1946536959e8977967d3cbaf161baf337bfd653   exit 0
python -m benchmarks.validate_iteration17_evidence --check
  … FAILED (0/16 targets), bound to e9faff403908937ebe6de640b1f041a3de2c97c1   exit 0
python -m benchmarks.validate_iteration18_evidence --check
  … FAILED (0/16 targets), bound to 8813cebd57dbff898ac3c14e2ab0bfca355dbdb3   exit 0
python -m benchmarks.validate_iteration19_evidence --check
  … published PASSED, revalidated PASSED (12/12 checks), bound to 18ad9740f835e7babb0a7f0fb727752660b2b8f0   exit 0
python -m benchmarks.validate_iteration20_evidence --check
  … published PASSED, revalidated PASSED (12/12 checks), bound to 64392a7bc4d4eba45a0fc15aacd4b32e3761dd98   exit 0
python -m benchmarks.validate_iteration21_evidence --check
  … published PASSED, revalidated PASSED (13/13 checks), bound to 40c063093c8d773d20f828fb290c68b5790a7cc5   exit 0
python -m benchmarks.validate_iteration22_evidence --check
  … published PASSED, revalidated PASSED (11/11 checks), bound to f0ce026d446e2c69a87f2bb4c155dcf0d36cd58b   exit 0
python -m benchmarks.validate_iteration23_evidence --check
  … published PASSED, revalidated PASSED (12/12 checks), bound to 749cba244b58fd76a3b91efe46df0c6bac204af6   exit 0
python -m benchmarks.validate_consolidated_closure_evidence --check
  … published PASSED, revalidated PASSED (21/21 checks), bound to 690f39a125ef091dee61ae9f18550ab068587c4e   exit 0
```

Iterations 14–18 stay **FAILED (0/16)** — the historical failures are preserved, not repaired. The closure validator compares the published status and the exit code only, so a historical `FAILED` is the expected and required result.

Test suite, same commit, same checkout:

```
python -m pytest -q
  841 passed, 7 skipped in 89.92s
```

and the same suite on the PR head for the comparison:

```
python -m pytest -q            # at d3201c9
  840 passed, 7 skipped in 92.20s
```

The delta is exactly the one ported test of §3.5 — no test changed its verdict, none changed its skip state.

The seven skips are the live-provider probes that need tools this machine does not have:

```
SKIPPED [3] tests/test_iteration14_evidence_integrity.py:1065: NOT_RUN: Real Foundry integration unavailable on system PATH
SKIPPED [1] tests/test_real_benchmark_execution.py:2054:  NOT_RUN: Real Slither integration unavailable: slither executable not found on system PATH
SKIPPED [2] tests/test_real_benchmark_execution.py:2083:  NOT_RUN: Real Foundry integration unavailable on system PATH
SKIPPED [1] tests/test_real_benchmark_execution.py:2153:  NOT_RUN: Real Foundry integration unavailable on system PATH
```

The live Foundry and Slither probes therefore remain **NOT_RUN** locally; the CI job `foundry-integration` on a Linux runner with the Foundry toolchain is the only place they can run.

### 6.2 The line-ending caveat, and how to reproduce

This repository has no `.gitattributes` and the local `core.autocrlf=true`. The working tree therefore holds **CRLF** while the blobs hold **LF**, and the validators hash the bytes **on disk**:

| File | digest of the LF blob (what the evidence pins) | bytes on disk in a CRLF checkout |
|---|---|---|
| `CPU-SMOKE-01_stage_evidence_cpu_smoke.json` | `d797c328…` (6 129 B) | `e86e8815…` (6 260 B) |
| `ITER20-01_stage_evidence_evm_sandbox.json` | `cdf0653f…` (6 337 B) | `9e029cca…` (6 448 B) |
| `ITER21-01_stage_evidence_evm_sandbox.json` | `f877d581…` (7 327 B) | `7913a836…` (7 438 B) |

So on a CRLF checkout the Iteration 19–23 validators and the closure validator fail **on a pristine checkout of the PR head as well** — this is a property of the Windows checkout, not of the merge. The reproduction used for the numbers above:

```bash
git -c core.autocrlf=false worktree add --detach <path> b0826f4
cd <path> && python -m benchmarks.validate_consolidated_closure_evidence --check
```

CI checks out with LF on Linux, which is why the PR #12 run was green there.

---

## 7. Open decisions for the maintainer

1. **The conflict resolutions of §3 are proposals.** Each one keeps the stricter validator and the published evidence it produced. A different choice is possible for any of the five, but it needs a matching regeneration of the affected evidence.
2. **§4.3 / §5 item 1 is the real question.** Upstream's rewrite of the published run artifacts removes 66 manufactured pseudo-URIs and the four hardcoded legacy constants that the current validator rejects. It cannot be taken inside a merge, because it invalidates the SHA-256 pins of the Iteration 19–23 evidence and of the join table's `app_id_evidence_ref`. It needs an authorised regeneration iteration.
3. **Upstream's billing reconciliation validator (§5 item 2)** was ported rather than imported. If the upstream validator is preferred, it has to be reconciled with the schema 3.0.0 contract first, otherwise the two lines validate two different schemas of the same table.
4. **The final merge of PR #12** is a separate gate and is explicitly not part of this branch.

---

## 8. What was deliberately not done

* PR #12 was not merged, and no decision about merging it was taken.
* No push to `minimax/iteration-14-evidence-integrity`, `integration/minimax-antigravity-reconciled`, `feat/empirical-benchmark-runner` or `main`; PR #8 was not touched.
* No rebase, no squash, no cherry-pick, no history rewrite, no change of merge direction.
* No live Modal call, no deployment, no redeployment, no GPU (H100/T4), no paid computation.
* No published evidence file was regenerated, renamed or rewritten; every published digest still resolves to the same bytes it resolved to at `d3201c9`.
* No validator and no test was weakened, relaxed or skipped. The ported test of §3.5 only adds negative cases.
* The historical failures of Iterations 14–18 were kept as `FAILED (0/16)`.
