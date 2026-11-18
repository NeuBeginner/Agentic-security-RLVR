# Modal CPU audit acceptance record — 2026-11-15

## Scope

Live execution against the deployed `aegis-rlvr-cpu-audit` application in Modal environment `main`. This was a CPU-only audit; no GPU or model inference was requested.

- Modal application: `aegis-rlvr-cpu-audit`
- Modal app id: `ap-dhWbTc7uufRgnidkOz0WDW`
- Deployed application version observed: `6`
- Runtime: Python 3.10.17, Modal SDK 1.5.5, Slither 0.11.6, Foundry forge 1.9.0, pinned solc 0.8.20
- Declared resources: CPU 2, memory 2048 MiB, timeout 600s, retries 0, GPU `null`, network blocked
- Environment probe: no NVIDIA device nodes, no CUDA/NVIDIA visible-device variables, GPU not exposed
- Model cache: read-only mount; write probe rejected with `EROFS`
- Results volume: writable

## Runs

### Vulnerable target: Vault

- Request id / run id: `cpu-audit-acceptance-20261115-vault-01` / `acceptance-20261115-vault-01`
- Result: `COMPLETED`
- Static analysis: real Slither run completed, exit code 0, 5 findings (including `reentrancy-eth`)
- Trusted harness verdict: `BREACH`
- Classification: `EXPLOIT_CONFIRMED`
- Vulnerability class: `Reentrancy`
- Reward: `1.0`
- Replay: `CONFIRMED`, independently reproduced
- Trusted invariant event: `INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE`
- Evidence basis: `trusted_harness_event`
- Consistency checks: all passed
- Stored artifact: `runs/acceptance-20261115-vault-01/result.json`
- Stored bytes: 358096
- Stored SHA-256: `3a0d368aa1efc11b8e869d272e2b737ed645edb2879f9ba7573ff6de719188e2`
- Read-back: parsed successfully; stored digest matched the read-back digest

**Qualification:** the result's `state_delta_verified` is `false` and its state snapshot is not a real snapshot. The confirmed breach is supported by the trusted harness event and independent replay, not by a verified before/after state snapshot.

### Safe control: SecureVault

- Request id / run id: `cpu-audit-acceptance-20261115-control-01` / `acceptance-20261115-control-01`
- Result: `COMPLETED`
- Static analysis: real Slither run completed, exit code 0, 1 finding (`solc-version`)
- Trusted harness verdict: `NO_BREACH`
- Classification: `SAFE_RUN`
- Reward: `-0.1`
- Replay status: `NOT_ELIGIBLE`; no independent replay was established
- Consistency checks: all passed
- Stored artifact: `runs/acceptance-20261115-control-01/result.json`
- Stored bytes: 187752
- Stored SHA-256: `4eb48cf6a493787653352f9ed2a49b22e5f6c269b24529a40233198e65e1dc71`
- Read-back: parsed successfully; stored digest matched the read-back digest

The safe control did not produce a breach. Its non-confirmed replay is not represented as a replay pass.

## Service-level checks

- Environment probe suite: passed; GPU absent and declared GPU is null.
- Candidate registry suite: passed; registry contains the `Vault` breach target and `SecureVault` no-breach control.
- Evidence read-back suite: passed; a previously stored evidence artifact was present and readable.
- Model-cache and results-volume probe: read-only enforcement and writable results volume both confirmed.
- No GPU dispatch, model generation, or training was performed.

## Acceptance status

The deployed CPU service has now been exercised directly through Modal MCP, including a vulnerable target, a safe control, persisted evidence, and read-back. This is stronger than the earlier Iteration 19 GitHub smoke test and closes the missing direct-service execution check for these two registered targets.

This record does **not** accept the historical 16-target benchmark evidence, regenerate Iterations 14–23, authorize R1 dispatch, merge any stacked PR, or authorize GPU/H100 spend. The remaining evidence-integrity and PR dependency gates must be reviewed separately.


## Archived evidence and source-revision qualification

The two complete parsed audit results have been archived in the repository in addition to the original Modal Volume objects:

- `benchmarks/evidence/cpu_audit/modal_cpu_audit_20261115_vault.json`
- `benchmarks/evidence/cpu_audit/modal_cpu_audit_20261115_securevault_control.json`

The envelope preserves each Modal Volume artifact's original byte length and SHA-256. The GitHub JSON envelope is a separately serialized archival copy, so its Git blob digest is not the original Modal object digest.

**Source revision is UNAVAILABLE.** Modal app metadata exposes app version 6 and deployment time, but neither the app metadata nor the audit result includes a Git commit SHA or image-to-commit attestation. Therefore these live Modal runs prove that the deployed CPU service completed the two audits; they do **not** prove that the deployed image contained requested source SHA `b8bcb4c18cd0cd3e49034c411b2bdd636fc64969`. No claim of exact-SHA remote execution is made. The minimum remaining step is a CPU-only rebuild/deploy that embeds and emits the exact Git SHA (or an immutable image digest cryptographically attested to that SHA), followed by a fresh audit. No deployment was attempted in this pass.

Run timestamps from the Modal service logs: Vault `2026-11-15T11:06:47Z`; SecureVault control `2026-11-15T11:06:58Z`. Slither returned exit code 0 in both runs; its analysis status was `completed`, with valid reports.


## Invocation and CI verification

The two remote calls were made through the Modal CPU audit service API with these exact arguments (the service itself resolves the registered candidate and trusted harness):

```text
modal_run_cpu_audit(
  target_name="Vault",
  request_id="cpu-audit-acceptance-20261115-vault-01",
  run_id="acceptance-20261115-vault-01",
  run_replay=True
)

modal_run_cpu_audit(
  target_name="SecureVault",
  request_id="cpu-audit-acceptance-20261115-control-01",
  run_id="acceptance-20261115-control-01",
  run_replay=True
)
```

GitHub verification on archival commit `ad8f2d9adc332e7e424f58d82ac15c5d52006823`:

- [Aegis-RLVR CI](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43708062875): **SUCCESS**; complete suite **1151 passed, 11 skipped, 5 warnings**; real Foundry integration probe **SUCCESS**.
- [Modal CPU audit contract + live smoke workflow](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43708058715): **SUCCESS**; offline CPU contract **88 passed** and the separate ephemeral Iteration 19 CPU smoke job **SUCCESS**.
- [Second CI run on the same SHA](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43708058769): **SUCCESS**.
- The full suite includes `tests/test_slither_analysis_status.py` (including completed/partial/fallback and timeout evidence cases) and `tests/test_runner_timeout_semantics.py`.

These GitHub Actions results are bound to the archival commit above. They do not repair the separate limitation that the deployed Modal application's image/source revision is not exposed by its metadata; exact source-SHA attestation for the two live Modal calls remains `UNAVAILABLE`.

---

# Acceptance pass II — the SHA-attested deployment (commit `594da83`)

The first pass could not prove which commit it ran (§ *Source-revision qualification*
above). This pass deploys an exact commit, proves it from the running container and
runs the two control audits on that deployment.

## What was defective and what was fixed

Three defects kept the deployment from proving its own commit. All three were fixed in
commit `594da83` (`fix(modal): attest the deployed commit and make the deployment
reachable`).

| # | Defect | Evidence | Fix |
|---|---|---|---|
| 1 | **`SOURCE_COMMIT` never reached the container.** It was read from `os.environ` at import time, but the provider forwards neither the environment of the client nor an arbitrary environment variable into the container — only the secrets of the function and the `ENV` directives of the image do. Every deployed container would have reported `"unknown"`. | source of `modal_cpu_audit_app.py` before the fix; the behaviour of the provider | the commit is baked into the image (`Image.env({SOURCE_COMMIT_ENV_VAR: SOURCE_COMMIT})`) |
| 2 | **The deployment workflow could not be triggered.** GitHub resolves `workflow_dispatch` against the default branch, and the workflow file exists only on the feature branch: `HTTP 404: workflow modal-cpu-deploy.yml not found on the default branch`. | the dispatch attempt against `main` | the deployment runs on a **push** to `feat/modal-cpu-audit` — the event that executes the branch-local workflow file; the manual dispatch stays available for the day the file reaches the default branch |
| 3 | **The read-back could read a stale snapshot.** `read_saved_result` opened the artifact of the results volume without refreshing the snapshot of the volume, so a warm container whose snapshot predated the commit of the artifact answered `ARTIFACT_NOT_FOUND` for an artifact that existed. | the behaviour of the provider's volume snapshots | the snapshot is refreshed before the read (`results_volume.reload()`), and a failing refresh is reported in `volume_reload_error` instead of being hidden |

The offline contract suite covers the three invariants (80 tests in
`tests/test_cpu_audit_contract.py`, 6 of them new).

## The deployment

| Fact | Value |
|---|---|
| Deployed commit | `594da8302c3e8999d5f742ac2a73f31401e52e20` |
| Deployment job | [Deploy Aegis CPU audit to Modal](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43715407912) — **SUCCESS** (1m22s) |
| Modal application | `aegis-rlvr-cpu-audit`, app id `ap-dhWbTc7uufRgnidkOz0WDW`, **version 7**, environment `main` |
| Deployed at | 2026-11-15T12:46:14Z |
| Workspace | `neubeginner` (the job refuses credentials of another workspace) |
| Runtime confirmation | `{"status": "DEPLOYED_AND_VERIFIED", "source_commit": "594da8302c3e8999d5f742ac2a73f31401e52e20", "source_commit_state": "known", "declared_resources": {"block_network": true, "cpu": 2.0, "gpu": null, "memory": 2048, "retries": 0, "timeout": 600}}` |

The `source_commit` of that line is the value the **running container** reported —
the commit is baked into the image, so the container really carries it. The job
compares it with `github.sha` and fails the deployment when they differ.

The environment probe of the deployed application confirms the rest: `gpu_device_exposed`
is `false`, there is no NVIDIA device node and no CUDA/NVIDIA variable, the model cache
is mounted read-only (`READ_ONLY_ENFORCED`, `EROFS`), the results volume is writable,
and the toolchain is forge 1.9.0, Slither 0.11.6 and the pinned solc 0.8.20.

## The two control audits on that deployment

| | Vulnerable target `Vault` | Safe control `SecureVault` |
|---|---|---|
| Request id | `cpu-audit-594da83-vault-01` | `cpu-audit-594da83-control-01` |
| Run id | `acceptance-594da83-vault-01` | `acceptance-594da83-control-01` |
| Result | `COMPLETED` | `COMPLETED` |
| `source_commit` of the result | `594da8302c3e8999d5f742ac2a73f31401e52e20` | `594da8302c3e8999d5f742ac2a73f31401e52e20` |
| Static analysis | real Slither 0.11.6, `analysis_status: completed`, exit code **0**, `exit_code_disposition: clean_exit` | real Slither 0.11.6, `analysis_status: completed`, exit code **0**, `clean_exit` |
| Trusted harness | `BREACH` (`test/VaultHarness.t.sol`), return code 0 | `NO_BREACH` (`test/SecureVaultHarness.t.sol`) |
| Classification | `EXPLOIT_CONFIRMED`, `Reentrancy` | `SAFE_RUN` |
| Reward | **1.0** | **-0.1** |
| Replay | `CONFIRMED`, independently reproduced, `breach_evidence_basis: trusted_harness_event` | `NOT_ELIGIBLE`, `replay_confirmed: false` — no breach to reproduce |
| Consistency | `all_consistent: true` | `all_consistent: true` |
| Artifact | `runs/acceptance-594da83-vault-01/result.json`, 358169 bytes, SHA-256 `b50494f58e691b446d84d5ee7acb715e3465a76a87560bc783a3ef39fdd6c924` | `runs/acceptance-594da83-control-01/result.json`, 187815 bytes, SHA-256 `c0b323623ae0f325dbb88419015b2baffd2079547b592914d834b66b9023108c` |
| Read-back through the volume API | `OK`, same byte length, same SHA-256 | `OK`, same byte length, same SHA-256 |
| Read-back through the deployed service | `READ_BACK`, same byte length, same SHA-256, `volume_reload_error: null` | `READ_BACK`, same byte length, same SHA-256, `volume_reload_error: null` |

Three independent copies of the stored bytes agree: the digest the producing container
wrote, the digest the volume API reads back and the digest the deployed service reads
back in a separate invocation. The `source_commit` inside both results is the deployed
commit, so the audits are bound to the image that was verified.

The archived envelopes are in the repository:

- `benchmarks/evidence/cpu_audit/modal_cpu_audit_20261115_594da83_vault.json`
- `benchmarks/evidence/cpu_audit/modal_cpu_audit_20261115_594da83_control.json`

## The CI of the same commit

| Workflow | Result |
|---|---|
| [CI Pipeline (push)](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43715407766) | **SUCCESS** — reward v2 and trusted harness regression suite + real Foundry EVM integration probe |
| [CI Pipeline (pull request)](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43715412113) | **SUCCESS** — the same two jobs |
| [Modal CPU audit contract + live smoke](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43715408244) | **SUCCESS** — offline CPU contract and the separate ephemeral CPU-only smoke test |
| [Deploy Aegis CPU audit to Modal](https://github.com/NeuBeginner/Agentic-security-RLVR/actions/runs/43715407912) | **SUCCESS** — deployment and provenance verification |

Local run of the complete suite on the same commit: **1179 passed, 7 skipped** (the seven
skips are the live-provider tests that the Linux runner of the `foundry-integration` job
executes).

## What this pass does not claim

- It does **not** merge PR #17 and does **not** move the draft out of draft.
- It does **not** touch the GPU path, the production application `modal_app.py` or any
  volume of the model cache (the cache is mounted read-only in every call).
- It does **not** regenerate the Iteration 14–23 evidence and does **not** authorise the
  R1 dispatch — the two live runs are the CPU audit service, not the authorised
  evidence-regeneration trace.
- The acceptance criteria 14 and 18 of §11.3 of the architecture plan remain open: they
  belong to the replacement run of the regeneration plan, which has not been made (there is
  no `reproducibility_manifest.json` and no approval record of a compute step in the
  repository). The criteria that are checkable today are met — the billing join table
  validates (`PASSED`, schema 3.0.0, `aggregate_bucket_allocation: FORBIDDEN`,
  `source_raw_export.sha256: 1529b1b9…`) and every validator reports its expected
  verdict (Iterations 14–18 `FAILED (0/16)` unchanged, Iterations 19–23 `PASSED`, closure
  `21/21 PASSED`).

