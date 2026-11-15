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
