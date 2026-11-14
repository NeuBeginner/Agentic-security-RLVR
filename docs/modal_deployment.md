# Modal deployment — the CPU-only audit service

This document describes the CPU-only Modal application of this repository: what it
is, how it is deployed, how it is verified, what it costs, what it cannot do, and how
the GPU path is attached afterwards.

| | |
|---|---|
| Application | `aegis-rlvr-cpu-audit` (app id `ap-dhWbTc7uufRgnidkOz0WDW`) |
| Deployment page | <https://modal.com/apps/neubeginner/main/deployed/aegis-rlvr-cpu-audit> |
| Workspace | `neubeginner` (environment `main`) |
| Entry point | `modal_cpu_audit_app.py` (the application) |
| Driver | `benchmarks/run_cpu_audit.py` (the end-to-end test) |
| Candidates | `benchmarks/cpu_audit_pocs/` (repository-owned PoC registry) |
| Inventory | [`docs/modal_integration_inventory.md`](modal_integration_inventory.md) |

---

## 1. Architecture

```
          client (this repository)                Modal workspace `neubeginner`
  ┌────────────────────────────────┐        ┌─────────────────────────────────────┐
  │ benchmarks/run_cpu_audit.py    │        │ app aegis-rlvr-cpu-audit            │
  │  - refuses without approval    │ ─────▶ │  ├─ probe_environment()             │
  │  - drives the end-to-end test  │ remote │  ├─ audit_contract(request)         │
  │  - writes the evidence         │        │  └─ read_saved_result(run_id)       │
  └────────────────────────────────┘        └─────────────────────────────────────┘
                                                     │
                    ┌────────────────────────────────┴─────────────────────────┐
                    │ inside the container (no GPU, no secret)                │
                    │                                                          │
                    │  1. static analysis   sandbox.runner.run_slither_analysis │
                    │  2. hypothesis        core.hypothesis_manager           │
                    │  3. verification      sandbox.runner.run_payload_in_sandbox
                    │                       → forge test --offline --json -vvvv│
                    │                       → verdict of the trusted harness   │
                    │  4. replay            sandbox.runner.verify_independent_  │
                    │                       replay_result (a fresh EVM)         │
                    │  5. result            core.evaluator.evaluate_execution_  │
                    │                       trace (reward specification 2.0.0)  │
                    │  6. storage           /vol/results/runs/<run_id>/         │
                    └──────────────────────────────────────────────────────────┘
```

### 1.1 Why a separate application

`modal_app.py` is the **production** application: it declares the H100 class
`ProductionAuditAgent` and the T4 class `DevReasoningAgent`. The CPU service is a
separate app with its own name so that it can be declared, deployed, inspected and
billed completely independently of the GPU path:

* **no GPU class is declared** in `modal_cpu_audit_app.py` — a GPU cannot be allocated
  by this app, because nothing in it asks for one;
* the module **never imports** `modal_app.py` and **never imports**
  `core.r1_bounds` — it therefore cannot change a single entry of the R1 dispatch
  registry and cannot weaken the fail-closed approval mechanism of the benchmark
  (this is asserted by `tests/test_cpu_audit_contract.py`);
* the R1 gate, the rate card, the approval key and the historical evidence are
  untouched.

### 1.2 The stage that is deliberately **not** part of the CPU service

The synthesis of an exploit candidate is the **GPU/LLM stage** of this project (the
30B audit model on H100). It is not part of the CPU service, and the service never
pretends otherwise:

* a candidate is either supplied by the caller (`candidate_code`) or resolved from the
  repository-owned candidate registry (`benchmarks/cpu_audit_pocs/registry.json`);
* when no candidate is available, the run ends with the explicit status
  `CANDIDATE_UNAVAILABLE` — **never** with an invented verdict.

### 1.3 The entry point is a function, not an HTTP endpoint

An unauthenticated public endpoint that compiles and executes untrusted Solidity is an
abuse and denial-of-service surface. The acceptance criteria of this workstream ask
for a reachable entry point, not for a public web route, so the service is a Modal
**function** that is reachable from any client holding the credentials of the
workspace. The application therefore declares **no** `web_endpoint`.

### 1.4 The authorisation is enforced on the server side

A function is reachable by **every** client that holds the credentials of the
workspace. An authorisation that lives in the caller is therefore no authorisation at
all: the local environment variable of the driver was never the gate, and the service
has to refuse a direct call on its own.

The service therefore keeps a shared token in a Modal **secret** and every public
function checks it **before it does any work**:

| | |
|---|---|
| The secret | `aegis-cpu-audit-auth` (key `AEGIS_CPU_AUDIT_TOKEN`) |
| The check | `assert_authorised(call, presented_token)` — `hmac.compare_digest`, constant time |
| The refusal | `{"status": "UNAUTHORIZED", "error": {"code": "NOT_AUTHORISED", …}}` |
| The order | the check is the **first** statement of `audit_contract`, `probe_environment` and `read_saved_result` — before the validation, before the static analysis, before the EVM and before any access to a volume |
| The failure mode | a container **without** the secret has no expected token, so it refuses every call — a missing secret closes the service, it never opens it |

The token of the caller is compared, never echoed: it never travels into a result, an
artifact or a log record.

The end-to-end test proves the refusal by calling all three functions **without** the
token and recording the refusals as part of the evidence (§8).

---

## 2. Connecting Modal — the order of the steps

```powershell
# 0. the workspace of the project. The active profile of the machine is NOT it.
$env:MODAL_PROFILE = 'neubeginner'

# 1. the credentials
modal token set --profile neubeginner

# 2. the inventory (read-only) - it must be complete before any resource is created
modal app list     --profile neubeginner
modal volume list --profile neubeginner
modal billing summary --profile neubeginner

# 3. the authorisation secret of the service (control plane, free of charge)
$token = python -c "import secrets; print(secrets.token_urlsafe(32))"
modal secret create aegis-cpu-audit-auth "AEGIS_CPU_AUDIT_TOKEN=$token" --profile neubeginner
"AEGIS_CPU_AUDIT_TOKEN=$token" | Out-File -FilePath .env -Encoding utf8   # .env is excluded from git

# 4. the deployment
modal deploy modal_cpu_audit_app.py --profile neubeginner

# 5. the end-to-end test
$env:AEGIS_APPROVE_CPU_AUDIT = '1'
python -m benchmarks.run_cpu_audit --profile neubeginner --mode deployed
```

The CLI profile flag and `MODAL_PROFILE` must agree: the SDK reads the profile from
the environment, the CLI from its own flag. Mixing them sends the SDK to a **different
workspace** that happens to own a volume of the same name (see the inventory, §0).

The token of the service is read by the driver from the environment variable
`AEGIS_CPU_AUDIT_TOKEN` or from the local `.env` file (which is excluded from git).
The driver refuses to start without it — a call without the token would be refused by
the service anyway, and a refused call still starts a container.

---

## 3. Commands

| Purpose | Command |
|---|---|
| Create/rotate the authorisation secret | `modal secret create aegis-cpu-audit-auth "AEGIS_CPU_AUDIT_TOKEN=<token>" --profile neubeginner` |
| Deploy | `modal deploy modal_cpu_audit_app.py --profile neubeginner` |
| Run ephemerally (no deployment) | `python -m benchmarks.run_cpu_audit --profile neubeginner --mode ephemeral` |
| Run against the deployment | `python -m benchmarks.run_cpu_audit --profile neubeginner --mode deployed` |
| Call one function directly | `python -c "import modal; print(modal.Function.from_name('aegis-rlvr-cpu-audit','probe_environment').remote('<token>'))"` |
| Call one function directly **without** the token | `python -c "import modal; print(modal.Function.from_name('aegis-rlvr-cpu-audit','probe_environment').remote())"` — the answer is `UNAUTHORIZED` |
| Logs of the app | `modal app logs aegis-rlvr-cpu-audit --profile neubeginner` |
| Containers of the app | `modal container list --app-id ap-dhWbTc7uufRgnidkOz0WDW --profile neubeginner` |
| Stop the app (the deployment stays) | `modal app stop aegis-rlvr-cpu-audit --profile neubeginner` |
| Remove the deployment | `modal app remove aegis-rlvr-cpu-audit --profile neubeginner` |
| Billed usage of the workspace | `modal billing report --for today --json --profile neubeginner` |
| Local contract tests | `python -m pytest tests/test_cpu_audit_contract.py tests/test_cpu_audit_evidence_consistency.py -q` |

---

## 4. The CPU configuration

The resources are declared **once**, in the module, and every function uses that
declaration:

```python
DECLARED_RESOURCES: Dict[str, Any] = {
    "gpu": None,      # explicit: no GPU can be allocated
    "cpu": 2.0,
    "memory": 2048,
    "timeout": 600,
    "retries": 0,
    "block_network": True,   # the egress of the container is closed by the provider
}
```

| Resource | Value | Why |
|---|---|---|
| GPU | `None` | the CPU path needs none; the request is explicit |
| CPU | 2.0 cores | the Foundry run and Slither are the only consumers |
| Memory | 2,048 MiB | the same value the repository's sandbox profile declares (`core/config.py:38`) |
| Timeout | 600 s | one audit = Slither (≤30 s) + two EVM runs (≤60 s each) + overhead |
| Retries | 0 | a failed audit is a result, not something to repeat silently |
| Network | **blocked** | the whole pipeline is offline by construction; the provider closes the egress, so an unauthorised external call is impossible rather than merely unintended |
| Min / buffer / max containers | 0 / 0 / 32 | no container is kept warm; nothing runs between the calls |

The egress block was verified live: the end-to-end test with `block_network=True`
reproduced the same result — Slither still reports the five real detectors
(`reentrancy-eth`, `reentrancy-benign`, `reentrancy-events`, `solc-version`,
`low-level-calls`), because the compiler and the libraries are baked into the image,
and the Foundry run stays offline (`forge test --offline`).

The toolchain inside the image is the repository's own: Foundry (`forge`, `cast`,
`anvil`), the pinned solc releases 0.8.19–0.8.28 with SHA-256 validation
(`sandbox/prebake_solc.py`), `forge-std` v1.9.5, OpenZeppelin v5.0.2, Slither and
`solc-select`. The image is the sandbox image of the production application
(`sandbox.runner.sandbox_image`) — the business logic is not duplicated.

### 4.1 The one change this workstream made to the shared image

`sandbox/runner.py` mounted the Python packages of the repository **on container
start** (`add_local_python_source("core", "sandbox")`). Modal does not allow any
further image layer on top of such an image, so the CPU service — which has to add the
`benchmarks` package and the candidate registry — could not be built at all.

The minimal change: the packages are now **copied** into the image
(`add_local_python_source("core", "sandbox", copy=True)`). The content of the
container is the same; only the moment at which the files arrive changes. This is the
"describe the problem and propose the minimal change" case of the assignment, and it
is the only modification of the shared production code of this workstream.

---

## 5. The volumes

| Volume | Mount | Mode | Content |
|---|---|---|---|
| `aegis-model-cache` | `/vol/models` | **read-only** (`with_mount_options(read_only=True)`) | the existing model cache — never written, never deleted |
| `aegis-cpu-audit-results` | `/vol/results` | read-write | the artifacts of this service: `runs/<run_id>/result.json` |

* The model cache is mounted **without** `create_if_missing`: the service fails closed
  when the cache is absent instead of silently creating an empty one.
* The read-only mount is not a promise, it is a **fact**: the probe of the service
  attempts a write on the mounted cache and records the result. The measured result is
  `READ_ONLY_ENFORCED` (the write fails with `EROFS`).
* The artifacts are written into a **separate** volume and a separate directory, so
  that no write of this service can ever touch the existing data. The measured
  footprint of the results volume after the end-to-end test is well under 1 MiB
  (two result files of ~0.2 MiB and ~0.35 MiB).
* After the write the volume is committed and the file is read back; the digest of the
  bytes that were read back equals the digest of the bytes that were written
  (`reread_verified: true`).

---

## 6. Environment variables and secrets

Only these variables are read by the service or its driver.

| Variable | Where | Meaning | Value in the repository |
|---|---|---|---|
| `MODAL_PROFILE` | client | the Modal workspace | `neubeginner` — **not** committed, set by the operator |
| `AEGIS_APPROVE_CPU_AUDIT` | driver | the explicit authorisation of the live invocation | **not committed** — set by the operator (`1`, `true` or `yes`) |
| `AEGIS_CPU_AUDIT_TOKEN` | driver **and** container | the shared authorisation token of the service | **not committed** — the operator reads it from the Modal secret `aegis-cpu-audit-auth`; the driver also accepts it from the local `.env` file, which is excluded from git |
| `GEMINI_API_KEY` | `core/config.py:14` | the frontier API key of the *production* pipeline | never read by the CPU service; never logged |

The service reads **exactly one** secret: the authorisation token of
`aegis-cpu-audit-auth`. It is compared, never echoed — the token of the caller never
travels into a result, an artifact or a log record. The service logs the **names** of
the `MODAL_*` environment variables of the container and never their values. The driver
scans the whole result for secret-shaped strings (`AIza…`, `sk-…`, `ghp_…`, private key
headers, `api_key=…`) — the measured result of the end-to-end test is a clean scan.

---

## 7. What happened during the deployment — the honest log

| Attempt | Command | Result |
|---|---|---|
| 1 | `modal deploy modal_cpu_audit_app.py --profile neubeginner` | **failed** in 0.4 s: *"An image tried to run a build step after using `image.add_local_*` to include local files."* — the local files of the CPU service were added after the build steps of the sandbox image |
| 2 | same, with `copy=True` on the local additions | **failed** identically: the base image itself ends in a deferred mount, and Modal forbids a layer on top of such an image |
| 3 | same, after `sandbox/runner.py` copies the Python packages into the image | **succeeded**: `✓ App deployed in 32.770s! 🎉` |

The failed attempts created no volume and no lasting application; they are visible in
the application history as stopped applications and cost nothing (`Billed Cost: $0.00`
throughout). The two stopped placeholders of the failed attempts can be left in place
or removed with `modal app remove <app-id>`; they hold no function and no data.

The full deployment log is the console output of the third attempt; the deployment
page is <https://modal.com/apps/neubeginner/main/deployed/aegis-rlvr-cpu-audit>.

---

## 8. The verification commands

```powershell
# the offline contract suite (no provider call)
python -m pytest tests/test_cpu_audit_contract.py tests/test_cpu_audit_evidence_consistency.py -q

# the live end-to-end test against the deployment
$env:AEGIS_APPROVE_CPU_AUDIT = '1'
python -m benchmarks.run_cpu_audit --profile neubeginner --mode deployed

# the evidence of the run
python -c "import json;d=json.load(open('benchmarks/evidence/cpu_audit/<run_id>_evidence.json',encoding='utf-8'));print(json.dumps(d['expectations'],indent=2))"

# a direct call WITHOUT the token - the answer is UNAUTHORIZED
python -c "import modal;print(modal.Function.from_name('aegis-rlvr-cpu-audit','probe_environment').remote())"
```

The end-to-end test performs **eight** invocations and checks **29** expectations:

| # | Invocation | What it proves |
|---|---|---|
| 1 | `probe_environment` (with the token) | the volumes, the toolchain, the pinned compiler and the GPU state |
| 2 | `audit_contract` on the vulnerable target `Vault` | the whole pipeline: static analysis, hypothesis, verification in a real Foundry EVM, independent replay, verdict, artifact |
| 3 | `audit_contract` on the safe control `SecureVault` with the **same** candidate | the trusted harness must not report a breach — no false confirmation |
| 4 | `audit_contract` with a target that has no trusted harness | the service refuses it in a structured way |
| 5 | `read_saved_result` in a **separate invocation** | the artifact is read back by a container that did not produce it |
| 6 | `audit_contract` **without** the token | the service refuses the call |
| 7 | `probe_environment` **without** the token | the service refuses the call |
| 8 | `read_saved_result` **with a wrong token** | the service refuses the call |

The expectations are read from the evidence itself, never from a summary flag:

* the **first** Foundry run really ran — `return_code == 0`, `test_status == "Success"`,
  a trusted harness suite and its verdict;
* the **replay** was a second, independent execution — the identity of the two
  executions (`first_execution_id` / `replay_execution_id`) is different and the
  service states the basis of that statement;
* the trusted verdict of the first run, of the replay and of the service agree;
* the safe control is **not** confirmed — and its own replay reports `NO_BREACH`;
* the reward is **the sum of its own components** and the replay credit is there
  exactly when the replay was confirmed;
* every field of the verdict tells the same story (`is_verified`, `reproducible`,
  `replay_status`, `replay_confirmed`, `verification_result.replay_confirmed`,
  `verification_result.confidence_status`);
* the `state_delta_verified` claim matches the state delta it describes, and the
  basis of the breach is named (`trusted_harness_event`);
* the static analysis states its provenance **and** its status — `analysis_mode` is
  `slither` for the real detector and `fallback_heuristics` for the fallback, and the
  run is only accepted with the real detector **and** with `analysis_status:
  completed`;
* the exit code of the detector, the status of the analysis, the validity of its
  report and the fallback flag agree with each other (see 8.2);
* the service's own self-check (`consistency.all_consistent`) is true;
* the three unauthorised calls are refused with `UNAUTHORIZED` / `NOT_AUTHORISED`.

A run is **not** accepted because `reproducible=True`: the reproducibility alone is
never a criterion — the independent replay, the trusted verdict, the reward and the
field consistency are.

---

## 8.1 The consistency of the evidence

A result is one statement about one execution, and every field of that statement has
to agree with the others. The service therefore writes a **self-check** into every
result (`consistency`), and the verdict carries the fields that make the statement
checkable:

| Field | Meaning |
|---|---|
| `replay_status` | `CONFIRMED` / `FAILED` / `INFRA_ERROR` / `NOT_ELIGIBLE` — the state of the independent replay |
| `replay_confirmed` | the same statement as a boolean |
| `is_verified` | true only for a confirmed exploit |
| `reproducible` | true only when an **independent** replay confirmed the verdict — the same meaning as in the GPU path (`modal_app.py`) and in `core/candidate_lifecycle.py` |
| `verification_result.replay_confirmed` | the oracle result is **aligned** with the replay, so a verdict never claims a confirmed exploit while its own embedded oracle result still calls the breach provisional |
| `verification_result.confidence_status` | `CONFIRMED` after a confirmed replay, `PROVISIONAL_BREACH` before it |
| `state_delta_verified` | true **only** when a real state snapshot exists and the state changed |
| `breach_evidence_basis` | how the breach was established: `trusted_harness_event` or `verified_state_snapshot` |
| `reward_components` / `reward_penalty` / `reward_score` | the score is always the sum of its own components and its penalty |

## 8.2 The status of the static analysis
The exit code of the Slither CLI does **not** say whether the analysis succeeded. With
its default `--fail-on pedantic` the CLI leaves with `sys.exit(-1)` (the shell code
`255`) as soon as it found anything — and it writes the JSON report *before* that
exit. The same code is used when the analysis itself failed. The evidence of the
earlier runs carried `slither_exit_code: 255` next to `analysis_mode: "slither"` and a
report with findings, and the gate accepted it: the mere presence of a report was
treated as the proof of a successful analysis.

The status of the run is therefore derived from the observable facts and written into
the evidence of every run (`core/slither_status.py`):

| Field | Meaning |
|---|---|
| `analysis_status` | `completed` (the target really was analysed), `partial` (a report that Slither did not finish), `fallback` (no usable report), `unavailable` (the stage did not run) |
| `analysis_mode` | where the findings come from: `slither` (the real detectors) or `fallback_heuristics` (the heuristics of this repository) |
| `exit_code_disposition` | the **named** reason of the exit code: `clean_exit`, `slither_findings_fail_on_policy`, `analysis_error`, `unparsable_report`, `unexplained_exit_code`, `no_valid_report`, `timed_out`, `not_run` |
| `slither_exit_code`, `slither_argv`, `slither_stdout_tail`, `slither_stderr_tail` | the observable facts the disposition was derived from |
| `slither_report_present` / `slither_report_valid` / `slither_report_success` / `slither_report_error` | whether a report was written, whether it could be parsed, and what the report itself states (`success` is written by the Slither CLI) |
| `partial_findings` | the findings of a partial run — they are the evidence of the partial run and are **never** the findings of the analysis |

The rules:

1. the repository calls Slither with `--fail-none`, so the findings policy of the CLI
   cannot turn a successful analysis into a non-zero exit code;
2. a run with a non-zero exit code is **never** silently marked as a successful
   analysis: the disposition names the cause, and a cause that cannot be named makes
   the run `partial`;
3. the findings of a partial run are the heuristics of this repository — the fallback
   always names its reason (`fallback_reason`);
4. `core.slither_status.static_analysis_evidence_is_consistent` is the single rule
   that the acceptance gate and the offline tests share: the exit code, the status,
   the validity of the report and the fallback flag may not contradict each other.

The repair that this workstream made in `core/evaluator.py` (the shared evaluator of
the repository, so the GPU path inherits it):

1. **The verdict carries its own replay status.** Before the repair the verdict always
   said `NOT_ELIGIBLE`, even when the replay had confirmed the exploit — while the
   trajectory validator of `core/schemas.py` demands `CONFIRMED` for an
   `EXPLOIT_CONFIRMED` trajectory. The vocabulary of the verdict is now the vocabulary
   of `core/candidate_lifecycle.py`.
2. **The embedded oracle result agrees with the verdict.** It is built from the first
   execution, before the replay is known, so it said `replay_confirmed: false` and
   `PROVISIONAL_BREACH` next to a verdict of `EXPLOIT_CONFIRMED` and a reward of
   `+1.0`. It is now aligned (as a copy — the evidence of the execution is never
   mutated).
3. **`state_delta_verified` is no longer a claim without evidence.** The trusted
   harness proves a breach through a verified event, so there is no state delta to
   verify: the flag is `false` and the basis of the breach is named.
4. **A replay that could not run is an infrastructure failure.** It is reported as
   `INFRA_ERROR` with a reward of `0.0` — not as an unreplayed breach with `+0.5`,
   which would have claimed that the exploit was observed while nothing was observed.
5. **`reproducible` means the same thing everywhere.** A safe run reproduces no
   exploit, so the flag is `false` for it.

The three historical runs of `benchmarks/evidence/cpu_audit/` are **kept**: they are
the evidence of the defect. `tests/test_cpu_audit_evidence_consistency.py` asserts
that a run of the fixed service contradicts itself nowhere, and that the historical
runs do carry the contradiction — so the defect cannot be quietly forgotten, and the
repair cannot silently regress.

---

## 9. Known limitations

1. **The LLM stage is out of scope on CPU.** The audit service verifies a candidate;
   it does not invent one. A target without a candidate ends in
   `CANDIDATE_UNAVAILABLE`. The synthesis stage needs the GPU class.
2. **The candidate registry covers one target pair.** `Vault` (expects a breach) and
   `SecureVault` (the negative control). A caller may pass `candidate_code` for any
   other allowlisted target, but the registry itself holds no further candidate.
3. **The static analysis depends on the toolchain of the image.** Slither runs against
   the pre-baked solc 0.8.20; when Slither cannot run, the repository's own
   deterministic fallback heuristics produce the findings. The result states which
   engine produced them (`analysis_mode`: `slither` or `fallback_heuristics`), and the
   end-to-end test **rejects** a run whose analysis fell back — the fallback is part of
   the repository's static analysis stage, but it is never passed off as an analysis
   result. The fallback is not a stand-in for the EVM verification, which always runs.
4. **The service verifies targets of the repository's allowlist only.** A contract
   without an immutable repository-owned harness is refused, because there is no
   verdict that could be trusted for it.
5. **The entry point is not a web service.** There is no HTTP route and no rate
   limiting to configure — and therefore no public abuse surface either. The
   authorisation is a **shared token** (§1.4): it closes the service, it does not
   implement a user management, a quota or a rotation schedule. A production use of
   the service would need at least a rotation of the token and a per-caller
   identification; that is beyond this workstream.
6. **The result of one audit is stored, not a training trajectory.** The service
   writes the structured audit result; it does not write RLVR trajectories into the
   model cache. The trajectory stage of the production pipeline is untouched.
7. **The trusted harness proves the breach with an event, not with a state snapshot.**
   The verdict therefore reports `state_delta_verified: false` together with
   `breach_evidence_basis: "trusted_harness_event"`: there is no state delta to
   verify, and the claim is made about the event that the immutable harness emitted
   (emitter, topic and deficit). The field is `true` only when a real snapshot exists
   and the state actually changed.

---

## 10. The cost estimate

| Item | Measured |
|---|---|
| Billed cost of the workspace | **$0.00** (free credits and the free storage allowance cover everything) |
| Metered cost of the workspace today | $6.09 — credits −$4.11, free storage −$1.98, network egress allowance −$0.00 → **billed $0.00** |
| Billed cost of this application alone | **$0.04866051** for the whole day of 2026-11-14 (the provider's own line item for `ap-dhWbTc7uufRgnidkOz0WDW`: the three historical runs, the two runs of the fix and the unauthorised-call checks) — covered by the credits of the workspace |
| Storage used | 59.93 GiB of 1 TiB (5.85 %) |
| Storage added by this workstream | < 1 MiB (the results volume) |
| Wall-clock time of the end-to-end test | **40 s**, **55 s** and **52 s** for the three historical runs; **60 s** and **66 s** for the two runs of the fix — eight invocations each |
| CPU | 2 cores per container, no warm container between the calls |
| GPU | **none** — `gpu: None` in the declaration, `gpu_device_exposed: false` and no `nvidia*` device node in the container |

The free allowance covers the workload: a CPU container that runs a Foundry test for a
few seconds is far below the included credits, and the storage stays two orders of
magnitude below the allowance. A long-running campaign (thousands of audits) would
have to be re-estimated — the rate card of the repository
(`benchmarks/evidence/r1_rate_card.json`) is the instrument for that, and it is
**not** approved by the maintainer.

---

## 10.1 The governance of the new call sites

The repository keeps an exhaustive inventory of every provider call site
(`benchmarks/evidence/r1_call_site_inventory.json`), and
`tests/test_r1_dispatch_contract.py` fails when a call site is not classified. The
three call sites of this service are therefore registered as **refused**:

| Call site | Registry |
|---|---|
| `audit_contract` | `core/r1_bounds.UNAUTHORISED_CALL_SITES` |
| `probe_environment` | `core.r1_bounds.UNAUTHORISED_CALL_SITES` |
| `read_saved_result` | `core.r1_bounds.UNAUTHORISED_CALL_SITES` |

The reason is the same as for the Iteration 19 CPU smoke: this service is a separate
deployment that is not part of the authorised evidence-regeneration trace, so the R1
gate refuses it at the call boundary, and the service is only reachable through the
driver, which refuses the live invocation without a separate maintainer approval. The
refusal registry is a **deny-list**; adding to it strengthens the fail-closed posture
and does not change the dispatch envelope of the R1 plan (the envelope does not read
this registry).

---

## 11. How the GPU path is attached afterwards

The GPU path is **not** part of this workstream, and the CPU service is the
prerequisite for it rather than a substitute for it. The order is the one of the
repository's own plan:

1. **The prefetch step (R2p)** writes `model_cache_manifest.json` into the model cache
   and pins the revision. The manifest is still absent — the CPU service does not
   need it, the GPU class does: `ProductionAuditAgent.load_model` fails closed without
   it.
2. **The approval.** The repository pins **no** approval key
   (`core/r1_approval.PINNED_PUBLIC_KEY is None`), so the R1 dispatch gate refuses
   every provider dispatch. The rate card is a proposal, not an approval. Both have to
   be settled by the maintainer — and the assignment of this workstream explicitly
   does not authorise them.
3. **The deployment of the GPU application.** `modal deploy modal_app.py --profile
   neubeginner` with the bounds of `core/r1_bounds.GPU_PROFILE` (H100, 1200 s). The
   image of that application is the same sandbox image extended by the GPU stack
   (`modal_app.py:57`), so the toolchain of the EVM verification is identical to the
   one that is proven here.
4. **The dispatch.** Only then does the pipeline run
   `static analysis → hypothesis → exploit synthesis (H100) → EVM verification (CPU,
   the code proven here) → independent replay → trajectory`. The CPU stages of that
   pipeline are exactly the stages this workstream has proven in a real Modal
   container: the only missing part is the H100 synthesis.
5. **The billing question.** The GPU path is the first step of this project that
   costs real money. The estimation is the job of
   `benchmarks/r1_estimator.py` and of the rate card — and the decision to spend is
   the maintainer's.

**Is the project ready for the H100 step?** The CPU process is real, deployed and
verified end to end: a Solidity contract goes in, Slither analyses it, the hypothesis
manager derives the vulnerability, the repository's immutable harness judges it in a
real Foundry EVM, the result is replayed in a fresh EVM and stored, and the artifact is
read back by another container. The blocks that remain are **not** in the CPU path:
they are the approval of the maintainer (approval key, rate card) and the manifest of
the prefetch step. Those are decisions of the maintainer, and this workstream does
not take them.
