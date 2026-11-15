# Aegis-RLVR 2.0: Autonomous Multi-Agent Web3 Security Framework

[![Modal Serverless](https://img.shields.io/badge/Powered%20By-Modal%20Cloud-blue?logo=python)](https://modal.com)
[![EVM Engine](https://img.shields.io/badge/EVM%20Engine-Foundry%20%7C%20Anvil-black)](https://getfoundry.sh)
[![Static Analysis](https://img.shields.io/badge/Static%20Analysis-Slither-yellow)](https://github.com/crytic/slither)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Research: RLVR](https://img.shields.io/badge/Research-RLVR%20%26%20GRPO%20Buffer-orange)](#research-overview)

**Aegis-RLVR 2.0** is an autonomous smart contract security auditing, exploit synthesis, and reinforcement learning framework designed to reduce false positives in Web3 audits. It couples multi-agent frontier reasoning with **deterministic EVM invariant verification**, strict cheatcode barriers, and **Reinforcement Learning from Verifiable Rewards (RLVR)** data collection for GRPO policy training.

---

## 🔬 Architecture & Methodology (Aegis-RLVR 2.0)

Aegis-RLVR 2.0 addresses the critical gap between static LLM auditors and executable proof-of-concept verification:

```mermaid
flowchart TD
    TargetContract["Solidity Target Contract (.sol)"] --> Slither["Phase 1: Slither AST Static Analysis"]
    
    subgraph MultiAgentReasoning["Phase 2: Specialized Reasoning Layer"]
        Slither --> Auditor["Security Auditor: Qwen3-Coder-30B-A3B-Audit<br/>(Outputs structured JSON findings)"]
        Slither --> Generator["Exploit Synthesizer: Gemini 2.5 Flash / Coder<br/>(Outputs unprivileged ExploitModule)"]
    end
    
    subgraph ModalExecution["Phase 3: Parallel Ephemeral Foundry Sandboxes (.map)"]
        Generator --> Box1["Worker #1 (t=0.20)"]
        Generator --> Box2["Worker #2 (t=0.40)"]
        Generator --> BoxN["Worker #N (t=0.70)"]
        
        Box1 --> Forge1["forge test --offline --json -vvvv"]
        Box2 --> Forge2["forge test --offline --json -vvvv"]
        BoxN --> ForgeN["forge test --offline --json -vvvv"]
    end
    
    subgraph VerificationConsensus["Phase 4 & 5: Multi-Factor Verification & Replay"]
        Forge1 --> Evaluator["Multi-Factor Evaluator<br/>(Anti-Cheatcode Guard + State Delta)"]
        Forge2 --> Evaluator
        ForgeN --> Evaluator
        
        Evaluator -->|Breached| Replay["Phase 5: Independent Replay Verification<br/>(Clean second EVM worker checks reproducibility)"]
        Evaluator -->|Failed| Refine["Phase 4: Closed-Loop Multi-Round Refinement"]
        Refine -.-> Generator
    end
    
    Replay -->|Confirmed Replay| PoC["Verified 0-Day PoC (Reward: +1.00)"]
    Replay --> Trajectory["Phase 6: RLVR Trajectory Buffer (Modal Volume)<br/>(Ready for GRPO Policy Fine-Tuning)"]
```

---

## 📊 Benchmark Evidence Status

The repository contains Solidity benchmark targets and trusted Foundry harnesses, but this branch does **not** publish a completed five-baseline empirical comparison. Precision, recall, runtime, cost, and replay-rate figures must only be reported after the corresponding baselines have actually run against the dataset with retained execution evidence.

The trusted verification path uses the structured result of the repository-owned harness suite. Candidate-controlled log markers are diagnostic output only and never establish a breach.

---

## ⚡ Specialized Division of Labor

1. **Static Analysis Layer (Slither):** Runs on ephemeral Modal CPU workers to extract AST detector signals (`reentrancy-eth`, `divide-before-multiply`, `uninitialized-state`) to prime downstream LLMs with hard architectural facts.
2. **Security Auditor (Qwen3-Coder-30B-A3B-Audit on Modal H100):** Operates in its native domain-trained role—analyzing Solidity source code to output structured JSON finding arrays without hallucinations.
3. **Primary Exploit Synthesizer (Gemini 2.5 Flash / Coder Models):** Generates clean, unprivileged `ExploitModule` contracts targeting formal security invariants.
4. **Cheatcode & Sandbox Barrier:** Pre-execution AST checks block any attempt to use privileged Foundry cheatcodes (`vm.deal`, `vm.prank`, `vm.store`, `Test.sol`), ensuring the exploit acts strictly as an external on-chain entity. The barrier also covers **verification-channel hijacks**: importing the Foundry test framework or the console library, or declaring a public `test*` entrypoint, is rejected as a security violation.
5. **Multi-Candidate Parallel Execution (Modal `.map`):** Dispatches $K$ parallel candidate hypotheses simultaneously across ephemeral Linux Foundry containers.
6. **Independent Replay Verification:** Every candidate that passes the trusted harness can be re-executed in a fresh EVM worker; replay is an empirical reproducibility check, not a mathematical guarantee.
7. **RLVR Ground-Truth Trajectory Buffer:** Commits `(prompt, hypothesis, exploit, trace, reward)` pairs into persistent Modal Volume (`/vol/models/trajectories`) for offline **GRPO (Group Relative Policy Optimization)** fine-tuning.

---

## 📊 RLVR Reward Shaping (Specification 2.0.0)

| Execution Outcome | Ground-Truth Reward | Impact on Policy / Action |
| :--- | :---: | :--- |
| **Verified Exploit + Confirmed Replay** | **`+1.00`** | Deterministic 0-day exploit confirmed |
| **Breached Invariant (Flaky / No Replay)** | **`+0.50`** | Partial success, non-deterministic |
| **Infrastructure / Harness Error** | **`0.00`** | Not the model's fault — excluded from GRPO groups |
| **Clean Execution (Invariant Intact)** | **`-0.10`** | Safe run, target contract defended |
| **EVM Runtime Revert** | **`-0.25`** | Syntactically valid, reverted during execution |
| **Execution Timeout (Out-of-Gas)** | **`-0.30`** | Execution timed out (>60s) |
| **Malformed Output / Interface Mismatch** | **`-0.35`** | Cheap mechanical fix (name/shape), strictly closer to success than a compile failure |
| **Solidity Compiler Error (`solc`)** | **`-0.50`** | Compilation / syntax failure — requires real semantic repair |
| **Cheatcode Tampering Attempt (`vm.*`)** | **`-1.00`** | Immediate disqualification & penalty |

> Format failures and compilation failures are deliberately **not** equal: the interface
> mismatch is mechanically cheap to repair, while a compile error means the exploit
> logic itself needs rework. Equal rewards would erase that gradient.

### Reward components — every reward is fully attributable

The total is decomposed into five **evidence-scoped components** plus one outcome
penalty (`core/reward_shaping.py`):

```
total = sum(component credits) + outcome penalty
```

| Component | Weight | Trusted evidence class |
| :--- | :---: | :--- |
| `generation` | `+0.05` | the static, deterministic format gate accepted the candidate |
| `compilation` | `+0.10` | the trusted compiler (`solc`/`forge`) accepted it |
| `verification` | `+0.10` | the candidate executed in the EVM without reverting |
| `invariant` | `+0.25` | the **trusted harness oracle** confirmed the invariant breach |
| `replay` | `+0.50` | an **independent** fresh-EVM run reproduced the same verdict |

The penalty table is calibrated so that the totals above stay **byte-compatible** with
the legacy ladder — the observable reward does not change, but every point is now
traceable to exactly one piece of evidence.

**No double counting.** Each component belongs to exactly one evidence class and is
credited at most once: the `invariant` credit comes from the trusted verdict of the
current execution, the `replay` credit only from the verdict of a **second,
independent** execution.

**Fail-closed.** An unknown or untrusted outcome never produces a positive reward for a
confirmed vulnerability.

### Trusted evidence — the reward is never more trustworthy than its source

The breach verdict comes from the **structured test result of the immutable,
repository-owned harness suite** (`test/<Target>Harness.t.sol`), never from the logs:

```
status == "Success"                          -> BREACH      (harness returned normally)
status == "Failure" + "EXPLOIT_FAILED: ..."  -> NO_BREACH   (exploit ran, invariant held)
status == "Failure" + other reason           -> EXEC_REVERT (the exploit call reverted)
no trusted suite / no result                 -> UNKNOWN     (fail-closed)
```

The previous implementation grepped the logs for `[INVARIANT_BREACHED`. That marker is
printed by the **model-controlled exploit itself**, so it was never evidence. The marker
is now kept for diagnostics only. In addition, the candidate can no longer reach the
verification channel at all: importing the Foundry test framework, importing the console
library, or declaring a public `test*` entrypoint are rejected as security violations
before Foundry is even invoked.

The harness contract the verdict relies on is *asserted*, not assumed —
`tests/test_harness_contract.py` fails if a harness ever stops returning normally on
the breach path.

### Reward specification version in the provenance

Every verdict and every trajectory carries `reward_spec_version` plus the full
`reward_components` attribution. GRPO groups include the specification version in their
identity, so **trajectories scored by incompatible reward specifications are never
merged into one advantage group**. `verify_reward_reproducibility()` re-derives a stored
reward from its stored components (fail-closed when the attribution is missing).

---

## 🧩 Mechanical Contract-Name Normalization

The verification harness imports the candidate as `contract ExploitModule`. Models
frequently emit a descriptive name instead (`VaultAttack`, `ReentrancyDrain`, ...),
which used to reject the candidate **before** Foundry ever ran — so it could never
produce a verifiable reward, and the group received a uniform penalty with zero
learning signal.

`normalize_exploit_contract_name()` now repairs exactly that case before validation.
The repair is **proof-based and fail-closed**:

- Renames the declaration and **only proven references** to it (self-references, type
  casts, `new`, inheritance, static member access).
- Declines the repair when the name is ambiguous: a second top-level contract, a
  same-named `interface` / `library` / `struct` / `event` / `function` / state variable /
  parameter, an import binding the same name, or an inner-scope shadow. The file then
  stays **byte-identical** — an unrelated declaration is never rewritten.
- Rewrites only identifier tokens — string literals and comments are never altered.
- Never renames symbols inside `import` statements, never renames member names
  (`x.VaultAttack`).
- Is idempotent: running it on normalized code is a no-op.
- The strict validator stays strict and is still used directly for diagnostics.
- Every repair is recorded on the payload (`contract_name_normalized`,
  `original_contract_name`, `contract_normalization_reason`) so it remains auditable,
  while `full_completion_text` keeps the model's **original** output so token lineage
  and the trained completion stay byte-identical.

The normalized contracts are compiled with a real `solc 0.8.20` in the test suite
(`tests/test_contract_normalization_v2.py`).

Set `ENABLE_CONTRACT_NAME_NORMALIZATION = False` in `core/config.py` to restore the
previous behaviour.

---

## 📁 Repository Structure

```
Agentic-security-RLVR/
├── core/
│   ├── config.py              # Modal cloud settings, Gemini API, RLVR reward shaping
│   ├── schemas.py             # Pydantic schemas (Target, Hypothesis, Result, Trajectory)
│   ├── evidence.py            # Trusted evidence contract (harness verdicts, anti-forgery rules)
│   ├── evm_oracle.py          # Trusted EVM State Oracle (ABI OracleSnapshot + SecurityInvariantBreached)
│   ├── invariants.py          # Formal state invariants across all 12 vulnerable classes
│   ├── reward_shaping.py      # Reward Specification 2.0.0 (components, penalties, versions)
│   ├── r1_bounds.py           # R1 pre-dispatch bounds, pinned model/toolchain & GPU ceilings
│   ├── r1_approval.py         # Cryptographic approval artifact verification for R1 dispatch
│   ├── llm_generator.py       # Target-agnostic prompts, Solidity lexer, contract-name normalization
│   ├── hypothesis_manager.py  # Findings-to-hypotheses deduplication & lifecycle management
│   ├── evaluator.py           # Multi-factor invariant evaluation & GRPO trajectory packager
│   ├── grpo_trainer.py        # GRPO primitives, advantage computation, group spread diagnostics, LoRA setup
│   ├── candidate_lifecycle.py # Candidate ranking, replay selection, finalized trajectory construction
│   ├── ab_evaluator.py        # Audit-grade A/B metric recomputation from raw candidate records
│   └── dropbox_bridge.py      # Supervisor<->agent file bridge (Dropbox), env-driven workspace paths
├── sandbox/
│   ├── runner.py              # Foundry runner (16 allowlisted harnesses), Slither, cheatcode barrier, replay
│   └── prebake_solc.py        # Solc compiler prebaking script with SHA256 integrity validation
├── benchmarks/
│   ├── benchmark_dataset.json # 16-target dataset (12 vulnerable classes + 4 safe controls)
│   ├── benchmark_runner.py    # 5-baseline benchmark runner (--mode smoke / --mode real)
│   ├── adapters.py            # Baseline 1..5 adapters with stage-by-stage provenance capture
│   ├── evaluator.py           # Confusion matrix & derived metrics evaluator
│   ├── evidence_integrity.py  # Cryptographic evidence & provenance integrity validators
│   ├── r1_dispatch.py         # Fail-closed DispatchGate enforcing r1_bounds + r1_approval
│   ├── r1_estimator.py        # Deterministic R1 Modal cost & call-volume estimator
│   └── targets/solidity/      # 16 Solidity targets paired with immutable *Harness.t.sol suites
├── tests/                     # 800+ unit & integration tests (including 16-target real Foundry E2E)
├── modal_app.py               # Aegis-RLVR 2.0 distributed orchestrator on Modal Cloud
├── requirements.txt
└── README.md
```

---

## 🧪 Reproducible Local Verification & Evidence Integrity

### 1. Run the Complete Test Suite
```bash
python -m pytest -q
```

### 2. Verify All 16 Targets (12 Vulnerable + 4 Safe Controls) Against Real Local Foundry
Executes every vulnerable target exploit and safe-control probe inside isolated ephemeral Foundry sandboxes (`forge test --offline --json -vvvv` with `forge 1.9.0` and `solc 0.8.20`), verifies independent replay reproducibility, validates ABI-encoded `OracleSnapshot(string,string,string)` decoding, and runs closed-loop RLVR + GRPO advantage/loss computation:
```bash
python -m pytest tests/test_real_foundry_e2e_all_targets.py -v
python tests/test_real_foundry_e2e_all_targets.py
```
Writes the deterministic verification report to `benchmarks/evidence/real_foundry_16_target_verification.json`.

### 3. Run Evidence Integrity & R1 Pre-Dispatch Validators
```bash
python -m benchmarks.r1_estimator --scenario benchmarks/evidence/r1_cost_scenario.json --provisional
python -m pytest tests/test_r1_bounds_contract.py tests/test_r1_dispatch_boundary.py tests/test_r1_estimator.py -v
python -m pytest tests/test_iteration19_evidence_integrity.py tests/test_iteration20_evidence_integrity.py tests/test_iteration21_evidence_integrity.py tests/test_iteration22_evidence_integrity.py tests/test_iteration23_evidence_integrity.py -v
```

---

## 🚀 Running Aegis-RLVR 2.0 on Modal

### Prerequisites
```bash
pip install modal google-genai
modal profile activate neubeginner
```

### 1. Gemini Flash Mode (Frontier API Reasoning + Modal Foundry Sandboxes)
```bash
modal run modal_app.py --generator gemini --target-name ERC4626Vault --num-candidates 3
```

### 2. Production Mode (H100 + 30B Qtum Security Model + Slither)
```bash
modal run modal_app.py --mode audit --target-name Vault --num-candidates 5
```

### 3. Dev / CI Smoke-Test Mode (T4 GPU + Ephemeral EVM Sandboxes)
```bash
modal run modal_app.py --mode dev --target-name ERC4626Vault --num-candidates 3
```

### 4. Read-Only Trajectory Audit (no training, no checkpoint writes)
```bash
modal run modal_app.py --mode audit-trajectories
# or on Windows: audit_trajectories.bat
```
Reports the partition/provenance breakdown of the persistent trajectory volume and
the exact count of records eligible for GRPO. The audit and the production loader
share one eligibility evaluator, so their numbers cannot drift apart.

### 5. Diagnostic Forward Pass (loss only, no optimizer step)
```bash
modal run modal_app.py --mode diagnostic-forward
```

### 6. Harness Control Tests (real Foundry execution)
```bash
modal run modal_app.py --mode test-harness
```

> GRPO training (`--mode train`) is blocked by an explicit fail-closed gate while the
> AI Supervisor's acceptance criteria are open.

---

## 🔍 GRPO Signal Diagnostics

`diagnose_group_spread()` reports whether the accumulated trajectories can actually
teach the model anything:

```python
from core.grpo_trainer import diagnose_group_spread, group_rollouts_by_prompt

spread = diagnose_group_spread(group_rollouts_by_prompt(trajectories))
# {'total_groups': 12, 'degenerate_groups': 12, 'informative_groups': 0, ...}
```

A group whose rollouts all received the same reward yields **all-zero advantages**
and therefore exactly zero gradient. `train_grpo_epochs()` now fails closed when
every group is degenerate, instead of silently reporting a meaningless loss.

Group identity also carries the **reward specification version** (`reward_spec_version`),
so trajectories scored by incompatible specifications never share one advantage group:

```python
from core.grpo_trainer import verify_reward_reproducibility

verify_reward_reproducibility(trajectory)
# {'reward_spec_version': '2.0.0', 'reproducible': True, 'recomputed_total': 1.0, ...}
```

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
