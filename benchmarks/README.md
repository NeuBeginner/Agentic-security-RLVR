# Aegis-RLVR Multi-Baseline Empirical Benchmark

## 1. Overview & Architecture

The Aegis-RLVR benchmark framework provides an empirical evaluation across 5 distinct smart contract vulnerability detection and exploit verification paradigms:

1. **Baseline 1 — Static Analysis Only (`baseline_1`):** Slither AST and taint analysis execution on target contracts with full project context and remappings.
2. **Baseline 2 — LLM Auditor Only (`baseline_2`):** Zero-shot auditor LLM producing structured findings without exploit generation or verification.
3. **Baseline 3 — LLM Auditor + Unverified PoC (`baseline_3`):** LLM synthesized exploit code with dynamic candidate sizing; verification is strictly 0 (`verified_breaches == 0`).
4. **Baseline 4 — LLM + Naive Foundry (`baseline_4`):** LLM exploit synthesis executed in standard Foundry, considering a finding verified if returncode == 0 or text markers appear in logs (no anti-spoofing or hardened oracle).
5. **Baseline 5 — Full Aegis-RLVR (`baseline_5`):** Complete hypothesis-driven RLVR pipeline: `HypothesisManager` -> isolated sandbox execution with repository-owned trusted harness -> EVM State Oracle event/topic validation -> independent replay verification in an ephemeral container.

---

## 2. Core Security & Scientific Guarantees

- **Zero Ground-Truth Leakage:**
  Baseline adapters receive only public `TargetSpecification` objects. Fields containing `is_vulnerable`, `vulnerable_functions`, or `ground_truth_invariant` are strictly sequestered in `GroundTruth` and only accessible post-execution by `evaluate_baseline_run` to compute confusion matrices.
- **Fail-Closed Availability & Completeness Reporting:**
  If an external tool (`slither`, `forge`) or API credential is missing, or if any target fails during execution, the baseline is marked `UNAVAILABLE`, `FAILED`, or `INCOMPLETE`. The evaluator sets `precision`, `recall`, `f1_score`, `FPR`, `FNR`, `ESR`, `VFR`, `RRR` to `None`. **Failed or missing runs are NEVER treated as negative findings (`detected=False`), and fabricating fake 0% or 100% metrics on unexecuted runs is strictly prohibited.**
- **Slither Strict Returncode Enforcement:**
  `SlitherBaselineAdapter` requires `returncode == 0` before interpreting output. Any non-zero exit code (even if partial JSON was emitted) is classified as `FAILED`, never `SUCCESS`. Full stdout, stderr, SHA-256 hashes, command, and compiler remappings context are recorded.
- **Naive Foundry Signal Separation:**
  `LLMNaiveFoundryBaselineAdapter` parses structured Forge JSON and records a passing test as `naive_signal: True` / `detected: True`, but strictly maintains `verified_breaches == 0` and `replayed_breaches == 0`. Exit code 0 without executed tests or compilation errors are classified as unverified / failed.
- **Run-Level Reproducibility Manifest (`reproducibility_manifest.json`):**
  Every benchmark run records an immutable, machine-readable reproducibility manifest capturing:
  * Git commit SHA, branch, and clean/dirty working tree status;
  * Environment metadata: Python, Slither, Forge, Solc, and Modal versions and authentication state;
  * Benchmark dataset version, dataset file SHA-256 hash, and target IDs;
  * Per-adapter exact execution commands, timeout limits, durations, and config hashes;
  * Provenance for all generated artifact files with byte size and cryptographic SHA-256 hash;
  * Strictly repository-relative portable paths (no machine-local developer paths).
- **Explicit Provider Routing:**
  LLM baselines require explicit provider configuration (`--provider gemini` or `--provider openai`). Credential verification checks only the requested provider, avoiding mismatched provider crashes.
- **Unmeasured Cost Integrity:**
  Unless actual token usage and a versioned pricing schedule are provided, `cost_usd` is stored as `null` (`None`). Hardcoded constant dollar amounts are strictly excluded from empirical reports.
- **Dynamic Candidate Sizing:**
  Exploit candidate counts are extracted from real generator outputs, never hardcoded constants.
- **Production Allowlist Isolation:**
  Baseline 5 enforces the repository trusted harness allowlist (`Vault` -> `VaultTrustedHarness`, `ERC4626Vault` -> `ERC4626TrustedHarness`). Targets outside the allowlist receive `status = UNAVAILABLE` with explicit boundary reason.

---

## 3. Execution Commands

### Fast Smoke Mode (CI Plumbing)
Executes deterministic synthetic fixtures to validate pipeline plumbing. Every artifact is explicitly tagged with `is_synthetic_smoke: True`.
```bash
python benchmarks/benchmark_runner.py --mode smoke
```

### Real Empirical Mode (Live Tools & Credentials)
Executes live toolchains against the 16 target benchmark dataset (12 vulnerability classes + 4 synthetic safe controls).
```bash
python benchmarks/benchmark_runner.py --mode real --model-id gemini-1.5-pro --provider gemini
```

### With OpenAI Provider
```bash
python benchmarks/benchmark_runner.py --mode real --model-id gpt-4o --provider openai
```

### Filter Specific Baselines
```bash
python benchmarks/benchmark_runner.py --mode real --baselines baseline_1 baseline_5
```

---

## 4. Environment Requirements for Live Execution

To execute live experiments for each baseline, the host environment must supply:

| Baseline | Required Executable | Required Credentials | Allowlist Requirement |
|---|---|---|---|
| **Baseline 1** | `slither` (Python 3.10+) | None | None |
| **Baseline 2** | Python | `GEMINI_API_KEY`/`GOOGLE_API_KEY` (Gemini) or `OPENAI_API_KEY` (OpenAI) | None |
| **Baseline 3** | Python | `GEMINI_API_KEY`/`GOOGLE_API_KEY` (Gemini) or `OPENAI_API_KEY` (OpenAI) | None |
| **Baseline 4** | `forge` (Foundry) | `GEMINI_API_KEY`/`GOOGLE_API_KEY` (Gemini) or `OPENAI_API_KEY` (OpenAI) | None |
| **Baseline 5** | `forge` (local) or Modal (`~/.modal.toml` / `MODAL_TOKEN_ID`) | `GEMINI_API_KEY`/`GOOGLE_API_KEY` (Gemini) or `OPENAI_API_KEY` (OpenAI) | Trusted harness allowlist (`Vault`, `ERC4626Vault`) |

---

## 5. Machine-Readable Artifacts

When executing with `save_results=True`, execution records are written to:

```
benchmarks/
├── benchmark_results.json               # Main benchmark summary report (gitignored)
└── artifacts/                           # Gitignored run artifacts directory
    ├── latest_summary.json              # Symlink/copy of the most recent summary
    └── run_<timestamp>_<git_sha>/       # Unique run directory
        ├── summary.json                 # Run metadata and evaluation metrics
        ├── baseline_1/                  # Per-target JSON records for Baseline 1
        │   ├── REENT-01.json
        │   ├── ERC4626-01.json
        │   └── ...
        ├── baseline_2/
        ├── baseline_3/
        ├── baseline_4/
        └── baseline_5/
```

### Artifact Schema (`TargetExecutionArtifact`)
```json
{
  "baseline_id": "baseline_1",
  "target_id": "REENT-01",
  "target_name": "Vault",
  "status": "SUCCESS",
  "unavailable_reason": null,
  "detected": true,
  "candidates_generated": 0,
  "verified_breaches": 0,
  "replayed_breaches": 0,
  "duration_seconds": 1.45,
  "cost_usd": null,
  "tool_metadata": {
    "slither_version": "0.10.4",
    "exit_code": 0,
    "detectors_count": 3
  },
  "raw_output": {
    "findings": [...],
    "stdout": "...",
    "stderr": "..."
  },
  "logs": [...]
}
```
