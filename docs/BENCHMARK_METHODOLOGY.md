# Benchmark methodology and evidence status

## Dataset

The benchmark dataset contains 12 vulnerable Solidity target classes and 4 safe controls.
Each target and harness is stored under `benchmarks/targets/solidity/`; the dataset
records the expected class and the repository-owned harness path.

## Modes

- `smoke` is a deterministic synthetic fixture used only to verify report shape,
  metric calculations, CI plumbing, and schema compatibility.
- `real` is intentionally disabled until every baseline has a separately implemented,
  executable adapter with recorded model, toolchain, commit, prompt, candidate, and
  replay provenance. Calling it raises `NotImplementedError`.

Smoke outputs must not be described as empirical results, model rankings, precision,
recall, exploit success, or reproducibility evidence. No ground-truth label is allowed
to create a candidate, verification, or replay result in real mode.

## Required real-experiment protocol

A future adapter must execute the declared baseline rather than substitute another
baseline's output; persist raw findings and generated candidates; run the same target
and toolchain for every baseline; classify positives only from trusted harness evidence;
and compute TP/FP/TN/FN only after adapter outputs are complete. Replay credit requires
a second independent execution. Missing adapter output is an infrastructure/unknown
result, never a negative finding or a safe pass.
