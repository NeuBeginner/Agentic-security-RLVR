# Reconciled MiniMax + Antigravity integration

This branch keeps MiniMax's proof-based Solidity contract normalization and Reward
Specification 2.0.0 as the training/reward foundation, and retains the trusted harness
loading and bounded-process changes from the stacked security audit branch.

The selected Antigravity additions are:
- a findings-to-hypotheses manager with deduplication, severity ranking, and feedback
  lifecycle;
- the 12-class vulnerable-target dataset plus 4 safe controls;
- target-specific invariant evaluation from trusted raw EVM event evidence;
- Solidity fixtures and documentation for the benchmark and hypothesis pipeline.

The hypothesis manager normalizes findings supplied by an auditor or static-analysis
adapter. It is not itself an LLM auditor. The benchmark's smoke mode is synthetic;
real comparative mode stays disabled until executable adapters exist for each baseline.

Unknown target names, malformed event payloads, and untrusted log text fail closed.
The EVM State Oracle is invoked as a secondary diagnostic over raw Foundry evidence and its typed invariant results are persisted with verdicts/trajectories. The MiniMax immutable structured-harness verdict remains the sole authority for Reward Spec 2.0.0 scoring; an Oracle diagnostic alone can never award reward.

The benchmark Solidity harnesses are dataset fixtures, not production trusted-runner
allowlist entries. PR #4's runtime allowlist remains limited to Vault and ERC4626Vault;
new targets must pass a separate harness review and adversarial verification before
being promoted into the Modal image.

The Modal deployment and H100 performance path still require runtime testing and are
not asserted by this source-only integration.
