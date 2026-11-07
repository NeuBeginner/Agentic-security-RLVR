"""
core/reward_shaping.py

Reward Specification 2.0.0 - deterministic, evidence-scoped RLVR reward shaping.

THE CONTRACT
------------
The total reward is the sum of two disjoint parts::

    total = sum(component credits) + outcome penalty

A *component credit* is awarded at most once and only from exactly one evidence
class:

===================  ========  ==================================================
Component            Weight    Trusted evidence class
===================  ========  ==================================================
``generation``        0.05     static, deterministic format gate accepted the
                               candidate (no LLM opinion involved)
``compilation``       0.10     the trusted compiler (solc/forge) accepted it
``verification``      0.10     the candidate executed in the EVM and the exploit
                               call completed without reverting
``invariant``         0.25     the TRUSTED harness oracle confirmed the invariant
                               breach (state-based verdict, never log text)
``replay``            0.50     an INDEPENDENT fresh-EVM execution reproduced the
                               very same trusted verdict
===================  ========  ==================================================

The *outcome penalty* encodes the deficit of the failing stage and is always
<= 0. The penalty table is calibrated so that::

    sum(credits) + penalty == the legacy reward constant of the category

Therefore the observable reward ladder is unchanged (and the schema invariants
that pin ``EXPLOIT_CONFIRMED -> 1.0`` and
``INVARIANT_BREACH_UNREPLAYED -> 0.5`` remain valid), while the reward is now
fully attributable to individual pieces of evidence.

NO DOUBLE COUNTING
------------------
Every component belongs to one evidence class and is credited at most once:

* the ``invariant`` credit is derived ONLY from the trusted harness verdict of
  the current execution - never from a log marker, never from the replay;
* the ``replay`` credit requires the verdict of a SECOND, independent execution
  (its own fresh EVM), it is never a re-read of the first run;
* the first three credits are backed by three independent, non-overlapping
  facts (the source parsed, the compiler accepted it, the EVM ran it).

FAIL-CLOSED
-----------
An unknown or untrusted outcome never produces a positive reward for a
confirmed vulnerability. The reward is never more trustworthy than its evidence
source: if the trusted harness did not return a verdict, the breach is not
confirmed and no positive exploit reward is awarded.

REPRODUCIBILITY
---------------
``RewardBreakdown`` is a pure function of the evidence, carries the version of
the specification that produced it and exposes a stable ``fingerprint`` so a
stored trajectory can be re-checked against the recorded components.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.config import config
from core.schemas import ResultCategory


# Version of the reward specification that produced a given reward.
# Legacy trajectories (recorded before this specification existed) carry
# LEGACY_REWARD_SPEC_VERSION and are therefore never merged with 2.x
# trajectories inside a GRPO group.
REWARD_SPEC_VERSION: str = config.REWARD_SPEC_VERSION
LEGACY_REWARD_SPEC_VERSION: str = "1.0.0-legacy"


class RewardComponent(str, Enum):
    """The five evidence classes a reward can be composed of."""

    GENERATION = "generation"
    COMPILATION = "compilation"
    VERIFICATION = "verification"
    INVARIANT = "invariant"
    REPLAY = "replay"


COMPONENT_ORDER = (
    RewardComponent.GENERATION,
    RewardComponent.COMPILATION,
    RewardComponent.VERIFICATION,
    RewardComponent.INVARIANT,
    RewardComponent.REPLAY,
)

# The trusted source that must back each component credit.
COMPONENT_EVIDENCE: Dict[RewardComponent, str] = {
    RewardComponent.GENERATION: "static_format_gate",
    RewardComponent.COMPILATION: "trusted_compiler",
    RewardComponent.VERIFICATION: "evm_execution",
    RewardComponent.INVARIANT: "trusted_harness_verdict",
    RewardComponent.REPLAY: "independent_replay_verdict",
}


def _weights() -> Dict[RewardComponent, float]:
    return {
        RewardComponent.GENERATION: config.REWARD_COMPONENT_GENERATION,
        RewardComponent.COMPILATION: config.REWARD_COMPONENT_COMPILATION,
        RewardComponent.VERIFICATION: config.REWARD_COMPONENT_VERIFICATION,
        RewardComponent.INVARIANT: config.REWARD_COMPONENT_INVARIANT,
        RewardComponent.REPLAY: config.REWARD_COMPONENT_REPLAY,
    }


def _penalties() -> Dict[ResultCategory, float]:
    return {
        ResultCategory.GENERATION_FORMAT_ERROR: config.REWARD_PENALTY_FORMAT,
        ResultCategory.CHEATCODE_DETECTED: config.REWARD_PENALTY_CHEATCODE,
        ResultCategory.INFRA_ERROR: config.REWARD_PENALTY_INFRA,
        ResultCategory.COMPILATION_ERROR: config.REWARD_PENALTY_COMPILATION,
        ResultCategory.RUNTIME_REVERT: config.REWARD_PENALTY_REVERT,
        ResultCategory.SAFE_RUN: config.REWARD_PENALTY_SAFE_RUN,
        ResultCategory.INVARIANT_BREACH_UNREPLAYED: config.REWARD_PENALTY_BREACH,
        ResultCategory.EXPLOIT_CONFIRMED: config.REWARD_PENALTY_BREACH,
    }


@dataclass(frozen=True)
class RewardEvidence:
    """
    The proven facts a reward may be derived from.

    Every field must be backed by a trusted source; ``False`` always means
    "not proven" (fail-closed), never "probably fine".
    """

    format_valid: bool = False
    compiled: bool = False
    executed: bool = False
    invariant_confirmed: bool = False
    replay_confirmed: bool = False
    timed_out: bool = False


@dataclass(frozen=True)
class RewardBreakdown:
    """A fully attributable, reproducible reward computation."""

    spec_version: str
    category: str
    components: Dict[str, float]
    penalty: float
    total: float
    evidence: Dict[str, str] = field(default_factory=dict)

    # -- accessors ---------------------------------------------------------
    def component(self, name: RewardComponent) -> float:
        return float(self.components.get(name.value, 0.0))

    @property
    def credits(self) -> float:
        return round(sum(self.components.values()), 10)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "spec_version": self.spec_version,
            "category": self.category,
            "components": dict(self.components),
            "penalty": self.penalty,
            "total": self.total,
            "evidence": dict(self.evidence),
        }

    def fingerprint(self) -> str:
        """Stable digest of the computation, used to prove reproducibility."""
        canonical = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def describe(self) -> str:
        parts = [f"{name}={self.components[name]:+.2f}" for name in COMPONENT_ORDER]
        return (
            f"reward_spec={self.spec_version} total={self.total:+.2f} "
            f"penalty={self.penalty:+.2f} [" + ", ".join(parts) + "]"
        )


def compute_reward_breakdown(
    category: ResultCategory,
    evidence: RewardEvidence,
) -> RewardBreakdown:
    """
    Computes the reward breakdown for a single outcome.

    Pure and deterministic: the same (category, evidence) always yields the same
    components, penalty and total.
    """
    if not isinstance(category, ResultCategory):
        category = ResultCategory(str(category))

    weights = _weights()
    penalties = _penalties()

    components: Dict[str, float] = {c.value: 0.0 for c in COMPONENT_ORDER}
    evidence_sources: Dict[str, str] = {}

    # Nothing is proven when the candidate never reached the trusted pipeline:
    # a format error, a rejected (cheatcode) candidate or an infrastructure
    # failure all stop before any evidence could be collected.
    pipeline_reached = category not in (
        ResultCategory.GENERATION_FORMAT_ERROR,
        ResultCategory.CHEATCODE_DETECTED,
        ResultCategory.INFRA_ERROR,
    )

    if pipeline_reached:
        if evidence.format_valid:
            components[RewardComponent.GENERATION.value] = weights[RewardComponent.GENERATION]
            evidence_sources[RewardComponent.GENERATION.value] = COMPONENT_EVIDENCE[RewardComponent.GENERATION]
        if evidence.compiled:
            components[RewardComponent.COMPILATION.value] = weights[RewardComponent.COMPILATION]
            evidence_sources[RewardComponent.COMPILATION.value] = COMPONENT_EVIDENCE[RewardComponent.COMPILATION]
        if evidence.executed:
            components[RewardComponent.VERIFICATION.value] = weights[RewardComponent.VERIFICATION]
            evidence_sources[RewardComponent.VERIFICATION.value] = COMPONENT_EVIDENCE[RewardComponent.VERIFICATION]
        if evidence.invariant_confirmed:
            components[RewardComponent.INVARIANT.value] = weights[RewardComponent.INVARIANT]
            evidence_sources[RewardComponent.INVARIANT.value] = COMPONENT_EVIDENCE[RewardComponent.INVARIANT]
        if evidence.replay_confirmed:
            components[RewardComponent.REPLAY.value] = weights[RewardComponent.REPLAY]
            evidence_sources[RewardComponent.REPLAY.value] = COMPONENT_EVIDENCE[RewardComponent.REPLAY]

    penalty = penalties.get(category, 0.0)
    if evidence.timed_out:
        penalty = config.REWARD_PENALTY_TIMEOUT

    credits = round(sum(components.values()), 10)
    total = round(credits + penalty, 10)

    return RewardBreakdown(
        spec_version=REWARD_SPEC_VERSION,
        category=category.value,
        components=components,
        penalty=round(penalty, 10),
        total=total,
        evidence=evidence_sources,
    )


def expected_total_for_category(category: ResultCategory, timed_out: bool = False) -> float:
    """The reward the legacy ladder assigns to a category (regression anchor)."""
    if category == ResultCategory.GENERATION_FORMAT_ERROR:
        return config.REWARD_FORMAT_ERROR
    if category == ResultCategory.CHEATCODE_DETECTED:
        return config.REWARD_CHEATCODE_PENALTY
    if category == ResultCategory.INFRA_ERROR:
        return config.REWARD_INFRA_ERROR
    if category == ResultCategory.COMPILATION_ERROR:
        return config.REWARD_COMPILATION_FAIL
    if category == ResultCategory.RUNTIME_REVERT:
        return config.REWARD_TIMEOUT if timed_out else config.REWARD_RUNTIME_REVERT
    if category == ResultCategory.SAFE_RUN:
        return config.REWARD_SAFE_RUN
    if category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
        return config.REWARD_BREACH_NO_REPLAY
    if category == ResultCategory.EXPLOIT_CONFIRMED:
        return config.REWARD_INVARIANT_BREACH
    return 0.0


def verify_breakdown_consistency(breakdown: RewardBreakdown) -> bool:
    """
    Re-derives the total from the recorded components.

    Used to prove that a stored trajectory's reward is still reproducible from
    its own recorded components (no hidden re-weighting).
    """
    credits = round(sum(breakdown.components.values()), 10)
    return round(credits + breakdown.penalty, 10) == round(breakdown.total, 10)


def breakdown_from_components(
    spec_version: str,
    category: str,
    components: Dict[str, float],
    penalty: float,
    total: float,
) -> RewardBreakdown:
    """Rebuilds a breakdown from persisted fields (round-trip helper)."""
    return RewardBreakdown(
        spec_version=spec_version or LEGACY_REWARD_SPEC_VERSION,
        category=category,
        components={k: float(v) for k, v in (components or {}).items()},
        penalty=float(penalty),
        total=float(total),
        evidence={},
    )
