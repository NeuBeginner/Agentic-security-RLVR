"""
core/patch_verifier.py
======================

Blue-team RLVR patch verification & deterministic reward shaping (Dual-Loop:
Exploit -> Verified Patch).

5-stage fail-closed verification pipeline:
1. Static & Anti-Cheatcode Gate (`contract <TargetName>`, no `vm.`/`forge-std`/`selfdestruct`, non-noop diff)
2. Red Precondition Sanity Check (Red `ExploitModule` must breach `original_source`)
3. Functional Regression Gate (`*Functional.t.sol` Trusted Blue Oracle)
4. Security Gate (`*Harness.t.sol` + `ExploitModule.sol`: `exploit_blocked == True`)
5. Independent Fresh-EVM Replay (`reproducibility_confirmed == True`)
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

from core.schemas import (
    AttackHypothesis,
    ExecutionResult,
    ExploitPayload,
    ResultCategory,
    TargetProgram,
)
from sandbox.patch_runner import PatchSandboxResult, run_patch_in_sandbox
from sandbox.runner import run_payload_in_sandbox

BLUE_REWARD_SPEC_VERSION = "1.0.0"

_CHEATCODE_PATTERNS = (
    re.compile(r"\bvm\s*\."),
    re.compile(r"forge-std/"),
    re.compile(r"\bselfdestruct\s*\("),
)


class BluePatchCategory(str, Enum):
    PATCH_VERIFIED = "PATCH_VERIFIED"
    PATCH_VERIFIED_NO_REPLAY = "PATCH_VERIFIED_NO_REPLAY"
    EXPLOIT_STILL_SUCCEEDS = "EXPLOIT_STILL_SUCCEEDS"
    FUNCTIONAL_REGRESSION = "FUNCTIONAL_REGRESSION"
    PATCH_FORMAT_ERROR = "PATCH_FORMAT_ERROR"
    PATCH_COMPILATION_ERROR = "PATCH_COMPILATION_ERROR"
    PATCH_CHEATCODE_VIOLATION = "PATCH_CHEATCODE_VIOLATION"
    PATCH_INFRA_ERROR = "PATCH_INFRA_ERROR"


BLUE_REWARD_TABLE = {
    BluePatchCategory.PATCH_VERIFIED: 1.00,
    BluePatchCategory.PATCH_VERIFIED_NO_REPLAY: 0.50,
    BluePatchCategory.EXPLOIT_STILL_SUCCEEDS: -0.10,
    BluePatchCategory.FUNCTIONAL_REGRESSION: -0.25,
    BluePatchCategory.PATCH_FORMAT_ERROR: -0.35,
    BluePatchCategory.PATCH_COMPILATION_ERROR: -0.50,
    BluePatchCategory.PATCH_CHEATCODE_VIOLATION: -1.00,
    BluePatchCategory.PATCH_INFRA_ERROR: 0.00,
}


class PatchCandidate(BaseModel):
    target_name: str
    patched_source: str
    patch_rationale: str = ""
    candidate_id: str = ""


class BlueRewardBreakdown(BaseModel):
    category: BluePatchCategory
    reward_score: float
    spec_version: str = BLUE_REWARD_SPEC_VERSION
    compiled: bool = False
    functional_pass: bool = False
    exploit_blocked: bool = False
    reproducibility_confirmed: bool = False
    trainable: bool = True


class PatchVerificationResult(BaseModel):
    target_name: str
    category: BluePatchCategory
    reward_score: float
    compiled: bool = False
    functional_pass: bool = False
    exploit_blocked: bool = False
    reproducibility_confirmed: bool = False
    red_precondition_confirmed: bool = False
    reason: str = ""
    reward_breakdown: BlueRewardBreakdown


class DualLoopRecord(BaseModel):
    target_name: str
    red_exploit_code: str
    red_confirmed: bool
    patch_result: PatchVerificationResult


RedVerifierFn = Callable[[TargetProgram, ExploitPayload], ExecutionResult]
PatchRunnerFn = Callable[[str, str, str], PatchSandboxResult]


def _normalized_sha256(source: str) -> str:
    collapsed = re.sub(r"\s+", " ", (source or "").strip())
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def _detect_cheatcode_violation(patched_source: str) -> Optional[str]:
    for pat in _CHEATCODE_PATTERNS:
        m = pat.search(patched_source)
        if m:
            return f"Forbidden cheatcode or test-only construct detected: {m.group(0)!r}"
    return None


def _has_target_contract_declaration(target_name: str, patched_source: str) -> bool:
    return bool(re.search(rf"\bcontract\s+{re.escape(target_name)}\b", patched_source))


def compute_blue_reward_breakdown(
    category: BluePatchCategory,
    *,
    compiled: bool = False,
    functional_pass: bool = False,
    exploit_blocked: bool = False,
    reproducibility_confirmed: bool = False,
) -> BlueRewardBreakdown:
    """Compute deterministic Blue RLVR reward from verified patch outcome."""
    return BlueRewardBreakdown(
        category=category,
        reward_score=BLUE_REWARD_TABLE[category],
        spec_version=BLUE_REWARD_SPEC_VERSION,
        compiled=compiled,
        functional_pass=functional_pass,
        exploit_blocked=exploit_blocked,
        reproducibility_confirmed=reproducibility_confirmed,
        trainable=(category != BluePatchCategory.PATCH_INFRA_ERROR),
    )


def _make_result(
    target_name: str,
    category: BluePatchCategory,
    *,
    compiled: bool = False,
    functional_pass: bool = False,
    exploit_blocked: bool = False,
    reproducibility_confirmed: bool = False,
    red_precondition_confirmed: bool = False,
    reason: str = "",
) -> PatchVerificationResult:
    breakdown = compute_blue_reward_breakdown(
        category,
        compiled=compiled,
        functional_pass=functional_pass,
        exploit_blocked=exploit_blocked,
        reproducibility_confirmed=reproducibility_confirmed,
    )
    return PatchVerificationResult(
        target_name=target_name,
        category=category,
        reward_score=breakdown.reward_score,
        compiled=compiled,
        functional_pass=functional_pass,
        exploit_blocked=exploit_blocked,
        reproducibility_confirmed=reproducibility_confirmed,
        red_precondition_confirmed=red_precondition_confirmed,
        reason=reason,
        reward_breakdown=breakdown,
    )


def verify_patch(
    *,
    target_name: str,
    original_source: str,
    candidate: PatchCandidate,
    exploit_code: str,
    red_precondition_verified: bool = False,
    red_verifier: Optional[RedVerifierFn] = None,
    patch_runner: Optional[PatchRunnerFn] = None,
) -> PatchVerificationResult:
    """
    Execute the 5-stage fail-closed Blue patch verification pipeline.
    """
    patched_source = (candidate.patched_source or "").strip()

    # Stage 1: Static & Anti-Cheatcode Gate
    cheat_err = _detect_cheatcode_violation(patched_source)
    if cheat_err:
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_CHEATCODE_VIOLATION,
            reason=cheat_err,
        )

    if not patched_source or not _has_target_contract_declaration(target_name, patched_source):
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_FORMAT_ERROR,
            reason=f"Missing `contract {target_name}` declaration in patched source.",
        )

    if _normalized_sha256(patched_source) == _normalized_sha256(original_source):
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_FORMAT_ERROR,
            reason="No-op patch: normalized source is identical to original contract.",
        )

    # Stage 2: Red Precondition Sanity Check (fail-closed)
    if not red_precondition_verified:
        active_red = red_verifier or (
            lambda tgt, pld: run_payload_in_sandbox(tgt, pld, allow_train_split=True)
        )
        red_target = TargetProgram(
            name=target_name,
            source_code=original_source,
            language="solidity",
        )
        red_payload = ExploitPayload(
            target_name=target_name,
            hypothesis=AttackHypothesis(
                vulnerability_type="red_precondition",
                reasoning_trace="Verify Red exploit breaches original contract",
                attack_vector="red_exploit",
            ),
            test_code=exploit_code,
            format_valid=True,
            raw_model_response=exploit_code,
        )
        red_res = active_red(red_target, red_payload)
        if red_res.category != ResultCategory.EXPLOIT_CONFIRMED:
            raise ValueError(
                f"Fail-closed Red precondition failed for '{target_name}': "
                f"expected EXPLOIT_CONFIRMED on original source, got {red_res.category.value}"
            )

    # Stage 3 & 4: Functional Regression Gate + Security Gate
    active_runner = patch_runner or (
        lambda name, src, exp: run_patch_in_sandbox(name, src, exp)
    )
    sb_res = active_runner(target_name, patched_source, exploit_code)

    if sb_res.infra_error:
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_INFRA_ERROR,
            compiled=sb_res.compiled,
            functional_pass=sb_res.functional_pass,
            exploit_blocked=sb_res.exploit_blocked,
            red_precondition_confirmed=True,
            reason=sb_res.infra_error_reason or "Patch sandbox infrastructure error.",
        )

    if not sb_res.compiled:
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_COMPILATION_ERROR,
            compiled=False,
            red_precondition_confirmed=True,
            reason=sb_res.compile_error or "Patched contract failed to compile.",
        )

    if not sb_res.functional_pass:
        return _make_result(
            target_name,
            BluePatchCategory.FUNCTIONAL_REGRESSION,
            compiled=True,
            functional_pass=False,
            exploit_blocked=sb_res.exploit_blocked,
            red_precondition_confirmed=True,
            reason="Functional regression suite failed against patched contract.",
        )

    if not sb_res.exploit_blocked:
        return _make_result(
            target_name,
            BluePatchCategory.EXPLOIT_STILL_SUCCEEDS,
            compiled=True,
            functional_pass=True,
            exploit_blocked=False,
            red_precondition_confirmed=True,
            reason=f"Red exploit still breached invariant: {sb_res.breach_events}",
        )

    # Stage 5: Independent Fresh-EVM Replay
    replay_res = active_runner(target_name, patched_source, exploit_code)
    reproduced = (
        not replay_res.infra_error
        and replay_res.compiled
        and replay_res.functional_pass
        and replay_res.exploit_blocked
    )
    if not reproduced:
        return _make_result(
            target_name,
            BluePatchCategory.PATCH_VERIFIED_NO_REPLAY,
            compiled=True,
            functional_pass=True,
            exploit_blocked=True,
            reproducibility_confirmed=False,
            red_precondition_confirmed=True,
            reason="Patch passed initial verification but independent fresh-EVM replay did not confirm.",
        )

    return _make_result(
        target_name,
        BluePatchCategory.PATCH_VERIFIED,
        compiled=True,
        functional_pass=True,
        exploit_blocked=True,
        reproducibility_confirmed=True,
        red_precondition_confirmed=True,
        reason="Patch verified: functional tests pass, exploit blocked, and replay confirmed.",
    )
