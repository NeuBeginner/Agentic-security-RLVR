"""
core/evaluator.py

Multi-factor RLVR ground-truth reward evaluation and trajectory recording.
Enforces strict category separation:
- INFRA_ERROR (reward 0.0)
- GENERATION_FORMAT_ERROR (reward -0.35)
- COMPILATION_ERROR (reward -0.5)
- RUNTIME_REVERT (reward -0.25)
- SAFE_RUN (reward -0.1)
- CHEATCODE_DETECTED (reward -1.0)
- INVARIANT_BREACH_UNREPLAYED (reward +0.5, is_verified=False)
- EXPLOIT_CONFIRMED (reward +1.0, is_verified=True, strictly requires confirmed independent replay)

Reward Specification 2.0.0: every reward is decomposed into evidence-scoped
components (generation / compilation / verification / invariant / replay) plus a
single outcome penalty, and the specification version travels with the verdict
and the trajectory (see core/reward_shaping.py).

TRUSTED EVIDENCE: a breach is confirmed ONLY by the structured verdict of the
immutable, repository-owned harness. Log text is model-controllable and is
therefore never a source of evidence (see core/evidence.py).

CONSISTENCY OF THE VERDICT
---------------------------
A verdict is a single, self-consistent statement about one execution. The
fields that describe the independent replay therefore always agree with each
other and with the reward:

* ``replay_status``   - ``CONFIRMED`` when the independent replay reproduced
  the breach, ``FAILED`` when it did not, ``INFRA_ERROR`` when the replay
  itself failed for infrastructure reasons, ``NOT_ELIGIBLE`` when no breach
  was ever eligible for a replay confirmation;
* ``replay_confirmed`` - the same statement as a boolean;
* ``is_verified`` / ``reproducible`` - true only for a confirmed exploit;
* ``verification_result`` - the oracle result of the execution, aligned with
  the replay, so a verdict never claims a confirmed exploit while its own
  embedded oracle result still calls the breach provisional;
* ``state_delta_verified`` - true only when a real state snapshot exists AND
  the state actually changed. The trusted harness of this repository proves a
  breach through a verified event (emitter, topic and deficit), not through a
  state snapshot; in that case there is no state delta to verify and the
  verdict says so explicitly through ``breach_evidence_basis``.
"""

from __future__ import annotations

import uuid
import time
import hashlib
from core.schemas import (
    ExecutionResult,
    ExploitPayload,
    VerificationVerdict,
    TargetProgram,
    RLVRTrajectory,
    ResultCategory,
)
from core.config import config
from core.evidence import HarnessVerdict, is_trusted_breach_verdict
from core.reward_shaping import (
    RewardBreakdown,
    RewardEvidence,
    compute_reward_breakdown,
    REWARD_SPEC_VERSION,
)

#: The replay status vocabulary of a verdict. It mirrors the vocabulary of
#: ``core.candidate_lifecycle.finalize_candidate_replay``, so a verdict that
#: is produced by the evaluator and a verdict that is produced by the
#: candidate lifecycle speak the same language.
REPLAY_STATUS_CONFIRMED = "CONFIRMED"
REPLAY_STATUS_FAILED = "FAILED"
REPLAY_STATUS_INFRA_ERROR = "INFRA_ERROR"
REPLAY_STATUS_NOT_ELIGIBLE = "NOT_ELIGIBLE"

#: How the breach of the trusted harness was established.
BREACH_BASIS_NONE = "none"
BREACH_BASIS_STATE_SNAPSHOT = "verified_state_snapshot"
BREACH_BASIS_TRUSTED_EVENT = "trusted_harness_event"

#: The confidence of an oracle result whose breach was reproduced by an
#: independent replay.
CONFIDENCE_CONFIRMED = "CONFIRMED"
#: The confidence of an oracle result whose breach was not reproduced yet.
CONFIDENCE_PROVISIONAL_BREACH = "PROVISIONAL_BREACH"


def _aligned_verification_result(result: ExecutionResult):
    """
    The oracle result that travels with the verdict, aligned with the replay.

    The oracle builds its result from the FIRST execution, before the replay is
    known, so it carries ``replay_confirmed=False``. A verdict that claims a
    confirmed exploit while its own embedded oracle result still calls the
    breach provisional is a contradiction, so the result is aligned here. The
    alignment is a COPY: the evidence of the execution is never mutated.
    """
    verification = result.verification_result
    if verification is None:
        return None
    if result.reproducibility_confirmed:
        return verification.model_copy(
            update={
                "replay_confirmed": True,
                "confidence_status": CONFIDENCE_CONFIRMED,
            }
        )
    if verification.invariant_breach:
        return verification.model_copy(
            update={
                "replay_confirmed": False,
                "confidence_status": CONFIDENCE_PROVISIONAL_BREACH,
            }
        )
    return verification


def _state_delta_assessment(result: ExecutionResult):
    """
    The honest answer to the question "was a state delta verified?".

    A state delta is verified only when a real state snapshot exists AND the
    state actually changed. The trusted harness proves a breach through a
    verified event, so in that case there is no state delta to verify and
    claiming otherwise would contradict ``state_delta.has_real_snapshot=false``.

    Returns the pair ``(state_delta_verified, breach_evidence_basis)``.
    """
    evidence = result.evidence
    if evidence is None:
        return False, BREACH_BASIS_NONE
    state_delta = evidence.state_delta or {}
    has_real_snapshot = bool(state_delta.get("has_real_snapshot"))
    state_changed = bool(state_delta.get("state_changed"))
    if has_real_snapshot and state_changed:
        return True, BREACH_BASIS_STATE_SNAPSHOT
    trace_context = state_delta.get("trace_context") or {}
    if trace_context.get("verified_event"):
        return False, BREACH_BASIS_TRUSTED_EVENT
    return False, BREACH_BASIS_NONE


def _build_verdict(
    payload: ExploitPayload,
    category: ResultCategory,
    evidence: RewardEvidence,
    feedback: str,
    is_verified: bool,
    reproducible: bool,
    state_delta_verified: bool = False,
    execution_evidence=None,
    oracle_invariant_results=None,
    oracle_verification_result=None,
    replay_status: str = REPLAY_STATUS_NOT_ELIGIBLE,
    replay_confirmed: bool = False,
    breach_evidence_basis: str = BREACH_BASIS_NONE,
) -> VerificationVerdict:
    """
    Assembles a verdict from a category and the proven evidence.

    The reward is computed by the shared reward specification, so the verdict
    carries the full attribution (components + penalty + spec version) and the
    total always equals sum(components) + penalty.
    """
    breakdown: RewardBreakdown = compute_reward_breakdown(category, evidence)
    return VerificationVerdict(
        target_name=payload.target_name,
        is_verified=is_verified,
        reward_score=breakdown.total,
        category=category,
        vulnerability_type=payload.hypothesis.vulnerability_type,
        poc_code=payload.test_code,
        feedback=f"{feedback} | {breakdown.describe()}",
        state_delta_verified=state_delta_verified,
        reproducible=reproducible,
        refinement_iteration=payload.attempt_number,
        candidate_id=payload.candidate_id or "",
        run_id=payload.run_id or "run-default",
        replay_status=replay_status,
        replay_confirmed=replay_confirmed,
        breach_evidence_basis=breach_evidence_basis,
        reward_components=dict(breakdown.components),
        reward_penalty=breakdown.penalty,
        reward_spec_version=breakdown.spec_version,
        evidence=execution_evidence,
        invariant_results=list(oracle_invariant_results or []),
        verification_result=oracle_verification_result,
    )


def evaluate_execution_trace(payload: ExploitPayload, result: ExecutionResult) -> VerificationVerdict:
    """
    Computes a deterministic, verifiable reward score based on multi-factor execution feedback.
    Categorizes errors cleanly into Infra, Format, Compilation, Runtime Revert, Unreplayed Breach, and Confirmed Exploit.
    Serves as the RLVR ground-truth signal for GRPO training.
    """
    def build_verdict_from_result(*args, **kwargs):
        """Carry Oracle evidence forward without changing the trusted reward decision."""
        kwargs.setdefault("execution_evidence", result.evidence)
        kwargs.setdefault("oracle_invariant_results", result.invariant_results)
        kwargs.setdefault("oracle_verification_result", _aligned_verification_result(result))
        kwargs.setdefault("replay_status", REPLAY_STATUS_NOT_ELIGIBLE)
        kwargs.setdefault("replay_confirmed", bool(result.reproducibility_confirmed))
        kwargs.setdefault("breach_evidence_basis", BREACH_BASIS_NONE)
        return _build_verdict(*args, **kwargs)

    # 0. Check for structural/format failure in model output (Format validation)
    if not payload.format_valid:
        return build_verdict_from_result(
            payload,
            ResultCategory.GENERATION_FORMAT_ERROR,
            RewardEvidence(),
            f"GENERATION_FORMAT_ERROR: {payload.format_error_reason}",
            is_verified=False,
            reproducible=False,
        )

    # 1. Immediate rejection and severe penalty for cheatcode/sandbox tampering
    if result.cheatcode_detected or result.category == ResultCategory.CHEATCODE_DETECTED:
        return build_verdict_from_result(
            payload,
            ResultCategory.CHEATCODE_DETECTED,
            RewardEvidence(),
            "SECURITY VIOLATION: ExploitModule attempted to use Foundry cheatcodes (vm.*) or escape sandbox.",
            is_verified=False,
            reproducible=False,
        )

    # 2. Check for infrastructure failures (Harness setup / missing dependencies / toolchain crashes)
    # Infrastructure failures MUST NOT penalize the model (reward = 0.0)
    if result.category == ResultCategory.INFRA_ERROR:
        raw_infra_err = result.stderr if result.stderr.strip() else result.stdout
        return build_verdict_from_result(
            payload,
            ResultCategory.INFRA_ERROR,
            RewardEvidence(),
            f"INFRA_ERROR: Execution environment or harness failure: {raw_infra_err[:300].strip()}",
            is_verified=False,
            reproducible=False,
        )

    # 3. Check for execution timeout (DoS / out-of-gas / infinite loop)
    if result.timed_out:
        return build_verdict_from_result(
            payload,
            ResultCategory.RUNTIME_REVERT,
            RewardEvidence(
                format_valid=True,
                compiled=True,
                executed=False,
                timed_out=True,
            ),
            f"Execution timed out after {result.execution_time_sec:.1f}s. Possible out-of-gas or infinite recursion.",
            is_verified=False,
            reproducible=False,
        )

    # The harness intentionally reverts when the invariant held. That Forge
    # Failure status is a trusted no-breach result, not a candidate runtime crash.
    if result.harness_verdict == HarnessVerdict.NO_BREACH.value:
        # `reproducible` means, throughout this repository, that an INDEPENDENT
        # replay confirmed the verdict (see core.candidate_lifecycle and the GPU
        # path in modal_app.py). A safe run reproduces no exploit, so the flag
        # stays false and the replay was never eligible for a confirmation.
        return build_verdict_from_result(
            payload,
            ResultCategory.SAFE_RUN,
            RewardEvidence(format_valid=True, compiled=True, executed=True),
            "Safe Execution: trusted harness completed its no-breach assertion.",
            is_verified=False,
            reproducible=False,
            replay_status=REPLAY_STATUS_NOT_ELIGIBLE,
            replay_confirmed=False,
        )

    if result.harness_verdict == HarnessVerdict.EXEC_REVERT.value:
        return build_verdict_from_result(
            payload,
            ResultCategory.RUNTIME_REVERT,
            RewardEvidence(format_valid=True, compiled=True, executed=False),
            f"Execution Reverted: {result.revert_reason or 'trusted harness reported an exploit revert.'}",
            is_verified=False,
            reproducible=False,
        )

    # A replay that failed for infrastructure reasons is NOT an unreplayed
    # breach: it is an infrastructure failure with no reward at all. Reporting
    # it as an unreplayed breach would claim that the exploit was observed and
    # merely not reproduced, while in fact nothing was observed at all.
    if result.replay_error:
        return build_verdict_from_result(
            payload,
            ResultCategory.INFRA_ERROR,
            RewardEvidence(),
            (
                "INFRA_ERROR: the independent replay failed for infrastructure "
                f"reasons: {result.replay_error[:300].strip()}"
            ),
            is_verified=False,
            reproducible=False,
            replay_status=REPLAY_STATUS_INFRA_ERROR,
            replay_confirmed=False,
        )

    # 4. Multi-Factor Invariant Verification (TRUSTED EVIDENCE ONLY)
    # The breach is confirmed ONLY by the structured verdict of the immutable,
    # repository-owned harness. The log marker is deliberately NOT consulted:
    # the exploit itself can print arbitrary text, so log text can never be
    # evidence for a confirmed vulnerability.
    trusted_breach = (
        result.invariant_violated
        and result.return_code == 0
        and result.test_status == "Success"
        and not result.cheatcode_detected
        and is_trusted_breach_verdict(result.harness_verdict)
    )

    if trusted_breach:
        logs_detail = f" Logs: {result.decoded_logs}" if result.decoded_logs else ""
        verdict_source = result.harness_suite or "trusted_harness"

        # The state delta is reported the way it actually is: a verified state
        # snapshot only when one exists and changed, and the trusted harness
        # event otherwise.
        state_delta_verified, breach_evidence_basis = _state_delta_assessment(result)

        # Award full reward (+1.0) and is_verified=True ONLY if reproducibility was confirmed in independent replay
        if result.reproducibility_confirmed:
            return build_verdict_from_result(
                payload,
                ResultCategory.EXPLOIT_CONFIRMED,
                RewardEvidence(
                    format_valid=True,
                    compiled=True,
                    executed=True,
                    invariant_confirmed=True,
                    replay_confirmed=True,
                ),
                f"SUCCESS: Multi-factor verification passed and independently reproduced in clean EVM!{logs_detail}",
                is_verified=True,
                reproducible=True,
                state_delta_verified=state_delta_verified,
                replay_status=REPLAY_STATUS_CONFIRMED,
                replay_confirmed=True,
                breach_evidence_basis=breach_evidence_basis,
            )

        return build_verdict_from_result(
            payload,
            ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            RewardEvidence(
                format_valid=True,
                compiled=True,
                executed=True,
                invariant_confirmed=True,
                replay_confirmed=False,
            ),
            f"PARTIAL SUCCESS: Invariant breached in initial run (trusted verdict: {verdict_source}), but independent replay unconfirmed.{logs_detail}",
            is_verified=False,  # NOT marked as verified exploit until replay confirmation!
            reproducible=False,
            state_delta_verified=state_delta_verified,
            replay_status=REPLAY_STATUS_FAILED,
            replay_confirmed=False,
            breach_evidence_basis=breach_evidence_basis,
        )

    # 5. Check for compilation or EVM runtime revert failures
    if result.return_code != 0:
        if result.revert_reason:
            error_msg = f"EVM Runtime Revert: {result.revert_reason}"
            category = ResultCategory.RUNTIME_REVERT
        else:
            raw_err = result.stderr if result.stderr.strip() else result.stdout
            error_msg = f"Compilation Error: {raw_err[:350].strip()}"
            category = ResultCategory.COMPILATION_ERROR

        logs_detail = f" | Logs: {result.decoded_logs}" if result.decoded_logs else ""
        compiled = category == ResultCategory.RUNTIME_REVERT
        return build_verdict_from_result(
            payload,
            category,
            RewardEvidence(
                format_valid=True,
                compiled=compiled,
                executed=False,
            ),
            f"Execution Failed (exit code {result.return_code}): {error_msg}{logs_detail}",
            is_verified=False,
            reproducible=False,
        )

    # 6. Clean execution, but invariant was NOT breached (Safe run / No-op)
    return build_verdict_from_result(
        payload,
        ResultCategory.SAFE_RUN,
        RewardEvidence(
            format_valid=True,
            compiled=True,
            executed=True,
        ),
        "Safe Execution: Test completed cleanly, but target contract maintained all security invariants.",
        is_verified=False,
        reproducible=False,
        replay_status=REPLAY_STATUS_NOT_ELIGIBLE,
        replay_confirmed=False,
    )


def create_trajectory_record(
    target: TargetProgram,
    payload: ExploitPayload,
    verdict: VerificationVerdict,
    prompt_used: str = "",
    dataset_split: str = "train",
    dataset_partition: str = "production",
    is_synthetic: bool = False,
    token_provenance: str = "model_generate",
    trainable: bool = True
) -> RLVRTrajectory:
    """Packages the verified execution trajectory for GRPO fine-tuning (Round 4/5.2)."""
    cand_id = payload.candidate_id or (verdict.candidate_id or str(uuid.uuid4())[:8])
    run_id = payload.run_id or (verdict.run_id or "run-default")
    p_text = prompt_used or target.source_code
    prompt_hash = hashlib.sha256(" ".join(p_text.strip().split()).encode("utf-8")).hexdigest()

    rep_status = verdict.replay_status
    if verdict.category == ResultCategory.EXPLOIT_CONFIRMED and verdict.reproducible and rep_status == "NOT_ELIGIBLE":
        rep_status = "CONFIRMED"

    # Enforce provenance invariants
    tok_prov = token_provenance
    if is_synthetic:
        tok_prov = "synthetic"
        trainable = False
        if dataset_partition == "production":
            dataset_partition = "synthetic_control"
    elif payload.generated_token_ids is None or len(payload.generated_token_ids) == 0:
        tok_prov = "external_text_only"

    if verdict.category == ResultCategory.INFRA_ERROR:
        trainable = False

    return RLVRTrajectory(
        trajectory_id=f"traj_{run_id}_{cand_id}",
        candidate_id=cand_id,
        run_id=run_id,
        timestamp=time.time(),
        target_name=target.name,
        target_code=target.source_code,
        prompt_hash=prompt_hash,
        generation_iteration=payload.generation_iteration,
        candidate_index=payload.candidate_index,
        is_finalized=True,
        replay_status=rep_status,
        slither_hints=target.slither_findings,
        prompt_used=prompt_used,
        hypothesis=payload.hypothesis,
        full_completion_text=payload.raw_model_response or payload.test_code,
        generated_exploit=payload.test_code,
        reward=verdict.reward_score,
        category=verdict.category,
        is_verified=verdict.is_verified,
        reproduced=verdict.reproducible,
        feedback_trace=verdict.feedback,
        dataset_split=dataset_split,
        dataset_partition=dataset_partition,
        is_synthetic=is_synthetic,
        token_provenance=tok_prov,
        trainable=trainable,
        generated_token_ids=payload.generated_token_ids,
        contract_name_normalized=payload.contract_name_normalized,
        original_contract_name=payload.original_contract_name,
        contract_normalization_reason=payload.contract_normalization_reason,
        reward_components=dict(verdict.reward_components or {}),
        reward_penalty=verdict.reward_penalty,
        reward_spec_version=verdict.reward_spec_version or REWARD_SPEC_VERSION,
    )
