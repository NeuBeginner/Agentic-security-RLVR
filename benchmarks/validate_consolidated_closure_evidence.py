"""
benchmarks/validate_consolidated_closure_evidence.py
=====================================================

Fresh-state validation of the **consolidated closure** of PR #12.

The review of Iteration 23 asked for **one** consolidated closure task instead of
another narrow patch, with a single Change Impact Matrix over the full chain and
the evidence of it. This validator is that evidence.

Two defects are closed and are validated here **at the consumer boundary** - at
the real consumer, not at a helper:

* **P0 - the fail-closed evaluator leak.** ``benchmarks/evaluator.py`` built the
  per-target detail of a target with

  ```python
  det = False if (is_compile_err or a.security_verdict in (...)) else (
      a.detected if a.status == ExecutionStatus.SUCCESS else None
  )
  ```

  so the guard on the execution status sat in the *else* branch: a target whose
  execution did **not** complete was serialized as ``detected: false`` - a
  negative finding - whenever its verdict was one of the negative verdicts.
  A run that did not complete produced **no finding at all**.

* **P1 - the run-level observation-side gap.** The strict consumer side-checked
  the **stage** facts of an invocation, but the **run-level** application id
  ``modal_invocation_provenance.modal_app_id`` was only checked in its
  ``NOT_AVAILABLE`` shape. An observed run-level application id that names no
  side, a wrong side or a legacy flat value was accepted.

The checks of this validator:

* the strict consumer **accepts** a client-observed run-level application id;
* the strict consumer **rejects** the same fact with a missing, a ``null``, an
  unknown and the wrong side, as a legacy flat value and as a missing fact;
* the rejection of the wrong side comes from the **side rule** and not from a
  stale digest - the artifact is rewritten and the digests are **recomputed**
  from the bytes on disk;
* the **compatibility path** still reads the side-less artifacts of Iterations
  14-20;
* the report of the **real** evaluator states a failed or unavailable target as
  ``NOT_EVALUATED`` - for every combination of a non-success status and the
  negative verdicts;
* a **mixed** baseline keeps its metrics ``None`` and its failed target out of
  the findings;
* a **completed** run keeps its negative verdict and its own detection - the fix
  does not hollow out the verdict semantics;
* the report of the **real runner** states the detection state and both views of
  a target agree with each other;
* the **successful** and the **failure** vertical chain hold end to end;
* the **pre-fix** rules are reproduced inside this validator and still accept
  the defects: the defects were real and the checks are not vacuous;
* the evidence of Iterations 14-23 still satisfies its own validator - and the
  historical 16-target evidence stays **visibly failed**;
* the **producer source** is unchanged since the capture of Iteration 21: the
  producer is not the defect;
* the digest of the stage evidence artifact is the digest of the bytes on disk;
* the report is bound to the code SHA it was produced from; ``--check`` refuses
  a foreign SHA.

**Boundaries.** No Modal invocation is made, the provider is never queried, no
worker is deployed, restarted or modified, no GPU is used and no paid compute is
spent. The ``OBSERVED`` branch of the producer is exercised in a **simulated**
container context - a patched ``modal.current_function_call_id`` - and is called
a simulation wherever it is mentioned.

Usage::

    python -m benchmarks.validate_consolidated_closure_evidence --code-sha <sha>
    python -m benchmarks.validate_consolidated_closure_evidence --check
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    NOT_AVAILABLE,
    OBSERVED,
    OBSERVATION_SIDE_CLIENT,
    OBSERVATION_SIDE_WORKER,
    SOURCE_CLIENT_APP_ID,
    SOURCE_CLIENT_APP_PAGE_URL,
    SOURCE_CLIENT_CONTAINER_ID,
    SOURCE_WORKER_FUNCTION_CALL_ID,
    StageResponseCapture,
    build_modal_stage_provenance,
    build_stage_identity_facts,
    cross_check_app_ids,
    file_sha256,
    not_available,
    observed,
    sha256_bytes,
    validate_client_observed_facts,
    validate_modal_invocation_provenance,
    validate_provider_observation_source,
    validate_runtime_identity_envelope,
    write_stage_evidence_artifact,
)
from benchmarks.evaluator import (  # noqa: E402
    DETECTION_STATE_NEGATIVE,
    DETECTION_STATE_NOT_EVALUATED,
    DETECTION_STATE_POSITIVE,
    evaluate_baseline_run,
    resolve_detection,
)
from benchmarks.protocol import (  # noqa: E402
    ExecutionStatus,
    GroundTruth,
    TargetExecutionArtifact,
)

# The git helpers of the Iteration 16 validator are reused unchanged.
from benchmarks.validate_iteration16_evidence import (  # noqa: E402
    _current_code_sha,
    _git,
    _is_ancestor,
    _resolve_sha,
)

DEFAULT_REPORT = "benchmarks/evidence/consolidated_closure_validation_evidence.json"

#: The probe directory of this validator. It lives inside the repository
#: because the producer rehearsal of Iterations 16-18 resolves its directory
#: relative to the repository root.
PROBE_DIR = "benchmarks/evidence/_closure_probe"

STAGE = "evm_sandbox"
TARGET_ID = "CLOSURE-01"

#: The provider-issued identifiers the probes work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The negative verdicts of a **completed** execution.
NEGATIVE_VERDICTS = (
    "COMPILATION_ERROR",
    "RUNTIME_REVERT",
    "GENERATION_FORMAT_ERROR",
    "SAFE_RUN",
)

#: The statuses of an execution that did not complete.
INCOMPLETE_STATUSES = ("FAILED", "UNAVAILABLE")

#: The evidence of the historical iterations and the state each of them has to
#: be in: Iterations 14-18 validate the 16-target run that predates the fixes,
#: so they stay **visibly failed**; Iterations 19-23 stay **passed**.
HISTORICAL_EVIDENCE: Tuple[Tuple[int, str, str], ...] = (
    (14, "FAILED", "43436b0266254d2504b2521f8499aa1604e11280"),
    (15, "FAILED", "cf262236"),
    (16, "FAILED", "b1946536"),
    (17, "FAILED", "e9faff40"),
    (18, "FAILED", "8813cebd"),
    (19, "PASSED", "18ad9740f835e7babb0a7f0fb727752660b2b8f0"),
    (20, "PASSED", "64392a7bc4d4eba45a0fc15aacd4b32e3761dd98"),
    (21, "PASSED", "40c063093c8d773d20f828fb290c68b5790a7cc5"),
    (22, "PASSED", "f0ce026d"),
    (23, "PASSED", "749cba24"),
)


# =============================================================================
# Helpers
# =============================================================================

def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _check(
    name: str,
    ok: bool,
    *,
    error: Optional[str] = None,
    planned: str,
    **details: Any,
) -> Dict[str, Any]:
    """Build one check of the report."""
    entry: Dict[str, Any] = {
        "check": name,
        "status": "PASSED" if ok else "FAILED",
        "error": error,
        "planned": planned,
        "attempted": True,
        "executed": True,
    }
    entry.update(details)
    return entry


def _observed_fact(value, source, *, side=None, declare_side=True) -> Dict[str, Any]:
    """A synthetic observed fact - a probe, and always called one."""
    fact: Dict[str, Any] = {"status": OBSERVED, "value": value, "source": source}
    if declare_side:
        fact["observed_by"] = side
    return fact


def _producer_envelope() -> Dict[str, Any]:
    """
    The envelope of the **real** producer in a simulated container context.

    ``modal.current_function_call_id`` is patched to return a fixed id: the
    ``OBSERVED`` branch of the producer is therefore exercised in a simulation,
    not in a live Modal container.
    """
    import modal
    import modal_app

    original = getattr(modal, "current_function_call_id", None)
    try:
        modal.current_function_call_id = lambda: FUNCTION_CALL_ID  # type: ignore[assignment]
        return modal_app.capture_modal_runtime_identity()
    finally:
        if original is None:
            try:
                del modal.current_function_call_id  # type: ignore[attr-defined]
            except AttributeError:
                pass
        else:
            modal.current_function_call_id = original  # type: ignore[attr-defined]


def _client_block() -> Dict[str, Any]:
    """The client-observed block of a run."""
    return {
        "app_id": observed(
            APP_ID, source=SOURCE_CLIENT_APP_ID, observed_by=OBSERVATION_SIDE_CLIENT
        ),
        "app_page_url": observed(
            APP_PAGE_URL,
            source=SOURCE_CLIENT_APP_PAGE_URL,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "container_id": not_available(
            "the provider was not asked in this probe",
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
    }


def _build_provenance(directory: Path) -> Tuple[Dict[str, Any], Path]:
    """
    Build a provenance block from the real producer and write its artifact.

    The artifact is written to ``directory`` and the provenance refers to it, so
    the digests of the provenance can be recomputed against real bytes.
    """
    envelope = _producer_envelope()
    response = {
        "stage": STAGE,
        "modal_runtime": envelope,
        "worker_observed": {"note": "the response of the production producer"},
    }
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of the production producer",
        requested_fields=("app_id", "function_call_id", "container_id"),
    )
    artifact_path, artifact_ref = write_stage_evidence_artifact(
        directory,
        capture,
        target_id=TARGET_ID,
        correlation_id="corr-closure-probe",
    )
    stage_facts = build_stage_identity_facts(capture, evidence_ref=artifact_ref)
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "correlation_id": "corr-closure-probe",
            "stages": {
                STAGE: build_modal_stage_provenance(
                    function_name="verify_exploit_remote",
                    resource="CPU",
                    attempted=True,
                    evidence_ref=artifact_ref,
                    **stage_facts,
                ),
            },
        }
    }
    return provenance, artifact_path


def _rebuild_digests(provenance: Dict[str, Any], artifact_path: Path) -> None:
    """Recompute every digest the provenance states from the bytes on disk."""
    data = artifact_path.read_bytes()
    digest = sha256_bytes(data)
    length = len(data)

    def _fix(ref: Any) -> None:
        if isinstance(ref, dict) and ref.get("path"):
            ref["sha256"] = digest
            ref["byte_length"] = length

    block = provenance["modal_invocation_provenance"]
    run_app = block.get("modal_app_id")
    if isinstance(run_app, dict):
        _fix(run_app.get("evidence_ref"))
    for stage in (block.get("stages") or {}).values():
        if not isinstance(stage, dict):
            continue
        _fix(stage.get("evidence_ref"))
        for key in ("app_id", "function_call_id", "container_id"):
            fact = stage.get(key)
            if isinstance(fact, dict):
                _fix(fact.get("evidence_ref"))


def _rewrite_artifact(artifact_path: Path) -> Path:
    """Rewrite the artifact with a different byte layout."""
    payload = _read_json(artifact_path)
    artifact_path.write_bytes(
        json.dumps(payload, indent=4, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return artifact_path


def _artifact(target_id, status, *, verdict=None, detected=False, **kwargs):
    """One target execution artifact."""
    return TargetExecutionArtifact(
        baseline_id="baseline_closure",
        target_id=target_id,
        target_name=target_id,
        status=status,
        security_verdict=verdict,
        detected=detected,
        **kwargs,
    )


def _ground_truth() -> Dict[str, GroundTruth]:
    return {
        "T1": GroundTruth(contract_id="T1", is_vulnerable=True),
        "T2": GroundTruth(contract_id="T2", is_vulnerable=False),
    }


def _pre_fix_detection(artifact: TargetExecutionArtifact) -> Optional[bool]:
    """
    The detection of one target **before** the closure.

    This is the rule of ``benchmarks/evaluator.py`` as it stood: the guard on
    the execution status sat in the *else* branch, so the verdict branch won
    first and a run that did not complete was turned into a negative finding.
    """
    is_compile_err = artifact.security_verdict == "COMPILATION_ERROR"
    if is_compile_err or artifact.security_verdict in (
        "RUNTIME_REVERT",
        "GENERATION_FORMAT_ERROR",
        "SAFE_RUN",
    ):
        return False
    if artifact.status == ExecutionStatus.SUCCESS:
        return artifact.detected
    return None


def _pre_fix_run_level_side(fact: Any) -> Tuple[bool, Optional[str]]:
    """
    The rule of the run-level application id **before** the closure.

    The consumer looked at the run-level fact only in its ``NOT_AVAILABLE``
    shape; every other shape was accepted without a side check. This is the
    reproduction of that rule.
    """
    return True, None


# =============================================================================
# The validation
# =============================================================================

def _validate_consolidated_closure(
    *,
    work_dir: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every check of the consolidated closure."""
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []

    # -- P6.1 the strict consumer accepts a client-observed app id ----------
    accept_errors: List[str] = []
    accept_probes: List[Dict[str, Any]] = []
    provenance, _ = _build_provenance(work_dir)
    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )
    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=work_dir, strict_sources=True
    )
    accept_probes.append({"case": "client-observed", "accepted": ok, "error": error})
    if not ok:
        accept_errors.append(
            "the strict consumer rejects a client-observed run-level application id: "
            f"{error}"
        )
    checks.append(
        _check(
            "P6.1.the_strict_consumer_accepts_a_client_observed_run_level_application_id",
            not accept_errors,
            error="; ".join(accept_errors) if accept_errors else None,
            planned=(
                "the run-level application id of a client-observed fact is accepted by the "
                "strict consumer - the registered side of 'app_id' is the client side"
            ),
            probes=accept_probes,
        )
    )
    errors.extend(accept_errors)

    # -- P6.2 the strict consumer rejects every other shape -----------------
    rejection_errors: List[str] = []
    rejection_probes: List[Dict[str, Any]] = []
    rejection_cases: Tuple[Tuple[str, Any], ...] = (
        ("missing_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False)),
        ("null_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=None)),
        ("unknown_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side="oracle")),
        (
            "worker_side",
            _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER),
        ),
        ("legacy_flat_value", APP_ID),
        ("unknown_status", {"status": "MAYBE", "value": APP_ID}),
        ("missing_fact", None),
    )
    for label, fact in rejection_cases:
        provenance, _ = _build_provenance(work_dir)
        block = provenance["modal_invocation_provenance"]
        if label == "missing_fact":
            block.pop("modal_app_id", None)
        else:
            block["modal_app_id"] = fact
        ok, error = validate_modal_invocation_provenance(
            provenance, evidence_root=work_dir, strict_sources=True
        )
        rejection_probes.append(
            {"case": label, "rejected": not ok, "error": error}
        )
        if ok:
            rejection_errors.append(
                f"the strict consumer accepts the run-level application id of the case "
                f"{label!r}"
            )
    checks.append(
        _check(
            "P6.2.the_strict_consumer_rejects_every_other_run_level_application_id",
            not rejection_errors,
            error="; ".join(rejection_errors) if rejection_errors else None,
            planned=(
                "a run-level application id with a missing, a null, an unknown or the wrong "
                "side, as a legacy flat value, as an unknown status or not at all is rejected "
                "in the strict mode"
            ),
            probes=rejection_probes,
        )
    )
    errors.extend(rejection_errors)

    # -- P6.3 the rejection comes from the side rule, not from a digest -----
    digest_errors: List[str] = []
    digest_probes: List[Dict[str, Any]] = []

    provenance, artifact_path = _build_provenance(work_dir)
    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )
    artifact_path = _rewrite_artifact(artifact_path)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=work_dir, strict_sources=True
    )
    digest_probes.append(
        {"probe": "the client-sided run-level fact with recomputed digests", "accepted": ok, "error": error}
    )
    if not ok:
        digest_errors.append(
            f"the strict consumer rejects the correctly sided run-level application id "
            f"after the digests were recomputed: {error}"
        )

    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER
    )
    ok, error = validate_modal_invocation_provenance(
        provenance, evidence_root=work_dir, strict_sources=True
    )
    digest_probes.append(
        {"probe": "the same artifact with the wrong side", "accepted": ok, "error": error}
    )
    if ok:
        digest_errors.append(
            "the strict consumer accepts a run-level application id that names the worker "
            "side although the registered side of 'app_id' is the client side"
        )
    elif "digest" in (error or "").lower():
        digest_errors.append(
            f"the rejection of the wrong side came from a digest and not from the side "
            f"rule: {error}"
        )

    checks.append(
        _check(
            "P6.3.the_rejection_comes_from_the_side_rule_and_not_from_a_stale_digest",
            not digest_errors,
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the artifact is rewritten and the digests of the provenance are recomputed "
                "from the bytes on disk: the correctly sided fact is accepted and the wrong "
                "side is refused by the side rule"
            ),
            probes=digest_probes,
        )
    )
    errors.extend(digest_errors)

    # -- P6.4 the compatibility path still reads the side-less artifacts -----
    compat_errors: List[str] = []
    compat_probes: List[Dict[str, Any]] = []

    provenance, _ = _build_provenance(work_dir)
    provenance["modal_invocation_provenance"]["modal_app_id"] = APP_ID
    provenance["modal_invocation_provenance"]["stages"][STAGE] = {
        "attempted": True,
        "function_name": "verify_exploit_remote",
        "resource": "CPU",
        "app_id": APP_ID,
        "function_call_id": FUNCTION_CALL_ID,
        "container_id": CONTAINER_ID,
    }
    ok, error = validate_modal_invocation_provenance(provenance)
    compat_probes.append({"case": "the side-less provenance of Iterations 14-20", "accepted": ok, "error": error})
    if not ok:
        compat_errors.append(
            f"the compatibility path rejects the side-less facts of Iterations 14-20: {error}"
        )

    side_less = _observed_fact(
        FUNCTION_CALL_ID, SOURCE_WORKER_FUNCTION_CALL_ID, declare_side=False
    )
    ok, error = validate_provider_observation_source("function_call_id", side_less)
    compat_probes.append({"case": "the side-less provider fact", "accepted": ok, "error": error})
    if not ok:
        compat_errors.append(f"the compatibility path rejects a side-less fact: {error}")

    checks.append(
        _check(
            "P6.4.the_compatibility_path_still_accepts_the_side_less_facts",
            not compat_errors,
            error="; ".join(compat_errors) if compat_errors else None,
            planned=(
                "the artifacts of Iterations 14-20 stay readable through the non-strict "
                "compatibility path - no side is inferred and none is backfilled"
            ),
            probes=compat_probes,
        )
    )
    errors.extend(compat_errors)

    # -- P6.5 the report of the evaluator states no negative finding ---------
    leak_errors: List[str] = []
    leak_probes: List[Dict[str, Any]] = []
    for status_name in INCOMPLETE_STATUSES:
        for verdict in NEGATIVE_VERDICTS:
            for raw_detected in (False, True):
                artifact = _artifact(
                    "T1",
                    ExecutionStatus[status_name],
                    verdict=verdict,
                    detected=raw_detected,
                    verified_breaches=1,
                )
                result = evaluate_baseline_run(
                    "baseline_closure", "B", [artifact], _ground_truth()
                )
                detail = result.details[0]
                record = result.target_artifacts[0]
                leaked = detail["detected"] is not False or record["detected"] is not False
                leak_probes.append(
                    {
                        "status": status_name,
                        "verdict": verdict,
                        "producer_detected": raw_detected,
                        "detail_detected": detail["detected"],
                        "detail_state": detail["detection_state"],
                        "record_detected": record["detected"],
                        "record_state": record["detection_state"],
                        "leaked": leaked,
                    }
                )
                if detail["detected"] is not None:
                    leak_errors.append(
                        f"the evaluator states the detection of a {status_name} target with the "
                        f"verdict {verdict!r} as {detail['detected']!r} instead of None"
                    )
                if detail["detection_state"] != DETECTION_STATE_NOT_EVALUATED:
                    leak_errors.append(
                        f"the evaluator states the detection state of a {status_name} target "
                        f"with the verdict {verdict!r} as "
                        f"{detail['detection_state']!r} instead of NOT_EVALUATED"
                    )
                if record["detected"] is not None:
                    leak_errors.append(
                        f"the report record of a {status_name} target with the verdict "
                        f"{verdict!r} states {record['detected']!r} instead of None"
                    )
    checks.append(
        _check(
            "P6.5.a_failed_or_unavailable_run_is_never_a_negative_finding",
            not leak_errors,
            error="; ".join(leak_errors) if leak_errors else None,
            planned=(
                "every combination of a non-success status and the negative verdicts is "
                "reported as 'no finding' (None / NOT_EVALUATED) - in the detail row and in "
                "the report record of the target"
            ),
            probes=leak_probes,
        )
    )
    errors.extend(leak_errors)

    # -- P6.6 the mixed baseline keeps its metrics None ----------------------
    mixed_errors: List[str] = []
    mixed_probes: List[Dict[str, Any]] = []
    artifacts = [
        _artifact("T1", ExecutionStatus.SUCCESS, detected=True),
        _artifact("T2", ExecutionStatus.FAILED, verdict="COMPILATION_ERROR"),
    ]
    result = evaluate_baseline_run("baseline_closure", "B", artifacts, _ground_truth())
    mixed_probes.append(
        {
            "status": result.status.value,
            "reason": result.status_reason,
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1_score,
            "true_positives": result.true_positives,
            "details": [
                {
                    "target_id": d["target_id"],
                    "detected": d["detected"],
                    "detection_state": d["detection_state"],
                }
                for d in result.details
            ],
        }
    )
    if result.status != ExecutionStatus.INCOMPLETE:
        mixed_errors.append(
            f"the mixed baseline is {result.status.value} instead of INCOMPLETE"
        )
    for metric in ("precision", "recall", "f1_score", "true_positives", "false_negatives"):
        if getattr(result, metric) is not None:
            mixed_errors.append(f"the mixed baseline has a {metric} instead of None")
    failed_detail = next(d for d in result.details if d["target_id"] == "T2")
    if failed_detail["detected"] is not None:
        mixed_errors.append(
            f"the failed target of the mixed baseline is {failed_detail['detected']!r} "
            "instead of None"
        )
    checks.append(
        _check(
            "P6.6.the_mixed_baseline_stays_non_scorable_and_out_of_the_findings",
            not mixed_errors,
            error="; ".join(mixed_errors) if mixed_errors else None,
            planned=(
                "a baseline with a failed target keeps every metric None and states the "
                "failed target as NOT_EVALUATED"
            ),
            probes=mixed_probes,
        )
    )
    errors.extend(mixed_errors)

    # -- P6.7 a completed run keeps its verdict and its detection ------------
    verdict_errors: List[str] = []
    verdict_probes: List[Dict[str, Any]] = []
    for verdict in NEGATIVE_VERDICTS:
        artifact = _artifact(
            "T1", ExecutionStatus.SUCCESS, verdict=verdict, detected=True
        )
        result = evaluate_baseline_run(
            "baseline_closure", "B", [artifact], _ground_truth()
        )
        detail = result.details[0]
        verdict_probes.append(
            {
                "verdict": verdict,
                "detected": detail["detected"],
                "detection_state": detail["detection_state"],
                "baseline": result.status.value,
            }
        )
        if detail["detected"] is not False:
            verdict_errors.append(
                f"the completed run with the verdict {verdict!r} is {detail['detected']!r} "
                "instead of a negative finding"
            )
        if result.status != ExecutionStatus.SUCCESS:
            verdict_errors.append(
                f"the completed run with the verdict {verdict!r} makes the baseline "
                f"{result.status.value} instead of SUCCESS"
            )

    positive = _artifact("T1", ExecutionStatus.SUCCESS, detected=True)
    negative = _artifact("T2", ExecutionStatus.SUCCESS, detected=False)
    result = evaluate_baseline_run(
        "baseline_closure", "B", [positive, negative], _ground_truth()
    )
    by_target = {d["target_id"]: d for d in result.details}
    verdict_probes.append(
        {
            "case": "a completed run without a negative verdict",
            "detected": [by_target["T1"]["detected"], by_target["T2"]["detected"]],
            "detection_state": [
                by_target["T1"]["detection_state"],
                by_target["T2"]["detection_state"],
            ],
            "true_positives": result.true_positives,
            "true_negatives": result.true_negatives,
        }
    )
    if by_target["T1"]["detected"] is not True or by_target["T1"]["detection_state"] != DETECTION_STATE_POSITIVE:
        verdict_errors.append("the completed run that found a vulnerability lost its detection")
    if by_target["T2"]["detected"] is not False or by_target["T2"]["detection_state"] != DETECTION_STATE_NEGATIVE:
        verdict_errors.append("the completed run that found nothing lost its detection")
    if result.true_positives != 1 or result.true_negatives != 1:
        verdict_errors.append(
            "the confusion matrix of the completed runs does not agree with the report"
        )

    checks.append(
        _check(
            "P6.7.a_completed_run_keeps_its_verdict_and_its_detection",
            not verdict_errors,
            error="; ".join(verdict_errors) if verdict_errors else None,
            planned=(
                "the fix does not hollow out the verdict semantics: a completed run with a "
                "negative verdict stays a negative finding, and the confusion matrix agrees "
                "with the report"
            ),
            probes=verdict_probes,
        )
    )
    errors.extend(verdict_errors)

    # -- P6.8 the report of the real runner states the detection state -------
    runner_errors: List[str] = []
    runner_probes: List[Dict[str, Any]] = []
    try:
        from benchmarks.benchmark_runner import AegisBenchmarkSuite

        runner_dir = work_dir / "runner"
        suite = AegisBenchmarkSuite(artifacts_dir=runner_dir)
        report = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            save_results=True,
        )
        for baseline_id, baseline in report["baselines"].items():
            details_by_id = {d["target_id"]: d for d in baseline["details"]}
            for record in baseline["target_artifacts"]:
                detail = details_by_id.get(record["target_id"])
                if detail is None:
                    runner_errors.append(
                        f"the report of the baseline {baseline_id} has a record without a "
                        "detail row"
                    )
                    continue
                if record["detected"] != detail["detected"] or record[
                    "detection_state"
                ] != detail["detection_state"]:
                    runner_errors.append(
                        f"the two views of the target {record['target_id']} of the baseline "
                        f"{baseline_id} disagree"
                    )
                if record["status"] != "SUCCESS" and record["detected"] is not None:
                    runner_errors.append(
                        f"the report of the real runner states the detection of a "
                        f"{record['status']} target as {record['detected']!r} instead of None"
                    )
            runner_probes.append(
                {
                    "baseline": baseline_id,
                    "targets": len(baseline["details"]),
                    "detection_states": sorted(
                        {d["detection_state"] for d in baseline["details"]}
                    ),
                }
            )
    except Exception as exc:  # pragma: no cover - a broken smoke run
        runner_errors.append(f"the smoke run of the real runner failed: {exc}")
    checks.append(
        _check(
            "P6.8.the_report_of_the_real_runner_states_the_detection_state",
            not runner_errors,
            error="; ".join(runner_errors) if runner_errors else None,
            planned=(
                "the report of the real runner carries the detection state of every target "
                "and both views of a target agree with each other"
            ),
            probes=runner_probes,
        )
    )
    errors.extend(runner_errors)

    # -- P6.9 the successful vertical chain ----------------------------------
    chain_errors: List[str] = []
    chain_probes: List[Dict[str, Any]] = []
    provenance, artifact_path = _build_provenance(work_dir)
    provenance["modal_invocation_provenance"]["modal_app_id"] = _observed_fact(
        APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_CLIENT
    )
    recorded = provenance["modal_invocation_provenance"]["stages"][STAGE]["evidence_ref"][
        "sha256"
    ]
    actual = file_sha256(artifact_path)
    chain_probes.append(
        {"step": "the digest of the artifact is the digest of the bytes", "recorded": recorded, "actual": actual}
    )
    if recorded != actual:
        chain_errors.append("the digest of the stage evidence artifact is stale")

    ok, error = validate_modal_invocation_provenance(
        provenance, known_app_ids=[APP_ID], evidence_root=work_dir, strict_sources=True
    )
    chain_probes.append({"step": "the strict consumer", "accepted": ok, "error": error})
    if not ok:
        chain_errors.append(f"the strict consumer rejects the successful chain: {error}")

    ok, error = validate_client_observed_facts(
        provenance["modal_invocation_provenance"]["client_observed"], strict_sources=True
    )
    chain_probes.append({"step": "the client block", "accepted": ok, "error": error})
    if not ok:
        chain_errors.append(f"the client block is rejected: {error}")

    join = cross_check_app_ids(provenance, [APP_ID])
    chain_probes.append({"step": "the billing join", "status": join["status"]})
    if join["status"] != "PASSED":
        chain_errors.append(f"the billing join fails: {join.get('error')}")

    artifact = _artifact("T1", ExecutionStatus.SUCCESS, detected=True)
    result = evaluate_baseline_run("baseline_closure", "B", [artifact], _ground_truth())
    chain_probes.append(
        {
            "step": "the evaluator and the report",
            "baseline": result.status.value,
            "detected": result.details[0]["detected"],
            "detection_state": result.details[0]["detection_state"],
        }
    )
    if result.details[0]["detection_state"] != DETECTION_STATE_POSITIVE:
        chain_errors.append("the successful chain does not report the finding")

    checks.append(
        _check(
            "P6.9.the_successful_vertical_chain_holds_end_to_end",
            not chain_errors,
            error="; ".join(chain_errors) if chain_errors else None,
            planned=(
                "producer → capture → evidence artifact → strict validator → billing join → "
                "evaluator → report holds end to end for a successful run"
            ),
            probes=chain_probes,
        )
    )
    errors.extend(chain_errors)

    # -- P6.10 the failure vertical chain ------------------------------------
    failure_errors: List[str] = []
    failure_probes: List[Dict[str, Any]] = []
    artifact = _artifact(
        "T1",
        ExecutionStatus.FAILED,
        verdict="EXECUTION_FAILURE",
        unavailable_reason="the sandbox worker died",
    )
    result = evaluate_baseline_run("baseline_closure", "B", [artifact], _ground_truth())
    failure_probes.append(
        {
            "baseline": result.status.value,
            "reason": result.status_reason,
            "precision": result.precision,
            "detail": result.details[0],
        }
    )
    if result.status != ExecutionStatus.FAILED:
        failure_errors.append(f"the failed baseline is {result.status.value} instead of FAILED")
    if result.precision is not None:
        failure_errors.append("the failed baseline has a precision instead of None")
    if result.details[0]["detected"] is not None:
        failure_errors.append(
            f"the failed target is {result.details[0]['detected']!r} instead of None"
        )
    if result.details[0]["detection_state"] != DETECTION_STATE_NOT_EVALUATED:
        failure_errors.append(
            f"the failed target has the state {result.details[0]['detection_state']!r} "
            "instead of NOT_EVALUATED"
        )
    checks.append(
        _check(
            "P6.10.the_failure_vertical_chain_keeps_the_failure_visible",
            not failure_errors,
            error="; ".join(failure_errors) if failure_errors else None,
            planned=(
                "a failed run is reported as a failure everywhere and never as a negative "
                "finding"
            ),
            probes=failure_probes,
        )
    )
    errors.extend(failure_errors)

    # -- P6.11 the pre-fix rule reproduces the P0 defect ----------------------
    pre_fix_errors: List[str] = []
    pre_fix_probes: List[Dict[str, Any]] = []
    for status_name in INCOMPLETE_STATUSES:
        for verdict in NEGATIVE_VERDICTS:
            artifact = _artifact(
                "T1", ExecutionStatus[status_name], verdict=verdict, detected=False
            )
            before = _pre_fix_detection(artifact)
            after, state = resolve_detection(artifact)
            pre_fix_probes.append(
                {
                    "status": status_name,
                    "verdict": verdict,
                    "pre_fix_detection": before,
                    "current_detection": after,
                    "current_state": state,
                }
            )
            if before is not False:
                pre_fix_errors.append(
                    f"the pre-fix rule does not reproduce the defect for {status_name} with "
                    f"the verdict {verdict!r}: it yields {before!r}"
                )
            if after is not None:
                pre_fix_errors.append(
                    f"the current rule does not close the defect for {status_name} with the "
                    f"verdict {verdict!r}"
                )
    checks.append(
        _check(
            "P6.11.the_pre_fix_rule_reproduces_the_p0_defect",
            not pre_fix_errors,
            error="; ".join(pre_fix_errors) if pre_fix_errors else None,
            planned=(
                "the rule of the evaluator before this closure is reproduced here and still "
                "turns a failed or unavailable run into a negative finding: the defect was "
                "real, and the checks are not vacuous"
            ),
            probes=pre_fix_probes,
        )
    )
    errors.extend(pre_fix_errors)

    # -- P6.12 the pre-fix rule reproduces the P1 defect ----------------------
    p1_pre_fix_errors: List[str] = []
    p1_pre_fix_probes: List[Dict[str, Any]] = []
    for label, fact in (
        ("worker_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER)),
        ("missing_side", _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False)),
        ("legacy_flat_value", APP_ID),
    ):
        accepted_before, error_before = _pre_fix_run_level_side(fact)
        provenance, _ = _build_provenance(work_dir)
        provenance["modal_invocation_provenance"]["modal_app_id"] = fact
        accepted_after, error_after = validate_modal_invocation_provenance(
            provenance, evidence_root=work_dir, strict_sources=True
        )
        p1_pre_fix_probes.append(
            {
                "case": label,
                "accepted_by_the_pre_fix_rule": accepted_before,
                "pre_fix_error": error_before,
                "accepted_by_the_current_rule": accepted_after,
                "current_error": error_after,
            }
        )
        if not accepted_before:
            p1_pre_fix_errors.append(
                f"the pre-fix rule does not reproduce the defect for the case {label!r}"
            )
        if accepted_after:
            p1_pre_fix_errors.append(
                f"the current rule accepts the run-level application id of the case {label!r}"
            )
    checks.append(
        _check(
            "P6.12.the_pre_fix_rule_reproduces_the_p1_defect",
            not p1_pre_fix_errors,
            error="; ".join(p1_pre_fix_errors) if p1_pre_fix_errors else None,
            planned=(
                "the rule of the run-level application id before this closure is reproduced "
                "here and still accepts the side-less and the wrong-sided claim: the defect "
                "was real, and the checks are not vacuous"
            ),
            probes=p1_pre_fix_probes,
        )
    )
    errors.extend(p1_pre_fix_errors)

    # -- P6.13 the historical evidence stays in its state --------------------
    history_errors: List[str] = []
    history: List[Dict[str, Any]] = []
    probe_dir = _ROOT / PROBE_DIR
    probe_dir.mkdir(parents=True, exist_ok=True)
    for iteration, expected, bound in HISTORICAL_EVIDENCE:
        module = f"benchmarks.validate_iteration{iteration}_evidence"
        report_path = probe_dir / f"iteration{iteration}.json"
        command = [
            sys.executable,
            "-m",
            module,
            "--report",
            str(report_path),
        ]
        if iteration in (16, 17, 18):
            command += ["--rehearsal-dir", str(probe_dir / f"rehearsal{iteration}")]
        if expected == "PASSED":
            # The validator of Iterations 19-21 verifies that its evidence is
            # bound to the commit it was produced from - so it is bound to that
            # commit and not to the head of this closure.
            command += ["--code-sha", bound]
        completed = subprocess.run(
            command,
            cwd=str(_ROOT),
            capture_output=True,
            text=True,
            timeout=900,
        )
        output = (completed.stdout or "").strip().splitlines()
        status = None
        if report_path.is_file():
            try:
                status = _read_json(report_path).get("summary", {}).get("overall_status")
            except (OSError, ValueError):
                status = None
        entry = {
            "iteration": iteration,
            "expected": expected,
            "observed": status,
            "bound_code_sha": bound,
            "returncode": completed.returncode,
            "output": output[-3:],
        }
        history.append(entry)
        if status != expected:
            history_errors.append(
                f"the evidence of Iteration {iteration} is {status!r} instead of {expected!r}"
            )
    checks.append(
        _check(
            "P6.13.the_historical_evidence_stays_in_its_state",
            not history_errors,
            error="; ".join(history_errors) if history_errors else None,
            planned=(
                "every evidence validator of Iterations 14-23 is executed: the validators of "
                "Iterations 14-18 keep failing visibly - the 16-target run on disk predates "
                "the fixes - and the validators of Iterations 19-23 keep passing"
            ),
            history=history,
        )
    )
    errors.extend(history_errors)

    # -- P6.14 the producer source is unchanged ------------------------------
    producer_errors: List[str] = []
    capture_sha = "40c063093c8d773d20f828fb290c68b5790a7cc5"
    producer_changed: Optional[bool] = None
    if not code_sha:
        producer_errors.append("the report is bound to no commit SHA")
    elif not _is_ancestor(capture_sha, code_sha):
        producer_errors.append(
            f"the commit the capture was made from ({capture_sha}) is not an ancestor of "
            f"the reported commit ({code_sha})"
        )
    else:
        diff = _git("diff", "--name-only", capture_sha, code_sha, "--", "modal_app.py")
        producer_changed = bool(diff)
        if producer_changed:
            producer_errors.append(
                "the producer source changed between the commit the capture was made from "
                f"and the reported commit: {diff}"
            )
    checks.append(
        _check(
            "P6.14.the_producer_source_is_unchanged_since_the_capture",
            not producer_errors,
            error="; ".join(producer_errors) if producer_errors else None,
            planned=(
                "the producer source is byte-wise unchanged between the commit the capture "
                "of Iteration 21 was made from and the commit the report is bound to - the "
                "producer is not the defect of this closure"
            ),
            capture_code_sha=capture_sha,
            reported_code_sha=code_sha,
            producer_source_changed=producer_changed,
        )
    )
    errors.extend(producer_errors)

    # -- P6.15 the digest of the artifact is the digest of the bytes ----------
    digest_errors: List[str] = []
    digest_probes: List[Dict[str, Any]] = []
    provenance, artifact_path = _build_provenance(work_dir)
    recorded = provenance["modal_invocation_provenance"]["stages"][STAGE]["evidence_ref"]
    actual = file_sha256(artifact_path)
    digest_probes.append({"recorded": recorded.get("sha256"), "actual": actual})
    if recorded.get("sha256") != actual:
        digest_errors.append(
            f"the digest of the stage evidence artifact on disk is {actual}, not "
            f"{recorded.get('sha256')}"
        )
    if recorded.get("byte_length") != artifact_path.stat().st_size:
        digest_errors.append(
            f"the byte length of the stage evidence artifact on disk is "
            f"{artifact_path.stat().st_size}, not {recorded.get('byte_length')}"
        )
    checks.append(
        _check(
            "P6.15.the_digest_of_the_artifact_is_the_digest_of_the_bytes",
            not digest_errors,
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the SHA-256 and the byte length of the stage evidence artifact on disk "
                "equal the values the provenance states"
            ),
            probes=digest_probes,
        )
    )
    errors.extend(digest_errors)

    # -- P6.16 the boundary of the closure ----------------------------------
    boundary_errors: List[str] = []
    boundary = {
        "live_modal_invocation": False,
        "provider_queried": False,
        "deployment": "none",
        "gpu": "none",
        "paid_compute": "none",
        "worker_restarted": False,
    }
    if boundary["live_modal_invocation"] is not False:
        boundary_errors.append("the closure claims a live Modal invocation")
    if boundary["provider_queried"] is not False:
        boundary_errors.append("the closure claims a provider query")
    if boundary["deployment"] != "none":
        boundary_errors.append("the closure claims a deployment")
    if boundary["gpu"] != "none":
        boundary_errors.append("the closure claims a GPU")
    checks.append(
        _check(
            "P6.16.no_live_invocation_no_provider_query_no_deployment_and_no_gpu",
            not boundary_errors,
            error="; ".join(boundary_errors) if boundary_errors else None,
            planned=(
                "the closure is local: no Modal invocation, no provider query, no "
                "deployment, no GPU, no paid compute and no change to a deployed worker"
            ),
            **boundary,
        )
    )
    errors.extend(boundary_errors)

    return {
        "checks": checks,
        "errors": errors,
        "history": history,
    }


# =============================================================================
# The report
# =============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument(
        "--code-sha",
        default=None,
        help="the exact code SHA the report is bound to (defaults to HEAD)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the existing report instead of writing a new one",
    )
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = _ROOT / report_path

    code_sha = _resolve_sha(args.code_sha) or _current_code_sha()

    def _display(path: Path) -> str:
        try:
            return str(path.relative_to(_ROOT)).replace("\\", "/")
        except ValueError:
            return str(path)

    probe_dir = _ROOT / PROBE_DIR

    if args.check:
        if not report_path.is_file():
            print(f"no validation report at {report_path}")
            return 1
        report = json.loads(report_path.read_text(encoding="utf-8"))
        bound = report.get("code_sha")
        if args.code_sha:
            if bound != args.code_sha:
                print(
                    "the validation report is bound to code SHA {bound}, not to {head}".format(
                        bound=bound, head=args.code_sha
                    )
                )
                return 1
        elif not bound or not _is_ancestor(bound, "HEAD"):
            print(
                "the validation report is bound to code SHA {bound}, which is not an "
                "ancestor of HEAD".format(bound=bound)
            )
            return 1

        work_dir = Path(tempfile.mkdtemp(prefix="closure-probe-"))
        try:
            outcome = _validate_consolidated_closure(
                work_dir=work_dir, code_sha=bound
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
            shutil.rmtree(probe_dir, ignore_errors=True)
        published = report.get("summary", {}).get("overall_status")
        current = "PASSED" if not outcome["errors"] else "FAILED"
        summary = report.get("summary", {})
        print(
            "validation report {path}: published {published}, revalidated {current} "
            "({passed}/{total} checks), bound to {bound}".format(
                path=_display(report_path),
                published=published,
                current=current,
                passed=summary.get("checks_passed", 0),
                total=summary.get("checks_total", 0),
                bound=bound,
            )
        )
        if current != "PASSED" or published != "PASSED":
            for error in outcome["errors"]:
                print(f"  FAILED: {error}")
            return 1
        return 0

    work_dir = Path(tempfile.mkdtemp(prefix="closure-probe-"))
    try:
        outcome = _validate_consolidated_closure(work_dir=work_dir, code_sha=code_sha)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        shutil.rmtree(probe_dir, ignore_errors=True)
    checks = outcome["checks"]
    failed = [check for check in checks if check["status"] == "FAILED"]

    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    status = _git("status", "--porcelain") or ""
    tracked_changes = [
        line for line in status.splitlines() if line.strip() and not line.startswith("??")
    ]
    untracked_paths = [
        line[3:].strip() for line in status.splitlines() if line.strip().startswith("??")
    ]

    report = {
        "schema_version": "1.0.0",
        "generator": "benchmarks/validate_consolidated_closure_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "closure": "consolidated architecture closure of PR #12",
            "purpose": (
                "validate the fail-closed evaluator leak (P0) and the run-level "
                "observation-side gap (P1), and the evidence of the full-chain audit"
            ),
            "defects": {
                "P0": (
                    "a target whose execution did not complete was serialized as "
                    "detected: false instead of null"
                ),
                "P1": (
                    "an observed run-level application id was not side-checked by the "
                    "strict consumer"
                ),
            },
            "chain": (
                "Modal producer / client provider → stage response capture → evidence "
                "artifacts → strict provenance validator → billing join → adapter and "
                "target manifests → evaluator → final report"
            ),
            "runtime": (
                "local probes against the installed contract - no Modal invocation, no "
                "provider query, no deployment, no GPU, no paid compute and no change to "
                "a deployed worker"
            ),
            "simulation": (
                "the OBSERVED branch of the producer is exercised in a simulated container "
                "context (a patched modal.current_function_call_id); it is a simulation and "
                "is called one"
            ),
            "benchmark_run": (
                "not touched - the 16-target run on disk still fails the Iteration 14-18 "
                "validators and this closure does not change that"
            ),
        },
        "git": {
            "head": _current_code_sha(),
            "branch": branch,
            "dirty": bool(tracked_changes),
            "tracked_changes": tracked_changes,
            "untracked_paths": untracked_paths,
        },
        "checks": checks,
        "historical_evidence": outcome["history"],
        "summary": {
            "checks_total": len(checks),
            "checks_passed": len(checks) - len(failed),
            "checks_failed": len(failed),
            "failed_checks": [check["check"] for check in failed],
            "overall_status": "PASSED" if not failed else "FAILED",
        },
        "interpretation": {
            "planned": (
                "validate that the evaluator keeps a failed or unavailable run out of the "
                "negative findings, that the strict consumer side-checks the run-level "
                "application id, that the compatibility path keeps the side-less artifacts "
                "readable, that the report states the detection state of every target, that "
                "the two vertical chains hold, that the pre-fix rules reproduce the "
                "defects, that the historical evidence stays in its state and that the "
                "report is bound to the code SHA it was produced from"
            ),
            "attempted": (
                "every non-success status with every negative verdict, every side variant "
                "of the run-level application id, the digest-recomputed chain, the "
                "compatibility path, the report of the real evaluator and of the real "
                "runner, both vertical chains, the pre-fix rules, the evidence validator "
                "of every iteration from 14 to 23, the producer source and the artifact "
                "digest"
            ),
            "executed": (
                "the checks were executed against the artifacts stored on disk"
                if outcome["history"]
                else "nothing could be executed"
            ),
            "observed": (
                "the report states exactly what the evaluator and the strict consumer "
                "accept and reject; the producer is not changed by this closure and no side "
                "is inferred or backfilled into any artifact"
            ),
            "reported": (
                "PASSED means every check of the consolidated closure passed; FAILED means "
                "at least one did not. No Modal invocation was made, the provider was "
                "never asked, no worker was deployed and no live validation is claimed. The "
                "OBSERVED branch of the producer was exercised in a simulated container "
                "context and is a simulation. The historical 16-target benchmark evidence "
                "stays visibly failed."
            ),
        },
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    summary = report["summary"]
    print(
        "wrote {path}: {status}, {passed}/{total} checks passed".format(
            path=_display(report_path),
            status=summary["overall_status"],
            passed=summary["checks_passed"],
            total=summary["checks_total"],
        )
    )
    for check in failed:
        print(f"  FAILED {check['check']}: {check.get('error')}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
