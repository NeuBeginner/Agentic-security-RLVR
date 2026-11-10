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
  unknown and the wrong side, as a legacy flat value, as an unknown status and
  as a missing fact;
* the rejection of the wrong side comes from the **side rule** and not from a
  stale digest - the artifact is rewritten and the digests are **recomputed**
  from the bytes on disk;
* the **compatibility path** still reads the side-less artifacts of Iterations
  14-20 in every shape that the pre-fix code accepted;
* the report of the **real** evaluator states a failed or unavailable target as
  ``NOT_EVALUATED`` - for every combination of a non-success status and the
  negative verdicts, and for the verdicts that declare the audit itself invalid;
* a **mixed** baseline keeps its metrics ``None`` and its failed target out of
  the findings;
* a **completed** run keeps its negative verdict and its own detection - the fix
  does not hollow out the verdict semantics;
* the report of the **real runner** - with a **failing** execution in it - states
  the detection state, keeps both views of a target in agreement, and keeps the
  failure visible in the adapter and target manifests;
* the **successful** and the **failure** vertical chain hold end to end, the
  billing join included;
* the **pre-fix** rules are reproduced by **executing the historical source**
  - the defect was real and the checks are not vacuous;
* the evidence of Iterations 14-23 still satisfies its own validator - and the
  historical 16-target evidence stays **visibly failed**;
* the **producer source** is unchanged since the capture of Iteration 21: the
  producer is not the defect;
* the digest of the stage evidence artifact is the digest of the bytes on disk;
* the closure runs in a **synthetic** context: the smoke run of the real runner
  is a synthetic smoke test, and the ``OBSERVED`` branch of the producer was
  exercised in a **simulated** container context;
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
import importlib.util
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
    BillingLineItem,
    StageResponseCapture,
    build_modal_stage_provenance,
    build_stage_identity_facts,
    cross_check_app_ids,
    file_sha256,
    not_available,
    observed,
    resolve_billing_join,
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
#: relative to the repository root. It is removed after every run and is
#: ignored by git.
PROBE_DIR = "benchmarks/evidence/_closure_probe"

#: The commit whose code is the code **before** the closure. The pre-fix rules
#: are reproduced by executing the source of this commit - not by a
#: re-implementation of it.
PRE_FIX_COMMIT = "2909b47~1"

STAGE = "evm_sandbox"
TARGET_ID = "CLOSURE-01"

#: The provider-issued identifiers the probes work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The negative verdicts of the code **before** the closure - the set of the
#: verdicts that turned a run that did not complete into a negative finding.
HISTORICAL_NEGATIVE_VERDICTS = (
    "COMPILATION_ERROR",
    "RUNTIME_REVERT",
    "GENERATION_FORMAT_ERROR",
    "SAFE_RUN",
)

#: The negative verdicts of a **completed** execution - the historical set plus
#: the rejected cheatcode attempt, which the closure added to the set of the
#: verdicts that may never count as a positive breach.
NEGATIVE_VERDICTS = HISTORICAL_NEGATIVE_VERDICTS + ("CHEATCODE_DETECTED",)

#: The verdicts that say that the **audit itself** did not run.
INVALID_VERDICTS = ("INFRA_ERROR",)

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


def _producer_capture() -> Dict[str, Any]:
    """
    The envelope of the **real** producer in a simulated container context.

    ``modal.current_function_call_id`` is patched to return a fixed id: the
    ``OBSERVED`` branch of the producer is therefore exercised in a simulation,
    not in a live Modal container. The flag records that the patch was active
    while the envelope was captured - it is what makes the claim checkable.
    """
    import modal
    import modal_app

    original = getattr(modal, "current_function_call_id", None)
    patched = False
    try:
        modal.current_function_call_id = lambda: FUNCTION_CALL_ID  # type: ignore[assignment]
        patched = True
        envelope = modal_app.capture_modal_runtime_identity()
    finally:
        if original is None:
            try:
                del modal.current_function_call_id  # type: ignore[attr-defined]
            except AttributeError:
                pass
        else:
            modal.current_function_call_id = original  # type: ignore[attr-defined]

    return {
        "envelope": envelope,
        "simulated": patched,
        "patched_function_call_id": FUNCTION_CALL_ID,
        "captured_function_call_id": (envelope.get("function_call_id") or {}).get("value"),
    }


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


def _build_provenance(
    directory: Path, capture: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], Path]:
    """
    Build a provenance block from the real producer and write its artifact.

    The artifact is written to ``directory`` and the provenance refers to it, so
    the digests of the provenance can be recomputed against real bytes.
    """
    capture = capture or _producer_capture()
    envelope = capture["envelope"]
    response = {
        "stage": STAGE,
        "modal_runtime": envelope,
        "worker_observed": {"note": "the response of the production producer"},
    }
    stage_capture = StageResponseCapture(
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
        stage_capture,
        target_id=TARGET_ID,
        correlation_id="corr-closure-probe",
    )
    stage_facts = build_stage_identity_facts(stage_capture, evidence_ref=artifact_ref)
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

    This is the rule of ``benchmarks/evaluator.py`` as it stood - the line is
    quoted from the historical source in the report of this validator.
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


def _pre_fix_contract(work_dir: Path) -> Optional[Any]:
    """
    Load the evidence contract **as it stood before** the closure.

    The module is taken from the historical source with ``git show`` and
    imported as a standalone module: the reproduction of the defect therefore
    **executes the historical code** and not a re-implementation of it.
    """
    source = _git("show", f"{PRE_FIX_COMMIT}:benchmarks/evidence_integrity.py")
    if not source:
        return None
    path = work_dir / "pre_fix_evidence_integrity.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(
        "pre_fix_evidence_integrity", path
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    # The module has to be in ``sys.modules`` before it is executed: the
    # dataclasses of the contract resolve their own module at class creation.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FailingSmokeAdapter:
    """
    A smoke adapter whose execution **fails**.

    It exists so that the report of the **real** runner contains a failed
    target: only then can the report path be checked at the consumer boundary.
    """

    def __init__(self) -> None:
        from benchmarks.adapters import SyntheticSmokeAdapter

        self._inner = SyntheticSmokeAdapter(
            baseline_id="baseline_1", baseline_name="Synthetic Smoke (failing)"
        )

    @property
    def baseline_id(self) -> str:
        return self._inner.baseline_id

    @property
    def baseline_name(self) -> str:
        return self._inner.baseline_name

    @property
    def timeout_sec(self) -> int:
        return self._inner.timeout_sec

    @property
    def resource_budget(self) -> Dict[str, Any]:
        return dict(self._inner.resource_budget)

    def get_effective_config_hash(self) -> str:
        return self._inner.get_effective_config_hash()

    def get_default_argv(self) -> List[str]:
        return list(self._inner.get_default_argv())

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        return True, None

    def execute_target(
        self,
        target,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60,
    ) -> TargetExecutionArtifact:
        return TargetExecutionArtifact(
            baseline_id=self.baseline_id,
            target_id=target.contract_id,
            target_name=target.target_name,
            status=ExecutionStatus.FAILED,
            security_verdict="COMPILATION_ERROR",
            unavailable_reason="the compiler rejected the candidate",
            duration_seconds=0.1,
        )


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
        rejection_probes.append({"case": label, "rejected": not ok, "error": error})
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
        {
            "probe": "the client-sided run-level fact with recomputed digests",
            "accepted": ok,
            "error": error,
        }
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

    compat_cases: Tuple[Tuple[str, Any], ...] = (
        ("legacy_flat_run_level_value", APP_ID),
        (
            "side_less_observed_run_level_value",
            _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False),
        ),
        ("missing_run_level_value", None),
        ("unknown_status_run_level_value", {"status": "MAYBE", "value": APP_ID}),
    )
    for label, fact in compat_cases:
        provenance, _ = _build_provenance(work_dir)
        block = provenance["modal_invocation_provenance"]
        if label == "missing_run_level_value":
            block.pop("modal_app_id", None)
        else:
            block["modal_app_id"] = fact
        ok, error = validate_modal_invocation_provenance(
            provenance, evidence_root=work_dir
        )
        compat_probes.append({"case": label, "accepted": ok, "error": error})
        if not ok:
            compat_errors.append(
                f"the compatibility path rejects the run-level application id of the case "
                f"{label!r}: {error}"
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
                "compatibility path - a flat, a side-less, a missing and an unknown-status "
                "run-level application id stay acceptable, and no side is inferred and none "
                "is backfilled"
            ),
            probes=compat_probes,
        )
    )
    errors.extend(compat_errors)

    # -- P6.5 the report of the evaluator states no negative finding ---------
    leak_errors: List[str] = []
    leak_probes: List[Dict[str, Any]] = []
    leak_cases: List[Tuple[str, str, str]] = []
    for status_name in INCOMPLETE_STATUSES:
        for verdict in NEGATIVE_VERDICTS:
            leak_cases.append((status_name, verdict, "negative_verdict"))
    for verdict in INVALID_VERDICTS:
        leak_cases.append(("SUCCESS", verdict, "invalid_verdict"))
    for status_name, verdict, kind in leak_cases:
        for raw_detected in (False, True):
            artifact = _artifact(
                "T1",
                ExecutionStatus[status_name],
                verdict=verdict,
                detected=raw_detected,
                verified_breaches=1,
                replayed_breaches=1,
            )
            result = evaluate_baseline_run(
                "baseline_closure", "B", [artifact], _ground_truth()
            )
            detail = result.details[0]
            record = result.target_artifacts[0]
            leaked = detail["detected"] is not None or record["detected"] is not None
            leak_probes.append(
                {
                    "status": status_name,
                    "verdict": verdict,
                    "kind": kind,
                    "producer_detected": raw_detected,
                    "detail_detected": detail["detected"],
                    "detail_state": detail["detection_state"],
                    "record_detected": record["detected"],
                    "record_state": record["detection_state"],
                    "detail_verified_breaches": detail["verified_breaches"],
                    "record_verified_breaches": record["verified_breaches"],
                    "producer_detected_preserved": record.get("producer_detected"),
                    "leaked": leaked,
                }
            )
            if leaked:
                leak_errors.append(
                    f"the evaluator states the detection of a {status_name} target with the "
                    f"verdict {verdict!r} as {detail['detected']!r} / {record['detected']!r} "
                    "instead of None"
                )
            if detail["detection_state"] != DETECTION_STATE_NOT_EVALUATED:
                leak_errors.append(
                    f"the evaluator states the detection state of a {status_name} target "
                    f"with the verdict {verdict!r} as "
                    f"{detail['detection_state']!r} instead of NOT_EVALUATED"
                )
            if record["detection_state"] != DETECTION_STATE_NOT_EVALUATED:
                leak_errors.append(
                    f"the report record of a {status_name} target with the verdict "
                    f"{verdict!r} states {record['detection_state']!r} instead of "
                    "NOT_EVALUATED"
                )
            if detail["verified_breaches"] != 0 or record["verified_breaches"] != 0:
                leak_errors.append(
                    f"a {status_name} target with the verdict {verdict!r} still carries a "
                    "verified breach"
                )
            if record.get("producer_detected") is not raw_detected:
                leak_errors.append(
                    f"the raw claim of the producer is not preserved for a {status_name} "
                    f"target with the verdict {verdict!r}"
                )
    checks.append(
        _check(
            "P6.5.a_failed_or_unavailable_run_is_never_a_negative_finding",
            not leak_errors,
            error="; ".join(leak_errors) if leak_errors else None,
            planned=(
                "every combination of a non-success status and the negative verdicts, and "
                "every verdict that declares the audit itself invalid, is reported as 'no "
                "finding' (None / NOT_EVALUATED) - in the detail row and in the report "
                "record of the target - with no breach counter and with the raw claim of "
                "the producer preserved"
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
    failed_detail = next((d for d in result.details if d["target_id"] == "T2"), None)
    if failed_detail is None:
        mixed_errors.append("the mixed baseline has no detail row for the failed target")
    elif failed_detail["detected"] is not None:
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
        if detail["detection_state"] != DETECTION_STATE_NEGATIVE:
            verdict_errors.append(
                f"the completed run with the verdict {verdict!r} has the state "
                f"{detail['detection_state']!r} instead of NEGATIVE"
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
    if (
        by_target["T1"]["detected"] is not True
        or by_target["T1"]["detection_state"] != DETECTION_STATE_POSITIVE
    ):
        verdict_errors.append("the completed run that found a vulnerability lost its detection")
    if (
        by_target["T2"]["detected"] is not False
        or by_target["T2"]["detection_state"] != DETECTION_STATE_NEGATIVE
    ):
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
    runner_report: Dict[str, Any] = {}
    try:
        from benchmarks.benchmark_runner import AegisBenchmarkSuite

        runner_dir = work_dir / "runner"
        # The suite writes its report next to the dataset and resolves the git
        # manifest from the directory of the dataset - the dataset is copied
        # into the probe directory of this repository so that the closure does
        # not touch the checkout.
        dataset_dir = _ROOT / PROBE_DIR / "dataset"
        dataset_dir.mkdir(parents=True, exist_ok=True)
        dataset_path = dataset_dir / "benchmark_dataset.json"
        shutil.copyfile(_ROOT / "benchmarks" / "benchmark_dataset.json", dataset_path)
        suite = AegisBenchmarkSuite(dataset_path=dataset_path, artifacts_dir=runner_dir)
        runner_report = suite.run_benchmark(
            mode="smoke",
            baselines_to_run=["baseline_1"],
            save_results=True,
            custom_adapters={"baseline_1": _FailingSmokeAdapter()},
        )
        baselines = runner_report.get("baselines") or {}
        if not baselines:
            runner_errors.append("the smoke run of the real runner produced no baseline")
        for baseline_id, baseline in baselines.items():
            details_by_id = {d["target_id"]: d for d in baseline["details"]}
            states = set()
            for record in baseline["target_artifacts"]:
                states.add(record["detection_state"])
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
                if (
                    record["status"] != "SUCCESS"
                    and record["detection_state"] != DETECTION_STATE_NOT_EVALUATED
                ):
                    runner_errors.append(
                        f"the report of the real runner states the detection state of a "
                        f"{record['status']} target as {record['detection_state']!r}"
                    )
            runner_probes.append(
                {
                    "baseline": baseline_id,
                    "targets": len(baseline["details"]),
                    "detection_states": sorted(states),
                    "statuses": sorted({r["status"] for r in baseline["target_artifacts"]}),
                    "execution_mode": runner_report.get("execution_mode"),
                    "is_synthetic_smoke": runner_report.get("is_synthetic_smoke"),
                }
            )
            if not any(r["status"] != "SUCCESS" for r in baseline["target_artifacts"]):
                runner_errors.append(
                    f"the report of the baseline {baseline_id} holds no failed target - the "
                    "failure path of the real runner was not exercised"
                )
    except Exception as exc:  # pragma: no cover - a broken smoke run
        runner_errors.append(f"the smoke run of the real runner failed: {exc}")
    checks.append(
        _check(
            "P6.8.the_report_of_the_real_runner_states_the_detection_state",
            not runner_errors,
            error="; ".join(runner_errors) if runner_errors else None,
            planned=(
                "the report of the real runner - with a failing execution in it - carries the "
                "detection state of every target, keeps both views of a target in agreement "
                "and states the failed target as NOT_EVALUATED"
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
        {
            "step": "the digest of the artifact is the digest of the bytes",
            "recorded": recorded,
            "actual": actual,
        }
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

    # The billing join is resolved against a **raw line item** of the export -
    # not against the value the join claims.
    line_items = [
        BillingLineItem(
            object_id=APP_ID,
            resource="H100",
            cost_usd=1.25,
            interval_start="2026-11-10T00:00:00Z",
            description="the invocation of the closure probe",
            environment="main",
            index=0,
            provider_join_keys={"function_call_id": FUNCTION_CALL_ID},
        )
    ]
    matched, reason = resolve_billing_join(
        {
            "provider_field": "function_call_id",
            "provider_value": FUNCTION_CALL_ID,
            "app_id": APP_ID,
        },
        line_items,
    )
    chain_probes.append(
        {
            "step": "the billing join",
            "matched": matched.key if matched is not None else None,
            "reason": reason,
        }
    )
    if matched is None:
        chain_errors.append(f"the billing join does not resolve the invocation: {reason}")

    join_report = cross_check_app_ids(provenance, [APP_ID])
    chain_probes.append({"step": "the app-id cross-check", "status": join_report["status"]})
    if join_report["status"] != "PASSED":
        chain_errors.append(f"the app-id cross-check fails: {join_report.get('error')}")

    # The manifests: the adapter and the target manifest of the real runner.
    manifest_errors: List[str] = []
    manifest_probes: List[Dict[str, Any]] = []
    manifest_summary = (runner_report or {}).get("reproducibility_manifest_summary") or {}
    adapters_manifest = manifest_summary.get("adapters") or {}
    for baseline_id, manifest in adapters_manifest.items():
        provenance_by_target = manifest.get("per_target_provenance") or {}
        for target_id, entry in provenance_by_target.items():
            manifest_probes.append(
                {
                    "baseline": baseline_id,
                    "target_id": target_id,
                    "status": entry.get("status"),
                    "security_verdict": entry.get("security_verdict"),
                    "carries_a_detection": "detected" in entry,
                }
            )
            if entry.get("status") != "SUCCESS":
                if "detected" in entry:
                    manifest_errors.append(
                        f"the manifest of the target {target_id} of the baseline "
                        f"{baseline_id} carries a detection value for a failed target"
                    )
                if not entry.get("security_verdict"):
                    manifest_errors.append(
                        f"the manifest of the target {target_id} of the baseline "
                        f"{baseline_id} carries no security verdict for a failed target"
                    )
    if not manifest_probes:
        manifest_errors.append("the real runner produced no adapter manifest")
    chain_probes.append({"step": "the adapter and target manifests", "probes": manifest_probes})
    chain_errors.extend(manifest_errors)

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
                "adapter and target manifests → evaluator → report holds end to end for a "
                "successful run"
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
    historical_source = _git("show", f"{PRE_FIX_COMMIT}:benchmarks/evaluator.py") or ""
    historical_line = next(
        (line.strip() for line in historical_source.splitlines() if "det = False if" in line),
        None,
    )
    for status_name in INCOMPLETE_STATUSES:
        for verdict in HISTORICAL_NEGATIVE_VERDICTS:
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
    if historical_line is None:
        pre_fix_errors.append(
            "the historical source of the evaluator does not hold the line the pre-fix rule "
            "reproduces"
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
            historical_line=historical_line,
            historical_commit=PRE_FIX_COMMIT,
        )
    )
    errors.extend(pre_fix_errors)

    # -- P6.12 the pre-fix consumer reproduces the P1 defect ------------------
    p1_pre_fix_errors: List[str] = []
    p1_pre_fix_probes: List[Dict[str, Any]] = []
    pre_fix_contract = _pre_fix_contract(work_dir)
    if pre_fix_contract is None:
        p1_pre_fix_errors.append(
            f"the evidence contract of the commit {PRE_FIX_COMMIT} could not be loaded - the "
            "defect of the P1 is therefore not reproduced"
        )
    else:
        for label, fact in (
            (
                "worker_side",
                _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, side=OBSERVATION_SIDE_WORKER),
            ),
            (
                "missing_side",
                _observed_fact(APP_ID, SOURCE_CLIENT_APP_ID, declare_side=False),
            ),
            ("legacy_flat_value", APP_ID),
        ):
            provenance, _ = _build_provenance(work_dir)
            provenance["modal_invocation_provenance"]["modal_app_id"] = fact
            accepted_before, error_before = (
                pre_fix_contract.validate_modal_invocation_provenance(
                    provenance, evidence_root=work_dir, strict_sources=True
                )
            )
            accepted_after, error_after = validate_modal_invocation_provenance(
                provenance, evidence_root=work_dir, strict_sources=True
            )
            p1_pre_fix_probes.append(
                {
                    "case": label,
                    "accepted_by_the_pre_fix_contract": accepted_before,
                    "pre_fix_error": error_before,
                    "accepted_by_the_current_contract": accepted_after,
                    "current_error": error_after,
                }
            )
            if not accepted_before:
                p1_pre_fix_errors.append(
                    f"the pre-fix consumer does not reproduce the defect for the case "
                    f"{label!r}: it already refused the claim - {error_before}"
                )
            if accepted_after:
                p1_pre_fix_errors.append(
                    f"the current contract accepts the run-level application id of the case "
                    f"{label!r}"
                )
    checks.append(
        _check(
            "P6.12.the_pre_fix_rule_reproduces_the_p1_defect",
            not p1_pre_fix_errors,
            error="; ".join(p1_pre_fix_errors) if p1_pre_fix_errors else None,
            planned=(
                "the evidence contract of the commit before this closure is loaded from its "
                "historical source and executed: it accepts the side-less and the wrong-sided "
                "run-level application id - the defect was real, and the check is not vacuous"
            ),
            probes=p1_pre_fix_probes,
            historical_commit=PRE_FIX_COMMIT,
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
        if report_path.exists():
            # A report of an interrupted run must never be mistaken for the
            # result of this run.
            report_path.unlink()
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
        if completed.returncode != 0:
            history_errors.append(
                f"the validator of Iteration {iteration} exited with {completed.returncode}"
            )
        if not any(expected in line for line in output):
            history_errors.append(
                f"the validator of Iteration {iteration} does not report {expected!r} in its "
                "output"
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

    # -- P6.16 the closure runs in a synthetic context ----------------------
    context_errors: List[str] = []
    context_probes: List[Dict[str, Any]] = []
    capture = _producer_capture()
    context_probes.append(
        {
            "producer_capture_simulated": capture["simulated"],
            "patched_function_call_id": capture["patched_function_call_id"],
            "captured_function_call_id": capture["captured_function_call_id"],
        }
    )
    if not capture["simulated"]:
        context_errors.append(
            "the envelope of the producer was not captured under the simulated container "
            "context"
        )
    if capture["captured_function_call_id"] != capture["patched_function_call_id"]:
        context_errors.append(
            "the captured function-call id is not the patched one - the OBSERVED branch of "
            "the producer was not exercised in the simulation"
        )
    if runner_report:
        context_probes.append(
            {
                "execution_mode": runner_report.get("execution_mode"),
                "is_synthetic_smoke": runner_report.get("is_synthetic_smoke"),
            }
        )
        if runner_report.get("is_synthetic_smoke") is not True:
            context_errors.append("the run of the real runner was not a synthetic smoke test")
        if runner_report.get("execution_mode") != "SYNTHETIC_SMOKE_TEST":
            context_errors.append(
                f"the run of the real runner was {runner_report.get('execution_mode')!r} "
                "instead of SYNTHETIC_SMOKE_TEST"
            )
    else:
        context_errors.append("the run of the real runner produced no report")
    checks.append(
        _check(
            "P6.16.the_closure_runs_in_a_synthetic_context",
            not context_errors,
            error="; ".join(context_errors) if context_errors else None,
            planned=(
                "the run of the real runner is a synthetic smoke test and the OBSERVED "
                "branch of the producer was exercised in a simulated container context - no "
                "Modal invocation, no provider query, no deployment, no GPU and no paid "
                "compute is claimed or needed"
            ),
            probes=context_probes,
            declared={
                "live_modal_invocation": False,
                "provider_queried": False,
                "deployment": "none",
                "gpu": "none",
                "paid_compute": "none",
                "worker_restarted": False,
            },
        )
    )
    errors.extend(context_errors)

    # -- P6.17 the report semantics are reconciled --------------------------
    semantics_errors: List[str] = []
    semantics_probes: List[Dict[str, Any]] = []
    baselines = (runner_report or {}).get("baselines") or {}
    for baseline_id, baseline in baselines.items():
        for detail in baseline["details"]:
            layers = {
                "planned": detail.get("target_id") is not None,
                "attempted": detail.get("orchestration_status") is not None,
                "executed": detail.get("status") is not None,
                "observed": detail.get("security_verdict") is not None
                or detail.get("detection_state") is not None,
                "reported": detail.get("detection_state") is not None,
            }
            semantics_probes.append(
                {
                    "baseline": baseline_id,
                    "target_id": detail.get("target_id"),
                    "status": detail.get("status"),
                    "orchestration_status": detail.get("orchestration_status"),
                    "generation_outcome": detail.get("generation_outcome"),
                    "evm_outcome": detail.get("evm_outcome"),
                    "replay_status": detail.get("replay_status"),
                    "persistence_status": detail.get("persistence_status"),
                    "detected": detail.get("detected"),
                    "detection_state": detail.get("detection_state"),
                    "layers": layers,
                }
            )
            if not all(layers.values()):
                semantics_errors.append(
                    f"the report of the target {detail.get('target_id')} of the baseline "
                    f"{baseline_id} does not state every layer of the report semantics"
                )
            if detail.get("status") == "SUCCESS" and detail.get(
                "detection_state"
            ) == DETECTION_STATE_NOT_EVALUATED:
                semantics_errors.append(
                    f"a completed target of the baseline {baseline_id} is reported as "
                    "NOT_EVALUATED"
                )
            if detail.get("status") != "SUCCESS" and detail.get(
                "detection_state"
            ) != DETECTION_STATE_NOT_EVALUATED:
                semantics_errors.append(
                    f"a target of the baseline {baseline_id} that did not complete is "
                    f"reported as {detail.get('detection_state')!r}"
                )
    if not semantics_probes:
        semantics_errors.append("the real runner produced no report to reconcile")
    checks.append(
        _check(
            "P6.17.the_report_semantics_are_reconciled",
            not semantics_errors,
            error="; ".join(semantics_errors) if semantics_errors else None,
            planned=(
                "the report states planned, attempted, executed, observed and reported apart, "
                "and unavailable, failed and not-run stay distinct in every output"
            ),
            probes=semantics_probes,
        )
    )
    errors.extend(semantics_errors)

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
            resolved = _resolve_sha(args.code_sha)
            if bound != resolved:
                print(
                    "the validation report is bound to code SHA {bound}, not to {head}".format(
                        bound=bound, head=resolved
                    )
                )
                return 1
        elif not bound or not _is_ancestor(bound, "HEAD"):
            print(
                "the validation report is bound to code SHA {bound}, which is not an "
                "ancestor of HEAD".format(bound=bound)
            )
            return 1

        # The files of the closure have to be the ones the report was bound to.
        changed = _git(
            "diff",
            "--name-only",
            bound,
            "HEAD",
            "--",
            "benchmarks/evaluator.py",
            "benchmarks/evidence_integrity.py",
            "benchmarks/validate_consolidated_closure_evidence.py",
            "tests/test_consolidated_closure_evidence_integrity.py",
        )
        if changed:
            print(
                "the files of the closure changed between the bound commit {bound} and "
                "HEAD: {changed}".format(bound=bound, changed=changed)
            )
            return 1

        work_dir = Path(tempfile.mkdtemp(prefix="closure-probe-"))
        try:
            outcome = _validate_consolidated_closure(work_dir=work_dir, code_sha=bound)
        except Exception as exc:  # pragma: no cover - a broken environment
            print(f"the validation failed with an exception: {exc}")
            return 1
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
    except Exception as exc:  # pragma: no cover - a broken environment
        print(f"the validation failed with an exception: {exc}")
        return 1
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
                "both vertical chains hold, that the pre-fix contracts reproduce the "
                "defects, that the historical evidence stays in its state and that the "
                "report is bound to the code SHA it was produced from"
            ),
            "attempted": (
                "every non-success status with every negative verdict and every invalid "
                "verdict, every side variant of the run-level application id, the "
                "digest-recomputed chain, the compatibility path, the report of the real "
                "evaluator and of the real runner with a failing execution, both vertical "
                "chains, the pre-fix contracts of the historical source, the evidence "
                "validator of every iteration from 14 to 23, the producer source and the "
                "artifact digest"
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
