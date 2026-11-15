"""
benchmarks/validate_iteration23_evidence.py
============================================

Fresh-state validation of the **registered observation side** in the strict
stage validation (Iteration 23).

The Iteration 22 review kept one narrow validator gap open as a P1: the strict
stage loop of ``validate_modal_invocation_provenance()`` called
``validate_provider_observation_source(key, fact, expected_side="worker",
require_side=True)`` for **every** key of ``PROVIDER_OBSERVATION_SOURCES``.
The registry registers ``function_call_id`` as worker-side, but ``app_id``,
``app_page_url`` and ``container_id`` as **client**-side - so a correctly
typed, correctly sourced and correctly sided client-side stage fact was
rejected as contradictory. The strict consumer overrode the registry with a
hardcoded side.

This validator checks the fix and the evidence of it:

* the strict consumer **accepts** a stage that holds a worker-observed
  ``function_call_id`` and client-observed ``app_id``, ``app_page_url`` and
  ``container_id`` - the registered side is honoured;
* the strict consumer **rejects** the same facts with a missing, a ``null``,
  an unknown and the wrong side - the cross-side direction stays closed;
* the separate rule that a **worker runtime-identity envelope** may never
  carry a client observation is **preserved**;
* the rejection of a wrong side comes from the side rule and not from a stale
  digest: the artifact is rewritten, the digests are **recomputed** from the
  bytes on disk, and the very same artifact is accepted once the side is right;
* the published capture of Iteration 21 - the producer names the side of every
  fact - still passes the strict mode, and the producer source is **byte-wise
  unchanged** since the commit the capture was made from;
* the digest of the stage evidence artifact is the digest of the bytes on
  disk;
* the historical evidence of Iterations 20, 21 and 22 still satisfies its own
  validator;
* the **pre-fix** rule - the hardcoded ``worker`` side - is reproduced inside
  the validator and still rejects the correctly sided client fact: the defect
  was real and the checks are not vacuous;
* the report is bound to the code SHA it was produced from; ``--check``
  refuses a foreign SHA.

**Boundaries.** No Modal invocation is made, the provider is never queried, no
worker is deployed, restarted or modified, no GPU is used and no paid compute
is spent. The ``OBSERVED`` branch of the producer is exercised in a
**simulated** container context - a patched ``modal.current_function_call_id``
- and is called a simulation wherever it is mentioned.

The capture this iteration re-reads is the **local** capture of Iteration 21:
the producer is not changed by this iteration, so no new capture is made.

Usage::

    python -m benchmarks.validate_iteration23_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration23_evidence --check
"""

from __future__ import annotations

import argparse
import json
import shutil
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
    PROVIDER_OBSERVATION_SOURCES,
    SOURCE_CLIENT_APP_ID,
    SOURCE_CLIENT_APP_PAGE_URL,
    SOURCE_CLIENT_CONTAINER_ID,
    SOURCE_WORKER_FUNCTION_CALL_ID,
    StageResponseCapture,
    build_modal_stage_provenance,
    build_stage_identity_facts,
    canonical_json_bytes,
    file_sha256,
    not_available,
    observed,
    sha256_bytes,
    validate_client_observed_facts,
    validate_modal_invocation_provenance,
    validate_observation_side,
    validate_provider_observation_source,
    validate_runtime_identity_envelope,
    write_stage_evidence_artifact,
)

# The git helpers of the Iteration 16 validator are reused unchanged.
from benchmarks.validate_iteration16_evidence import (  # noqa: E402
    _current_code_sha,
    _git,
    _is_ancestor,
    _resolve_sha,
)

#: The capture this iteration re-reads. The producer is not changed by
#: Iteration 23, so the local capture of Iteration 21 - which was made with a
#: hostile environment and without a provider-issued identifier - stays the
#: capture of the producer.
DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration21_producer_capture"
DEFAULT_REPORT = "benchmarks/evidence/iteration23_validation_evidence.json"

STAGE = "evm_sandbox"
TARGET_ID = "ITER23-01"

#: The producer source file.
PRODUCER_SOURCE = _ROOT / "modal_app.py"

#: The provider-issued identifiers the probes work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
APP_PAGE_URL = f"https://modal.com/id/{APP_ID}"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"

#: The registered client-side fields, with their registered source and value.
CLIENT_FIELDS: Tuple[Tuple[str, str, str], ...] = (
    ("app_id", SOURCE_CLIENT_APP_ID, APP_ID),
    ("app_page_url", SOURCE_CLIENT_APP_PAGE_URL, APP_PAGE_URL),
    ("container_id", SOURCE_CLIENT_CONTAINER_ID, CONTAINER_ID),
)

#: The value every registered field carries in the probes.
FIELD_VALUES: Dict[str, str] = {
    "function_call_id": FUNCTION_CALL_ID,
    "app_id": APP_ID,
    "app_page_url": APP_PAGE_URL,
    "container_id": CONTAINER_ID,
}


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


def _observed_fact(
    value: str,
    source: str,
    *,
    side: Optional[str] = None,
    declare_side: bool = True,
) -> Dict[str, Any]:
    """A synthetic observed fact - a probe, and always called one."""
    fact: Dict[str, Any] = {"status": OBSERVED, "value": value, "source": source}
    if declare_side:
        fact["observed_by"] = side
    return fact


def _producer_envelope() -> Dict[str, Any]:
    """
    The envelope of the **real** producer in a simulated container context.

    ``modal.current_function_call_id`` is patched to return a fixed id: the
    ``OBSERVED`` branch of the producer is therefore exercised in a
    simulation, not in a live Modal container.
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
            modal.current_function_call_id = original  # type: ignore[assignment]


def _client_block() -> Dict[str, Any]:
    """The client-observed block of a run."""
    return {
        "app_id": observed(
            APP_ID,
            source=SOURCE_CLIENT_APP_ID,
            observed_by=OBSERVATION_SIDE_CLIENT,
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


def _build_provenance(tmp_dir: Path) -> Tuple[Dict[str, Any], Path]:
    """
    Build a provenance block from the real producer and write its artifact.

    The artifact is written to ``tmp_dir`` and the provenance refers to it, so
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
        tmp_dir,
        capture,
        target_id=TARGET_ID,
        correlation_id="corr-iteration23-probe",
    )
    stage_facts = build_stage_identity_facts(capture, evidence_ref=artifact_ref)
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "correlation_id": "corr-iteration23-probe",
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
    """
    Rewrite the artifact with a different byte layout.

    The content stays the same, the bytes do not - so the digest of the file
    changes and a provenance that still holds the old digest is stale.
    """
    payload = _read_json(artifact_path)
    artifact_path.write_bytes(
        json.dumps(payload, indent=4, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    return artifact_path


def _stage_of(provenance: Dict[str, Any]) -> Dict[str, Any]:
    """The stage of the provenance block."""
    return provenance["modal_invocation_provenance"]["stages"][STAGE]


def _bound_code_sha(report_rel_path: str) -> Optional[str]:
    """The code SHA a published validation report is bound to."""
    path = _ROOT / report_rel_path
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("code_sha")
    except (OSError, ValueError):
        return None


def _pre_fix_stage_side(field_name: str, fact: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    The rule of the strict stage loop **before** this iteration.

    The pre-fix loop called the helper with a hardcoded ``worker`` side for
    every registered field. This is the reproduction of that rule.
    """
    return validate_provider_observation_source(
        field_name,
        fact,
        expected_side=OBSERVATION_SIDE_WORKER,
        require_side=True,
    )


def _validate_iteration23(
    *,
    evidence_dir: Path,
    code_sha: Optional[str],
    work_dir: Path,
) -> Dict[str, Any]:
    """Run every Iteration 23 check over the artifacts stored on disk."""
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []

    record_path = evidence_dir / "capture_record.json"
    if not record_path.is_file():
        message = f"the capture record does not exist: {record_path}"
        checks.append(
            _check("P5.0.capture_present", False, error=message, planned="a capture exists")
        )
        return {"checks": checks, "errors": [message], "record": {}, "artifact": {}}

    record = _read_json(record_path)

    # -- P5.1 the strict consumer accepts the registered side ---------------
    accept_errors: List[str] = []
    accept_probes: List[Dict[str, Any]] = []
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        provenance, artifact_path = _build_provenance(work_dir)
        stage = _stage_of(provenance)
        stage[field_name] = _observed_fact(
            FIELD_VALUES[field_name],
            registered["source"],
            side=registered["side"],
        )
        ok, error = validate_modal_invocation_provenance(
            provenance,
            evidence_root=work_dir,
            strict_sources=True,
        )
        accept_probes.append(
            {
                "field": field_name,
                "registered_side": registered["side"],
                "accepted": ok,
                "error": error,
            }
        )
        if not ok:
            accept_errors.append(
                f"the strict consumer rejects the correctly sided stage fact for "
                f"'{field_name}' (registered side {registered['side']!r}): {error}"
            )
    checks.append(
        _check(
            "P5.1.the_strict_consumer_accepts_the_registered_side_of_every_field",
            not accept_errors,
            error="; ".join(accept_errors) if accept_errors else None,
            planned=(
                "the side of a stage fact is the side registered for its field: the worker "
                "field 'function_call_id' and the client fields 'app_id', 'app_page_url' and "
                "'container_id' are accepted with their own registered side"
            ),
            probes=accept_probes,
        )
    )
    errors.extend(accept_errors)

    # -- P5.2 the missing, null and unknown side are rejected ----------------
    omission_errors: List[str] = []
    omission_probes: List[Dict[str, Any]] = []
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        for label, kwargs in (
            ("missing", {"declare_side": False}),
            ("null", {"side": None}),
            ("unknown", {"side": "oracle"}),
        ):
            provenance, _ = _build_provenance(work_dir)
            stage = _stage_of(provenance)
            stage[field_name] = _observed_fact(
                FIELD_VALUES[field_name],
                registered["source"],
                **kwargs,
            )
            ok, error = validate_modal_invocation_provenance(
                provenance,
                evidence_root=work_dir,
                strict_sources=True,
            )
            omission_probes.append(
                {"field": field_name, "side": label, "rejected": not ok, "error": error}
            )
            if ok:
                omission_errors.append(
                    f"the strict consumer accepts the stage fact for '{field_name}' whose side "
                    f"is {label}"
                )
    checks.append(
        _check(
            "P5.2.the_missing_null_and_unknown_side_are_rejected",
            not omission_errors,
            error="; ".join(omission_errors) if omission_errors else None,
            planned=(
                "an observed stage fact has to name the side that observed it - a missing, a "
                "'null' and an unknown side are rejected for every registered field"
            ),
            probes=omission_probes,
        )
    )
    errors.extend(omission_errors)

    # -- P5.3 the cross-side direction stays closed --------------------------
    cross_errors: List[str] = []
    cross_probes: List[Dict[str, Any]] = []
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        wrong_side = (
            OBSERVATION_SIDE_WORKER
            if registered["side"] == OBSERVATION_SIDE_CLIENT
            else OBSERVATION_SIDE_CLIENT
        )
        provenance, _ = _build_provenance(work_dir)
        stage = _stage_of(provenance)
        stage[field_name] = _observed_fact(
            FIELD_VALUES[field_name],
            registered["source"],
            side=wrong_side,
        )
        ok, error = validate_modal_invocation_provenance(
            provenance,
            evidence_root=work_dir,
            strict_sources=True,
        )
        cross_probes.append(
            {
                "field": field_name,
                "registered_side": registered["side"],
                "declared_side": wrong_side,
                "rejected": not ok,
                "error": error,
            }
        )
        if ok:
            cross_errors.append(
                f"the strict consumer accepts the stage fact for '{field_name}' that names the "
                f"side {wrong_side!r} although the registered side is {registered['side']!r}"
            )
    checks.append(
        _check(
            "P5.3.the_cross_side_direction_stays_closed",
            not cross_errors,
            error="; ".join(cross_errors) if cross_errors else None,
            planned=(
                "a client field may not be presented as a worker observation and the worker "
                "field may not be presented as a client observation"
            ),
            probes=cross_probes,
        )
    )
    errors.extend(cross_errors)

    # -- P5.4 a worker envelope may not carry a client observation ----------
    envelope_errors: List[str] = []
    envelope_probes: List[Dict[str, Any]] = []
    for field_name, source, value in CLIENT_FIELDS:
        fact = _observed_fact(value, source, side=OBSERVATION_SIDE_CLIENT)
        ok, error = validate_runtime_identity_envelope(
            {field_name: fact},
            strict_sources=True,
        )
        envelope_probes.append(
            {"field": field_name, "rejected": not ok, "error": error}
        )
        if ok:
            envelope_errors.append(
                f"a worker runtime-identity envelope accepts the client observation of "
                f"'{field_name}'"
            )
        side_ok, side_error = validate_observation_side(
            fact,
            expected_side=OBSERVATION_SIDE_WORKER,
        )
        if side_ok:
            envelope_errors.append(
                f"the worker envelope rule accepts a client observation of '{field_name}'"
            )
    checks.append(
        _check(
            "P5.4.a_worker_envelope_may_not_carry_a_client_observation",
            not envelope_errors,
            error="; ".join(envelope_errors) if envelope_errors else None,
            planned=(
                "the rule that a worker runtime-identity envelope is worker-side by "
                "construction is preserved - the fix of this iteration changes the stage "
                "validation only"
            ),
            probes=envelope_probes,
        )
    )
    errors.extend(envelope_errors)

    # -- P5.5 the rejection comes from the side rule, not from a digest ------
    digest_errors: List[str] = []
    digest_probes: List[Dict[str, Any]] = []

    provenance, artifact_path = _build_provenance(work_dir)
    stage = _stage_of(provenance)
    stage["app_id"] = _observed_fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_CLIENT,
    )
    artifact_path = _rewrite_artifact(artifact_path)
    _rebuild_digests(provenance, artifact_path)

    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=work_dir,
        strict_sources=True,
    )
    digest_probes.append(
        {"probe": "the client-sided stage fact with recomputed digests", "accepted": ok, "error": error}
    )
    if not ok:
        digest_errors.append(
            f"the strict consumer rejects the correctly sided stage fact after the digests "
            f"were recomputed: {error}"
        )

    # The same artifact with a wrong side: the digests are the same, so the
    # rejection can only come from the side rule.
    stage["app_id"] = _observed_fact(
        APP_ID,
        SOURCE_CLIENT_APP_ID,
        side=OBSERVATION_SIDE_WORKER,
    )
    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=work_dir,
        strict_sources=True,
    )
    digest_probes.append(
        {"probe": "the same artifact with the wrong side", "accepted": ok, "error": error}
    )
    if ok:
        digest_errors.append(
            "the strict consumer accepts a stage fact that names the worker side although the "
            "registered side of 'app_id' is the client side"
        )
    elif "digest" in (error or "").lower():
        digest_errors.append(
            f"the rejection of the wrong side came from a digest and not from the side rule: "
            f"{error}"
        )

    checks.append(
        _check(
            "P5.5.the_rejection_comes_from_the_side_rule_and_not_from_a_stale_digest",
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

    # -- P5.6 the published capture passes the strict mode -------------------
    capture_errors: List[str] = []
    envelope = record.get("runtime_identity")
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    if not ok:
        capture_errors.append(
            f"the published envelope of Iteration 21 does not pass the strict mode: {error}"
        )
    provenance_artifact = (record.get("provenance") or {}).get("artifact")
    if not isinstance(provenance_artifact, dict):
        capture_errors.append("the capture states no provenance artifact")
    else:
        ok, error = validate_modal_invocation_provenance(
            provenance_artifact,
            evidence_root=evidence_dir,
            strict_sources=True,
        )
        if not ok:
            capture_errors.append(
                f"the published provenance of Iteration 21 does not pass the strict mode: {error}"
            )
    checks.append(
        _check(
            "P5.6.the_published_capture_passes_the_strict_mode",
            not capture_errors,
            error="; ".join(capture_errors) if capture_errors else None,
            planned=(
                "the local capture of Iteration 21 - the producer names the side of every "
                "fact - still passes the strict mode, and no side is backfilled into it"
            ),
        )
    )
    errors.extend(capture_errors)

    # -- P5.7 the producer source is unchanged since the capture -------------
    producer_errors: List[str] = []
    capture_sha = ((record.get("source") or {}).get("code_sha"))
    producer_changed: Optional[bool] = None
    if not isinstance(capture_sha, str) or len(capture_sha) != 40:
        producer_errors.append("the capture names no commit SHA")
    elif not code_sha:
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
            "P5.7.the_producer_source_is_unchanged_since_the_capture",
            not producer_errors,
            error="; ".join(producer_errors) if producer_errors else None,
            planned=(
                "the producer source is byte-wise unchanged between the commit the capture "
                "was made from and the commit the report is bound to - the capture is "
                "therefore still the capture of this producer"
            ),
            capture_code_sha=capture_sha,
            reported_code_sha=code_sha,
            producer_source_changed=producer_changed,
        )
    )
    errors.extend(producer_errors)

    # -- P5.8 the digest of the artifact is the digest of the bytes -----------
    digest_errors = []
    artifact_ref = record.get("evidence_artifact") or {}
    recorded_digest = artifact_ref.get("sha256") if isinstance(artifact_ref, dict) else None
    artifact_rel_path = artifact_ref.get("path") if isinstance(artifact_ref, dict) else None
    actual_digest: Optional[str] = None
    if not artifact_rel_path:
        digest_errors.append("the capture record names no evidence artifact")
    else:
        artifact_file = _ROOT / artifact_rel_path
        if not artifact_file.is_file():
            digest_errors.append(f"the evidence artifact does not exist: {artifact_rel_path}")
        else:
            actual_digest = file_sha256(artifact_file)
            if actual_digest != recorded_digest:
                digest_errors.append(
                    f"the digest of the artifact on disk is {actual_digest}, not {recorded_digest}"
                )
    checks.append(
        _check(
            "P5.8.the_artifact_digest_is_the_digest_of_the_bytes_on_disk",
            not digest_errors,
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the SHA-256 of the stage evidence artifact on disk equals the digest the "
                "capture record claims"
            ),
            recorded_sha256=recorded_digest,
            actual_sha256=actual_digest,
        )
    )
    errors.extend(digest_errors)

    # -- P5.9 the historical evidence stays valid ----------------------------
    history_errors: List[str] = []
    history: List[Dict[str, Any]] = []
    for iteration, module_name, entry_point in (
        (20, "validate_iteration20_evidence", "_validate_iteration20"),
        (21, "validate_iteration21_evidence", "_validate_iteration21"),
        (22, "validate_iteration22_evidence", "_validate_iteration22"),
    ):
        module = __import__(f"benchmarks.{module_name}", fromlist=["_validate_iteration"])
        entry: Dict[str, Any] = {"iteration": iteration}
        kwargs: Dict[str, Any] = {"code_sha": None}
        if iteration == 22:
            # The validator of Iteration 22 verifies that the producer source
            # is unchanged between the commit its capture was made from and the
            # commit its report is bound to - so it needs that binding.
            kwargs["work_dir"] = work_dir
            kwargs["code_sha"] = _bound_code_sha(module.DEFAULT_REPORT)
        try:
            outcome = getattr(module, entry_point)(
                evidence_dir=_ROOT / module.DEFAULT_EVIDENCE_DIR,
                **kwargs,
            )
        except Exception as exc:  # pragma: no cover - a missing artifact
            history_errors.append(
                f"the evidence of Iteration {iteration} could not be validated: {exc}"
            )
            continue
        entry["errors"] = outcome["errors"]
        entry["checks_total"] = len(outcome["checks"])
        entry["code_sha"] = kwargs.get("code_sha")
        history.append(entry)
        if outcome["errors"]:
            history_errors.append(
                f"the evidence of Iteration {iteration} no longer satisfies its own validator: "
                f"{outcome['errors']}"
            )
    checks.append(
        _check(
            "P5.9.the_historical_evidence_stays_valid",
            not history_errors,
            error="; ".join(history_errors) if history_errors else None,
            planned=(
                "the published evidence of Iterations 20, 21 and 22 still satisfies its own "
                "validator - the compatibility path is intact"
            ),
            history=history,
        )
    )
    errors.extend(history_errors)

    # -- P5.10 no live invocation, no deployment, no GPU ----------------------
    invocation = record.get("invocation") or {}
    boundary_errors: List[str] = []
    if invocation.get("live_modal_invocation") is not False:
        boundary_errors.append(
            f"the capture declares live_modal_invocation={invocation.get('live_modal_invocation')!r}, "
            "not False"
        )
    if invocation.get("provider_queried") is not False:
        boundary_errors.append(
            f"the capture declares provider_queried={invocation.get('provider_queried')!r}, not False"
        )
    if invocation.get("deployment") != "none":
        boundary_errors.append(
            f"the capture declares deployment={invocation.get('deployment')!r}, not 'none'"
        )
    if invocation.get("gpu") != "none":
        boundary_errors.append(f"the capture declares gpu={invocation.get('gpu')!r}, not 'none'")
    checks.append(
        _check(
            "P5.10.no_live_invocation_no_provider_query_no_deployment_and_no_gpu",
            not boundary_errors,
            error="; ".join(boundary_errors) if boundary_errors else None,
            planned=(
                "the capture was made locally: no Modal invocation, no provider query, no "
                "deployment, no GPU and no change to a deployed worker"
            ),
            live_modal_invocation=invocation.get("live_modal_invocation"),
            provider_queried=invocation.get("provider_queried"),
            deployment=invocation.get("deployment"),
            gpu=invocation.get("gpu"),
        )
    )
    errors.extend(boundary_errors)

    # -- P5.11 the pre-fix rule reproduces the defect ------------------------
    pre_fix_errors: List[str] = []
    pre_fix_probes: List[Dict[str, Any]] = []
    for field_name, registered in PROVIDER_OBSERVATION_SOURCES.items():
        fact = _observed_fact(
            FIELD_VALUES[field_name],
            registered["source"],
            side=registered["side"],
        )
        # The behaviour of the contract **before** this iteration: the expected
        # side of a stage fact was hardcoded to 'worker' for every registered
        # field, so the correctly sided client fact was refused.
        accepted_before, pre_fix_error = _pre_fix_stage_side(field_name, fact)
        pre_fix_probes.append(
            {
                "field": field_name,
                "registered_side": registered["side"],
                "accepted_by_the_pre_fix_rule": accepted_before,
                "pre_fix_error": pre_fix_error,
            }
        )
        if field_name == "function_call_id":
            continue
        if accepted_before:
            pre_fix_errors.append(
                f"the pre-fix rule does not reproduce the defect for '{field_name}': the "
                "correctly sided client fact was already accepted"
            )
    checks.append(
        _check(
            "P5.11.the_pre_fix_rule_reproduces_the_defect",
            not pre_fix_errors,
            error="; ".join(pre_fix_errors) if pre_fix_errors else None,
            planned=(
                "the rule of Iteration 22 - the expected side of a stage fact is hardcoded to "
                "'worker' for every registered field - is reproduced here and still rejects "
                "the correctly sided client fact: the defect was real, and the checks are not "
                "vacuous"
            ),
            probes=pre_fix_probes,
        )
    )
    errors.extend(pre_fix_errors)

    # -- P5.12 the compatibility path still accepts the side-less facts ------
    compat_errors: List[str] = []
    legacy_provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": APP_ID,
            "client_observed": _client_block(),
            "target_id": TARGET_ID,
            "stages": {
                STAGE: {
                    "attempted": True,
                    "function_name": "verify_exploit_remote",
                    "resource": "CPU",
                    "app_id": APP_ID,
                    "function_call_id": FUNCTION_CALL_ID,
                    "container_id": CONTAINER_ID,
                }
            },
        }
    }
    ok, error = validate_modal_invocation_provenance(legacy_provenance)
    if not ok:
        compat_errors.append(
            f"the compatibility path rejects the side-less facts of Iterations 14-20: {error}"
        )
    side_less = _observed_fact(
        FUNCTION_CALL_ID,
        SOURCE_WORKER_FUNCTION_CALL_ID,
        declare_side=False,
    )
    ok, error = validate_provider_observation_source("function_call_id", side_less)
    if not ok:
        compat_errors.append(
            f"the compatibility path rejects a side-less fact: {error}"
        )
    checks.append(
        _check(
            "P5.12.the_compatibility_path_still_accepts_the_side_less_facts",
            not compat_errors,
            error="; ".join(compat_errors) if compat_errors else None,
            planned=(
                "the artifacts of Iterations 14-20 stay readable through the non-strict "
                "compatibility path - no side is inferred and none is backfilled"
            ),
        )
    )
    errors.extend(compat_errors)

    return {
        "checks": checks,
        "errors": errors,
        "record": record,
        "artifact": {},
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR)
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
    evidence_dir = Path(args.evidence_dir)
    if not evidence_dir.is_absolute():
        evidence_dir = _ROOT / evidence_dir

    code_sha = _resolve_sha(args.code_sha) or _current_code_sha()

    def _display(path: Path) -> str:
        try:
            return str(path.relative_to(_ROOT)).replace("\\", "/")
        except ValueError:
            return str(path)

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

        # The report is validated against the commit it is bound to - not
        # against the current HEAD, which may be a later commit.
        work_dir = Path(tempfile.mkdtemp(prefix="iteration23-probe-"))
        try:
            outcome = _validate_iteration23(
                evidence_dir=evidence_dir,
                code_sha=bound,
                work_dir=work_dir,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
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

    work_dir = Path(tempfile.mkdtemp(prefix="iteration23-probe-"))
    try:
        outcome = _validate_iteration23(
            evidence_dir=evidence_dir,
            code_sha=code_sha,
            work_dir=work_dir,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    checks = outcome["checks"]
    failed = [check for check in checks if check["status"] == "FAILED"]

    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    status = _git("status", "--porcelain") or ""
    tracked_changes = [
        line for line in status.splitlines() if line.strip() and not line.startswith("??")
    ]
    untracked_paths = [line[3:].strip() for line in status.splitlines() if line.strip().startswith("??")]

    report = {
        "schema_version": "1.0.0",
        "generator": "benchmarks/validate_iteration23_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "iteration": 23,
            "purpose": (
                "validate that the strict stage validation uses the registered observation "
                "side of every field, and the evidence of it"
            ),
            "evidence_dir": str(args.evidence_dir).replace("\\", "/"),
            "capture_source": (
                "the local capture of Iteration 21 is re-read: the producer is not changed by "
                "this iteration, so no new capture is made"
            ),
            "stage": STAGE,
            "target_id": TARGET_ID,
            "runtime": (
                "local probes against the installed contract - no Modal invocation, no "
                "provider query, no deployment, no GPU, no change to a deployed worker"
            ),
            "simulation": (
                "the OBSERVED branch of the producer is exercised in a simulated container "
                "context (a patched modal.current_function_call_id); it is a simulation and "
                "is called one"
            ),
            "benchmark_run": (
                "not touched - the 16-target run on disk still fails the Iteration 16-18 "
                "validators and this iteration does not change that"
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
        "summary": {
            "checks_total": len(checks),
            "checks_passed": len(checks) - len(failed),
            "checks_failed": len(failed),
            "failed_checks": [check["check"] for check in failed],
            "overall_status": "PASSED" if not failed else "FAILED",
        },
        "interpretation": {
            "planned": (
                "validate that the strict mode accepts the registered side of every field in "
                "a stage, that it rejects a missing, a null, an unknown and the wrong side, "
                "that the worker-envelope rule is preserved, that the rejection comes from "
                "the side rule and not from a stale digest, that the compatibility path keeps "
                "the side-less artifacts of Iterations 14-20 readable, and that the report is "
                "bound to the code SHA it was produced from"
            ),
            "attempted": (
                "every registered field, the missing, null, unknown and wrong side, the worker "
                "envelope, the digest-recomputed chain, the published capture of Iteration 21, "
                "the producer source, the artifact digest, the historical evidence, the "
                "boundary of the iteration and the pre-fix rule"
            ),
            "executed": (
                "the checks were executed against the artifacts stored on disk"
                if outcome["record"]
                else "nothing could be executed: there is no capture record"
            ),
            "observed": (
                "the report states exactly what the strict validators accept and reject; the "
                "producer is not changed by this iteration and no side is inferred or "
                "backfilled into any artifact"
            ),
            "reported": (
                "PASSED means every check of the registered observation side passed; FAILED "
                "means at least one did not. No Modal invocation was made, the provider was "
                "never asked, no worker was deployed and no live validation is claimed. The "
                "OBSERVED branch of the producer was exercised in a simulated container "
                "context and is a simulation."
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
