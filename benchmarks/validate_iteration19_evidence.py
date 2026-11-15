"""
benchmarks/validate_iteration19_evidence.py
============================================

Fresh-state validation of the live CPU-only Modal runtime smoke test of
Iteration 19.

Iterations 14-18 hardened the evidence contract of the benchmark run, but every
published validation artifact up to now was produced **offline** - the
"producer rehearsal" executes the real producer path against faithful
reconstructions of worker responses. A rehearsal can prove that the contract
holds; it cannot prove that a **real Modal worker** is reached and reports its
own runtime identity.

Iteration 19 therefore validates the evidence of one **live, CPU-only**
invocation:

* the stage evidence artifact of the smoke stage, written by the unchanged
  Iteration 18 producer (``write_stage_evidence_artifact``);
* the invocation record that states what actually happened - the
  provider-issued identifiers, the worker-observed runtime metadata, the
  billed usage (or the exact reason why it is unavailable) and the source
  commit the run was made from.

The script re-reads both artifacts **from disk**, recomputes the digest of the
stored bytes and runs the repository validators over them. It never trusts the
producer, and it never claims more than the artifacts prove:

* a missing artifact, a digest that does not match the bytes, a detached
  envelope, an impossible stage state or an unexplained missing field is a
  ``FAILED`` check - not a warning;
* an unavailable field is only acceptable when it carries the exact reason why
  it could not be observed;
* the billed usage is never estimated: it is either a provider-backed fact or
  an explicit ``NOT_AVAILABLE``.

Usage::

    python -m benchmarks.validate_iteration19_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration19_evidence --check
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    FORBIDDEN_SYNTHETIC_CONTAINER_IDS,
    MODAL_APP_ID_RE,
    MODAL_CONTAINER_ID_RE,
    MODAL_FUNCTION_CALL_ID_RE,
    MODAL_IDENTITY_FIELDS,
    MODAL_IMAGE_ID_RE,
    NOT_AVAILABLE,
    OBSERVED,
    STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE,
    STAGE_STATE_TABLE,
    SYNTHETIC_CONTAINER_ID_RE,
    canonical_json_bytes,
    file_sha256,
    validate_runtime_identity_envelope,
    validate_stage_evidence_artifact,
)

# The git helpers of the Iteration 16 validator are reused unchanged.
from benchmarks.validate_iteration16_evidence import (  # noqa: E402
    _current_code_sha,
    _git,
    _is_ancestor,
    _resolve_sha,
)

DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration19_cpu_smoke"
DEFAULT_REPORT = "benchmarks/evidence/iteration19_validation_evidence.json"

STAGE = "cpu_smoke"
TARGET_ID = "CPU-SMOKE-01"
ENVELOPE_SOURCE = "modal_runtime"

#: The identifiers the Modal runtime issues, and the shape each of them has.
_IDENTIFIER_SHAPES = {
    "app_id": MODAL_APP_ID_RE,
    "function_call_id": MODAL_FUNCTION_CALL_ID_RE,
    "container_id": MODAL_CONTAINER_ID_RE,
    "image_id": MODAL_IMAGE_ID_RE,
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


def _fact_is_well_formed(fact: Any) -> bool:
    """True when a fact is a documented typed fact with the right payload."""
    if not isinstance(fact, dict):
        return False
    if fact.get("status") == OBSERVED:
        value = fact.get("value")
        return isinstance(value, str) and bool(value.strip()) and bool(
            str(fact.get("source") or "").strip()
        )
    if fact.get("status") == NOT_AVAILABLE:
        return fact.get("value") is None and bool(str(fact.get("reason") or "").strip())
    return False


def _validate_iteration19(
    *,
    evidence_dir: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 19 check over the artifacts stored on disk."""
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []

    record_path = evidence_dir / "invocation_record.json"
    if not record_path.is_file():
        message = f"the invocation record does not exist: {record_path}"
        checks.append(
            _check("P1.1.live_invocation", False, error=message, planned="a live invocation exists")
        )
        return {
            "checks": checks,
            "errors": [message],
            "record": {},
            "artifact": {},
        }

    record = _read_json(record_path)

    # -- P1.1 the live invocation ------------------------------------------
    invocation = record.get("invocation") if isinstance(record, dict) else {}
    invocation = invocation if isinstance(invocation, dict) else {}
    invocation_errors: List[str] = []
    if invocation.get("status") != "SUCCEEDED":
        invocation_errors.append(
            f"the invocation status is {invocation.get('status')!r}, not 'SUCCEEDED'"
        )
    if not invocation.get("executed"):
        invocation_errors.append("the invocation did not execute")
    if not invocation.get("response_received"):
        invocation_errors.append("the invocation received no response")
    if invocation.get("invocation_count") != 1:
        invocation_errors.append(
            f"the invocation count is {invocation.get('invocation_count')!r}, not 1"
        )
    checks.append(
        _check(
            "P1.1.live_invocation",
            not invocation_errors,
            error="; ".join(invocation_errors) if invocation_errors else None,
            planned=(
                "one CPU-only invocation of the smoke function succeeded and returned a "
                "response"
            ),
            invocation_status=invocation.get("status"),
            invocation_count=invocation.get("invocation_count"),
            duration_seconds=invocation.get("duration_seconds"),
            started_at_utc=invocation.get("started_at_utc"),
            finished_at_utc=invocation.get("finished_at_utc"),
        )
    )
    errors.extend(invocation_errors)

    # -- the artifact of the stage -----------------------------------------
    artifact_ref = record.get("evidence_artifact") if isinstance(record, dict) else {}
    artifact_ref = artifact_ref if isinstance(artifact_ref, dict) else {}
    artifact_rel_path = artifact_ref.get("path")
    artifact_path: Optional[Path] = None
    artifact: Dict[str, Any] = {}
    if isinstance(artifact_rel_path, str) and artifact_rel_path:
        # The artifact of a stage belongs to the evidence directory of its run.
        # The repository-relative path of the record is the published location
        # of exactly that file.
        candidates = [
            evidence_dir / Path(artifact_rel_path).name,
            _ROOT / artifact_rel_path,
        ]
        for candidate in candidates:
            if candidate.is_file():
                artifact_path = candidate
                break
        if artifact_path is None:
            errors.append(f"the stage evidence artifact does not exist: {artifact_rel_path}")
        else:
            try:
                artifact = _read_json(artifact_path)
            except ValueError as exc:
                errors.append(f"the stage evidence artifact is not readable JSON: {exc}")

    # -- P1.2 the Iteration 18 artifact contract ---------------------------
    if artifact:
        ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    else:
        ok, error = False, "there is no stage evidence artifact to validate"
    checks.append(
        _check(
            "P1.2.stage_evidence_contract",
            ok,
            error=error,
            planned=(
                "the stage evidence artifact satisfies the unchanged Iteration 18 "
                "validator"
            ),
            artifact_path=artifact_rel_path,
        )
    )
    if not ok:
        errors.append(error or "the stage evidence artifact failed the Iteration 18 validator")

    # -- P1.3 the runtime-identity envelope --------------------------------
    envelope = artifact.get("runtime_identity") if isinstance(artifact, dict) else None
    ok, error = validate_runtime_identity_envelope(envelope)
    extra_errors: List[str] = []
    image_fact = envelope.get("image_id") if isinstance(envelope, dict) else None
    if image_fact is not None and not _fact_is_well_formed(image_fact):
        extra_errors.append(
            "the runtime-identity envelope carries a malformed fact for 'image_id'"
        )
    checks.append(
        _check(
            "P1.3.runtime_identity_envelope",
            ok and not extra_errors,
            error="; ".join([e for e in [error, *extra_errors] if e]),
            planned=(
                "every identity field of the envelope is a documented typed fact, and the "
                "additional provider key 'image_id' is one as well"
            ),
            identity_fields=[
                field for field in MODAL_IDENTITY_FIELDS if isinstance(envelope, dict) and field in envelope
            ],
        )
    )
    if not (ok and not extra_errors):
        errors.append(error or "the runtime-identity envelope is malformed")

    # -- P1.4 the response/envelope binding ---------------------------------
    binding_errors: List[str] = []
    provider_response = artifact.get("provider_response") if isinstance(artifact, dict) else None
    source = artifact.get("runtime_identity_source") if isinstance(artifact, dict) else None
    if not isinstance(provider_response, dict):
        binding_errors.append("the captured response is not an object")
    else:
        if not source or source not in provider_response:
            binding_errors.append(
                f"the captured response does not carry the runtime-identity envelope at {source!r}"
            )
        elif canonical_json_bytes(provider_response[source]) != canonical_json_bytes(envelope):
            binding_errors.append(
                "the stored runtime-identity envelope is not the one the captured response carries"
            )
    if bool(artifact.get("response_received")) != (provider_response is not None):
        binding_errors.append(
            "the response flag and the stored payload contradict each other"
        )
    if bool(artifact.get("runtime_envelope_received")) != (envelope is not None):
        binding_errors.append(
            "the envelope flag and the stored envelope contradict each other"
        )
    checks.append(
        _check(
            "P1.4.response_envelope_binding",
            not binding_errors,
            error="; ".join(binding_errors) if binding_errors else None,
            planned=(
                "the flag, the stored payload and the runtime-identity envelope describe "
                "one event, in both directions"
            ),
            runtime_identity_source=source,
        )
    )
    errors.extend(binding_errors)

    # -- P1.5 the stage state machine ---------------------------------------
    flags = (
        bool(artifact.get("attempted")),
        bool(artifact.get("executed")),
        bool(artifact.get("response_received")),
        bool(artifact.get("runtime_envelope_received")),
    )
    state = STAGE_STATE_TABLE.get(flags)
    state_ok = state == STAGE_STATE_EXECUTED_WITH_RUNTIME_ENVELOPE
    checks.append(
        _check(
            "P1.5.stage_state_machine",
            state_ok,
            error=None if state_ok else f"the stage is in the state {state!r}",
            planned=(
                "the four flags of the stage describe exactly one state, and the state of "
                "the live smoke stage is EXECUTED_WITH_RUNTIME_ENVELOPE"
            ),
            state=state,
        )
    )
    if not state_ok:
        errors.append(f"the stage is in the state {state!r}")

    # -- P1.6 the provider-issued identifiers --------------------------------
    identifiers = record.get("identifiers") if isinstance(record, dict) else {}
    identifiers = identifiers if isinstance(identifiers, dict) else {}
    identifier_errors: List[str] = []
    observed_identifiers: Dict[str, Any] = {}
    for field_name, shape in _IDENTIFIER_SHAPES.items():
        fact = identifiers.get(field_name)
        if not isinstance(fact, dict):
            identifier_errors.append(f"the record carries no fact for '{field_name}'")
            continue
        if not _fact_is_well_formed(fact):
            identifier_errors.append(f"the fact for '{field_name}' is not a documented typed fact")
            continue
        if fact.get("status") == NOT_AVAILABLE:
            # An unavailable identifier is acceptable, but only with its reason.
            if not str(fact.get("reason") or "").strip():
                identifier_errors.append(
                    f"the unavailable '{field_name}' carries no reason"
                )
            continue
        value = str(fact.get("value"))
        observed_identifiers[field_name] = value
        if not shape.fullmatch(value):
            identifier_errors.append(
                f"the observed '{field_name}' {value!r} does not match the provider shape"
            )
    container_value = observed_identifiers.get("container_id")
    if container_value is not None:
        if container_value in FORBIDDEN_SYNTHETIC_CONTAINER_IDS:
            identifier_errors.append(
                f"the container id {container_value!r} is a forbidden synthetic identity"
            )
        if SYNTHETIC_CONTAINER_ID_RE.fullmatch(container_value):
            identifier_errors.append(
                f"the container id {container_value!r} has the shape of a synthetic identity"
            )

    # An identifier the record claims the worker observed must be the one the
    # worker really observed - the client may not report a different value.
    for field_name in ("function_call_id", "image_id"):
        fact = identifiers.get(field_name)
        if not isinstance(fact, dict) or fact.get("observed_by") != "worker":
            continue
        if fact.get("status") != OBSERVED:
            continue
        envelope_fact = envelope.get(field_name) if isinstance(envelope, dict) else None
        if not isinstance(envelope_fact, dict) or envelope_fact.get("status") != OBSERVED:
            identifier_errors.append(
                f"the record claims that the worker observed '{field_name}', but the "
                "runtime-identity envelope carries no observed fact for it"
            )
            continue
        if envelope_fact.get("value") != fact.get("value"):
            identifier_errors.append(
                f"the record claims a different '{field_name}' than the worker observed"
            )
    checks.append(
        _check(
            "P1.6.provider_issued_identifiers",
            not identifier_errors,
            error="; ".join(identifier_errors) if identifier_errors else None,
            planned=(
                "every identifier the record claims was observed carries the shape the "
                "provider issues, and no synthetic identity slipped in"
            ),
            observed_identifiers=observed_identifiers,
        )
    )
    errors.extend(identifier_errors)

    # -- P1.7 the digest of the artifact, verified from disk -----------------
    digest_errors: List[str] = []
    actual_digest = file_sha256(artifact_path) if artifact_path is not None else None
    declared_digest = artifact_ref.get("sha256")
    if actual_digest is None:
        digest_errors.append("the artifact bytes cannot be read from disk")
    elif actual_digest != declared_digest:
        digest_errors.append(
            f"the digest of the artifact on disk ({actual_digest}) differs from the digest "
            f"the record claims ({declared_digest})"
        )
    declared_length = artifact_ref.get("byte_length")
    if artifact_path is not None and isinstance(declared_length, int):
        actual_length = artifact_path.stat().st_size
        if actual_length != declared_length:
            digest_errors.append(
                f"the byte length of the artifact on disk ({actual_length}) differs from the "
                f"length the record claims ({declared_length})"
            )
    checks.append(
        _check(
            "P1.7.artifact_digest_from_disk",
            not digest_errors,
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the digest of the stage evidence artifact is recomputed from the bytes on "
                "disk and equals the digest the record claims"
            ),
            sha256_from_disk=actual_digest,
            sha256_claimed=declared_digest,
        )
    )
    errors.extend(digest_errors)

    # -- P1.8 the binding to the source code ---------------------------------
    source_state = record.get("source") if isinstance(record, dict) else {}
    source_state = source_state if isinstance(source_state, dict) else {}
    source_errors: List[str] = []
    recorded_sha = source_state.get("commit_sha")
    if not isinstance(recorded_sha, str) or len(recorded_sha) != 40:
        source_errors.append(f"the recorded source commit SHA is {recorded_sha!r}")
    elif not _is_ancestor(recorded_sha, "HEAD"):
        source_errors.append(
            f"the recorded source commit {recorded_sha} is not an ancestor of HEAD"
        )
    if source_state.get("clean") is not True:
        source_errors.append(
            "the tracked files of the source tree were modified when the run was made"
        )
    if code_sha and recorded_sha and code_sha != recorded_sha:
        source_errors.append(
            f"the report would be bound to the commit {code_sha}, but the run was made "
            f"from the commit {recorded_sha}"
        )
    checks.append(
        _check(
            "P1.8.source_binding",
            not source_errors,
            error="; ".join(source_errors) if source_errors else None,
            planned=(
                "the run is bound to the commit it was made from, that commit is an "
                "ancestor of HEAD, and the report is bound to exactly that commit"
            ),
            recorded_commit=recorded_sha,
            report_bound_to=code_sha,
            tracked_files_modified=source_state.get("tracked_files_modified"),
        )
    )
    errors.extend(source_errors)

    # -- P1.9 the worker-observed runtime metadata ---------------------------
    observed = record.get("worker_observed") if isinstance(record, dict) else {}
    observed = observed if isinstance(observed, dict) else {}
    metadata_errors: List[str] = []
    for field_name in ("python_version", "platform", "modal_sdk_version", "kernel_release"):
        value = observed.get(field_name)
        if not isinstance(value, str) or not value.strip():
            metadata_errors.append(f"the worker observed no '{field_name}'")
    for field_name in ("image_digest", "session_id"):
        fact = identifiers.get(field_name)
        if not isinstance(fact, dict) or not _fact_is_well_formed(fact):
            metadata_errors.append(
                f"the record carries no well-formed fact for '{field_name}'"
            )
        elif fact.get("status") == NOT_AVAILABLE and not str(fact.get("reason") or "").strip():
            metadata_errors.append(f"the unavailable '{field_name}' carries no reason")
    checks.append(
        _check(
            "P1.9.worker_observed_runtime_metadata",
            not metadata_errors,
            error="; ".join(metadata_errors) if metadata_errors else None,
            planned=(
                "the runtime metadata is worker-observed, and every field the runtime did "
                "not expose carries the exact reason"
            ),
            python_version=observed.get("python_version"),
            platform=observed.get("platform"),
            modal_sdk_version=observed.get("modal_sdk_version"),
            image_id=observed.get("modal_image_id_env"),
        )
    )
    errors.extend(metadata_errors)

    # -- P1.10 the billed usage ----------------------------------------------
    billed = record.get("billed_usage") if isinstance(record, dict) else {}
    billed = billed if isinstance(billed, dict) else {}
    billed_errors: List[str] = []
    if billed.get("status") == OBSERVED:
        value = billed.get("value")
        if not isinstance(value, dict) or not value.get("line_items"):
            billed_errors.append(
                "the billed usage is marked observed but carries no provider line item"
            )
    elif billed.get("status") == NOT_AVAILABLE:
        if not str(billed.get("reason") or "").strip():
            billed_errors.append("the unavailable billed usage carries no reason")
    else:
        billed_errors.append(
            f"the billed usage has the unknown status {billed.get('status')!r}"
        )
    checks.append(
        _check(
            "P1.10.billed_usage",
            not billed_errors,
            error="; ".join(billed_errors) if billed_errors else None,
            planned=(
                "the billed CPU/runtime usage is a provider-backed fact or an explicit "
                "NOT_AVAILABLE with a reason - never an estimate"
            ),
            billed_usage_status=billed.get("status"),
        )
    )
    errors.extend(billed_errors)

    # -- P1.11 zero GPU allocation -------------------------------------------
    gpu_statement = record.get("gpu_statement") if isinstance(record, dict) else {}
    gpu_statement = gpu_statement if isinstance(gpu_statement, dict) else {}
    gpu_evidence = gpu_statement.get("worker_observed_evidence")
    gpu_evidence = gpu_evidence if isinstance(gpu_evidence, dict) else {}
    gpu_errors: List[str] = []
    if gpu_statement.get("gpu_requested") is not None:
        gpu_errors.append(
            f"the function requested the GPU {gpu_statement.get('gpu_requested')!r}"
        )
    if gpu_evidence.get("gpu_device_exposed") is not False:
        gpu_errors.append("the worker observed a GPU device")
    if gpu_evidence.get("nvidia_device_nodes"):
        gpu_errors.append(
            f"the worker observed the NVIDIA device nodes {gpu_evidence.get('nvidia_device_nodes')!r}"
        )
    if gpu_evidence.get("cuda_runtime_libraries"):
        gpu_errors.append("the worker observed a CUDA runtime library")
    if gpu_statement.get("gpu_allocated") is not False:
        gpu_errors.append("the record does not state that no GPU was allocated")
    checks.append(
        _check(
            "P1.11.zero_gpu_allocation",
            not gpu_errors,
            error="; ".join(gpu_errors) if gpu_errors else None,
            planned=(
                "no GPU was requested and the worker observed no GPU device, no NVIDIA node "
                "and no CUDA runtime library"
            ),
            gpu_requested=gpu_statement.get("gpu_requested"),
            worker_observed=gpu_evidence,
        )
    )
    errors.extend(gpu_errors)

    # -- P1.12 no production deployment and no production change --------------
    production_errors: List[str] = []
    if invocation.get("deployment_kind") != "ephemeral":
        production_errors.append(
            f"the deployment kind is {invocation.get('deployment_kind')!r}, not 'ephemeral'"
        )
    production_change = str(invocation.get("production_change") or "")
    if not production_change.strip():
        production_errors.append("the record states no production-change statement")
    checks.append(
        _check(
            "P1.12.no_production_change",
            not production_errors,
            error="; ".join(production_errors) if production_errors else None,
            planned=(
                "the run used an ephemeral app of its own and changed no deployed "
                "production worker"
            ),
            deployment_kind=invocation.get("deployment_kind"),
            production_change=production_change,
        )
    )
    errors.extend(production_errors)

    return {
        "checks": checks,
        "errors": errors,
        "record": record,
        "artifact": artifact,
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
        outcome = _validate_iteration19(evidence_dir=evidence_dir, code_sha=bound)
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

    outcome = _validate_iteration19(evidence_dir=evidence_dir, code_sha=code_sha)
    checks = outcome["checks"]
    failed = [check for check in checks if check["status"] == "FAILED"]

    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    status = _git("status", "--porcelain") or ""
    tracked_changes = [
        line for line in status.splitlines() if line.strip() and not line.startswith("??")
    ]
    untracked_paths = [
        line[3:].strip()
        for line in status.splitlines()
        if line.strip().startswith("??")
    ]

    report = {
        "schema_version": "1.0.0",
        "generator": "benchmarks/validate_iteration19_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "iteration": 19,
            "purpose": "live Modal CPU-only runtime smoke test",
            "evidence_dir": str(args.evidence_dir).replace("\\", "/"),
            "stage": STAGE,
            "target_id": TARGET_ID,
            "runtime": "Modal CPU-only - no GPU, no model, no volume, no production change",
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
                "validate the evidence of one live CPU-only Modal invocation with the "
                "unchanged Iteration 18 validators, verify the digest of the artifact from "
                "the bytes on disk and bind the report to the code SHA it was produced from"
            ),
            "attempted": (
                "the live invocation, the Iteration 18 artifact contract, the envelope "
                "schema, the response/envelope binding, the stage state machine, the "
                "provider-issued identifiers, the digest from disk, the source binding, the "
                "worker-observed metadata, the billed usage, the zero-GPU proof and the "
                "absence of a production change"
            ),
            "executed": (
                "the checks were executed against the artifacts stored on disk"
                if outcome["record"]
                else "nothing could be executed: there is no invocation record"
            ),
            "observed": (
                "the report states exactly what the invocation record and the stage "
                "evidence artifact contain; an unavailable field is reported as "
                "NOT_AVAILABLE with its reason and is never filled in"
            ),
            "reported": (
                "PASSED means every check of the live CPU-only smoke test passed; FAILED "
                "means at least one did not. This is a runtime smoke test, not a "
                "benchmark validation, and no claim about the sixteen benchmark targets "
                "is made"
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
