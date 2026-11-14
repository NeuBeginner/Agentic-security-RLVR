"""
benchmarks/validate_iteration20_evidence.py
============================================

Fresh-state validation of the runtime-identity producer of the **production**
Modal workers (Iteration 20).

The Iteration 19 review accepted the live CPU-only smoke test but kept one P0
defect of the production provenance path open: ``modal_app.py`` called
``modal.running_app()``, which is a **module** and not a callable in Modal SDK
1.5.5. Both calls raised and were swallowed, so the deployed workers silently
reported ``NOT_AVAILABLE`` for the application id and for the app page URL.

This validator checks the fix and the evidence of it:

* the **source** of the producer contains no call of ``modal.running_app`` -
  the defect was a defect of the source, so the source is what is checked;
* the capture of the **real** producer was made with a sentinel on
  ``modal.running_app``: the sentinel must not have been touched at all;
* the runtime-identity envelope the producer built is a valid envelope of the
  unchanged Iteration 18 schema, and every fact of it names the worker side;
* the facts the worker cannot observe are explicit absences with the exact
  reason - never a guessed value and never a fabricated URL;
* the **client-side** observation of the application id and of the app page URL
  is a client-side fact with the provider's shape, and it never appears in the
  worker envelope;
* the stage evidence artifact of the capture satisfies the unchanged Iteration
  18 artifact contract, and its digest is the digest of the bytes on disk;
* the report is bound to the code SHA it was produced from; ``--check`` refuses
  a foreign SHA.

The capture is a **local** capture of the producer: no Modal invocation is made
by this validator, and no claim about a live run is made.

Usage::

    python -m benchmarks.validate_iteration20_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration20_evidence --check
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    OBSERVATION_SIDE_CLIENT,
    OBSERVATION_SIDE_WORKER,
    StageResponseCapture,
    build_stage_identity_facts,
    canonical_json_bytes,
    file_sha256,
    validate_client_observed_facts,
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

DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration20_producer_capture"
DEFAULT_REPORT = "benchmarks/evidence/iteration20_validation_evidence.json"

STAGE = "evm_sandbox"
TARGET_ID = "ITER20-01"
ENVELOPE_SOURCE = "modal_runtime"

#: The source file of the production producer.
PRODUCER_SOURCE = _ROOT / "modal_app.py"


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


def find_running_app_calls(source_path: Path) -> List[Dict[str, Any]]:
    """
    Every place where the source calls ``modal.running_app`` (or an attribute
    of it).

    The check is made on the **parsed syntax tree**, not on a string: a
    comment, a docstring or a variable name that merely mentions the API does
    not count as a call.
    """
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    hits: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "running_app":
            continue
        owner = func.value
        owner_name = None
        if isinstance(owner, ast.Name):
            owner_name = owner.id
        elif isinstance(owner, ast.Attribute):
            owner_name = owner.attr
        hits.append(
            {
                "line": getattr(node, "lineno", None),
                "owner": owner_name,
                "attribute": func.attr,
            }
        )
    return hits


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


def _validate_iteration20(
    *,
    evidence_dir: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 20 check over the artifacts stored on disk."""
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []

    record_path = evidence_dir / "capture_record.json"
    if not record_path.is_file():
        message = f"the capture record does not exist: {record_path}"
        checks.append(
            _check("P2.1.capture_present", False, error=message, planned="a capture exists")
        )
        return {
            "checks": checks,
            "errors": [message],
            "record": {},
            "artifact": {},
        }

    record = _read_json(record_path)
    envelope = record.get("runtime_identity") if isinstance(record, dict) else None
    envelope = envelope if isinstance(envelope, dict) else {}

    # -- P2.1 the producer source contains no call of the unsupported API ----
    source_hits = find_running_app_calls(PRODUCER_SOURCE)
    checks.append(
        _check(
            "P2.1.producer_source_has_no_running_app_call",
            not source_hits,
            error=(
                f"the producer source calls modal.running_app at line(s) "
                f"{[hit['line'] for hit in source_hits]}"
                if source_hits
                else None
            ),
            planned=(
                "the source of the production producer contains no call of "
                "modal.running_app, which is a module and not a callable in Modal SDK 1.5.5"
            ),
            producer_source=str(PRODUCER_SOURCE.relative_to(_ROOT)).replace("\\", "/"),
            calls=source_hits,
        )
    )
    if source_hits:
        errors.append(
            f"the producer source calls modal.running_app at line(s) "
            f"{[hit['line'] for hit in source_hits]}"
        )

    # -- P2.2 the capture declares its own boundary --------------------------
    invocation = record.get("invocation") if isinstance(record, dict) else {}
    invocation = invocation if isinstance(invocation, dict) else {}
    boundary_errors: List[str] = []
    if invocation.get("live_modal_invocation") is not False:
        boundary_errors.append(
            f"the capture declares live_modal_invocation={invocation.get('live_modal_invocation')!r}, "
            "not False"
        )
    if invocation.get("deployment") != "none":
        boundary_errors.append(
            f"the capture declares deployment={invocation.get('deployment')!r}, not 'none'"
        )
    if not str(invocation.get("production_change") or "").strip():
        boundary_errors.append("the capture states no production-change statement")
    checks.append(
        _check(
            "P2.2.no_live_invocation_and_no_deployment",
            not boundary_errors,
            error="; ".join(boundary_errors) if boundary_errors else None,
            planned=(
                "the capture was made locally: no Modal invocation, no deployment, no GPU and "
                "no change to a deployed worker"
            ),
            live_modal_invocation=invocation.get("live_modal_invocation"),
            deployment=invocation.get("deployment"),
            gpu=invocation.get("gpu"),
        )
    )
    errors.extend(boundary_errors)

    # -- P2.3 the sentinel was never touched ---------------------------------
    sentinel = record.get("sentinel") if isinstance(record, dict) else {}
    sentinel = sentinel if isinstance(sentinel, dict) else {}
    accesses = sentinel.get("accesses")
    sentinel_errors: List[str] = []
    if not isinstance(accesses, list):
        sentinel_errors.append("the capture states no list of sentinel accesses")
    elif accesses:
        sentinel_errors.append(
            f"the producer touched modal.running_app: {accesses}"
        )
    checks.append(
        _check(
            "P2.3.sentinel_never_touched",
            not sentinel_errors,
            error="; ".join(sentinel_errors) if sentinel_errors else None,
            planned=(
                "the sentinel that stood in for modal.running_app while the producer ran was "
                "never touched"
            ),
            accesses=accesses,
        )
    )
    errors.extend(sentinel_errors)

    # -- P2.4 the envelope carries typed facts that name their side ---------
    envelope_errors: List[str] = []
    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if not _fact_is_well_formed(fact):
            envelope_errors.append(
                f"the envelope carries no well-formed fact for '{field_name}'"
            )
            continue
        side = fact.get("observed_by")
        if side != OBSERVATION_SIDE_WORKER:
            envelope_errors.append(
                f"the fact for '{field_name}' declares the observation side {side!r}, not "
                f"{OBSERVATION_SIDE_WORKER!r}: the envelope of a worker response is worker-side"
            )
    ok, error = validate_runtime_identity_envelope(envelope)
    if not ok:
        envelope_errors.append(error or "the envelope is not valid")
    checks.append(
        _check(
            "P2.4.envelope_is_typed_and_worker_side",
            not envelope_errors,
            error="; ".join(envelope_errors) if envelope_errors else None,
            planned=(
                "every identity fact of the envelope is a typed fact that names the worker "
                "side, and the envelope satisfies the unchanged Iteration 18 schema"
            ),
            envelope_fields=sorted(k for k in envelope if k in MODAL_IDENTITY_FIELDS),
        )
    )
    errors.extend(envelope_errors)

    # -- P2.5 / P2.6 / P2.7 the facts the worker cannot observe --------------
    import modal_app  # noqa: E402  (the production producer itself)

    reason_expectations = (
        ("P2.5.app_id_is_an_explicit_absence", "app_id", modal_app.MODAL_APP_ID_UNAVAILABLE_REASON),
        (
            "P2.6.app_page_url_is_an_explicit_absence",
            "app_page_url",
            modal_app.MODAL_APP_PAGE_URL_UNAVAILABLE_REASON,
        ),
        (
            "P2.7.container_id_is_an_explicit_absence",
            "container_id",
            modal_app.MODAL_CONTAINER_ID_UNAVAILABLE_REASON,
        ),
    )
    for check_name, field_name, expected_reason in reason_expectations:
        fact = envelope.get(field_name)
        field_errors: List[str] = []
        if not isinstance(fact, dict):
            field_errors.append(f"the envelope carries no fact for '{field_name}'")
        elif fact.get("status") != NOT_AVAILABLE:
            field_errors.append(
                f"the fact for '{field_name}' is {fact.get('status')!r}, not {NOT_AVAILABLE!r}"
            )
        elif fact.get("value") is not None:
            field_errors.append(f"the fact for '{field_name}' holds a value")
        else:
            reason = str(fact.get("reason") or "")
            if reason != expected_reason:
                field_errors.append(
                    f"the reason of '{field_name}' is not the exact reason of the producer"
                )
        checks.append(
            _check(
                check_name,
                not field_errors,
                error="; ".join(field_errors) if field_errors else None,
                planned=(
                    f"'{field_name}' is an explicit NOT_AVAILABLE with the exact reason of the "
                    "producer and holds no value"
                ),
                field=field_name,
            )
        )
        errors.extend(field_errors)

    # -- P2.8 the client-side observation is a client-side fact -------------
    client_errors: List[str] = []
    from benchmarks.adapters import (  # noqa: E402
        _client_observed_app_id,
        _client_observed_app_page_url,
    )

    client_block = {
        "app_id": _client_observed_app_id(),
        "app_page_url": _client_observed_app_page_url(),
    }
    ok, error = validate_client_observed_facts(client_block)
    if not ok:
        client_errors.append(error or "the client-observed block is not valid")
    for field_name, fact in client_block.items():
        if not isinstance(fact, dict):
            client_errors.append(f"the client-observed fact for '{field_name}' is not a fact")
            continue
        if fact.get("observed_by") != OBSERVATION_SIDE_CLIENT:
            client_errors.append(
                f"the client-observed fact for '{field_name}' does not name the client side"
            )
    # A client observation may never sit inside the worker envelope.
    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if isinstance(fact, dict) and fact.get("observed_by") == OBSERVATION_SIDE_CLIENT:
            client_errors.append(
                f"the worker envelope carries a client-side fact for '{field_name}'"
            )
    checks.append(
        _check(
            "P2.8.client_observation_is_client_side",
            not client_errors,
            error="; ".join(client_errors) if client_errors else None,
            planned=(
                "the application id and the app page URL are client-side facts with the "
                "provider's shape, and the worker envelope holds no client-side fact"
            ),
            client_observed={
                name: fact.get("status") for name, fact in client_block.items()
            },
        )
    )
    errors.extend(client_errors)

    # -- the artifact of the stage -------------------------------------------
    artifact_ref = record.get("evidence_artifact") if isinstance(record, dict) else {}
    artifact_ref = artifact_ref if isinstance(artifact_ref, dict) else {}
    artifact_rel_path = artifact_ref.get("path")
    artifact_path: Optional[Path] = None
    artifact: Dict[str, Any] = {}
    artifact_errors: List[str] = []
    if not artifact_rel_path:
        artifact_errors.append("the capture record names no evidence artifact")
    else:
        artifact_path = _ROOT / artifact_rel_path
        if not artifact_path.is_file():
            artifact_errors.append(f"the evidence artifact does not exist: {artifact_rel_path}")
        else:
            artifact = _read_json(artifact_path)

    # -- P2.9 the digest of the artifact is the digest of the bytes ----------
    digest_errors: List[str] = []
    if artifact:
        actual = file_sha256(artifact_path)
        if actual != artifact_ref.get("sha256"):
            digest_errors.append(
                f"the digest of the artifact on disk is {actual}, not "
                f"{artifact_ref.get('sha256')}"
            )
    checks.append(
        _check(
            "P2.9.artifact_digest_matches_the_bytes_on_disk",
            not digest_errors and bool(artifact),
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the SHA-256 of the stage evidence artifact on disk equals the digest the "
                "capture record claims"
            ),
            recorded_sha256=artifact_ref.get("sha256"),
            actual_sha256=file_sha256(artifact_path) if artifact_path and artifact_path.is_file() else None,
        )
    )
    errors.extend(digest_errors)

    # -- P2.10 the artifact satisfies the Iteration 18 contract -------------
    contract_errors: List[str] = []
    if not artifact:
        contract_errors.append("there is no stage evidence artifact to validate")
    else:
        ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
        if not ok:
            contract_errors.append(error or "the stage evidence artifact is not valid")
        else:
            # The envelope must be the one the captured response carries.
            response = artifact.get("provider_response")
            carried = response.get(ENVELOPE_SOURCE) if isinstance(response, dict) else None
            if canonical_json_bytes(carried) != canonical_json_bytes(envelope):
                contract_errors.append(
                    "the envelope of the artifact is not the envelope the captured response carries"
                )
    checks.append(
        _check(
            "P2.10.stage_evidence_artifact_satisfies_the_contract",
            not contract_errors,
            error="; ".join(contract_errors) if contract_errors else None,
            planned=(
                "the stage evidence artifact satisfies the unchanged Iteration 18 artifact "
                "contract and carries exactly the envelope of the captured response"
            ),
            stage=STAGE,
            target_id=TARGET_ID,
        )
    )
    errors.extend(contract_errors)

    # -- P2.11 the stage facts keep the side of the envelope ----------------
    side_errors: List[str] = []
    if artifact:
        capture = StageResponseCapture(
            stage=STAGE,
            attempted=True,
            executed=True,
            response_received=True,
            provider_response=artifact.get("provider_response"),
            runtime_identity=artifact.get("runtime_identity"),
            runtime_identity_source=ENVELOPE_SOURCE,
            response_source="the captured response of the production producer",
            requested_fields=MODAL_IDENTITY_FIELDS,
        )
        facts = build_stage_identity_facts(capture)
        for field_name, fact in facts.items():
            side = fact.get("observed_by") if isinstance(fact, dict) else None
            if side is not None and side != OBSERVATION_SIDE_WORKER:
                side_errors.append(
                    f"the stage fact for '{field_name}' declares the side {side!r}"
                )
    else:
        side_errors.append("there is no stage evidence artifact to derive the facts from")
    checks.append(
        _check(
            "P2.11.stage_facts_keep_the_side_of_the_envelope",
            not side_errors,
            error="; ".join(side_errors) if side_errors else None,
            planned=(
                "the facts derived from the envelope keep the side the envelope declared"
            ),
        )
    )
    errors.extend(side_errors)

    # -- P2.12 the capture is bound to the code it was made from -------------
    source = record.get("source") if isinstance(record, dict) else {}
    source = source if isinstance(source, dict) else {}
    bound_sha = source.get("code_sha")
    binding_errors: List[str] = []
    if not isinstance(bound_sha, str) or len(bound_sha) != 40:
        binding_errors.append(f"the capture names no commit SHA: {bound_sha!r}")
    elif code_sha and bound_sha != code_sha:
        binding_errors.append(
            f"the capture was made from {bound_sha}, not from the reported {code_sha}"
        )
    checks.append(
        _check(
            "P2.12.capture_is_bound_to_its_code_sha",
            not binding_errors,
            error="; ".join(binding_errors) if binding_errors else None,
            planned=(
                "the capture names the commit it was made from, and that commit is the one "
                "the report is bound to"
            ),
            capture_code_sha=bound_sha,
            reported_code_sha=code_sha,
        )
    )
    errors.extend(binding_errors)

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
        outcome = _validate_iteration20(evidence_dir=evidence_dir, code_sha=bound)
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

    outcome = _validate_iteration20(evidence_dir=evidence_dir, code_sha=code_sha)
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
        "generator": "benchmarks/validate_iteration20_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "iteration": 20,
            "purpose": (
                "validate the fixed production runtime-identity producer and the evidence "
                "of the fix"
            ),
            "evidence_dir": str(args.evidence_dir).replace("\\", "/"),
            "stage": STAGE,
            "target_id": TARGET_ID,
            "runtime": (
                "local producer capture - no Modal invocation, no deployment, no GPU, no "
                "change to a deployed worker"
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
                "validate the source of the fixed production producer, the capture of the real "
                "producer, the unchanged Iteration 18 artifact and envelope contracts, the "
                "worker/client distinction of every fact and the binding of the report to the "
                "code SHA it was produced from"
            ),
            "attempted": (
                "the producer source, the sentinel on modal.running_app, the envelope of the "
                "capture, the client-side observation, the stage evidence artifact and its "
                "digest, and the source binding"
            ),
            "executed": (
                "the checks were executed against the artifacts stored on disk"
                if outcome["record"]
                else "nothing could be executed: there is no capture record"
            ),
            "observed": (
                "the report states exactly what the capture record and the stage evidence "
                "artifact contain; a fact the worker cannot observe is reported as "
                "NOT_AVAILABLE with its reason and is never filled in"
            ),
            "reported": (
                "PASSED means every check of the fixed production producer passed; FAILED "
                "means at least one did not. The capture is a LOCAL capture of the producer: "
                "no Modal invocation was made, no worker was deployed and no live validation "
                "is claimed. The deployed workers still need a new deployment to carry the "
                "fix, and that is outside this iteration"
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
