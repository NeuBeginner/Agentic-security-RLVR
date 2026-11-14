"""
benchmarks/validate_iteration21_evidence.py
============================================

Fresh-state validation of the **provider-backed** container identity
(Iteration 21).

The Iteration 20 review kept the container-identity path of the production
producer open as a P0: ``modal_app.py`` treated ``MODAL_WORKER_ID`` or
``HOSTNAME`` as an observed Modal container id, although neither is a
provider-issued identifier, and the client-observed block held no container
identity at all.

This validator checks the fix and the evidence of it:

* the **source** of the producer reads **no** environment variable for the
  container identity - the defect was a defect of the source, so the source is
  what is checked (on the parsed syntax tree, not on a string);
* the capture was made with a **hostile environment**: ``MODAL_WORKER_ID``,
  ``HOSTNAME`` and ``MODAL_TASK_ID`` held fake, well-formed values - and the
  container id still stayed ``NOT_AVAILABLE``;
* the runtime-identity envelope the producer built is a valid envelope of the
  unchanged Iteration 18 schema, every fact of it names the worker side, and
  every observed fact names a **registered** observation source;
* the worker envelope holds **no** observed container id - ever;
* the **client-side** block is client-side, provider-shaped, and its
  container id is either an explicit absence or a provider-observed fact with
  a correlation record that ties it to this very invocation;
* the stage evidence artifact of the capture satisfies the unchanged Iteration
  18 artifact contract, and its digest is the digest of the bytes on disk;
* the **provenance block** of the capture satisfies the repository's own
  provenance validator in the strict source mode;
* the report is bound to the code SHA it was produced from; ``--check`` refuses
  a foreign SHA.

The capture is a **local** capture of the producer: no Modal invocation is made
by this validator, no provider is queried, and no claim about a live run is
made.

Usage::

    python -m benchmarks.validate_iteration21_evidence --code-sha <sha>
    python -m benchmarks.validate_iteration21_evidence --check
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
    validate_modal_invocation_provenance,
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

DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration21_producer_capture"
DEFAULT_REPORT = "benchmarks/evidence/iteration21_validation_evidence.json"

STAGE = "evm_sandbox"
TARGET_ID = "ITER21-01"
ENVELOPE_SOURCE = "modal_runtime"

#: The source file of the production producer.
PRODUCER_SOURCE = _ROOT / "modal_app.py"

#: The environment variables the producer must not read for the container
#: identity. They are plausible names - and none of them is a provider-issued
#: container identifier.
FORBIDDEN_ENVIRONMENT_NAMES = (
    "MODAL_WORKER_ID",
    "HOSTNAME",
    "MODAL_TASK_ID",
)


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


def _dotted_name(node: ast.AST) -> Optional[str]:
    """The dotted name of an attribute chain - ``os.environ`` and the like."""
    parts: List[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _constant_string(node: ast.AST) -> Optional[str]:
    """The value of a string literal - ``None`` for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def find_environment_lookups(source_path: Path) -> List[Dict[str, Any]]:
    """
    Every place where the source reads an environment variable.

    The check is made on the **parsed syntax tree**, not on a string: a
    comment, a docstring or a constant that merely mentions an environment
    variable does not count as a lookup. A docstring may therefore explain
    *why* a variable is not read.
    """
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    hits: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            owner = _dotted_name(func.value)
            if func.attr == "get" and owner in ("os.environ", "environ"):
                kind = "environ.get"
            elif func.attr == "getenv" and owner == "os":
                kind = "os.getenv"
            else:
                continue
            if not node.args:
                continue
            name = _constant_string(node.args[0])
            if name is None:
                continue
            hits.append(
                {
                    "line": getattr(node, "lineno", None),
                    "name": name,
                    "kind": kind,
                }
            )
        elif isinstance(node, ast.Subscript):
            if _dotted_name(node.value) != "os.environ":
                continue
            name = _constant_string(node.slice)
            if name is None:
                continue
            hits.append(
                {
                    "line": getattr(node, "lineno", None),
                    "name": name,
                    "kind": "environ[]",
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


def _validate_iteration21(
    *,
    evidence_dir: Path,
    code_sha: Optional[str],
) -> Dict[str, Any]:
    """Run every Iteration 21 check over the artifacts stored on disk."""
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []

    record_path = evidence_dir / "capture_record.json"
    if not record_path.is_file():
        message = f"the capture record does not exist: {record_path}"
        checks.append(
            _check("P3.1.capture_present", False, error=message, planned="a capture exists")
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

    # -- P3.1 the producer source reads no forbidden environment variable ----
    lookups = find_environment_lookups(PRODUCER_SOURCE)
    forbidden = [
        hit for hit in lookups if hit["name"] in FORBIDDEN_ENVIRONMENT_NAMES
    ]
    checks.append(
        _check(
            "P3.1.producer_source_reads_no_forbidden_environment_variable",
            not forbidden,
            error=(
                f"the producer source reads the environment variable(s) "
                f"{sorted({hit['name'] for hit in forbidden})} at line(s) "
                f"{[hit['line'] for hit in forbidden]}"
                if forbidden
                else None
            ),
            planned=(
                "the source of the production producer reads neither MODAL_WORKER_ID (the "
                "SDK's 'worker_id' configuration setting, documented as internal debugging "
                "use), nor HOSTNAME (a generic container hostname), nor MODAL_TASK_ID (read "
                "only by an internal experimental module) - none of them is a "
                "provider-issued container identifier"
            ),
            producer_source=str(PRODUCER_SOURCE.relative_to(_ROOT)).replace("\\", "/"),
            forbidden_names=list(FORBIDDEN_ENVIRONMENT_NAMES),
            forbidden_lookups=forbidden,
            other_lookups=lookups,
        )
    )
    if forbidden:
        errors.append(
            f"the producer source reads the environment variable(s) "
            f"{sorted({hit['name'] for hit in forbidden})}"
        )

    # -- P3.2 the capture declares its own boundary --------------------------
    invocation = record.get("invocation") if isinstance(record, dict) else {}
    invocation = invocation if isinstance(invocation, dict) else {}
    boundary_errors: List[str] = []
    if invocation.get("live_modal_invocation") is not False:
        boundary_errors.append(
            f"the capture declares live_modal_invocation={invocation.get('live_modal_invocation')!r}, "
            "not False"
        )
    if invocation.get("provider_queried") is not False:
        boundary_errors.append(
            f"the capture declares provider_queried={invocation.get('provider_queried')!r}, "
            "not False"
        )
    if invocation.get("deployment") != "none":
        boundary_errors.append(
            f"the capture declares deployment={invocation.get('deployment')!r}, not 'none'"
        )
    if invocation.get("gpu") != "none":
        boundary_errors.append(
            f"the capture declares gpu={invocation.get('gpu')!r}, not 'none'"
        )
    if not str(invocation.get("production_change") or "").strip():
        boundary_errors.append("the capture states no production-change statement")
    checks.append(
        _check(
            "P3.2.no_live_invocation_no_provider_query_and_no_deployment",
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

    # -- P3.3 the sentinel was never touched ---------------------------------
    sentinel = record.get("sentinel") if isinstance(record, dict) else {}
    sentinel = sentinel if isinstance(sentinel, dict) else {}
    accesses = sentinel.get("accesses")
    sentinel_errors: List[str] = []
    if not isinstance(accesses, list):
        sentinel_errors.append("the capture states no list of sentinel accesses")
    elif accesses:
        sentinel_errors.append(f"the producer touched modal.running_app: {accesses}")
    checks.append(
        _check(
            "P3.3.sentinel_never_touched",
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

    # -- P3.4 the hostile environment did not become an observation ----------
    environment = record.get("environment") if isinstance(record, dict) else {}
    environment = environment if isinstance(environment, dict) else {}
    spoofed = environment.get("spoofed_environment_variables")
    spoofed_errors: List[str] = []
    if not isinstance(spoofed, dict) or not spoofed:
        spoofed_errors.append("the capture states no spoofed environment variables")
    else:
        for name in FORBIDDEN_ENVIRONMENT_NAMES:
            if name not in spoofed:
                spoofed_errors.append(f"the capture did not spoof {name!r}")
    container_fact = envelope.get("container_id")
    if not isinstance(container_fact, dict):
        spoofed_errors.append("the envelope carries no fact for 'container_id'")
    elif container_fact.get("status") != NOT_AVAILABLE:
        spoofed_errors.append(
            f"the container id is {container_fact.get('status')!r}, not {NOT_AVAILABLE!r}: a "
            "spoofed environment value became an observation"
        )
    elif container_fact.get("value") is not None:
        spoofed_errors.append("the container id holds a value")
    checks.append(
        _check(
            "P3.4.a_spoofed_environment_does_not_become_an_observation",
            not spoofed_errors,
            error="; ".join(spoofed_errors) if spoofed_errors else None,
            planned=(
                "the capture ran with MODAL_WORKER_ID, HOSTNAME and MODAL_TASK_ID set to "
                "fake, well-formed values, and the container id stayed NOT_AVAILABLE"
            ),
            spoofed_environment_variables=spoofed,
            container_id_status=(
                container_fact.get("status") if isinstance(container_fact, dict) else None
            ),
        )
    )
    errors.extend(spoofed_errors)

    # -- P3.5 the envelope carries typed facts that name their side ---------
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
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    if not ok:
        envelope_errors.append(error or "the envelope is not valid")
    checks.append(
        _check(
            "P3.5.envelope_is_typed_worker_side_and_source_checked",
            not envelope_errors,
            error="; ".join(envelope_errors) if envelope_errors else None,
            planned=(
                "every identity fact of the envelope is a typed fact that names the worker "
                "side, and every observed fact names a registered observation source"
            ),
            envelope_fields=sorted(k for k in envelope if k in MODAL_IDENTITY_FIELDS),
        )
    )
    errors.extend(envelope_errors)

    # -- P3.6 the worker holds no observed container id ----------------------
    worker_container_errors: List[str] = []
    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if isinstance(fact, dict) and fact.get("status") == OBSERVED:
            if field_name == "container_id":
                worker_container_errors.append(
                    "the worker envelope records an OBSERVED container id: a function "
                    "container has no supported source of a provider-issued container id"
                )
    if envelope.get("container_id_value") is not None:
        worker_container_errors.append(
            "the worker envelope still carries a raw container_id_value"
        )
    checks.append(
        _check(
            "P3.6.the_worker_holds_no_observed_container_id",
            not worker_container_errors,
            error="; ".join(worker_container_errors) if worker_container_errors else None,
            planned=(
                "the worker envelope holds no observed container id and no raw container id "
                "value: the worker attests only what the SDK gives it"
            ),
            container_id_value=envelope.get("container_id_value"),
        )
    )
    errors.extend(worker_container_errors)

    # -- P3.7 the container id is an explicit absence with the exact reason --
    import modal_app  # noqa: E402  (the production producer itself)

    reason_errors: List[str] = []
    fact = envelope.get("container_id")
    if not isinstance(fact, dict):
        reason_errors.append("the envelope carries no fact for 'container_id'")
    elif fact.get("status") != NOT_AVAILABLE:
        reason_errors.append(
            f"the fact for 'container_id' is {fact.get('status')!r}, not {NOT_AVAILABLE!r}"
        )
    elif fact.get("value") is not None:
        reason_errors.append("the fact for 'container_id' holds a value")
    else:
        reason = str(fact.get("reason") or "")
        if reason != modal_app.MODAL_CONTAINER_ID_NOT_ATTESTABLE_REASON:
            reason_errors.append(
                "the reason of 'container_id' is not the exact reason of the producer"
            )
        elif "MODAL_WORKER_ID" not in reason or "HOSTNAME" not in reason:
            reason_errors.append(
                "the reason of 'container_id' does not name the rejected environment "
                "variables"
            )
    checks.append(
        _check(
            "P3.7.container_id_is_an_explicit_absence_with_the_precise_reason",
            not reason_errors,
            error="; ".join(reason_errors) if reason_errors else None,
            planned=(
                "'container_id' is an explicit NOT_AVAILABLE with the exact reason of the "
                "producer and holds no value"
            ),
            field="container_id",
        )
    )
    errors.extend(reason_errors)

    # -- P3.8 the client-observed block is client-side and correlated --------
    client_errors: List[str] = []
    client_block = record.get("client_observed") if isinstance(record, dict) else None
    if not isinstance(client_block, dict):
        client_errors.append("the capture states no client-observed block")
        client_block = {}

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

    ok, error = validate_client_observed_facts(client_block, strict_sources=True)
    if not ok:
        client_errors.append(error or "the client-observed block is not valid")

    container_fact = client_block.get("container_id")
    if isinstance(container_fact, dict) and container_fact.get("status") == OBSERVED:
        correlation = container_fact.get("correlation")
        if not isinstance(correlation, dict):
            client_errors.append(
                "the client-observed container id carries no correlation record"
            )
        else:
            call_id = correlation.get("function_call_id")
            if call_id != envelope.get("function_call_id", {}).get("value"):
                client_errors.append(
                    "the correlation of the client-observed container id names another "
                    "function call than the one the worker observed"
                )
    elif isinstance(container_fact, dict) and container_fact.get("status") == NOT_AVAILABLE:
        if not str(container_fact.get("reason") or "").strip():
            client_errors.append(
                "the client-observed container id is NOT_AVAILABLE without a reason"
            )

    checks.append(
        _check(
            "P3.8.client_observation_is_client_side_and_correlated",
            not client_errors,
            error="; ".join(client_errors) if client_errors else None,
            planned=(
                "the client-observed facts name the client side, the worker envelope holds "
                "no client-side fact, and the client-side container id is either an explicit "
                "absence or correlated to the very function call the worker observed"
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

    # -- P3.9 the digest of the artifact is the digest of the bytes ----------
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
            "P3.9.artifact_digest_matches_the_bytes_on_disk",
            not digest_errors and bool(artifact),
            error="; ".join(digest_errors) if digest_errors else None,
            planned=(
                "the SHA-256 of the stage evidence artifact on disk equals the digest the "
                "capture record claims"
            ),
            recorded_sha256=artifact_ref.get("sha256"),
            actual_sha256=(
                file_sha256(artifact_path)
                if artifact_path and artifact_path.is_file()
                else None
            ),
        )
    )
    errors.extend(digest_errors)

    # -- P3.10 the artifact satisfies the Iteration 18 contract -------------
    contract_errors: List[str] = []
    if not artifact:
        contract_errors.append("there is no stage evidence artifact to validate")
    else:
        ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
        if not ok:
            contract_errors.append(error or "the stage evidence artifact is not valid")
        else:
            response = artifact.get("provider_response")
            carried = response.get(ENVELOPE_SOURCE) if isinstance(response, dict) else None
            if canonical_json_bytes(carried) != canonical_json_bytes(envelope):
                contract_errors.append(
                    "the envelope of the artifact is not the envelope the captured response "
                    "carries"
                )
    checks.append(
        _check(
            "P3.10.stage_evidence_artifact_satisfies_the_contract",
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

    # -- P3.11 the stage facts keep the side of the envelope ----------------
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
            "P3.11.stage_facts_keep_the_side_of_the_envelope",
            not side_errors,
            error="; ".join(side_errors) if side_errors else None,
            planned=(
                "the facts derived from the envelope keep the side the envelope declared"
            ),
        )
    )
    errors.extend(side_errors)

    # -- P3.12 the provenance block passes the provenance validator ----------
    provenance = record.get("provenance") if isinstance(record, dict) else {}
    provenance = provenance if isinstance(provenance, dict) else {}
    provenance_errors: List[str] = []
    provenance_artifact = provenance.get("artifact")
    if not isinstance(provenance_artifact, dict):
        provenance_errors.append("the capture states no provenance artifact")
    else:
        ok, error = validate_modal_invocation_provenance(
            provenance_artifact,
            evidence_root=evidence_dir,
            strict_sources=True,
        )
        if not ok:
            provenance_errors.append(error or "the provenance block is not valid")
    if provenance.get("validated") is not True:
        provenance_errors.append("the capture does not state that the provenance validated")
    checks.append(
        _check(
            "P3.12.provenance_block_satisfies_the_provenance_validator",
            not provenance_errors,
            error="; ".join(provenance_errors) if provenance_errors else None,
            planned=(
                "the provenance block of the capture satisfies the repository's own "
                "provenance validator in the strict source mode, with the stage evidence "
                "artifact of this very capture as its evidence"
            ),
        )
    )
    errors.extend(provenance_errors)

    # -- P3.13 the capture is bound to the code it was made from -------------
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
            "P3.13.capture_is_bound_to_its_code_sha",
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
        outcome = _validate_iteration21(evidence_dir=evidence_dir, code_sha=bound)
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

    outcome = _validate_iteration21(evidence_dir=evidence_dir, code_sha=code_sha)
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
        "generator": "benchmarks/validate_iteration21_evidence.py",
        "code_sha": code_sha,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "iteration": 21,
            "purpose": (
                "validate the provider-backed container identity of the production producer "
                "and the evidence of it"
            ),
            "evidence_dir": str(args.evidence_dir).replace("\\", "/"),
            "stage": STAGE,
            "target_id": TARGET_ID,
            "runtime": (
                "local producer capture under a hostile environment - no Modal invocation, "
                "no provider query, no deployment, no GPU, no change to a deployed worker"
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
                "validate the source of the fixed production producer, the hostile "
                "environment the capture ran in, the registry of the allowed observation "
                "sources, the client-side correlation, the unchanged Iteration 18 artifact "
                "contract, the provenance consumer and the binding of the report to the code "
                "SHA it was produced from"
            ),
            "attempted": (
                "the producer source, the sentinel on modal.running_app, the spoofed "
                "environment, the envelope of the capture, the client-observed block, the "
                "stage evidence artifact and its digest, the provenance block and the source "
                "binding"
            ),
            "executed": (
                "the checks were executed against the artifacts stored on disk"
                if outcome["record"]
                else "nothing could be executed: there is no capture record"
            ),
            "observed": (
                "the report states exactly what the capture record, the stage evidence "
                "artifact and the provenance block contain; a fact the worker cannot observe "
                "is reported as NOT_AVAILABLE with its reason and is never filled in"
            ),
            "reported": (
                "PASSED means every check of the provider-backed container identity passed; "
                "FAILED means at least one did not. The capture is a LOCAL capture of the "
                "producer: no Modal invocation was made, the provider was never asked, no "
                "worker was deployed and no live validation is claimed. The deployed workers "
                "still need a new deployment to carry the fix, and that is outside this "
                "iteration"
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
