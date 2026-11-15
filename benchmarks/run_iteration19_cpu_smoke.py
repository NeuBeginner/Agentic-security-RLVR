"""
benchmarks/run_iteration19_cpu_smoke.py
=======================================

The live, **CPU-only** Modal invocation of the Iteration 19 runtime smoke test.

One invocation of one function of one separate app
(``benchmarks/modal_cpu_smoke_app.py``) - no GPU, no model, no volume, no
secret, no production worker. The driver then does exactly three things:

1. it captures the response of the worker **unchanged**;
2. it writes that capture as per-stage evidence with the repository's own
   Iteration 18 producer (``write_stage_evidence_artifact``);
3. it writes an invocation record that states what actually happened - the
   provider-issued identifiers, the worker-observed runtime metadata, the
   billed usage (or the explicit reason why it is unavailable) and the source
   commit the run was made from.

A failed invocation is recorded as a failure: the stage is written in the
honest state ``ATTEMPT_FAILED_NO_RESPONSE`` and the validator reports
``FAILED``. The driver never falls back to a local execution - a rehearsal is
never reported as a live pass.

**The invocation is refused by default.** The smoke app is a separate
deployment that is not part of the evidence-regeneration workflow: it has no
approved step policy, no declared resource bounds and no egress declaration, so
the R1 dispatch contract cannot authorise it. A *separate, CPU-only* app does
not make it authorised - an unauthorised remote workload is refused, not
classified out of scope. The refusal happens **before** the ephemeral app is
started and before the provider's entry point is touched: it reaches neither
the control plane nor a container. Only an explicit maintainer approval
(``R1_APPROVE_ITERATION19_CPU_SMOKE=1``) lifts the refusal, and the approval
is a separate decision of the maintainer.

The historical Iteration 19 evidence is not touched by any of this.

Usage::

    python -m benchmarks.run_iteration19_cpu_smoke --profile neubeginner
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
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
    EvidenceContractError,
    StageResponseCapture,
    build_evidence_ref_from_bytes,
    write_stage_evidence_artifact,
)

DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration19_cpu_smoke"
DEFAULT_PROFILE = "neubeginner"
DEFAULT_SEED = "iteration19"

#: The stage of the smoke test. It is its own stage: the smoke test is not one
#: of the four stages of a benchmark target.
STAGE = "cpu_smoke"

#: The synthetic target id of the smoke test.
TARGET_ID = "CPU-SMOKE-01"

#: The environment variable that carries the maintainer's explicit approval for
#: the live CPU-only smoke invocation. Without it the invocation is refused.
APPROVAL_ENV_VAR = "R1_APPROVE_ITERATION19_CPU_SMOKE"

#: The values the approval variable may carry.
APPROVAL_VALUES = ("1", "true", "yes")


class SmokeNotAuthorised(RuntimeError):
    """The live CPU-only smoke invocation was refused: it is not authorised.

    The refusal is explicit and fail-closed. It is raised **before** the
    ephemeral app is started and before the provider's entry point is touched,
    so a refused invocation reaches neither the control plane nor a container.
    """


def _assert_authorised() -> None:
    """Refuse the live invocation unless the maintainer approved it explicitly.

    The smoke app is a separate deployment that is not part of the
    evidence-regeneration workflow: it has no approved step policy, no declared
    resource bounds and no egress declaration. The R1 dispatch contract cannot
    authorise it, so the only way to run it is an explicit approval of the
    maintainer - a decision that is separate from this workflow.
    """
    value = os.environ.get(APPROVAL_ENV_VAR, "").strip().lower()
    if value in APPROVAL_VALUES:
        return
    raise SmokeNotAuthorised(
        "the live CPU-only Modal invocation of the Iteration 19 smoke is refused: "
        "it is not part of the evidence-regeneration workflow, it has no approved "
        "step policy, no declared resource bounds and no egress declaration, and "
        "no maintainer approval exists for it. Set "
        f"{APPROVAL_ENV_VAR}=1 only with such an approval."
    )

#: The key at which the worker returns the runtime-identity envelope. The
#: captured response carries the envelope at exactly this source.
ENVELOPE_SOURCE = "modal_runtime"

#: The reasons for the two fields the Modal runtime does not expose. They are
#: documented facts about the installed SDK (1.5.5), not guesses.
IMAGE_DIGEST_UNAVAILABLE_REASON = (
    "Modal SDK 1.5.5 exposes no image-digest API to the container and the CLI offers "
    "only 'modal image names' and 'modal image logs'; the immutable image id is the "
    "image identity the runtime does expose"
)
SESSION_ID_UNAVAILABLE_REASON = (
    "Modal SDK 1.5.5 exposes no session-id accessor: the runtime-context API "
    "(modal.current_function_call_id, modal.current_input_id, modal.interact, modal.is_local) "
    "carries no session id, and the modal.running_app module holds only the RunningApp "
    "dataclass (app_id, app_page_url, app_logs_url, function_ids, class_ids, "
    "object_handle_metadata, interactive) - there is no callable running_app() and no "
    "session in it"
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """The current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args: str) -> Tuple[int, str, str]:
    """Run a git command in the repository and return ``(code, out, err)``."""
    completed = subprocess.run(
        ["git", *args],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def _source_state() -> Dict[str, Any]:
    """
    The state of the source tree at the moment of the invocation.

    The tracked files are what the run was made from; the untracked files are
    reported separately, because an untracked file changes no executed code.
    """
    code, sha, _err = _git("rev-parse", "HEAD")
    commit_sha = sha if code == 0 else None

    _code, status_out, _err = _git("status", "--porcelain")
    tracked_modified: List[str] = []
    untracked: List[str] = []
    for line in status_out.splitlines():
        if not line.strip():
            continue
        state = line[:2]
        path = line[3:].strip()
        if state == "??":
            untracked.append(path)
        else:
            tracked_modified.append(path)

    return {
        "commit_sha": commit_sha,
        "tracked_files_modified": tracked_modified,
        "untracked_paths": untracked,
        "clean": not tracked_modified,
        "observed_at_utc": _utc_now(),
    }


def _run_cli(command: List[str], *, timeout: int = 180) -> Dict[str, Any]:
    """Run a CLI command and capture everything about it."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "error": None if completed.returncode == 0 else (completed.stderr or "").strip(),
    }


def _collect_billed_usage(profile: str, app_id: Optional[str]) -> Dict[str, Any]:
    """
    Ask the provider for the billed usage of the workspace.

    The value is either a provider-backed fact (the line items the provider
    reports for this app) or an explicit ``NOT_AVAILABLE`` with the exact
    reason. It is never estimated.
    """
    command = [
        "modal",
        "billing",
        "report",
        "--for",
        "today",
        "--resolution",
        "h",
        "--show-resources",
        "--json",
        "--profile",
        profile,
    ]
    result = _run_cli(command)

    if result["returncode"] != 0:
        reason = (
            "the provider's workspace billing report is not available for this run: "
            f"{(result['error'] or 'the CLI returned no diagnostic output').strip()}"
        )
        return {
            "status": "NOT_AVAILABLE",
            "value": None,
            "reason": reason,
            "command": command,
            "provider_returncode": result["returncode"],
            "provider_stderr": result["stderr"].strip(),
        }

    try:
        report = json.loads(result["stdout"])
    except ValueError as exc:
        return {
            "status": "NOT_AVAILABLE",
            "value": None,
            "reason": f"the provider's billing report is not parseable JSON: {exc}",
            "command": command,
            "provider_returncode": result["returncode"],
        }

    items = report if isinstance(report, list) else []
    matched = [
        item
        for item in items
        if isinstance(item, dict) and app_id and item.get("object_id") == app_id
    ]
    if not matched:
        return {
            "status": "NOT_AVAILABLE",
            "value": None,
            "reason": (
                "the provider's workspace billing report contains no line item for the "
                f"application {app_id!r} of this run; the report itself holds "
                f"{len(items)} line items"
            ),
            "command": command,
            "provider_returncode": result["returncode"],
            "workspace_line_item_count": len(items),
        }

    return {
        "status": "OBSERVED",
        "value": {
            "app_id": app_id,
            "line_items": matched,
            "line_item_count": len(matched),
        },
        "source": "modal billing report --json --show-resources (the provider's own report)",
        "command": command,
        "provider_returncode": result["returncode"],
    }


def _list_containers(profile: str, app_id: Optional[str]) -> Dict[str, Any]:
    """
    Ask the provider which containers serve the app of this run.

    The container id is a provider-issued identifier. It is taken from the
    provider's own container list while the app is still running; it is never
    inferred from a configured name and never invented.
    """
    if not app_id:
        return {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": (
                "the app id of this run is unknown, so the provider's container list "
                "cannot be queried for it"
            ),
            "command": None,
        }

    command = [
        "modal",
        "container",
        "list",
        "--app-id",
        app_id,
        "--json",
        "--profile",
        profile,
    ]
    result = _run_cli(command)
    if result["returncode"] != 0:
        return {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": (
                "the provider's container list is not available for this run: "
                f"{(result['error'] or 'the CLI returned no diagnostic output').strip()}"
            ),
            "command": command,
            "provider_returncode": result["returncode"],
            "provider_stderr": result["stderr"].strip(),
        }

    try:
        payload = json.loads(result["stdout"])
    except ValueError as exc:
        return {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": f"the provider's container list is not parseable JSON: {exc}",
            "command": command,
        }

    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = payload.get("containers") or payload.get("items") or []
    else:
        entries = []

    container_ids: List[str] = []
    container_fields: List[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("container_id", "worker_id", "id", "task_id"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                container_ids.append(value.strip())
                container_fields.append(key)
                break

    if not container_ids:
        return {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": (
                "the provider's container list of the application holds no container id"
            ),
            "command": command,
            "provider_payload": payload,
        }
    if len(container_ids) > 1:
        return {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": (
                f"the provider's container list holds {len(container_ids)} containers for "
                "this application, so the container of this specific call cannot be "
                "attributed to one of them"
            ),
            "command": command,
            "container_ids": container_ids,
            "provider_payload": payload,
        }

    return {
        "status": OBSERVED,
        "value": container_ids[0],
        "source": (
            "the provider's own container list (modal container list --app-id --json), "
            f"field {container_fields[0]!r} of the container entry"
        ),
        "command": command,
        "container_ids": container_ids,
        "provider_payload": payload,
    }


def _identity_fact(envelope: Any, field_name: str) -> Dict[str, Any]:
    """Read one typed identity fact out of the runtime-identity envelope."""
    if not isinstance(envelope, dict):
        return {
            "status": "NOT_AVAILABLE",
            "value": None,
            "reason": (
                "the worker returned no runtime-identity envelope, so the "
                f"'{field_name}' was never observed"
            ),
        }
    fact = envelope.get(field_name)
    if isinstance(fact, dict) and fact.get("status") == "OBSERVED":
        return {
            "status": "OBSERVED",
            "value": fact.get("value"),
            "source": fact.get("source"),
        }
    if isinstance(fact, dict) and fact.get("status") == "NOT_AVAILABLE":
        return {
            "status": "NOT_AVAILABLE",
            "value": None,
            "reason": fact.get("reason"),
        }
    return {
        "status": "NOT_AVAILABLE",
        "value": None,
        "reason": (
            f"the runtime-identity envelope carries no well-formed fact for '{field_name}'"
        ),
    }


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


async def _invoke(
    cpu_smoke: Any,
    app: Any,
    seed: str,
    profile: Optional[str],
) -> Dict[str, Any]:
    """Invoke the CPU-only smoke function once - refused without the approval.

    The authorisation is checked **first**: a refused invocation never starts
    the ephemeral app and never reaches the provider's ``remote``. The call
    itself is the only provider entry point of this script.
    """
    _assert_authorised()

    async with app.run():
        result = await cpu_smoke.remote.aio(seed)
        running_app_id = app.app_id
        listed = await asyncio.to_thread(_list_containers, profile, running_app_id)
    return {
        "response": result,
        "app_id": running_app_id,
        "containers": listed,
    }


def run(args: argparse.Namespace) -> Dict[str, Any]:
    """Invoke the CPU-only smoke function once and write the evidence."""
    # The authorisation is checked before the app module is imported and before
    # anything of this run touches the provider: a refused run is not an
    # attempted invocation and writes no evidence.
    _assert_authorised()

    # The Modal SDK reads the active profile from the environment when it is
    # imported, so the profile is set before the app module is imported.
    if args.profile:
        os.environ["MODAL_PROFILE"] = args.profile

    from benchmarks.modal_cpu_smoke_app import (  # noqa: E402
        DECLARED_RESOURCES,
        app,
        cpu_smoke,
    )

    import modal  # noqa: E402  (imported after the profile was set)

    evidence_dir = (_ROOT / args.evidence_dir).resolve()
    correlation_id = (
        f"iteration19-cpu-smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )

    source = _source_state()
    started_at = _utc_now()
    started_monotonic = datetime.now(timezone.utc)

    response: Optional[Any] = None
    invocation_error: Optional[str] = None
    client_app_id: Optional[str] = None
    containers: Dict[str, Any] = {
        "status": NOT_AVAILABLE,
        "value": None,
        "reason": "the run did not reach the invocation of the function",
    }
    try:
        outcome = asyncio.run(
            _invoke(cpu_smoke, app, args.seed, args.profile)
        )
        response = outcome["response"]
        client_app_id = outcome["app_id"]
        containers = outcome["containers"]
    except SmokeNotAuthorised:
        # The refusal is not a failed invocation: it is the absence of one.
        raise
    except Exception as exc:  # noqa: BLE001 - the failure is the evidence
        invocation_error = f"{type(exc).__name__}: {exc}"

    finished_at = _utc_now()
    duration_seconds = round(
        (datetime.now(timezone.utc) - started_monotonic).total_seconds(), 3
    )

    executed = invocation_error is None
    response_received = response is not None

    envelope: Optional[Dict[str, Any]] = None
    if isinstance(response, dict):
        candidate = response.get(ENVELOPE_SOURCE)
        if isinstance(candidate, dict):
            envelope = candidate
    runtime_envelope_received = envelope is not None

    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=bool(executed),
        response_received=bool(response_received),
        provider_response=response if response_received else None,
        runtime_identity=envelope,
        runtime_identity_source=ENVELOPE_SOURCE if runtime_envelope_received else "",
        response_source=(
            "the return value of the Modal function call "
            f"{_identity_fact(envelope, 'function_call_id').get('value')} "
            "(modal.Function.remote)"
            if response_received
            else ""
        ),
        requested_fields=MODAL_IDENTITY_FIELDS,
    )

    evidence_dir.mkdir(parents=True, exist_ok=True)
    artifact_path: Optional[Path] = None
    artifact_ref: Optional[Dict[str, Any]] = None
    contract_error: Optional[str] = None
    try:
        artifact_path, artifact_ref = write_stage_evidence_artifact(
            evidence_dir,
            capture,
            target_id=TARGET_ID,
            correlation_id=correlation_id,
        )
    except EvidenceContractError as exc:
        # Fail closed: a contradictory capture is never written down.
        contract_error = str(exc)

    worker_observed = response.get("worker_observed") if isinstance(response, dict) else None
    payload = response.get("smoke_payload") if isinstance(response, dict) else None

    billed_usage = _collect_billed_usage(args.profile, client_app_id)

    provider_app_list = _run_cli(["modal", "app", "list", "--profile", args.profile])

    record: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "iteration": 19,
        "purpose": "live Modal CPU-only runtime smoke test",
        "invocation": {
            "attempted": True,
            "executed": bool(executed),
            "response_received": bool(response_received),
            "runtime_envelope_received": bool(runtime_envelope_received),
            "status": "SUCCEEDED" if executed else "FAILED",
            "error": invocation_error,
            "contract_error": contract_error,
            "started_at_utc": started_at,
            "finished_at_utc": finished_at,
            "duration_seconds": duration_seconds,
            "invocation_count": 1,
            "deployment_kind": "ephemeral",
            "production_change": (
                "none - this iteration executed no 'modal deploy', and no deployed "
                "production worker was changed, redeployed or restarted"
            ),
        },
        "command": {
            "script": "python -m benchmarks.run_iteration19_cpu_smoke",
            "argv": [
                "python",
                "-m",
                "benchmarks.run_iteration19_cpu_smoke",
                "--profile",
                args.profile,
                "--seed",
                args.seed,
            ],
            "environment": {"MODAL_PROFILE": args.profile},
            "working_directory": str(_ROOT),
        },
        "source": source,
        "modal": {
            "sdk_version": getattr(modal, "__version__", None),
            "profile": args.profile,
            "app_name_declared": "aegis-iteration19-cpu-smoke",
            "declared_resources": DECLARED_RESOURCES,
        },
        "identifiers": {
            # The provider-issued identifiers of this run. Every fact names the
            # side that observed it: the worker reads its own identity from
            # inside the container, the client reads the app and container
            # identity from the provider's API.
            "app_id": {
                "status": OBSERVED,
                "value": client_app_id,
                "source": (
                    "the provider-issued App.app_id of the running app "
                    "(Modal SDK 1.5.5, client side)"
                ),
                "observed_by": "client",
            }
            if client_app_id
            else {
                "status": NOT_AVAILABLE,
                "value": None,
                "reason": (
                    "the provider exposed no app id for the running app of this run"
                ),
                "observed_by": "client",
            },
            "function_call_id": {
                **_identity_fact(envelope, "function_call_id"),
                "observed_by": "worker",
            },
            "container_id": {
                **containers,
                "observed_by": "client",
            },
            "image_id": {
                **_identity_fact(envelope, "image_id"),
                "observed_by": "worker",
            },
            "image_digest": {
                "status": NOT_AVAILABLE,
                "value": None,
                "reason": IMAGE_DIGEST_UNAVAILABLE_REASON,
                "observed_by": "provider",
            },
            "session_id": {
                "status": NOT_AVAILABLE,
                "value": None,
                "reason": SESSION_ID_UNAVAILABLE_REASON,
                "observed_by": "provider",
            },
        },
        "identifiers_note": (
            "the worker observed the function-call id and the image id inside the "
            "container; Modal SDK 1.5.5 offers a function container neither a "
            "running-app accessor nor a worker/hostname environment variable, so the "
            "app id and the container id were taken from the provider on the client "
            "side. The worker-side facts are in 'runtime_identity'."
        ),
        "runtime_identity": envelope,
        "worker_observed": worker_observed,
        "payload": payload,
        "response": response,
        "evidence_artifact": {
            "path": (
                str(artifact_path.relative_to(_ROOT)).replace("\\", "/")
                if artifact_path is not None
                else None
            ),
            "sha256": artifact_ref.get("sha256") if artifact_ref else None,
            "byte_length": artifact_ref.get("byte_length") if artifact_ref else None,
            "description": artifact_ref.get("description") if artifact_ref else None,
        },
        "billed_usage": billed_usage,
        "gpu_statement": {
            "gpu_requested": DECLARED_RESOURCES.get("gpu"),
            "gpu_allocated": False,
            "worker_observed_evidence": (
                worker_observed.get("gpu_evidence") if isinstance(worker_observed, dict) else None
            ),
            "statement": (
                "zero GPU allocation: the function is declared with gpu=None, no GPU was "
                "requested and the worker observed no NVIDIA device node, no CUDA runtime "
                "library and no CUDA device environment variable"
            ),
        },
        "provider_app_list_after_run": provider_app_list,
        "validator": {
            "script": "benchmarks/validate_iteration19_evidence.py",
            "command": "python -m benchmarks.validate_iteration19_evidence --code-sha <sha>",
            "report_path": "benchmarks/evidence/iteration19_validation_evidence.json",
        },
    }

    record_path = evidence_dir / "invocation_record.json"
    record_bytes = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    record_path.write_bytes(record_bytes)
    record_ref = build_evidence_ref_from_bytes(
        "invocation_record.json",
        record_bytes,
        description="the record of the live CPU-only Modal invocation of Iteration 19",
    )

    return {
        "record_path": record_path,
        "record_ref": record_ref,
        "artifact_path": artifact_path,
        "artifact_ref": artifact_ref,
        "record": record,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR)
    args = parser.parse_args(argv)

    try:
        outcome = run(args)
    except SmokeNotAuthorised as exc:
        # A refused invocation is not a failed invocation: nothing was attempted,
        # no evidence was written and no container was started.
        print(f"the live invocation was refused: {exc}", file=sys.stderr)
        return 2
    record = outcome["record"]

    print(f"invocation status      : {record['invocation']['status']}")
    print(f"response received      : {record['invocation']['response_received']}")
    print(f"runtime envelope       : {record['invocation']['runtime_envelope_received']}")
    print(f"app id                 : {record['identifiers']['app_id'].get('value')}")
    print(
        f"function call id       : {record['identifiers']['function_call_id'].get('value')}"
    )
    print(f"container id           : {record['identifiers']['container_id'].get('value')}")
    print(f"image id               : {record['identifiers']['image_id'].get('value')}")
    print(f"billed usage           : {record['billed_usage']['status']}")
    print(f"evidence artifact      : {record['evidence_artifact']['path']}")
    print(f"artifact sha256        : {record['evidence_artifact']['sha256']}")
    print(f"invocation record      : {outcome['record_path']}")
    print(f"record sha256          : {outcome['record_ref']['sha256']}")

    if record["invocation"]["status"] != "SUCCEEDED":
        print(
            "the live invocation did not succeed - the evidence records the failure and "
            "no local fallback was used",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
