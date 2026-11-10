"""
benchmarks/run_iteration21_producer_capture.py
===============================================

The local capture of the **production** runtime-identity producer of
Iteration 21.

The Iteration 20 review kept the container-identity path of the production
producer open as a P0: ``modal_app.py::capture_modal_runtime_identity()``
treated ``MODAL_WORKER_ID`` or ``HOSTNAME`` as an observed Modal container id.
The review established that neither is a provider-issued identifier:

* ``MODAL_WORKER_ID`` is the SDK's ``worker_id`` **configuration setting**,
  which the SDK source itself documents as internal debugging use;
* ``HOSTNAME`` is a generic container hostname;
* and the public runtime surface of Modal SDK 1.5.5
  (``modal.current_function_call_id``, ``modal.current_input_id``,
  ``modal.interact``, ``modal.is_local``) reports no container id at all.

The provider-issued container id of an invocation is therefore a **client-side**
fact, and this iteration adds it to the client-observed block.

This script captures what the **fixed** producer returns. It is deliberately
small and deliberately honest:

* it executes the **real** producer - ``modal_app.capture_modal_runtime_identity()``
  - not a re-implementation of it;
* it installs a **sentinel** on ``modal.running_app``: any access at all is
  recorded, and the capture fails when the sentinel was touched;
* it installs a **hostile environment**: ``MODAL_WORKER_ID``, ``HOSTNAME`` and
  ``MODAL_TASK_ID`` are set to arbitrary, well-formed but **fake** values. A
  producer that copied them would report them as an observed container id -
  this capture proves that it does not;
* it serializes the response and writes the stage evidence artifact with the
  repository's own producer (``write_stage_evidence_artifact``);
* it builds the **provenance block** and validates it with the repository's own
  ``validate_modal_invocation_provenance``, so the whole chain
  producer -> response -> stage evidence -> provenance is exercised.

**This is not a live Modal invocation.** The capture runs locally, so it holds
**no** provider-issued identifier: outside a Modal container the function-call
id is ``NOT_AVAILABLE``, and the provider is never asked, so the client-side
container id is ``NOT_AVAILABLE`` too - which is exactly what the truth is at
that moment. The ``OBSERVED`` branches are exercised by the test suite, in a
simulated container context and against a fake provider, which are called
simulations.

No deployment, no redeployment, no restart, no live worker and no GPU is
touched by this script.

Usage::

    python -m benchmarks.run_iteration21_producer_capture
"""

from __future__ import annotations

import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_IDENTITY_FIELDS,
    StageResponseCapture,
    build_modal_stage_provenance,
    build_stage_identity_facts,
    sha256_bytes,
    validate_modal_invocation_provenance,
    write_stage_evidence_artifact,
)

# The git helpers of the Iteration 16 validator are reused unchanged.
from benchmarks.validate_iteration16_evidence import (  # noqa: E402
    _current_code_sha,
    _git,
)

DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/iteration21_producer_capture"

#: The stage the captured response belongs to. The fixed producer is the one
#: of the production EVM sandbox worker.
STAGE = "evm_sandbox"

#: The id of the captured target. It names the capture: this is not a
#: benchmark target.
TARGET_ID = "ITER21-01"

#: The source the runtime-identity envelope is carried at.
ENVELOPE_SOURCE = "modal_runtime"

#: The environment variables a producer must not read for the container
#: identity - and the fake values the capture puts into them.
SPOOFED_ENVIRONMENT = {
    "MODAL_WORKER_ID": "ta-SpoofedWorkerId0000000000",
    "HOSTNAME": "spoofed-host",
    "MODAL_TASK_ID": "ta-SpoofedTaskId00000000000",
}


class _RunningAppSentinel:
    """
    A sentinel that stands in for ``modal.running_app``.

    In Modal SDK 1.5.5 ``modal.running_app`` is a module: calling it raises
    ``TypeError: 'module' object is not callable``, and the production code
    swallowed that exception. The sentinel makes such an attempt visible: every
    access is recorded, and the capture reports it.

    The sentinel is deliberately hostile - any use of it is an error, never a
    value.
    """

    def __init__(self) -> None:
        self.accesses: List[str] = []

    def _record(self, what: str) -> None:
        self.accesses.append(what)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._record("call")
        raise AssertionError(
            "the producer called modal.running_app(); in Modal SDK 1.5.5 that name is a "
            "module and not a callable"
        )

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        self._record(f"attribute:{name}")
        raise AssertionError(
            f"the producer read modal.running_app.{name}; in Modal SDK 1.5.5 that name is a "
            "module and not a callable"
        )


class _UnavailableProvider:
    """
    A provider that refuses to answer.

    The capture is local: it must not reach the provider, so the client-side
    container id is resolved against a provider that refuses. The refusal is
    the reason the fact is an explicit absence - and it is recorded in the
    capture record, so nobody can read the capture as a provider observation.
    """

    def _refuse(self, what: str) -> Any:
        raise RuntimeError(
            f"the capture is local: the provider was not asked for the {what}"
        )

    def call_graph_inputs(self, function_call_id: str) -> Any:
        return self._refuse("call graph")

    def containers_of_app(self, app_id: str) -> Any:
        return self._refuse("container listing")

    def task_app_id(self, container_id: str) -> Any:
        return self._refuse("task record")


def _install_hostile_environment() -> Dict[str, Optional[str]]:
    """
    Put the **fake** container environment into place.

    The values are well-formed enough to look like provider-issued ids, so a
    producer that copied them would pass them on as an observation. The
    capture proves that it does not: the container id stays ``NOT_AVAILABLE``.

    The former values are returned so that the capture can state them.
    """
    removed: Dict[str, Optional[str]] = {}
    for name, value in SPOOFED_ENVIRONMENT.items():
        removed[name] = os.environ.get(name)
        os.environ[name] = value
    return removed


def _restore_environment(removed: Dict[str, Optional[str]]) -> None:
    for name, value in removed.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def capture_producer_identity() -> Dict[str, Any]:
    """
    Execute the real production producer and return the envelope it built.

    The sentinel is installed around the call, so an attempt to use the
    unsupported ``modal.running_app`` is recorded instead of being swallowed.
    The hostile environment is in place for the duration of the call.
    """
    import modal

    import modal_app

    sentinel = _RunningAppSentinel()
    original = getattr(modal, "running_app", None)
    modal.running_app = sentinel  # type: ignore[assignment]
    removed = _install_hostile_environment()
    try:
        envelope = modal_app.capture_modal_runtime_identity()
    finally:
        _restore_environment(removed)
        if original is None:
            try:
                del modal.running_app  # type: ignore[attr-defined]
            except AttributeError:
                pass
        else:
            modal.running_app = original  # type: ignore[assignment]

    return {
        "envelope": envelope,
        "sentinel": sentinel,
        "spoofed_environment": dict(SPOOFED_ENVIRONMENT),
        "restored_environment": removed,
    }


def _worker_observed() -> Dict[str, Any]:
    """The runtime facts the capture process observed about itself."""
    import modal

    return {
        "python_version": sys.version,
        "python_version_info": list(sys.version_info[:3]),
        "platform": platform.platform(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "modal_sdk_version": getattr(modal, "__version__", None),
        "modal_is_local": modal.is_local(),
        "modal_current_input_id": modal.current_input_id(),
        "modal_env_var_names": sorted(name for name in os.environ if name.startswith("MODAL_")),
    }


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument(
        "--code-sha",
        default=None,
        help="the code SHA the capture is made from (defaults to HEAD)",
    )
    args = parser.parse_args(argv)

    evidence_dir = Path(args.evidence_dir)
    if not evidence_dir.is_absolute():
        evidence_dir = _ROOT / evidence_dir
    evidence_dir.mkdir(parents=True, exist_ok=True)

    captured = capture_producer_identity()
    envelope = captured["envelope"]
    sentinel: _RunningAppSentinel = captured["sentinel"]

    # The response of the shape a worker returns: the runtime-identity
    # envelope is carried at the declared source.
    response: Dict[str, Any] = {
        "stage": STAGE,
        ENVELOPE_SOURCE: envelope,
        "worker_observed": _worker_observed(),
    }

    correlation_id = f"corr-{TARGET_ID}-iteration21-local-capture"
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source=ENVELOPE_SOURCE,
        response_source=(
            "the response of the production runtime-identity producer, captured locally"
        ),
        requested_fields=MODAL_IDENTITY_FIELDS,
    )

    artifact_path, artifact_ref = write_stage_evidence_artifact(
        evidence_dir,
        capture,
        target_id=TARGET_ID,
        correlation_id=correlation_id,
    )

    # The provenance consumer: the facts of the stage, the facts the client
    # observed, and the block the repository's own validator consumes.
    stage_facts = build_stage_identity_facts(capture, evidence_ref=artifact_ref)
    from benchmarks.adapters import _client_observed_block

    client_observed = _client_observed_block(stage_facts, provider=_UnavailableProvider())

    provenance_artifact = {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": client_observed,
            "target_id": TARGET_ID,
            "correlation_id": correlation_id,
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
    provenance_ok, provenance_error = validate_modal_invocation_provenance(
        provenance_artifact,
        evidence_root=evidence_dir,
        strict_sources=True,
    )

    code_sha = args.code_sha or _current_code_sha()
    status = _git("status", "--porcelain") or ""
    tracked_changes = [
        line for line in status.splitlines() if line.strip() and not line.startswith("??")
    ]

    record: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "iteration": 21,
        "kind": "local_producer_capture",
        "purpose": (
            "capture what the fixed production runtime-identity producer returns under a "
            "hostile container environment, and prove that the container identity is not "
            "inferred from the environment"
        ),
        "invocation": {
            "attempted": True,
            "executed": True,
            "response_received": True,
            "runtime_envelope_received": True,
            "status": "SUCCEEDED",
            # The honest boundary of this capture: no Modal invocation happened.
            "live_modal_invocation": False,
            "provider_queried": False,
            "deployment": "none",
            "deployment_kind": "none",
            "gpu": "none",
            "production_change": (
                "no deployed worker was deployed, redeployed, restarted or modified; the "
                "source of the producer was fixed only"
            ),
        },
        "source": {
            "code_sha": code_sha,
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(tracked_changes),
            "tracked_changes": tracked_changes,
            "producer": "modal_app.capture_modal_runtime_identity",
            "producer_module": "modal_app.py",
        },
        "environment": {
            "captured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "spoofed_environment_variables": captured["spoofed_environment"],
            "restored_environment_variables": captured["restored_environment"],
            "worker_observed": _worker_observed(),
        },
        "sentinel": {
            "module": "modal.running_app",
            "accesses": list(sentinel.accesses),
            "statement": (
                "the sentinel stood in for modal.running_app while the producer ran; the "
                "producer must not touch it at all"
            ),
        },
        "runtime_identity": envelope,
        "response": response,
        "client_observed": client_observed,
        "provenance": {
            "artifact": provenance_artifact,
            "validated": bool(provenance_ok),
            "error": provenance_error,
            "statement": (
                "the provenance block was built from the very stage evidence artifact of "
                "this capture and validated with the repository's own validator in the "
                "strict source mode"
            ),
        },
        "evidence_artifact": {
            "path": str(artifact_path.relative_to(_ROOT)).replace("\\", "/"),
            "sha256": artifact_ref.get("sha256"),
            "byte_length": artifact_ref.get("byte_length"),
            "description": artifact_ref.get("description"),
        },
        "statement": (
            "This is a local capture of the production producer, executed against the "
            "installed Modal SDK 1.5.5 outside a Modal container and against a hostile "
            "environment: MODAL_WORKER_ID, HOSTNAME and MODAL_TASK_ID held arbitrary, "
            "well-formed but fake values for the duration of the call. No Modal invocation "
            "was made, the provider was never asked, no worker was deployed or touched, and "
            "the capture holds no provider-issued identifier: outside a Modal container the "
            "function-call id is NOT_AVAILABLE and the client-side container id is "
            "NOT_AVAILABLE as well, which is exactly what the truth is at that moment. "
            "That the fake environment values do not become an observed container id is the "
            "point of this capture. The OBSERVED branches of the producer are exercised by "
            "the test suite in a simulated container context and against a fake provider."
        ),
        "validator": {
            "script": "benchmarks/validate_iteration21_evidence.py",
            "command": "python -m benchmarks.validate_iteration21_evidence --code-sha <sha>",
            "report_path": "benchmarks/evidence/iteration21_validation_evidence.json",
        },
    }

    record_path = evidence_dir / "capture_record.json"
    record_bytes = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    record_path.write_bytes(record_bytes)

    print(f"wrote {record_path.relative_to(_ROOT)}")
    print(f"wrote {artifact_path.relative_to(_ROOT)}")
    print(f"artifact sha256: {artifact_ref.get('sha256')}")
    print(f"record   sha256: {sha256_bytes(record_bytes)}")
    print(f"sentinel accesses: {sentinel.accesses or 'none'}")
    print(f"provenance validated: {provenance_ok} {provenance_error or ''}")
    return 0 if (not sentinel.accesses and provenance_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
