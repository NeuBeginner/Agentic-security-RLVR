"""
modal_cpu_audit_app.py
=======================

The **CPU-only** Modal application of the Aegis-RLVR Solidity audit service.

Why a separate application
--------------------------
``modal_app.py`` is the *production* application of this repository. It declares the
H100 class ``ProductionAuditAgent`` and the T4 class ``DevReasoningAgent``. This module
is a **separate app with its own name** so that the CPU service can be declared,
deployed, inspected and billed completely independently of the GPU path:

* no GPU class is declared here at all - a GPU cannot be allocated by this app, not
  even accidentally, because nothing in it asks for one;
* this module never imports ``modal_app.py`` and never imports ``core.r1_bounds``, so
  it cannot change a single entry of the R1 dispatch registry and cannot weaken the
  fail-closed approval mechanism of the benchmark;
* the R1 gate, the rate card, the approval key and the historical evidence are not
  touched by this file.

What the service really does
-----------------------------
The service accepts a Solidity contract and runs the **available CPU audit process**
of this repository, stage by stage:

1. ``static_analysis`` - ``sandbox.runner.run_slither_analysis``: the real Slither
   detector on the submitted source (with the repository's own deterministic fallback
   heuristics when Slither cannot run).
2. ``hypothesis`` - ``core.hypothesis_manager.HypothesisManager``: the repository's own
   normalisation, deduplication and ranking of the findings into vulnerability
   hypotheses.
3. ``verification`` - ``sandbox.runner.run_payload_in_sandbox``: the candidate is
   compiled by the pinned solc and executed in a real Foundry EVM against the
   **immutable, repository-owned trusted harness**. The verdict is read from the
   structured Forge result of the trusted suite, never from log text.
4. ``replay`` - ``sandbox.runner.verify_independent_replay_result``: the candidate is
   executed again in a fresh EVM, which is what turns an unreplayed breach into a
   confirmed exploit.
5. ``result`` - ``core.evaluator.evaluate_execution_trace``: the deterministic,
   evidence-scoped reward of Reward Specification 2.0.0.

The exploit candidate
---------------------
The synthesis of an exploit candidate is the **GPU/LLM stage** of this project (the
30B audit model on H100). It is deliberately *not* part of the CPU service, and the
service never pretends otherwise: a candidate is either supplied by the caller or
resolved from the repository-owned candidate registry
(``benchmarks/cpu_audit_pocs/registry.json``). When no candidate is available the run
ends with the explicit status ``CANDIDATE_UNAVAILABLE`` - never with an invented
verdict.

Volumes
-------
* ``aegis-model-cache`` (the existing cache) is mounted **read-only**. The service
  never writes into it, never deletes anything in it and never overwrites a file in it.
* ``aegis-cpu-audit-results`` (a new, dedicated volume) holds the audit artifacts of
  this service under ``runs/<run_id>/``. It is a separate place on purpose: the results
  never mix with the model cache.

The entry point is a Modal **function**, not an HTTP endpoint: an unauthenticated
public endpoint that compiles and executes untrusted Solidity would be an abuse and
denial-of-service surface, and the acceptance criteria of this workstream ask for a
reachable entry point, not for a public web route. The function is reachable from any
client that holds the Modal credentials of the workspace.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import modal

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.config import config
from core.evaluator import evaluate_execution_trace
from core.hypothesis_manager import HypothesisManager
from core.schemas import AttackHypothesis, ExploitPayload, TargetProgram
from sandbox.runner import (  # noqa: E402
    TRUSTED_HARNESS_CONTRACTS,
    is_safe_target_name,
    run_payload_in_sandbox,
    run_slither_analysis,
    verify_independent_replay_result,
)

# ---------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------

#: The name of this application. It is separate from ``config.APP_NAME``
#: (``aegis-rlvr-security``), which belongs to the GPU production application.
APP_NAME = "aegis-rlvr-cpu-audit"

#: The existing model cache. It is mounted read-only and never written into.
MODEL_VOLUME_NAME = config.MODEL_VOLUME_NAME

#: The dedicated volume of this service's artifacts. It holds nothing but the results
#: of this service.
RESULTS_VOLUME_NAME = "aegis-cpu-audit-results"

MODEL_VOLUME_MOUNT_PATH = "/vol/models"
RESULTS_VOLUME_MOUNT_PATH = "/vol/results"
RESULTS_RUNS_SUBDIR = "runs"

#: The repository-owned proof-of-concept candidates, mounted into the image.
POC_DIR_LOCAL = _ROOT / "benchmarks" / "cpu_audit_pocs"
POC_DIR_REMOTE = "/opt/aegis/cpu_audit_pocs"

#: The declared resources of this application - one source of truth, so the driver and
#: the documentation report exactly what the source declares. ``gpu`` is ``None``: the
#: request is explicit, so no GPU can be allocated.
DECLARED_RESOURCES: Dict[str, Any] = {
    "gpu": None,
    "cpu": 2.0,
    "memory": 2048,
    "timeout": 600,
    "retries": 0,
}

#: The schema of the structured result of one audit run.
RESULT_SCHEMA_VERSION = "aegis-cpu-audit-result/1.0.0"

#: The schema of the structured result of the environment probe.
PROBE_SCHEMA_VERSION = "aegis-cpu-audit-probe/1.0.0"

#: Hard input limits. The service is a compiler and an EVM, so the size of everything
#: it accepts is bounded before anything is executed.
MAX_TARGET_SOURCE_BYTES = 262_144
MAX_CANDIDATE_BYTES = 262_144
MAX_REQUEST_BYTES = 524_288
MAX_RUN_ID_LENGTH = 64

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

def sandbox_image_of_repository():
    """
    The sandbox image of the repository, imported lazily.

    The import lives in a function so that the module-level declaration order stays
    readable and so that the image is built from exactly the same source as the
    production application (``sandbox.runner.sandbox_image``).
    """
    from sandbox.runner import sandbox_image

    return sandbox_image


#: The image. It is the repository's own sandbox image (Foundry, pinned solc releases,
#: forge-std, OpenZeppelin, Slither and the trusted harnesses), extended with the
#: ``benchmarks`` package - ``sandbox.runner`` imports ``benchmarks.evidence_integrity``
#: for the observed-environment facts - and with the candidate registry.
#:
#: Both local additions use ``copy=True``: the sandbox image ends with build steps
#: (Foundry, the pre-baked solc releases, the pinned libraries), and Modal requires a
#: local file that is added *after* a build step to be copied into the image rather
#: than mounted on container start.
image = (
    sandbox_image_of_repository()
    .add_local_python_source("benchmarks", copy=True)
    .add_local_dir(str(POC_DIR_LOCAL), remote_path=POC_DIR_REMOTE, copy=True)
)


#: The existing model cache. ``create_if_missing`` is deliberately **not** set: the
#: service fails closed when the cache is absent instead of silently creating an empty
#: one.
model_volume = modal.Volume.from_name(MODEL_VOLUME_NAME)

#: The dedicated results volume. It is created on the first deploy of this app.
results_volume = modal.Volume.from_name(RESULTS_VOLUME_NAME, create_if_missing=True)

app = modal.App(APP_NAME, image=image)


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------


def log_event(event: str, **fields: Any) -> None:
    """
    Emit one structured log record.

    The record is a single JSON object per line. It never carries a value of an
    environment variable and never carries a secret - only names, digests, verdicts
    and measurements.
    """
    record: Dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "app": APP_NAME,
        "event": event,
    }
    record.update(fields)
    print(json.dumps(record, default=str, ensure_ascii=False), flush=True)


# ---------------------------------------------------------------------------
# The candidate registry
# ---------------------------------------------------------------------------


def candidate_registry_dir() -> str:
    """
    The directory that holds the candidate registry.

    In the container the registry is mounted at :data:`POC_DIR_REMOTE`. Outside the
    container - in the unit tests and in a local run - the repository copy is used.
    The directory is resolved, never guessed: the remote directory wins whenever it
    exists.
    """
    if os.path.isdir(POC_DIR_REMOTE):
        return POC_DIR_REMOTE
    return str(POC_DIR_LOCAL)


def load_candidate_registry() -> Dict[str, Any]:
    """Read the repository-owned candidate registry that ships in the image."""
    registry_path = f"{candidate_registry_dir()}/registry.json"
    try:
        with open(registry_path, "r", encoding="utf-8") as handle:
            registry = json.load(handle)
    except (OSError, ValueError) as exc:
        log_event("candidate_registry_unavailable", error=f"{type(exc).__name__}: {exc}")
        return {"schema_version": "unavailable", "entries": []}
    if not isinstance(registry, dict):
        return {"schema_version": "unavailable", "entries": []}
    entries = registry.get("entries")
    return registry if isinstance(entries, list) else {"schema_version": "unavailable", "entries": []}


def resolve_registry_candidate(target_name: str) -> Optional[Dict[str, Any]]:
    """
    Resolve the repository-owned candidate of one target, if the registry holds one.

    The returned dictionary carries the candidate source, its expectation (the
    maintainer's expectation, used by the end-to-end test as a cross-check) and the
    candidate source code.
    """
    registry = load_candidate_registry()
    for entry in registry.get("entries", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("target_name") != target_name:
            continue
        poc_file = entry.get("poc_file")
        if not isinstance(poc_file, str) or not poc_file:
            return None
        poc_path = f"{candidate_registry_dir()}/{poc_file}"
        try:
            with open(poc_path, "r", encoding="utf-8") as handle:
                candidate_code = handle.read()
        except OSError:
            return None
        resolved = dict(entry)
        resolved["candidate_code"] = candidate_code
        resolved["candidate_origin"] = "repository_registry"
        resolved["candidate_path"] = poc_path
        return resolved
    return None


# ---------------------------------------------------------------------------
# Input validation (fail-closed)
# ---------------------------------------------------------------------------


def reject(code: str, reason: str, **extra: Any) -> Dict[str, Any]:
    """Build the structured rejection of an invalid request."""
    log_event("request_rejected", code=code, reason=reason)
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "REJECTED",
        "error": {"code": code, "reason": reason, **extra},
    }


def validate_request(request: Any) -> Dict[str, Any]:
    """
    Validate the incoming request.

    Every rejection is explicit and every check is fail-closed: a target that is not
    in the repository's trusted-harness allowlist is refused, because there is no
    immutable harness that could judge it.
    """
    if not isinstance(request, dict):
        return reject("REQUEST_NOT_A_MAPPING", "the request must be a JSON object")

    try:
        request_bytes = len(json.dumps(request, default=str).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        return reject("REQUEST_NOT_SERIALISABLE", f"the request is not serialisable: {exc}")
    if request_bytes > MAX_REQUEST_BYTES:
        return reject(
            "REQUEST_TOO_LARGE",
            f"the request exceeds the accepted size of {MAX_REQUEST_BYTES} bytes",
            request_bytes=request_bytes,
            limit_bytes=MAX_REQUEST_BYTES,
        )

    target_name = request.get("target_name")
    if not isinstance(target_name, str) or not target_name:
        return reject("TARGET_NAME_MISSING", "the request carries no target name")
    if not is_safe_target_name(target_name):
        return reject(
            "TARGET_NAME_UNSAFE",
            "the target name is not a bounded Solidity identifier",
            target_name=target_name,
        )
    if target_name not in TRUSTED_HARNESS_CONTRACTS:
        return reject(
            "TARGET_NOT_ALLOWED",
            "the target has no immutable repository-owned trusted harness, so no "
            "verdict could be trusted for it",
            target_name=target_name,
            allowed_targets=sorted(TRUSTED_HARNESS_CONTRACTS),
        )

    source_code = request.get("source_code")
    if not isinstance(source_code, str) or not source_code.strip():
        return reject(
            "SOURCE_CODE_MISSING",
            "the request carries no Solidity source for the target",
            target_name=target_name,
        )
    source_bytes = len(source_code.encode("utf-8"))
    if source_bytes > MAX_TARGET_SOURCE_BYTES:
        return reject(
            "SOURCE_CODE_TOO_LARGE",
            f"the submitted source exceeds the accepted size of {MAX_TARGET_SOURCE_BYTES} bytes",
            target_name=target_name,
            source_bytes=source_bytes,
            limit_bytes=MAX_TARGET_SOURCE_BYTES,
        )

    run_id = request.get("run_id")
    if run_id is None:
        run_id = f"cpu-audit-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
    elif not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        return reject(
            "RUN_ID_INVALID",
            "the run id must be a short identifier of letters, digits, dots, dashes "
            "and underscores",
            run_id=str(run_id)[:MAX_RUN_ID_LENGTH],
        )

    candidate_code = request.get("candidate_code")
    candidate_origin = "request"
    registry_entry: Optional[Dict[str, Any]] = None
    if candidate_code is None:
        registry_entry = resolve_registry_candidate(target_name)
        if registry_entry is None:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "status": "CANDIDATE_UNAVAILABLE",
                "error": {
                    "code": "CANDIDATE_UNAVAILABLE",
                    "reason": (
                        "no exploit candidate was supplied and the repository candidate "
                        "registry holds none for this target. The synthesis of an exploit "
                        "candidate is the GPU/LLM stage of this project and is not part "
                        "of the CPU service, so the run stops here - no verdict is "
                        "invented."
                    ),
                    "target_name": target_name,
                    "run_id": run_id,
                },
            }
        candidate_code = registry_entry.get("candidate_code") or ""
        candidate_origin = "repository_registry"
    elif not isinstance(candidate_code, str) or not candidate_code.strip():
        return reject(
            "CANDIDATE_CODE_INVALID",
            "the supplied exploit candidate is empty",
            target_name=target_name,
        )

    candidate_bytes = len(candidate_code.encode("utf-8"))
    if candidate_bytes > MAX_CANDIDATE_BYTES:
        return reject(
            "CANDIDATE_CODE_TOO_LARGE",
            f"the supplied exploit candidate exceeds the accepted size of "
            f"{MAX_CANDIDATE_BYTES} bytes",
            target_name=target_name,
            candidate_bytes=candidate_bytes,
            limit_bytes=MAX_CANDIDATE_BYTES,
        )

    return {
        "ok": True,
        "target_name": target_name,
        "source_code": source_code,
        "source_bytes": source_bytes,
        "run_id": run_id,
        "candidate_code": candidate_code,
        "candidate_bytes": candidate_bytes,
        "candidate_origin": candidate_origin,
        "registry_entry": registry_entry,
        "run_replay": bool(request.get("run_replay", True)),
    }


# ---------------------------------------------------------------------------
# The audit pipeline
# ---------------------------------------------------------------------------


def build_attack_hypothesis(
    manager: HypothesisManager,
    ranked_hypotheses: List[Any],
    target_name: str,
) -> AttackHypothesis:
    """
    Build the hypothesis that the verification stage works on.

    The hypothesis is derived from the findings of the static analysis by the
    repository's own hypothesis manager. When the analysis produced no finding at all,
    the hypothesis says so explicitly - it is not filled with an invented class.
    """
    if ranked_hypotheses:
        hypothesis = manager.to_attack_hypothesis(ranked_hypotheses[0])
        return hypothesis

    return AttackHypothesis(
        vulnerability_type="Undetermined",
        reasoning_trace=(
            f"The static analysis of {target_name} produced no finding, so no "
            f"vulnerability class could be derived. The candidate is still executed "
            f"against the trusted harness, and the harness - not this hypothesis - "
            f"decides the outcome."
        ),
        attack_vector="No analysis-derived vector; the candidate is evaluated as submitted.",
        affected_functions=[],
        confidence_score=0.0,
    )


def observed_runtime_facts() -> Dict[str, Any]:
    """
    The facts about the running container that the container itself can observe.

    No secret is read: only the *names* of the Modal environment variables are
    reported, never their values.
    """
    facts: Dict[str, Any] = {
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "cpu_count": os.cpu_count(),
        "modal_sdk_version": getattr(modal, "__version__", None),
        "modal_is_local": modal.is_local(),
        "modal_env_var_names": sorted(name for name in os.environ if name.startswith("MODAL_")),
        "nvidia_device_nodes": sorted(
            name for name in (os.listdir("/dev") if os.path.isdir("/dev") else [])
            if name.startswith("nvidia")
        ),
        "cuda_visible_devices_env": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "nvidia_visible_devices_env": os.environ.get("NVIDIA_VISIBLE_DEVICES"),
    }
    facts["gpu_device_exposed"] = bool(facts["nvidia_device_nodes"])
    return facts


def save_result_artifact(run_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persist the structured result into the dedicated results volume.

    The artifact is written into ``runs/<run_id>/`` of the results volume - a place
    that holds nothing but the results of this service. The write is committed, and the
    file is read back afterwards to prove that the stored bytes are the bytes that were
    produced.
    """
    run_dir = os.path.join(RESULTS_VOLUME_MOUNT_PATH, RESULTS_RUNS_SUBDIR, run_id)
    os.makedirs(run_dir, exist_ok=True)

    result_path = os.path.join(run_dir, "result.json")
    payload = json.dumps(result, indent=2, default=str, ensure_ascii=False).encode("utf-8")
    with open(result_path, "wb") as handle:
        handle.write(payload)

    commit_error = None
    try:
        results_volume.commit()
    except Exception as exc:  # noqa: BLE001 - the failure is reported, not hidden
        commit_error = f"{type(exc).__name__}: {exc}"

    reread = b""
    reread_error = None
    try:
        with open(result_path, "rb") as handle:
            reread = handle.read()
    except OSError as exc:
        reread_error = f"{type(exc).__name__}: {exc}"

    import hashlib

    written_digest = hashlib.sha256(payload).hexdigest()
    reread_digest = hashlib.sha256(reread).hexdigest()

    return {
        "results_volume": RESULTS_VOLUME_NAME,
        "run_directory": run_dir,
        "result_path": result_path,
        "written_bytes": len(payload),
        "written_sha256": written_digest,
        "commit_error": commit_error,
        "reread_bytes": len(reread),
        "reread_sha256": reread_digest,
        "reread_error": reread_error,
        "reread_verified": bool(reread) and reread_digest == written_digest,
    }


def _execution_dump(execution: Any) -> Dict[str, Any]:
    """The serialisable form of one EVM execution."""
    try:
        return execution.model_dump()
    except AttributeError:
        return {"raw": str(execution)}


# ---------------------------------------------------------------------------
# The entry points
# ---------------------------------------------------------------------------


@app.function(
    image=image,
    volumes={
        MODEL_VOLUME_MOUNT_PATH: model_volume.with_mount_options(read_only=True),
        RESULTS_VOLUME_MOUNT_PATH: results_volume,
    },
    **DECLARED_RESOURCES,
)
def audit_contract(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit one Solidity contract on CPU and return the structured result.

    The request carries the contract (``target_name`` and ``source_code``), an
    optional ``run_id``, an optional ``candidate_code`` and an optional
    ``run_replay`` flag. The result carries the stage-by-stage record, the verdict of
    the trusted harness, the deterministic reward and the artifact that was stored.
    """
    started_monotonic = time.time()
    log_event("audit_started", request_keys=sorted(request.keys()) if isinstance(request, dict) else None)

    validation = validate_request(request)
    if not validation.get("ok"):
        return validation

    run_id = validation["run_id"]
    target_name = validation["target_name"]

    target = TargetProgram(name=target_name, source_code=validation["source_code"])

    # -- Stage 1: static analysis (real Slither, repository fallback) --------
    stage_started = time.time()
    try:
        findings = run_slither_analysis(target)
        analysis_error = None
    except Exception as exc:  # noqa: BLE001 - the failure is the evidence
        findings = []
        analysis_error = f"{type(exc).__name__}: {exc}"
    target.slither_findings = findings
    log_event(
        "stage_completed",
        stage="static_analysis",
        run_id=run_id,
        target_name=target_name,
        finding_count=len(findings),
        findings=[f.get("check") for f in findings if isinstance(f, dict)],
        duration_sec=round(time.time() - stage_started, 3),
        error=analysis_error,
    )

    # -- Stage 2: hypothesis (repository hypothesis manager) ------------------
    stage_started = time.time()
    manager = HypothesisManager(target)
    hypotheses = manager.ingest_slither_findings()
    ranked = manager.deduplicate_and_rank(hypotheses)
    attack_hypothesis = build_attack_hypothesis(manager, ranked, target_name)
    hypothesis_record = {
        "count": len(hypotheses),
        "ranked": [
            {
                "hypothesis_id": hyp.hypothesis_id,
                "vulnerability_class": hyp.vulnerability_class,
                "affected_contract": hyp.affected_contract,
                "affected_function": hyp.affected_function,
                "severity": hyp.severity,
                "confidence": hyp.confidence,
                "validation_status": hyp.validation_status,
            }
            for hyp in ranked
        ],
        "selected": {
            "vulnerability_type": attack_hypothesis.vulnerability_type,
            "reasoning_trace": attack_hypothesis.reasoning_trace,
            "attack_vector": attack_hypothesis.attack_vector,
            "confidence_score": attack_hypothesis.confidence_score,
            "derived_from": "static_analysis_findings" if ranked else "no_finding_derived",
        },
        "source": "core.hypothesis_manager.HypothesisManager (deterministic, no LLM)",
    }
    log_event(
        "stage_completed",
        stage="hypothesis",
        run_id=run_id,
        hypothesis_count=len(hypotheses),
        selected_class=attack_hypothesis.vulnerability_type,
        duration_sec=round(time.time() - stage_started, 3),
    )

    # -- Stage 3: verification (real Foundry EVM, trusted harness) -------------
    stage_started = time.time()
    payload = ExploitPayload(
        target_name=target_name,
        hypothesis=attack_hypothesis,
        test_code=validation["candidate_code"],
        generator_engine=(
            "cpu-audit-registry" if validation["candidate_origin"] == "repository_registry"
            else "cpu-audit-request"
        ),
        run_id=run_id,
        format_valid=True,
    )
    try:
        execution = run_payload_in_sandbox(target, payload)
        verification_error = None
    except Exception as exc:  # noqa: BLE001 - the failure is the evidence
        execution = None
        verification_error = f"{type(exc).__name__}: {exc}"
    log_event(
        "stage_completed",
        stage="verification",
        run_id=run_id,
        error=verification_error,
        harness_verdict=getattr(execution, "harness_verdict", None),
        category=getattr(getattr(execution, "category", None), "value", None),
        duration_sec=round(time.time() - stage_started, 3),
    )

    if execution is None:
        result = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "status": "FAILED",
            "run_id": run_id,
            "target_name": target_name,
            "error": {
                "code": "VERIFICATION_FAILED",
                "reason": verification_error or "the verification stage produced no result",
            },
            "stages": {
                "static_analysis": {"findings": findings, "error": analysis_error},
                "hypothesis": hypothesis_record,
            },
            "environment": observed_runtime_facts(),
        }
        artifacts = save_result_artifact(run_id, result)
        result["artifacts"] = artifacts
        return result

    # -- Stage 4: independent replay (fresh EVM) ------------------------------
    replay_record: Dict[str, Any] = {"executed": False}
    replay_confirmed = False
    if validation["run_replay"]:
        stage_started = time.time()
        try:
            replay = verify_independent_replay_result(target, payload)
            replay_confirmed = (
                getattr(replay, "harness_verdict", "") == "BREACH"
                and getattr(replay, "invariant_violated", False)
                and getattr(replay, "return_code", None) == 0
                and not getattr(replay, "cheatcode_detected", False)
                and getattr(getattr(replay, "category", None), "value", None) == "EXPLOIT_CONFIRMED"
            )
            replay_record = {
                "executed": True,
                "reproduced": bool(replay_confirmed),
                "harness_verdict": getattr(replay, "harness_verdict", None),
                "harness_suite": getattr(replay, "harness_suite", None),
                "return_code": getattr(replay, "return_code", None),
                "test_status": getattr(replay, "test_status", None),
                "category": getattr(getattr(replay, "category", None), "value", None),
                "stdout_sha256": getattr(replay, "stdout_sha256", None),
                "stderr_sha256": getattr(replay, "stderr_sha256", None),
                "stdout_byte_length": getattr(replay, "stdout_byte_length", None),
                "stderr_byte_length": getattr(replay, "stderr_byte_length", None),
                "duration_sec": round(time.time() - stage_started, 3),
            }
        except Exception as exc:  # noqa: BLE001 - the failure is the evidence
            replay_record = {"executed": True, "error": f"{type(exc).__name__}: {exc}"}
        log_event(
            "stage_completed",
            stage="replay",
            run_id=run_id,
            reproduced=replay_confirmed,
            duration_sec=round(time.time() - stage_started, 3),
        )

    # The replay is its own evidence: it is a fresh EVM, never a re-read of the
    # first run. Only a confirmed replay raises the verdict to EXPLOIT_CONFIRMED.
    execution.reproducibility_confirmed = bool(replay_confirmed)

    # -- Stage 5: the deterministic verdict and reward -------------------------
    stage_started = time.time()
    verdict = evaluate_execution_trace(payload, execution)
    log_event(
        "stage_completed",
        stage="result",
        run_id=run_id,
        category=verdict.category.value,
        reward_score=verdict.reward_score,
        is_verified=verdict.is_verified,
        reproducible=verdict.reproducible,
        duration_sec=round(time.time() - stage_started, 3),
    )

    registry_entry = validation.get("registry_entry") or {}
    result: Dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "COMPLETED",
        "run_id": run_id,
        "target_name": target_name,
        "stages": {
            "static_analysis": {
                "engine": "slither (sandbox.runner.run_slither_analysis)",
                "finding_count": len(findings),
                "findings": findings,
                "error": analysis_error,
                "note": (
                    "The findings are the real output of the repository's static analysis "
                    "stage, including its deterministic fallback heuristics when Slither "
                    "cannot run."
                ),
            },
            "hypothesis": hypothesis_record,
            "verification": {
                "engine": "foundry EVM (sandbox.runner.run_payload_in_sandbox)",
                "candidate_origin": validation["candidate_origin"],
                "candidate_bytes": validation["candidate_bytes"],
                "expected_vulnerability_class": registry_entry.get("expected_vulnerability_class"),
                "expected_outcome": registry_entry.get("expected_outcome"),
                "execution": _execution_dump(execution),
            },
            "replay": replay_record,
        },
        "verdict": verdict.model_dump(),
        "reward": {
            "score": verdict.reward_score,
            "components": dict(verdict.reward_components or {}),
            "penalty": verdict.reward_penalty,
            "spec_version": verdict.reward_spec_version,
            "is_verified": verdict.is_verified,
            "reproducible": verdict.reproducible,
        },
        "environment": observed_runtime_facts(),
        "declared_resources": DECLARED_RESOURCES,
        "timings": {"total_sec": round(time.time() - started_monotonic, 3)},
    }

    artifacts = save_result_artifact(run_id, result)
    result["artifacts"] = artifacts
    log_event(
        "audit_completed",
        run_id=run_id,
        target_name=target_name,
        category=verdict.category.value,
        reward_score=verdict.reward_score,
        artifact_path=artifacts.get("result_path"),
        artifact_reread_verified=artifacts.get("reread_verified"),
    )
    return result


@app.function(
    image=image,
    volumes={
        MODEL_VOLUME_MOUNT_PATH: model_volume.with_mount_options(read_only=True),
        RESULTS_VOLUME_MOUNT_PATH: results_volume,
    },
    **DECLARED_RESOURCES,
)
def read_saved_result(run_id: str) -> Dict[str, Any]:
    """
    Read back a stored audit result from the dedicated results volume.

    This is a **separate invocation**: it proves that the artifact survives the
    container that produced it, not only the write buffer of that container.
    """
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        return {
            "schema_version": PROBE_SCHEMA_VERSION,
            "status": "REJECTED",
            "error": {"code": "RUN_ID_INVALID", "reason": "the run id is not a valid identifier"},
        }

    result_path = os.path.join(
        RESULTS_VOLUME_MOUNT_PATH, RESULTS_RUNS_SUBDIR, run_id, "result.json"
    )
    try:
        with open(result_path, "rb") as handle:
            payload = handle.read()
    except OSError as exc:
        return {
            "schema_version": PROBE_SCHEMA_VERSION,
            "status": "NOT_FOUND",
            "run_id": run_id,
            "result_path": result_path,
            "error": {"code": "ARTIFACT_NOT_FOUND", "reason": f"{type(exc).__name__}: {exc}"},
        }

    import hashlib

    digest = hashlib.sha256(payload).hexdigest()
    try:
        stored = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        stored = None
        parse_error = f"{type(exc).__name__}: {exc}"
    else:
        parse_error = None

    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "status": "READ_BACK",
        "run_id": run_id,
        "result_path": result_path,
        "byte_length": len(payload),
        "sha256": digest,
        "parsed": stored is not None,
        "parse_error": parse_error,
        "result": stored,
    }


@app.function(
    image=image,
    volumes={
        MODEL_VOLUME_MOUNT_PATH: model_volume.with_mount_options(read_only=True),
        RESULTS_VOLUME_MOUNT_PATH: results_volume,
    },
    **DECLARED_RESOURCES,
)
def probe_environment() -> Dict[str, Any]:
    """
    Probe the environment of the service: the volumes, the toolchain and the GPU state.

    The probe is the evidence of stage 3 of the integration: the model cache is
    reachable and readable, the read-only mount is real, the results volume is
    writable and the container has no GPU.
    """
    probe: Dict[str, Any] = {
        "schema_version": PROBE_SCHEMA_VERSION,
        "status": "COMPLETED",
        "declared_resources": DECLARED_RESOURCES,
        "runtime": observed_runtime_facts(),
    }

    # -- the model cache (read-only) -----------------------------------------
    cache_root = MODEL_VOLUME_MOUNT_PATH
    cache_entry: Dict[str, Any] = {
        "volume": MODEL_VOLUME_NAME,
        "mount_path": cache_root,
        "read_only_requested": True,
        "exists": os.path.isdir(cache_root),
        "directories": [],
        "readable_files": [],
        "write_probe": None,
        "mount_table_entries": [],
    }
    if cache_entry["exists"]:
        try:
            cache_entry["directories"] = sorted(os.listdir(cache_root))
        except OSError as exc:
            cache_entry["list_error"] = f"{type(exc).__name__}: {exc}"
        # read one small, known metadata file of the pinned revision
        tree_candidates = []
        hub_root = os.path.join(cache_root, "huggingface")
        if os.path.isdir(hub_root):
            try:
                for repo in os.listdir(hub_root):
                    repo_dir = os.path.join(hub_root, repo, "trees")
                    if os.path.isdir(repo_dir):
                        for tree in os.listdir(repo_dir):
                            tree_candidates.append(os.path.join(repo_dir, tree))
            except OSError:
                pass
        for candidate in sorted(tree_candidates)[:5]:
            try:
                size = os.path.getsize(candidate)
                with open(candidate, "rb") as handle:
                    head = handle.read(64)
                cache_entry["readable_files"].append(
                    {
                        "path": candidate,
                        "byte_length": size,
                        "first_bytes_sha256_prefix": head[:16].hex(),
                    }
                )
            except OSError as exc:
                cache_entry["readable_files"].append({"path": candidate, "error": f"{type(exc).__name__}: {exc}"})

        # The read-only proof: a write attempt on the mounted cache must fail. The
        # probe file is removed immediately and only if the write unexpectedly
        # succeeded - the existing content of the cache is never touched.
        probe_path = os.path.join(cache_root, f".modal_readonly_probe_{uuid.uuid4().hex[:8]}")
        try:
            with open(probe_path, "wb") as handle:
                handle.write(b"modal-readonly-probe")
            cache_entry["write_probe"] = {
                "result": "WRITABLE",
                "note": "the mount accepted a write - the read-only request was NOT honoured",
            }
            try:
                os.remove(probe_path)
            except OSError:
                pass
        except OSError as exc:
            cache_entry["write_probe"] = {
                "result": "READ_ONLY_ENFORCED",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    # the mount table of the running container
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as handle:
            for line in handle:
                if cache_root in line or RESULTS_VOLUME_MOUNT_PATH in line:
                    cache_entry["mount_table_entries"].append(line.strip())
    except OSError as exc:
        cache_entry["mount_table_error"] = f"{type(exc).__name__}: {exc}"

    probe["model_cache"] = cache_entry

    # -- the results volume (read-write) --------------------------------------
    results_root = RESULTS_VOLUME_MOUNT_PATH
    results_entry: Dict[str, Any] = {
        "volume": RESULTS_VOLUME_NAME,
        "mount_path": results_root,
        "exists": os.path.isdir(results_root),
    }
    if results_entry["exists"]:
        probe_path = os.path.join(results_root, f".write_probe_{uuid.uuid4().hex[:8]}")
        try:
            with open(probe_path, "wb") as handle:
                handle.write(b"modal-write-probe")
            results_entry["write_probe"] = {"result": "WRITABLE"}
            try:
                os.remove(probe_path)
            except OSError:
                pass
        except OSError as exc:
            results_entry["write_probe"] = {
                "result": "NOT_WRITABLE",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
    probe["results_volume"] = results_entry

    # -- the toolchain -------------------------------------------------------
    import subprocess

    toolchain: Dict[str, Any] = {}
    for tool in ("forge", "solc", "slither"):
        try:
            completed = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            toolchain[tool] = (completed.stdout or completed.stderr or "").strip()[:200]
        except (OSError, subprocess.SubprocessError) as exc:
            toolchain[tool] = f"NOT_AVAILABLE: {type(exc).__name__}: {exc}"
    probe["toolchain"] = toolchain

    log_event(
        "environment_probed",
        cache_read_only=(cache_entry.get("write_probe") or {}).get("result"),
        cache_readable_files=len(cache_entry.get("readable_files") or []),
        results_writable=(results_entry.get("write_probe") or {}).get("result"),
        gpu_device_exposed=probe["runtime"].get("gpu_device_exposed"),
    )
    return probe
