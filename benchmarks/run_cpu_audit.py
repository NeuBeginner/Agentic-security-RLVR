"""
benchmarks/run_cpu_audit.py
===========================

The live driver of the **CPU-only** audit service of this repository.

It performs the end-to-end test of the service that the Modal application
``modal_cpu_audit_app.py`` implements and writes the evidence of that test into
``benchmarks/evidence/cpu_audit/``.

The sequence of the test
------------------------
1. ``probe_environment``  - the volumes, the toolchain and the GPU state of a real
   container (this is the evidence of the read-only model cache).
2. ``audit_contract`` on the vulnerable target ``Vault`` - the whole pipeline runs in
   the container: static analysis, hypothesis, verification in a real Foundry EVM,
   independent replay, deterministic verdict, artifact storage.
3. ``audit_contract`` on the safe control ``SecureVault`` with the **same** candidate
   - the trusted harness must not report a breach. This is the evidence that the
   service does not confirm vulnerabilities falsely.
4. ``audit_contract`` with an invalid contract - the service must refuse it in a
   structured way instead of crashing.
5. ``read_saved_result`` in a **separate invocation** - the stored artifact is read
   back from the volume by a container that did not produce it.

Authorisation
-------------
The invocation is refused by default. This service is not part of the R1
evidence-regeneration workflow, it has no approved step policy and no dispatch
envelope, so the R1 dispatch gate cannot authorise it - and it is not bypassed
either. The only way to run it is an explicit approval of the maintainer, which is
given out of band (the technical assignment of this workstream). The refusal happens
**before** the application is imported and before anything of this run touches the
provider, so a refused run reaches neither the control plane nor a container.

The service itself is authorised **on the server side**: every call has to present
the shared token of the Modal secret ``aegis-cpu-audit-auth``. The driver reads that
token from its own environment (``AEGIS_CPU_AUDIT_TOKEN``) and presents it with every
call. A direct call without the token is refused by the service before it does any
work - the local approval of the driver is not, and never was, the authorisation of
the service.

Usage::

    # one-off authorisation of this run
    $env:AEGIS_APPROVE_CPU_AUDIT = "1"

    # the token of the Modal secret of the service
    $env:AEGIS_CPU_AUDIT_TOKEN = "<the token of the secret aegis-cpu-audit-auth>"

    # deploy the CPU application
    modal deploy modal_cpu_audit_app.py --profile neubeginner

    # run the end-to-end test against the deployed application
    python -m benchmarks.run_cpu_audit --profile neubeginner
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.slither_status import static_analysis_evidence_is_consistent  # noqa: E402

DEFAULT_PROFILE = "neubeginner"
DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/cpu_audit"

#: The environment variable that carries the maintainer's explicit approval for this
#: live invocation. Without it the invocation is refused.
APPROVAL_ENV_VAR = "AEGIS_APPROVE_CPU_AUDIT"

#: The values the approval variable may carry.
APPROVAL_VALUES = ("1", "true", "yes")

#: The environment variable that carries the shared authorisation token of the
#: service. The token lives in the Modal secret ``aegis-cpu-audit-auth`` and is
#: presented with every call - the service checks it on its own side.
AUTH_TOKEN_ENV_VAR = "AEGIS_CPU_AUDIT_TOKEN"

#: The name of the Modal application under test.
APP_NAME = "aegis-rlvr-cpu-audit"

#: Patterns that must never appear in a log or in a stored result. The scan is part
#: of the security check of this workstream, not a formality.
SECRET_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_/+]{16,}"),
)


class AuditNotAuthorised(RuntimeError):
    """The live invocation was refused: it is not authorised."""


def _assert_authorised() -> None:
    """Refuse the live invocation unless the maintainer approved it explicitly."""
    value = os.environ.get(APPROVAL_ENV_VAR, "").strip().lower()
    if value in APPROVAL_VALUES:
        return
    raise AuditNotAuthorised(
        "the live CPU-only audit invocation is refused: this service is not part of the "
        "R1 evidence-regeneration workflow, it has no approved step policy and no "
        "dispatch envelope, and the R1 dispatch gate therefore cannot authorise it. "
        f"Set {APPROVAL_ENV_VAR}=1 only with an explicit maintainer approval."
    )


def _token_from_env_file() -> str:
    """
    The token of the service from the local ``.env`` file, when there is one.

    The file is excluded from git, so the token of the service never reaches
    the repository. The environment variable wins over the file.
    """
    env_path = _ROOT / ".env"
    if not env_path.is_file():
        return ""
    try:
        # ``utf-8-sig`` tolerates the byte order mark that Windows editors
        # write - without it the very first key of the file would be
        # unrecognisable.
        content = env_path.read_text(encoding="utf-8-sig")
    except OSError:
        return ""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(f"{AUTH_TOKEN_ENV_VAR}="):
            return stripped.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _auth_token() -> str:
    """
    The shared authorisation token of the service.

    The token is presented with every call. Without it the service refuses the
    call on its own side, so the driver refuses to start instead of burning a
    container on a call that is bound to be refused.
    """
    token = os.environ.get(AUTH_TOKEN_ENV_VAR, "").strip() or _token_from_env_file()
    if not token:
        raise AuditNotAuthorised(
            "the live CPU-only audit invocation is refused: the shared authorisation "
            f"token of the service is missing. Set {AUTH_TOKEN_ENV_VAR} (or put it "
            "into the local .env file) to the token of the Modal secret "
            "aegis-cpu-audit-auth - without it every call to the service is refused "
            "on the server side."
        )
    return token


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _scan_for_secrets(payload: str) -> List[Dict[str, Any]]:
    """Report every place of the payload that looks like a secret."""
    findings: List[Dict[str, Any]] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(payload):
            findings.append(
                {
                    "pattern": pattern.pattern,
                    "offset": match.start(),
                    "excerpt": match.group(0)[:16] + "...",
                }
            )
    return findings


def _run_cli(command: List[str], timeout: int = 600) -> Dict[str, Any]:
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


def _read_target_source(relative_path: str) -> str:
    """Read the source of a benchmark target from the repository."""
    path = _ROOT / relative_path
    return path.read_text(encoding="utf-8")


async def _run_deployed_suite(run_id: str) -> Dict[str, Any]:
    """Run the whole end-to-end test against the deployed application."""
    import modal

    # The three functions of the deployed application are resolved by name. The
    # call sites are the refused surface of this deployment: they are registered in
    # ``core.r1_bounds.UNAUTHORISED_CALL_SITES`` and classified in
    # ``benchmarks/evidence/r1_call_site_inventory.json``.
    audit_contract = modal.Function.from_name(APP_NAME, "audit_contract")
    probe_environment = modal.Function.from_name(APP_NAME, "probe_environment")
    read_saved_result = modal.Function.from_name(APP_NAME, "read_saved_result")

    # The authorisation of the service is checked on the server side: the token
    # of the Modal secret travels with every call.
    token = _auth_token()

    vault_source = _read_target_source("benchmarks/targets/solidity/Vault.sol")
    control_source = _read_target_source("benchmarks/targets/solidity/controls/SecureVault.sol")

    results: Dict[str, Any] = {}

    results["environment_probe"] = await probe_environment.remote.aio(token)

    results["vulnerable_target"] = await audit_contract.remote.aio(
        {
            "target_name": "Vault",
            "source_code": vault_source,
            "run_id": f"{run_id}-vault",
            "run_replay": True,
            "auth_token": token,
        }
    )

    results["safe_control"] = await audit_contract.remote.aio(
        {
            "target_name": "SecureVault",
            "source_code": control_source,
            "run_id": f"{run_id}-control",
            "run_replay": True,
            "auth_token": token,
        }
    )

    results["invalid_contract"] = await audit_contract.remote.aio(
        {
            "target_name": "NotAllowlisted",
            "source_code": "contract Whatever { function f() public {} }",
            "run_id": f"{run_id}-invalid",
            "auth_token": token,
        }
    )

    # The read-back happens in a separate invocation: a container that did not
    # produce the artifact reads it back from the volume.
    results["read_back"] = await read_saved_result.remote.aio(f"{run_id}-vault", token)

    # -- the authorisation of the service, proven by a DIRECT call ------------
    # The three public functions are called WITHOUT the token. The service has
    # to refuse every one of them, and it has to refuse them before it does
    # any work. This is the evidence that the authorisation does not depend on
    # the local environment of the driver.
    results["unauthorised_audit_contract"] = await audit_contract.remote.aio(
        {
            "target_name": "Vault",
            "source_code": vault_source,
            "run_id": f"{run_id}-unauthorised",
        }
    )
    results["unauthorised_probe_environment"] = await probe_environment.remote.aio("")
    results["unauthorised_read_saved_result"] = await read_saved_result.remote.aio(
        f"{run_id}-vault", "not-the-token"
    )

    return results


async def _run_ephemeral_suite(run_id: str) -> Dict[str, Any]:
    """Run the same suite against an ephemeral (not deployed) application."""
    from modal_cpu_audit_app import app, audit_contract, probe_environment, read_saved_result

    token = _auth_token()
    vault_source = _read_target_source("benchmarks/targets/solidity/Vault.sol")
    control_source = _read_target_source("benchmarks/targets/solidity/controls/SecureVault.sol")

    results: Dict[str, Any] = {}
    async with app.run():
        results["app_id"] = app.app_id
        results["environment_probe"] = await probe_environment.remote.aio(token)
        results["vulnerable_target"] = await audit_contract.remote.aio(
            {
                "target_name": "Vault",
                "source_code": vault_source,
                "run_id": f"{run_id}-vault",
                "run_replay": True,
                "auth_token": token,
            }
        )
        results["safe_control"] = await audit_contract.remote.aio(
            {
                "target_name": "SecureVault",
                "source_code": control_source,
                "run_id": f"{run_id}-control",
                "run_replay": True,
                "auth_token": token,
            }
        )
        results["invalid_contract"] = await audit_contract.remote.aio(
            {
                "target_name": "NotAllowlisted",
                "source_code": "contract Whatever { function f() public {} }",
                "run_id": f"{run_id}-invalid",
                "auth_token": token,
            }
        )
        results["read_back"] = await read_saved_result.remote.aio(f"{run_id}-vault", token)

        # -- the authorisation of the service, proven by a DIRECT call --------
        results["unauthorised_audit_contract"] = await audit_contract.remote.aio(
            {
                "target_name": "Vault",
                "source_code": vault_source,
                "run_id": f"{run_id}-unauthorised",
            }
        )
        results["unauthorised_probe_environment"] = await probe_environment.remote.aio("")
        results["unauthorised_read_saved_result"] = await read_saved_result.remote.aio(
            f"{run_id}-vault", "not-the-token"
        )
    return results


def _deployed_app_facts() -> Dict[str, Any]:
    """
    The provider-issued identity of the deployed application.

    The app id and the dashboard reference are client-side facts of the provider:
    they are read from the provider itself, never constructed.
    """
    try:
        import modal

        app = modal.App.lookup(APP_NAME)
        return {
            "app_id": app.app_id,
            "dashboard_url": app.get_dashboard_url(),
            "app_page_url": f"https://modal.com/apps/neubeginner/main/deployed/{APP_NAME}",
            "status": "OBSERVED",
        }
    except Exception as exc:  # noqa: BLE001 - the failure is reported, not hidden
        return {
            "app_id": None,
            "dashboard_url": None,
            "status": "NOT_AVAILABLE",
            "reason": f"{type(exc).__name__}: {exc}",
        }


def _collect_provider_facts(profile: str, app_id: Optional[str]) -> Dict[str, Any]:
    """Ask the provider for the identifiers and the billed usage of this run."""
    facts: Dict[str, Any] = {"profile": profile}

    containers = _run_cli(["modal", "container", "list", "--json", "--profile", profile])
    facts["container_list_command"] = containers["command"]
    facts["container_list_returncode"] = containers["returncode"]
    container_ids: List[str] = []
    try:
        payload = json.loads(containers["stdout"])
    except ValueError as exc:
        facts["container_list_error"] = f"the provider's container list is not JSON: {exc}"
        payload = None
    if isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            for key in ("container_id", "worker_id", "id", "task_id"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    container_ids.append(value.strip())
                    break
    facts["container_ids"] = container_ids

    billing = _run_cli(
        ["modal", "billing", "report", "--for", "today", "--json", "--profile", profile]
    )
    facts["billing_command"] = billing["command"]
    facts["billing_returncode"] = billing["returncode"]
    try:
        report = json.loads(billing["stdout"])
    except ValueError as exc:
        facts["billing_error"] = f"the billing report is not JSON: {exc}"
        report = None
    if isinstance(report, list):
        matched = [
            item
            for item in report
            if isinstance(item, dict) and app_id and item.get("object_id") == app_id
        ]
        facts["billing_line_items_for_app"] = matched
        facts["billing_line_item_count"] = len(report)

    summary = _run_cli(["modal", "billing", "summary", "--profile", profile])
    facts["billing_summary_command"] = summary["command"]
    facts["billing_summary"] = summary["stdout"].strip()

    return facts


def _evaluate_expectations(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check the recorded results against the expectations of the test.

    Every expectation is either met, violated or unobservable - never silently
    "passed". The checks look at the evidence itself, not at a summary flag: a
    result is only accepted when the first execution really ran, the replay
    really was a second and independent execution, the trusted verdict of the
    two runs agrees, the reward is the sum of its own components and every
    field of the result tells the same story.
    """
    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: Optional[bool], detail: str) -> None:
        checks.append(
            {
                "check": name,
                "status": "PASS" if ok is True else ("FAIL" if ok is False else "UNOBSERVED"),
                "detail": detail,
            }
        )

    # -- the environment ------------------------------------------------------
    probe = results.get("environment_probe") or {}
    cache = probe.get("model_cache") or {}
    write_probe = (cache.get("write_probe") or {}).get("result")
    check(
        "model_cache_mounted_read_only",
        write_probe == "READ_ONLY_ENFORCED",
        f"the write probe on the cache returned {write_probe!r}",
    )
    check(
        "model_cache_readable",
        bool(cache.get("readable_files")),
        f"{len(cache.get('readable_files') or [])} file(s) of the cache were read",
    )
    runtime = probe.get("runtime") or {}
    check(
        "no_gpu_in_container",
        runtime.get("gpu_device_exposed") is False,
        f"nvidia device nodes: {runtime.get('nvidia_device_nodes')}",
    )
    check(
        "no_gpu_requested_by_the_service",
        (probe.get("declared_resources") or {}).get("gpu") is None,
        f"declared gpu: {(probe.get('declared_resources') or {}).get('gpu')!r}",
    )
    pinned_solc = (probe.get("toolchain") or {}).get("pinned_solc") or {}
    check(
        "pinned_compiler_reported",
        bool(pinned_solc.get("version_output")),
        f"the pinned compiler {pinned_solc.get('requested_version')!r} reported: "
        f"{pinned_solc.get('version_output')!r} ({pinned_solc.get('error')!r})",
    )
    solc_entry = str((probe.get("toolchain") or {}).get("solc", ""))
    check(
        "the_bare_solc_entry_is_explained",
        "Traceback" not in solc_entry,
        f"the `solc` on the PATH reported: {solc_entry!r}",
    )

    # -- the vulnerable target ------------------------------------------------
    vulnerable = results.get("vulnerable_target") or {}
    verdict = vulnerable.get("verdict") or {}
    stages = vulnerable.get("stages") or {}
    execution = (stages.get("verification") or {}).get("execution") or {}
    replay = stages.get("replay") or {}
    verification_result = verdict.get("verification_result") or {}

    check(
        "vulnerable_target_executed",
        vulnerable.get("status") == "COMPLETED",
        f"status={vulnerable.get('status')!r}",
    )

    # The FIRST Foundry run has to have really happened: the trusted harness
    # ran, the suite passed and the harness itself reported the breach.
    check(
        "first_foundry_run_succeeded",
        (
            execution.get("return_code") == 0
            and execution.get("test_status") == "Success"
            and bool(execution.get("harness_suite"))
            and execution.get("harness_verdict") == "BREACH"
        ),
        f"return_code={execution.get('return_code')!r}, "
        f"test_status={execution.get('test_status')!r}, "
        f"harness_verdict={execution.get('harness_verdict')!r}, "
        f"harness_suite={execution.get('harness_suite')!r}",
    )

    # The replay has to be a SECOND and independent execution, not a re-read
    # of the first one.
    check(
        "independent_replay_executed",
        (
            replay.get("executed") is True
            and replay.get("independent_execution") is True
            and bool(replay.get("first_execution_id"))
            and replay.get("first_execution_id") != replay.get("replay_execution_id")
        ),
        f"executed={replay.get('executed')!r}, "
        f"independent_execution={replay.get('independent_execution')!r}, "
        f"basis={replay.get('independence_basis')!r}, "
        f"first_execution_id={replay.get('first_execution_id')!r}, "
        f"replay_execution_id={replay.get('replay_execution_id')!r}",
    )

    check(
        "replay_reproduced_the_breach",
        (
            replay.get("reproduced") is True
            and replay.get("harness_verdict") == "BREACH"
            and replay.get("return_code") == 0
        ),
        f"reproduced={replay.get('reproduced')!r}, "
        f"harness_verdict={replay.get('harness_verdict')!r}, "
        f"return_code={replay.get('return_code')!r}",
    )

    # The trusted verdict of the first run and of the replay have to agree, and
    # they have to agree with the verdict of the service.
    check(
        "trusted_verdict_matches_across_both_runs",
        (
            execution.get("harness_verdict") == "BREACH"
            and replay.get("harness_verdict") == execution.get("harness_verdict")
            and verdict.get("category") == "EXPLOIT_CONFIRMED"
        ),
        f"first={execution.get('harness_verdict')!r}, "
        f"replay={replay.get('harness_verdict')!r}, "
        f"category={verdict.get('category')!r}",
    )

    check(
        "vulnerable_target_breach_confirmed",
        verdict.get("category") == "EXPLOIT_CONFIRMED",
        f"category={verdict.get('category')!r}, reward={verdict.get('reward_score')!r}",
    )

    # Every field of the verdict has to tell the same story.
    check(
        "verdict_fields_are_consistent",
        (
            verdict.get("is_verified") is True
            and verdict.get("reproducible") is True
            and verdict.get("replay_status") == "CONFIRMED"
            and verdict.get("replay_confirmed") is True
            and verification_result.get("replay_confirmed") is True
            and verification_result.get("confidence_status") == "CONFIRMED"
        ),
        f"is_verified={verdict.get('is_verified')!r}, "
        f"reproducible={verdict.get('reproducible')!r}, "
        f"replay_status={verdict.get('replay_status')!r}, "
        f"replay_confirmed={verdict.get('replay_confirmed')!r}, "
        f"verification_result.replay_confirmed="
        f"{verification_result.get('replay_confirmed')!r}, "
        f"verification_result.confidence_status="
        f"{verification_result.get('confidence_status')!r}",
    )

    # The state delta may only be claimed as verified when a real snapshot
    # exists and the state changed; otherwise the basis of the breach has to be
    # named explicitly.
    state_delta = ((verdict.get("evidence") or {}).get("state_delta")) or {}
    check(
        "state_delta_claim_matches_the_evidence",
        (
            bool(verdict.get("state_delta_verified"))
            == bool(state_delta.get("has_real_snapshot") and state_delta.get("state_changed"))
            and (
                verdict.get("state_delta_verified") is True
                or verdict.get("breach_evidence_basis") in ("trusted_harness_event", "none")
            )
        ),
        f"state_delta_verified={verdict.get('state_delta_verified')!r}, "
        f"has_real_snapshot={state_delta.get('has_real_snapshot')!r}, "
        f"state_changed={state_delta.get('state_changed')!r}, "
        f"breach_evidence_basis={verdict.get('breach_evidence_basis')!r}",
    )

    # The reward has to be the sum of its own components, and the replay credit
    # may only be there when the replay was confirmed.
    reward = vulnerable.get("reward") or {}
    components = reward.get("components") or {}
    component_total = round(
        sum(float(value) for value in components.values()) + float(reward.get("penalty", 0.0)), 6
    )
    check(
        "reward_is_correctly_awarded",
        (
            float(reward.get("score", 0.0)) == 1.0
            and abs(component_total - float(reward.get("score", 0.0))) < 1e-6
            and float(components.get("replay", 0.0)) > 0.0
            and verdict.get("replay_confirmed") is True
        ),
        f"score={reward.get('score')!r}, components={components!r}, "
        f"penalty={reward.get('penalty')!r}, sum={component_total!r}",
    )

    consistency = vulnerable.get("consistency") or {}
    check(
        "result_is_internally_consistent",
        consistency.get("all_consistent") is True,
        f"the self-check of the service reports: {consistency.get('checks')!r}",
    )

    analysis = stages.get("static_analysis") or {}
    check(
        "static_analysis_provenance_is_reported",
        analysis.get("analysis_mode") in ("slither", "fallback_heuristics", "unavailable", "refused"),
        f"analysis_mode={analysis.get('analysis_mode')!r}, "
        f"slither_version={analysis.get('slither_version')!r}",
    )
    check(
        "static_analysis_status_is_reported",
        analysis.get("analysis_status") in ("completed", "partial", "fallback", "unavailable"),
        f"analysis_status={analysis.get('analysis_status')!r}, "
        f"exit_code_disposition={analysis.get('exit_code_disposition')!r}",
    )
    # The exit code, the status of the analysis, the validity of the report and the
    # fallback flag have to tell the same story. The rule is the one of
    # ``core.slither_status``, so the gate and the detector judge a run by exactly
    # the same criteria.
    check(
        "static_analysis_evidence_is_consistent",
        static_analysis_evidence_is_consistent(analysis),
        f"analysis_mode={analysis.get('analysis_mode')!r}, "
        f"analysis_status={analysis.get('analysis_status')!r}, "
        f"slither_exit_code={analysis.get('slither_exit_code')!r}, "
        f"exit_code_disposition={analysis.get('exit_code_disposition')!r}, "
        f"slither_report_valid={analysis.get('slither_report_valid')!r}, "
        f"slither_report_success={analysis.get('slither_report_success')!r}, "
        f"fallback_reason={analysis.get('fallback_reason')!r}",
    )
    check(
        "static_analysis_used_the_real_slither",
        analysis.get("analysis_mode") == "slither" and analysis.get("analysis_status") == "completed",
        f"analysis_mode={analysis.get('analysis_mode')!r}, "
        f"analysis_status={analysis.get('analysis_status')!r}, "
        f"slither_exit_code={analysis.get('slither_exit_code')!r}, "
        f"fallback_reason={analysis.get('fallback_reason')!r}",
    )
    check(
        "static_analysis_produced_findings",
        bool(analysis.get("finding_count")),
        f"findings={analysis.get('finding_count')!r}",
    )
    check(
        "hypothesis_derived",
        bool((stages.get("hypothesis") or {}).get("count")),
        f"hypotheses={(stages.get('hypothesis') or {}).get('count')!r}",
    )

    # -- the safe control -----------------------------------------------------
    control = results.get("safe_control") or {}
    control_verdict = control.get("verdict") or {}
    control_replay = (control.get("stages") or {}).get("replay") or {}
    check(
        "safe_control_not_confirmed",
        control_verdict.get("category") != "EXPLOIT_CONFIRMED"
        and control_verdict.get("is_verified") is not True,
        f"category={control_verdict.get('category')!r}, "
        f"is_verified={control_verdict.get('is_verified')!r}, "
        f"reward={control_verdict.get('reward_score')!r}",
    )
    check(
        "safe_control_executed",
        control.get("status") == "COMPLETED",
        f"status={control.get('status')!r}",
    )
    check(
        "safe_control_replay_confirmed_no_breach",
        control_replay.get("executed") is True
        and control_replay.get("reproduced") is False
        and control_replay.get("harness_verdict") == "NO_BREACH",
        f"executed={control_replay.get('executed')!r}, "
        f"reproduced={control_replay.get('reproduced')!r}, "
        f"harness_verdict={control_replay.get('harness_verdict')!r}",
    )
    check(
        "safe_control_result_is_internally_consistent",
        (control.get("consistency") or {}).get("all_consistent") is True,
        f"the self-check of the service reports: "
        f"{(control.get('consistency') or {}).get('checks')!r}",
    )

    # -- the refusal and the read-back ---------------------------------------
    invalid = results.get("invalid_contract") or {}
    check(
        "invalid_contract_rejected",
        invalid.get("status") == "REJECTED",
        f"status={invalid.get('status')!r}, code={(invalid.get('error') or {}).get('code')!r}",
    )

    read_back = results.get("read_back") or {}
    check(
        "artifact_read_back",
        read_back.get("status") == "READ_BACK" and read_back.get("parsed") is True,
        f"status={read_back.get('status')!r}, parsed={read_back.get('parsed')!r}",
    )

    # -- the authorisation of the service ------------------------------------
    for key, call in (
        ("unauthorised_audit_contract", "audit_contract"),
        ("unauthorised_probe_environment", "probe_environment"),
        ("unauthorised_read_saved_result", "read_saved_result"),
    ):
        refused = results.get(key) or {}
        error = refused.get("error") or {}
        check(
            f"unauthorised_call_refused:{call}",
            refused.get("status") == "UNAUTHORIZED" and error.get("code") == "NOT_AUTHORISED",
            f"status={refused.get('status')!r}, code={error.get('code')!r}",
        )

    return {
        "checks": checks,
        "passed": sum(1 for c in checks if c["status"] == "PASS"),
        "failed": sum(1 for c in checks if c["status"] == "FAIL"),
        "unobserved": sum(1 for c in checks if c["status"] == "UNOBSERVED"),
        "all_passed": all(c["status"] == "PASS" for c in checks),
    }


def run(args: argparse.Namespace) -> Dict[str, Any]:
    """Run the end-to-end test and write the evidence."""
    # The authorisation is checked before the application is imported and before
    # anything of this run touches the provider.
    _assert_authorised()

    if args.profile:
        os.environ["MODAL_PROFILE"] = args.profile

    run_id = args.run_id or f"cpu-audit-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    started_at = _utc_now()

    if args.mode == "ephemeral":
        from modal_cpu_audit_app import app  # noqa: F401  (the import validates the module)

        results = asyncio.run(_run_ephemeral_suite(run_id))
        app_id = results.get("app_id")
        deployment = {
            "mode": "ephemeral",
            "app_id": app_id,
            "dashboard_url": None,
            "status": "OBSERVED",
        }
    else:
        deployment = _deployed_app_facts()
        app_id = deployment.get("app_id")
        results = asyncio.run(_run_deployed_suite(run_id))

    provider_facts = _collect_provider_facts(args.profile, app_id)
    provider_facts["deployment"] = deployment
    evaluation = _evaluate_expectations(results)

    payload_text = json.dumps(results, default=str, ensure_ascii=False, indent=2)
    secret_findings = _scan_for_secrets(payload_text)

    evidence = {
        "schema_version": "aegis-cpu-audit-evidence/1.0.0",
        "run_id": run_id,
        "mode": args.mode,
        "profile": args.profile,
        "started_at_utc": started_at,
        "finished_at_utc": _utc_now(),
        "results": results,
        "expectations": evaluation,
        "provider_facts": provider_facts,
        "secret_scan": {
            "patterns_checked": [p.pattern for p in SECRET_PATTERNS],
            "findings": secret_findings,
            "clean": not secret_findings,
        },
        "result_sha256": _sha256_text(payload_text),
    }

    evidence_dir = (_ROOT / args.evidence_dir).resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{run_id}_evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, default=str, ensure_ascii=False), encoding="utf-8"
    )
    evidence["evidence_path"] = str(evidence_path)

    print(json.dumps({
        "run_id": run_id,
        "evidence_path": str(evidence_path),
        "expectations": {
            "passed": evaluation["passed"],
            "failed": evaluation["failed"],
            "unobserved": evaluation["unobserved"],
            "all_passed": evaluation["all_passed"],
        },
        "checks": evaluation["checks"],
        "secret_scan_clean": evidence["secret_scan"]["clean"],
    }, indent=2, ensure_ascii=False))

    return evidence


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CPU-only Modal audit service end to end.")
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="the Modal profile to use")
    parser.add_argument(
        "--mode",
        choices=("deployed", "ephemeral"),
        default="deployed",
        help="call the deployed application or run it ephemerally",
    )
    parser.add_argument("--run-id", default=None, help="the identifier of this run")
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR)
    args = parser.parse_args(argv)

    try:
        evidence = run(args)
    except AuditNotAuthorised as exc:
        print(f"REFUSED: {exc}")
        return 2
    return 0 if evidence["expectations"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
