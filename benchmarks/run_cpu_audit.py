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

Usage::

    # one-off authorisation of this run
    $env:AEGIS_APPROVE_CPU_AUDIT = "1"

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

DEFAULT_PROFILE = "neubeginner"
DEFAULT_EVIDENCE_DIR = "benchmarks/evidence/cpu_audit"

#: The environment variable that carries the maintainer's explicit approval for this
#: live invocation. Without it the invocation is refused.
APPROVAL_ENV_VAR = "AEGIS_APPROVE_CPU_AUDIT"

#: The values the approval variable may carry.
APPROVAL_VALUES = ("1", "true", "yes")

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

    vault_source = _read_target_source("benchmarks/targets/solidity/Vault.sol")
    control_source = _read_target_source("benchmarks/targets/solidity/controls/SecureVault.sol")

    results: Dict[str, Any] = {}

    results["environment_probe"] = await probe_environment.remote.aio()

    results["vulnerable_target"] = await audit_contract.remote.aio(
        {
            "target_name": "Vault",
            "source_code": vault_source,
            "run_id": f"{run_id}-vault",
            "run_replay": True,
        }
    )

    results["safe_control"] = await audit_contract.remote.aio(
        {
            "target_name": "SecureVault",
            "source_code": control_source,
            "run_id": f"{run_id}-control",
            "run_replay": True,
        }
    )

    results["invalid_contract"] = await audit_contract.remote.aio(
        {
            "target_name": "NotAllowlisted",
            "source_code": "contract Whatever { function f() public {} }",
            "run_id": f"{run_id}-invalid",
        }
    )

    # The read-back happens in a separate invocation: a container that did not
    # produce the artifact reads it back from the volume.
    results["read_back"] = await read_saved_result.remote.aio(f"{run_id}-vault")

    return results


async def _run_ephemeral_suite(run_id: str) -> Dict[str, Any]:
    """Run the same suite against an ephemeral (not deployed) application."""
    from modal_cpu_audit_app import app, audit_contract, probe_environment, read_saved_result

    vault_source = _read_target_source("benchmarks/targets/solidity/Vault.sol")
    control_source = _read_target_source("benchmarks/targets/solidity/controls/SecureVault.sol")

    results: Dict[str, Any] = {}
    async with app.run():
        results["app_id"] = app.app_id
        results["environment_probe"] = await probe_environment.remote.aio()
        results["vulnerable_target"] = await audit_contract.remote.aio(
            {
                "target_name": "Vault",
                "source_code": vault_source,
                "run_id": f"{run_id}-vault",
                "run_replay": True,
            }
        )
        results["safe_control"] = await audit_contract.remote.aio(
            {
                "target_name": "SecureVault",
                "source_code": control_source,
                "run_id": f"{run_id}-control",
                "run_replay": True,
            }
        )
        results["invalid_contract"] = await audit_contract.remote.aio(
            {
                "target_name": "NotAllowlisted",
                "source_code": "contract Whatever { function f() public {} }",
                "run_id": f"{run_id}-invalid",
            }
        )
        results["read_back"] = await read_saved_result.remote.aio(f"{run_id}-vault")
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
    "passed".
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
    check(
        "no_gpu_in_container",
        probe.get("runtime", {}).get("gpu_device_exposed") is False,
        f"nvidia device nodes: {probe.get('runtime', {}).get('nvidia_device_nodes')}",
    )

    vulnerable = results.get("vulnerable_target") or {}
    verdict = vulnerable.get("verdict") or {}
    check(
        "vulnerable_target_executed",
        vulnerable.get("status") == "COMPLETED",
        f"status={vulnerable.get('status')!r}",
    )
    check(
        "vulnerable_target_breach_confirmed",
        verdict.get("category") == "EXPLOIT_CONFIRMED",
        f"category={verdict.get('category')!r}, reward={verdict.get('reward_score')!r}",
    )
    check(
        "vulnerable_target_replayed",
        verdict.get("reproducible") is True,
        f"reproducible={verdict.get('reproducible')!r}",
    )
    check(
        "static_analysis_executed",
        bool((vulnerable.get("stages", {}).get("static_analysis") or {}).get("finding_count")),
        f"findings={(vulnerable.get('stages', {}).get('static_analysis') or {}).get('finding_count')!r}",
    )
    check(
        "hypothesis_derived",
        bool((vulnerable.get("stages", {}).get("hypothesis") or {}).get("count")),
        f"hypotheses={(vulnerable.get('stages', {}).get('hypothesis') or {}).get('count')!r}",
    )

    control = results.get("safe_control") or {}
    control_verdict = control.get("verdict") or {}
    check(
        "safe_control_not_confirmed",
        control_verdict.get("category") != "EXPLOIT_CONFIRMED",
        f"category={control_verdict.get('category')!r}",
    )
    check(
        "safe_control_executed",
        control.get("status") == "COMPLETED",
        f"status={control.get('status')!r}",
    )

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
