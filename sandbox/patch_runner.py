"""
sandbox/patch_runner.py
=======================

Isolated Foundry runner for Blue-team patch verification (Dual-Loop Red + Blue RLVR).
Runs functional regression tests (`*Functional.t.sol`) and security harness tests
(`*Harness.t.sol` + `ExploitModule.sol`) in a fresh temporary Foundry workspace.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sandbox.runner import (
    FOUNDRY_TOML_CONTENT,
    LOCAL_TRAIN_HARNESSES_DIR,
    TRAIN_TRUSTED_HARNESS_CONTRACTS,
    _DEFAULT_FOUNDRY_BASE_LIB_DIR,
    _LOCAL_FOUNDRY_BIN_DIR,
    run_subprocess_capped,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_TRAIN_FUNCTIONAL_TESTS_DIR = str(
    (REPO_ROOT / "benchmarks" / "targets" / "solidity_train_functional").resolve()
)

#: Pilot mapping of train contracts to their trusted functional regression suites.
TRAIN_FUNCTIONAL_TESTS: Dict[str, str] = {
    "TrainAdminTreasury": "TrainAdminTreasuryFunctional",
    "TrainShareVault": "TrainShareVaultFunctional",
    "TrainReentrancyBank": "TrainReentrancyBankFunctional",
    "TrainUninitializedVault": "TrainUninitializedVaultFunctional",
    "TrainTimelockBypass": "TrainTimelockBypassFunctional",
}


@dataclass
class PatchSandboxResult:
    """Structured result from executing functional + security suites against a patched contract."""

    target_name: str
    compiled: bool = False
    functional_pass: bool = False
    exploit_blocked: bool = False
    infra_error: bool = False
    compile_error: str = ""
    infra_error_reason: str = ""
    functional_stdout: str = ""
    functional_stderr: str = ""
    security_stdout: str = ""
    security_stderr: str = ""
    breach_events: List[str] = field(default_factory=list)


def is_patch_sandbox_available() -> bool:
    """Return True when both `forge` and `forge-std` are locally available."""
    forge_exe = shutil.which("forge")
    if not forge_exe and _LOCAL_FOUNDRY_BIN_DIR:
        exe_name = "forge.exe" if os.name == "nt" else "forge"
        candidate = os.path.join(_LOCAL_FOUNDRY_BIN_DIR, exe_name)
        if os.path.isfile(candidate):
            forge_exe = candidate
    forge_std_dir = os.path.join(_DEFAULT_FOUNDRY_BASE_LIB_DIR, "forge-std", "src", "Test.sol")
    return bool(forge_exe) and os.path.isfile(forge_std_dir)


def _prepare_forge_env() -> Dict[str, str]:
    env = os.environ.copy()
    if _LOCAL_FOUNDRY_BIN_DIR:
        cur = env.get("PATH", "")
        if _LOCAL_FOUNDRY_BIN_DIR not in cur.split(os.pathsep):
            env["PATH"] = os.pathsep.join([_LOCAL_FOUNDRY_BIN_DIR, cur]) if cur else _LOCAL_FOUNDRY_BIN_DIR
    return env


def _link_or_copy_forge_std(lib_dir: Path) -> bool:
    src = Path(_DEFAULT_FOUNDRY_BASE_LIB_DIR) / "forge-std"
    if not src.is_dir():
        return False
    dst = lib_dir / "forge-std"
    try:
        os.symlink(str(src), str(dst), target_is_directory=True)
    except OSError:
        shutil.copytree(src, dst)
    return True


def _is_compile_failure(return_code: int, stdout: str, stderr: str) -> bool:
    if return_code == 0:
        return False
    combined = f"{stdout}\n{stderr}".lower()
    markers = (
        "compiler run failed",
        "parsererror",
        "typeerror:",
        "declarationerror:",
        "syntaxerror:",
        "error (2",
        "error (7",
        "error (9",
        "source file requires different compiler version",
    )
    return any(m in combined for m in markers)


#: keccak256("SecurityInvariantBreached(string,uint256)")
_SECURITY_BREACH_TOPIC = "0xedb78e99835b55ba5a68e662bb8f6fa6dbde579685bc85b0aae2d5547dc6dcfc"


def _extract_breach_events(stdout: str, stderr: str) -> List[str]:
    """Detect emitted `SecurityInvariantBreached` events from forge `--json` or text output."""
    events: List[str] = []
    combined = f"{stdout}\n{stderr}"
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        for suite_data in payload.values():
            if not isinstance(suite_data, dict):
                continue
            test_results = suite_data.get("test_results") or {}
            if not isinstance(test_results, dict):
                continue
            for test_res in test_results.values():
                if not isinstance(test_res, dict):
                    continue
                for log_entry in test_res.get("decoded_logs") or []:
                    if "SecurityInvariantBreached" in str(log_entry):
                        events.append(str(log_entry))
                for raw_log in test_res.get("logs") or []:
                    if isinstance(raw_log, dict):
                        topics = [str(t).lower() for t in (raw_log.get("topics") or [])]
                        if _SECURITY_BREACH_TOPIC in topics:
                            events.append(_SECURITY_BREACH_TOPIC)
                if test_res.get("status") == "Success" and not events:
                    events.append("SecurityInvariantBreached(status=Success)")
    if not events and "SecurityInvariantBreached" in combined:
        events.append("SecurityInvariantBreached")
    return events


def _did_functional_suite_pass(return_code: int, stdout: str) -> bool:
    if return_code != 0:
        return False
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        statuses: List[str] = []
        for suite_data in payload.values():
            if isinstance(suite_data, dict) and isinstance(suite_data.get("test_results"), dict):
                for test_res in suite_data["test_results"].values():
                    if isinstance(test_res, dict) and test_res.get("status"):
                        statuses.append(str(test_res["status"]))
        if statuses:
            return all(s == "Success" for s in statuses)
    return True


def run_patch_in_sandbox(
    target_name: str,
    patched_source: str,
    exploit_code: str,
    *,
    timeout_sec: int = 60,
    functional_tests_dir: str = LOCAL_TRAIN_FUNCTIONAL_TESTS_DIR,
    harnesses_dir: str = LOCAL_TRAIN_HARNESSES_DIR,
) -> PatchSandboxResult:
    """
    Verify a patched contract inside a fresh temporary Foundry workspace.

    Executes:
    1. `<TargetName>Functional.t.sol` (Trusted Blue Oracle)
    2. `<TargetName>Harness.t.sol` + `ExploitModule.sol` (Red exploit security check)
    """
    if target_name not in TRAIN_FUNCTIONAL_TESTS:
        return PatchSandboxResult(
            target_name=target_name,
            infra_error=True,
            infra_error_reason=f"No registered functional test suite for '{target_name}'",
        )
    if target_name not in TRAIN_TRUSTED_HARNESS_CONTRACTS:
        return PatchSandboxResult(
            target_name=target_name,
            infra_error=True,
            infra_error_reason=f"No registered train harness for '{target_name}'",
        )

    func_contract = TRAIN_FUNCTIONAL_TESTS[target_name]
    harness_contract = TRAIN_TRUSTED_HARNESS_CONTRACTS[target_name]
    func_file = Path(functional_tests_dir) / f"{func_contract}.t.sol"
    harness_file = Path(harnesses_dir) / f"{harness_contract}.t.sol"
    if not func_file.is_file() or not harness_file.is_file():
        return PatchSandboxResult(
            target_name=target_name,
            infra_error=True,
            infra_error_reason=f"Missing functional ({func_file}) or harness ({harness_file}) file",
        )

    if not is_patch_sandbox_available():
        return PatchSandboxResult(
            target_name=target_name,
            infra_error=True,
            infra_error_reason="Foundry `forge` or `forge-std` is not available in this environment",
        )

    env = _prepare_forge_env()
    with tempfile.TemporaryDirectory(prefix=f"aegis_patch_{target_name}_") as tmp_dir:
        root = Path(tmp_dir)
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "lib").mkdir()
        (root / "foundry.toml").write_text(FOUNDRY_TOML_CONTENT, encoding="utf-8")

        if not _link_or_copy_forge_std(root / "lib"):
            return PatchSandboxResult(
                target_name=target_name,
                infra_error=True,
                infra_error_reason="Failed to provision forge-std in temporary workspace",
            )

        (root / "src" / f"{target_name}.sol").write_text(patched_source, encoding="utf-8")
        (root / "test" / f"{func_contract}.t.sol").write_text(
            func_file.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (root / "test" / f"{harness_contract}.t.sol").write_text(
            harness_file.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (root / "test" / "ExploitModule.sol").write_text(exploit_code, encoding="utf-8")

        # 1. Functional regression gate
        func_res = run_subprocess_capped(
            ["forge", "test", "--match-contract", func_contract, "-vv", "--json"],
            cwd=str(root),
            env=env,
            timeout=timeout_sec,
        )
        if func_res.timed_out:
            return PatchSandboxResult(
                target_name=target_name,
                infra_error=True,
                infra_error_reason="Functional test execution timed out",
                functional_stdout=func_res.stdout,
                functional_stderr=func_res.stderr,
            )
        if _is_compile_failure(func_res.returncode, func_res.stdout, func_res.stderr):
            return PatchSandboxResult(
                target_name=target_name,
                compiled=False,
                compile_error=(func_res.stderr or func_res.stdout)[:1500],
                functional_stdout=func_res.stdout,
                functional_stderr=func_res.stderr,
            )

        functional_pass = _did_functional_suite_pass(func_res.returncode, func_res.stdout)

        # 2. Security gate (Red exploit against patched contract)
        sec_res = run_subprocess_capped(
            ["forge", "test", "--match-contract", harness_contract, "-vvv", "--json"],
            cwd=str(root),
            env=env,
            timeout=timeout_sec,
        )
        if sec_res.timed_out:
            return PatchSandboxResult(
                target_name=target_name,
                compiled=True,
                functional_pass=functional_pass,
                infra_error=True,
                infra_error_reason="Security harness execution timed out",
                functional_stdout=func_res.stdout,
                functional_stderr=func_res.stderr,
                security_stdout=sec_res.stdout,
                security_stderr=sec_res.stderr,
            )
        if _is_compile_failure(sec_res.returncode, sec_res.stdout, sec_res.stderr):
            return PatchSandboxResult(
                target_name=target_name,
                compiled=False,
                compile_error=(sec_res.stderr or sec_res.stdout)[:1500],
                functional_stdout=func_res.stdout,
                functional_stderr=func_res.stderr,
                security_stdout=sec_res.stdout,
                security_stderr=sec_res.stderr,
            )

        breach_events = _extract_breach_events(sec_res.stdout, sec_res.stderr)
        exploit_blocked = len(breach_events) == 0

        return PatchSandboxResult(
            target_name=target_name,
            compiled=True,
            functional_pass=functional_pass,
            exploit_blocked=exploit_blocked,
            infra_error=False,
            functional_stdout=func_res.stdout,
            functional_stderr=func_res.stderr,
            security_stdout=sec_res.stdout,
            security_stderr=sec_res.stderr,
            breach_events=breach_events,
        )
