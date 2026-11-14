import os
import json
import re
import signal
import threading
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, Optional

import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram, ResultCategory
from core.config import config
from core.slither_status import (
    DISPOSITION_NO_REPORT,
    DISPOSITION_NOT_RUN,
    MODE_FALLBACK,
    MODE_REFUSED,
    MODE_SLITHER,
    MODE_UNAVAILABLE,
    STATUS_COMPLETED,
    STATUS_FALLBACK,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    classify_slither_outcome,
)
from core.evidence import (
    HarnessVerdict,
    HARNESS_NO_BREACH_REASON_PREFIX,
    HARNESS_TEST_NAME,
    trusted_harness_suite_prefix,
)

# Path to pre-baking script
PREBAKE_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prebake_solc.py")

# This directory is copied into the Modal image from the repository at deploy time.
# Runtime request payloads are never allowed to supply trusted harness source.
LOCAL_TRUSTED_HARNESSES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmarks", "targets", "solidity")
)
TRUSTED_HARNESSES_DIR = "/opt/aegis/trusted_harnesses"
TRUSTED_HARNESS_CONTRACTS = {
    "Vault": "VaultTrustedHarness",
    "ERC4626Vault": "ERC4626TrustedHarness",
    "AccessControlVault": "AccessControlVaultHarness",
    "AuctionDoS": "AuctionDoSHarness",
    "CrossContractBridge": "CrossContractBridgeHarness",
    "FeeShareYieldVault": "FeeShareYieldVaultHarness",
    "FlashLoanRewardPool": "FlashLoanRewardPoolHarness",
    "LendingLiquidation": "LendingLiquidationHarness",
    "OracleLendingPool": "OracleLendingPoolHarness",
    "PrecisionStakingPool": "PrecisionStakingPoolHarness",
    "RewardDistributorLogic": "RewardDistributorLogicHarness",
    "SignatureReplayWallet": "SignatureReplayWalletHarness",
    "SecureVault": "SecureVaultTrustedHarness",
    "SecureAccessControlVault": "SecureAccessControlVaultHarness",
    "SecureERC4626Vault": "SecureERC4626TrustedHarness",
    "SecureOraclePool": "SecureOraclePoolHarness",
}

# Optimized, Pinned Foundry + Solc + OpenZeppelin + Slither Execution Image for Modal
sandbox_image = (
    modal.Image.debian_slim(python_version="3.10")
    .apt_install("curl", "git", "build-essential", "ca-certificates")
    # Copy verified solc prebake script into image
    .add_local_file(PREBAKE_SCRIPT_PATH, "/opt/prebake_solc.py", copy=True)
    .run_commands(
        # 1. Install Foundry toolchain (forge, cast, anvil)
        "curl -sSfL https://foundry.paradigm.xyz | bash",
        "/root/.foundry/bin/foundryup",
        # 2. Pre-bake verified solc compilers (0.8.19 - 0.8.28) with SHA256 validation
        "python3 /opt/prebake_solc.py",
        # 3. Pre-bake pinned standard libraries: forge-std (v1.9.5) and openzeppelin-contracts (v5.0.2)
        "mkdir -p /opt/foundry_base/lib && cd /opt/foundry_base/lib && "
        "git clone --depth 1 -b v1.9.5 https://github.com/foundry-rs/forge-std.git forge-std && "
        "git clone --depth 1 -b v5.0.2 https://github.com/OpenZeppelin/openzeppelin-contracts.git openzeppelin-contracts",
    )
    .env({"PATH": "/root/.foundry/bin:$PATH"})
    .pip_install("pydantic>=2.0.0", "slither-analyzer", "solc-select")
    .add_local_dir(LOCAL_TRUSTED_HARNESSES_DIR, remote_path=TRUSTED_HARNESSES_DIR, copy=True)
    # The Python packages of the repository are **copied** into the image instead of
    # being mounted on container start. A deferred mount may not be followed by any
    # further image layer, so an image that ends in a mount cannot be extended -
    # which is exactly what the separate CPU-only audit application
    # (`modal_cpu_audit_app.py`) needs: it adds the `benchmarks` package and its
    # candidate registry on top of this image. The content of the container is the
    # same either way; only the moment at which the files arrive changes.
    .add_local_python_source("core", "sandbox", copy=True)
)

FOUNDRY_TOML_CONTENT = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200
offline = true
fs_permissions = [{ access = "read-write", path = "./" }]
remappings = [
    "forge-std/=lib/forge-std/src/",
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@openzeppelin/=lib/openzeppelin-contracts/"
]
"""

# Prohibited cheatcode patterns to isolate exploit execution from harness privileges
PROHIBITED_CHEATCODES = [
    "forge-std/Test.sol",
    "forge-std/Vm.sol",
    "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D",
    "vm.deal",
    "vm.prank",
    "vm.store",
    "vm.warp",
    "vm.roll",
    "vm.mockCall",
    "vm.expectRevert",
    "vm.load",
    "vm.etch",
    "vm.sign",
    "Vm constant vm",
    "Vm public vm",
    # --- Verification-channel hijack ---------------------------------------
    # A candidate must not be able to influence the channel that decides whether
    # its exploit succeeded:
    #   * the Foundry test framework would let it inject its own `testExploit`
    #     suite, which forge would then collect as a passing test;
    #   * the console library would let it forge the breach marker in the logs.
    "forge-std/StdAssertions.sol",
    "forge-std/DSTest.sol",
    "forge-std/Script.sol",
    "forge-std/console.sol",
    "forge-std/console2.sol",
    "ds-test/test.sol",
]

# A public/external `test*` function inside the candidate can be collected by
# forge as a standalone test suite and would fake a passing verification run.
_CANDIDATE_TEST_ENTRYPOINT_RE = re.compile(
    r"function\s+test[A-Za-z0-9_]*\s*\([^)]*\)[^{;]*\b(public|external)\b",
    re.IGNORECASE,
)

# The candidate has no legitimate need for the Foundry test framework.
_CANDIDATE_IMPORT_RE = re.compile(r"import[^;]*?[\"']([^\"']+)[\"']", re.IGNORECASE)

# Trusted harness verdicts. They are produced by the IMMUTABLE, repository-owned
# harness and are read from forge's STRUCTURED test result - never from log text.
HARNESS_VERDICT_BREACH = HarnessVerdict.BREACH.value
HARNESS_VERDICT_NO_BREACH = HarnessVerdict.NO_BREACH.value
HARNESS_VERDICT_EXEC_REVERT = HarnessVerdict.EXEC_REVERT.value
HARNESS_VERDICT_UNKNOWN = HarnessVerdict.UNKNOWN.value

MAX_LOG_OUTPUT_BYTES = 1_000_000
_TARGET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def is_safe_target_name(name: str) -> bool:
    """Accept only a bounded Solidity identifier before it is used in a path."""
    return isinstance(name, str) and bool(_TARGET_NAME_RE.fullmatch(name))


def load_trusted_harness_code(target_name: str, harness_dir=None) -> str:
    """
    Load the immutable repository harness, never the value from TargetProgram.

    The optional harness_dir exists for hermetic tests only. Production callers
    use the fixed directory mounted into the Modal image at deploy time.
    """
    if not is_safe_target_name(target_name):
        raise ValueError("target name is not a safe Solidity identifier")
    if target_name not in TRUSTED_HARNESS_CONTRACTS:
        raise FileNotFoundError(f"No allowlisted repository harness for target {target_name}")

    default_dir = TRUSTED_HARNESSES_DIR if os.path.isdir(TRUSTED_HARNESSES_DIR) else LOCAL_TRUSTED_HARNESSES_DIR
    root = os.path.realpath(harness_dir or default_dir)
    harness_path = os.path.realpath(os.path.join(root, f"{target_name}Harness.t.sol"))
    if os.path.dirname(harness_path) != root:
        raise ValueError("trusted harness path escaped its immutable directory")
    if not os.path.isfile(harness_path):
        raise FileNotFoundError(f"No repository-owned trusted harness for target {target_name}")
    with open(harness_path, "r", encoding="utf-8") as source:
        return source.read()


class CappedProcessResult:
    def __init__(self, returncode: int, stdout: str, stderr: str, timed_out: bool = False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        # Byte-exact streams (Iteration 14 P0.2). The decoded strings above are
        # for human/diagnostic use; the digests of the evidence chain are
        # always computed over these raw bytes.
        self.stdout_bytes = b""
        self.stderr_bytes = b""


# ---------------------------------------------------------------------------
# Observed execution environment (Iteration 14 P0.3)
# ---------------------------------------------------------------------------
# The remote EVM toolchain description must be OBSERVED inside the worker that
# actually ran the EVM. Nothing here may be a hardcoded constant: every fact
# is read from the live container, and a fact that cannot be read is reported
# as NOT_AVAILABLE together with the reason.


def _observed_os_facts():
    """Read the operating system facts from the running container."""
    from benchmarks.evidence_integrity import NOT_AVAILABLE, observed, not_available

    remote_os = None
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("PRETTY_NAME="):
                        remote_os = line.split("=", 1)[1].strip().strip('"')
                        break
    except OSError:
        remote_os = None

    if not remote_os:
        return (
            not_available("/etc/os-release is not readable in this container"),
            observed("posix" if os.name == "posix" else os.name, source="os.name"),
        )

    return (
        observed(remote_os, source="/etc/os-release:PRETTY_NAME"),
        observed(os.name, source="os.name"),
    )


def _observed_forge_version(env: dict, cwd: str):
    """Read the exact Foundry version that is installed in this container."""
    from benchmarks.evidence_integrity import observed, not_available

    try:
        proc = run_subprocess_capped(
            ["forge", "--version"],
            cwd=cwd,
            env=env,
            timeout=30,
        )
    except (OSError, ValueError) as exc:
        return not_available(f"forge --version could not be executed: {type(exc).__name__}: {exc}")

    if proc.returncode != 0 or not proc.stdout.strip():
        return not_available(
            f"forge --version did not report a version (exit code {proc.returncode})"
        )
    return observed(proc.stdout.strip(), source="forge --version")


def _observed_compiler_settings(env: dict, cwd: str):
    """
    Read the EFFECTIVE compiler settings and the solc version in use.

    ``forge config --json`` reports the settings Foundry actually applies for
    the project it is executed in, which is exactly what a benchmark run has
    to attest.
    """
    from benchmarks.evidence_integrity import observed, not_available

    try:
        proc = run_subprocess_capped(
            ["forge", "config", "--json"],
            cwd=cwd,
            env=env,
            timeout=60,
        )
    except (OSError, ValueError) as exc:
        return (
            not_available(f"forge config --json could not be executed: {type(exc).__name__}: {exc}"),
            not_available("solc version could not be read without the effective Foundry config"),
        )

    if proc.returncode != 0:
        return (
            not_available(f"forge config --json failed with exit code {proc.returncode}"),
            not_available("solc version could not be read without the effective Foundry config"),
        )

    try:
        config_data = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        return (
            not_available(f"forge config --json did not return valid JSON: {exc}"),
            not_available("solc version could not be read without the effective Foundry config"),
        )

    settings = {
        "evm_version": config_data.get("evm_version"),
        "optimizer": config_data.get("optimizer"),
        "optimizer_runs": config_data.get("optimizer_runs"),
        "via_ir": config_data.get("via_ir"),
        "offline": config_data.get("offline"),
    }
    solc_version = config_data.get("solc")
    if isinstance(solc_version, str):
        solc_versions = [solc_version]
    elif isinstance(solc_version, list):
        solc_versions = [str(item) for item in solc_version]
    else:
        solc_versions = []
    if solc_versions:
        solc_fact = observed(solc_versions, source="forge config --json:solc")
    else:
        solc_fact = not_available("forge config --json did not report a solc version")

    return observed(settings, source="forge config --json"), solc_fact


def _observed_image_digest():
    """
    Read the immutable image identity of the running container.

    Modal exposes the image object id inside the container. It is immutable and
    therefore a valid environment identifier, unlike a mutable tag.
    """
    from benchmarks.evidence_integrity import observed, not_available

    try:
        image_id = modal.config.config.get("image_id")
    except Exception:
        image_id = None

    if image_id:
        return observed(str(image_id), source="modal.config.image_id")
    return not_available(
        "the Modal runtime did not expose an image id inside this container "
        "(modal.config.image_id is unset)"
    )


def observe_execution_environment(
    *,
    argv: list,
    working_directory: str,
    env: dict,
    observed_exit_code: int,
) -> dict:
    """
    Collect the observed remote EVM toolchain facts for one execution.

    Every entry is either an OBSERVED fact or a NOT_AVAILABLE fact with the
    reason. No value is ever templated.
    """
    from benchmarks.evidence_integrity import observed, not_available

    remote_os, remote_platform = _observed_os_facts()
    forge_version = _observed_forge_version(env, working_directory)
    compiler_settings, solc_versions = _observed_compiler_settings(env, working_directory)
    image_digest = _observed_image_digest()

    return {
        "remote_os": remote_os,
        "remote_platform": remote_platform,
        "image_digest": image_digest,
        "forge_version": forge_version,
        "solc_versions": solc_versions,
        "exact_forge_argv": observed(list(argv), source="the argv that was executed"),
        "working_directory": observed(working_directory, source="the cwd of the forge process"),
        "compiler_settings": compiler_settings,
        "observed_exit_code": observed(
            int(observed_exit_code), source="the exit code of the forge process"
        ),
    }


def run_subprocess_capped(
    cmd: list,
    *,
    cwd: str,
    env: dict,
    timeout: int,
    max_output_bytes: int = MAX_LOG_OUTPUT_BYTES,
) -> CappedProcessResult:
    """Drain both pipes continuously, retaining at most max_output_bytes per stream."""
    limit = max(1, int(max_output_bytes))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        text=False,
        bufsize=0,
        start_new_session=(os.name == "posix"),
    )

    def drain(pipe, key: str) -> None:
        while True:
            chunk = pipe.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(buffers[key])
            if remaining > 0:
                buffers[key].extend(chunk[:remaining])
            if len(chunk) > max(0, remaining):
                truncated[key] = True

    readers = [
        threading.Thread(target=drain, args=(proc.stdout, "stdout"), daemon=True),
        threading.Thread(target=drain, args=(proc.stderr, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        proc.wait()

    for reader in readers:
        reader.join(timeout=0.5)

    # A descendant may keep inherited pipes open after its parent exits.
    if any(reader.is_alive() for reader in readers):
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        for reader in readers:
            reader.join(timeout=2.0)

    for pipe in (proc.stdout, proc.stderr):
        try:
            pipe.close()
        except Exception:
            pass

    def decode(key: str) -> str:
        output = bytes(buffers[key]).decode("utf-8", errors="replace")
        if truncated[key]:
            output += "\n[LOG_TRUNCATED: retained output capped at configured byte limit]"
        return output

    result = CappedProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=decode("stdout"),
        stderr=decode("stderr"),
        timed_out=timed_out,
    )
    # The raw bytes are the evidence: the decoded strings may have replaced
    # undecodable sequences, the raw bytes never did.
    result.stdout_bytes = bytes(buffers["stdout"])
    result.stderr_bytes = bytes(buffers["stderr"])
    return result


def detect_prohibited_cheatcodes(code: str) -> bool:
    """
    Detects attempts by candidate ExploitModule to use privileged Foundry
    cheatcodes or to hijack the verification channel itself.

    Both classes are security violations: a candidate that reaches into the
    Foundry test framework could inject its own test suite, and a candidate that
    imports the console library could forge the breach marker inside the logs.
    """
    if not code:
        return False

    for pattern in PROHIBITED_CHEATCODES:
        if pattern in code:
            return True

    for match in _CANDIDATE_IMPORT_RE.finditer(code):
        path = match.group(1).lower()
        if "forge-std" in path or "ds-test" in path:
            return True

    if _CANDIDATE_TEST_ENTRYPOINT_RE.search(code):
        return True

    return False


def extract_trusted_harness_evidence(
    structured_data,
    target_name: str
):
    """
    Extract structured verdict, status, reason, deployed harness address,
    and raw EVM logs for exactly one repository-owned trusted harness suite.
    """
    if (
        not is_safe_target_name(target_name)
        or target_name not in TRUSTED_HARNESS_CONTRACTS
        or not isinstance(structured_data, dict)
    ):
        return HARNESS_VERDICT_UNKNOWN, "", None, None, None, []

    expected_path = trusted_harness_suite_prefix(target_name)
    matches = []
    for suite_key, suite_val in structured_data.items():
        if not isinstance(suite_val, dict):
            continue
        suite_path, separator, contract_name = str(suite_key).partition(":")
        path = suite_path.strip()
        if (
            not separator
            or path != expected_path
            or contract_name.strip() != TRUSTED_HARNESS_CONTRACTS[target_name]
        ):
            continue
        test_results = suite_val.get("test_results", {})
        if not isinstance(test_results, dict):
            continue
        for test_sig, test_info in test_results.items():
            if str(test_sig).strip() == f"{HARNESS_TEST_NAME}()" and isinstance(test_info, dict):
                status = test_info.get("status")
                reason = test_info.get("reason")
                logs = [log for log in test_info.get("logs", []) if isinstance(log, dict)]
                harness_addr = None
                traces = test_info.get("traces", [])
                if isinstance(traces, list):
                    for stage in traces:
                        if isinstance(stage, (list, tuple)) and len(stage) == 2 and isinstance(stage[1], dict):
                            arena = stage[1].get("arena", [])
                            if arena and isinstance(arena[0], dict):
                                addr = arena[0].get("trace", {}).get("address")
                                if addr and isinstance(addr, str):
                                    harness_addr = addr.strip().lower()
                                    break
                matches.append((path, status, reason, harness_addr, logs))

    if len(matches) != 1:
        return HARNESS_VERDICT_UNKNOWN, "", None, None, None, []

    suite_path, status, reason, harness_addr, raw_logs = matches[0]
    if status == "Success":
        verdict = HARNESS_VERDICT_BREACH
    elif status == "Failure":
        verdict = (
            HARNESS_VERDICT_NO_BREACH
            if reason and str(reason).startswith(HARNESS_NO_BREACH_REASON_PREFIX)
            else HARNESS_VERDICT_EXEC_REVERT
        )
    else:
        verdict = HARNESS_VERDICT_UNKNOWN
    return verdict, suite_path, status, reason, harness_addr, raw_logs


def extract_trusted_harness_verdict(
    structured_data,
    target_name: str
):
    """Read exactly one immutable repository harness and exact testExploit() result."""
    verdict, suite_path, status, reason, _, _ = extract_trusted_harness_evidence(
        structured_data, target_name
    )
    return verdict, suite_path, status, reason


def parse_forge_output(output_text: str):
    """Parses forge test --json structured output for status, revert reason, and logs."""
    structured_data = None
    test_status = None
    revert_reason = None
    decoded_logs = []

    start_idx = output_text.find("{")
    end_idx = output_text.rfind("}")

    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            structured_data = json.loads(output_text[start_idx : end_idx + 1])
        except Exception:
            pass

    if structured_data and isinstance(structured_data, dict):
        for _, suite_val in structured_data.items():
            if isinstance(suite_val, dict):
                test_results = suite_val.get("test_results", {})
                for test_sig, test_info in test_results.items():
                    if isinstance(test_info, dict):
                        status = test_info.get("status")
                        reason = test_info.get("reason")
                        logs = test_info.get("decoded_logs", [])
                        if logs:
                            decoded_logs.extend(logs)
                        if "testExploit" in test_sig or test_status is None:
                            test_status = status
                            revert_reason = reason

    return structured_data, test_status, revert_reason, decoded_logs


def resolve_pinned_solc(version: str = None) -> Optional[str]:
    """
    Resolve the pinned Solidity compiler of the image.

    The compiler is NOT on the PATH of the container: the image pre-bakes the
    verified binaries into the Foundry (svm) and the solc-select locations. A
    probe that asks a bare ``solc`` therefore reports a false negative, so the
    real binary is looked up in the places where it is actually installed.

    Returns the absolute path of the binary, or ``None`` when the pinned
    compiler is not installed.
    """
    wanted = version or config.SOLC_VERSION
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".svm", wanted, f"solc-{wanted}"),
        os.path.join(home, ".solc-select", "artifacts", f"solc-{wanted}", f"solc-{wanted}"),
        shutil.which("solc"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _slither_fallback_findings(source_code: str) -> list:
    """
    The deterministic fallback heuristics of this repository.

    These are NOT the output of the Slither detectors. They are used only when
    Slither cannot run, and every caller that reports them says so explicitly.
    """
    fallback_detectors = []
    src_lower = source_code.lower()
    if ".call{value:" in src_lower and "balances[" in src_lower:
        fallback_detectors.append({
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "High",
            "description": "Possible reentrancy via low-level call{value} prior to state updates."
        })
    if "totalsupply" in src_lower and "totalassets" in src_lower and "/" in src_lower:
        fallback_detectors.append({
            "check": "divide-before-multiply-inflation",
            "impact": "High",
            "confidence": "High",
            "description": "Exchange rate share division susceptible to first-depositor inflation attack."
        })
    return fallback_detectors


#: The flag that disables the findings policy of the Slither CLI. With the default
#: ``--fail-on pedantic`` the CLI leaves with ``sys.exit(-1)`` (the shell code 255)
#: as soon as it found anything - although the analysis itself succeeded and the
#: JSON report was written before that exit. The flag makes the exit code of a
#: successful run unambiguous.
SLITHER_FAIL_NONE_FLAG = "--fail-none"

#: How many characters of the output of Slither are kept in the evidence.
SLITHER_LOG_TAIL_CHARS = 2000


def _log_tail(text: Optional[str], limit: int = SLITHER_LOG_TAIL_CHARS) -> str:
    """The tail of a stream of a subprocess - the place where the reason lives."""
    if not text:
        return ""
    tail = text.strip()
    if len(tail) > limit:
        tail = "..." + tail[-limit:]
    return tail


def _is_unsupported_flag_failure(completed: CappedProcessResult, flag: str) -> bool:
    """
    Did the Slither build of the image refuse the flag because it does not know it?

    The image installs ``slither-analyzer`` without a version pin, so a future
    build may not know ``--fail-none`` any more. That is a usage error of the CLI
    (the exit code 2 of argparse) and it is detected here, so that the run can be
    repeated without the flag instead of losing the whole static analysis.
    """
    if completed.returncode != 2:
        return False
    stderr = (completed.stderr or "") + (completed.stdout or "")
    return flag in stderr and "unrecognized argument" in stderr


def run_slither_analysis_detailed(target: TargetProgram, include_version: bool = True) -> dict:
    """
    Run the static analysis and report WHERE the findings come from.

    The result states whether the findings are the output of a **completed** run of
    the real Slither detectors (``mode == "slither"``) or of the deterministic
    fallback heuristics of this repository (``mode == "fallback_heuristics"``). A
    fallback is never presented as an analysis result, and the reason for the
    fallback is part of the result.

    The presence of a JSON report with findings is **not** proof of a successful
    analysis. The Slither CLI writes that report before it leaves with a non-zero
    code, and it uses the same code for its findings policy and for an aborted
    analysis. The status of the run is therefore derived from the exit code, the
    validity of the report and the statement of the report itself - see
    ``core.slither_status``.

    The shape of the result::

        {
            "mode": "slither" | "fallback_heuristics" | "unavailable" | "refused",
            "analysis_status": "completed" | "partial" | "fallback" | "unavailable",
            "exit_code_disposition": "clean_exit" | "...",
            "engine": "slither (sandbox.runner.run_slither_analysis)",
            "findings": [...],
            "finding_count": int,
            "partial_findings": [...],
            "partial_finding_count": int,
            "detector_count": int | None,
            "slither_available": bool,
            "slither_version": str | None,
            "slither_exit_code": int | None,
            "slither_argv": [...],
            "slither_stdout_tail": str,
            "slither_stderr_tail": str,
            "slither_timed_out": bool,
            "slither_report_present": bool,
            "slither_report_valid": bool,
            "slither_report_success": bool | None,
            "slither_report_error": str | None,
            "error": str | None,
            "fallback_reason": str | None,
            "solc_version_requested": str,
        }
    """
    record: Dict[str, Any] = {
        "mode": MODE_UNAVAILABLE,
        "analysis_status": STATUS_UNAVAILABLE,
        "exit_code_disposition": DISPOSITION_NOT_RUN,
        "engine": "slither (sandbox.runner.run_slither_analysis)",
        "findings": [],
        "finding_count": 0,
        "partial_findings": [],
        "partial_finding_count": 0,
        "detector_count": None,
        "slither_available": False,
        "slither_version": None,
        "slither_exit_code": None,
        "slither_argv": [],
        "slither_stdout_tail": "",
        "slither_stderr_tail": "",
        "slither_timed_out": False,
        "slither_report_present": False,
        "slither_report_valid": False,
        "slither_report_success": None,
        "slither_report_error": None,
        "error": None,
        "fallback_reason": None,
        "solc_version_requested": config.SOLC_VERSION,
    }

    if not is_safe_target_name(target.name):
        record["mode"] = MODE_REFUSED
        record["error"] = "the target name is not a safe Solidity identifier"
        return record

    if include_version:
        try:
            version_proc = run_subprocess_capped(
                ["slither", "--version"],
                cwd=os.getcwd(),
                env=os.environ.copy(),
                timeout=30,
            )
            version_text = (version_proc.stdout or version_proc.stderr or "").strip()
            record["slither_version"] = version_text.splitlines()[0][:200] if version_text else None
            record["slither_available"] = version_proc.returncode == 0
        except Exception as exc:  # noqa: BLE001 - the failure is the evidence
            record["error"] = f"{type(exc).__name__}: {exc}"

    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir, exist_ok=True)

        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)

        json_out = os.path.join(tmpdir, "slither.json")
        base_cmd = [
            "slither",
            target_path,
            "--json",
            json_out,
            "--solc-solcs-select",
            config.SOLC_VERSION,
        ]
        cmd = base_cmd + [SLITHER_FAIL_NONE_FLAG]
        findings_policy_disabled = True

        try:
            completed = run_subprocess_capped(cmd, cwd=tmpdir, env=os.environ.copy(), timeout=30)

            if _is_unsupported_flag_failure(completed, SLITHER_FAIL_NONE_FLAG):
                # The Slither build of the image does not know the flag. The run is
                # repeated without it - from then on the findings policy of the CLI
                # is in effect and the code 255 has to be classified by it.
                # A report of the first attempt is removed first: the Slither CLI
                # refuses to overwrite an existing report file.
                if os.path.exists(json_out):
                    os.remove(json_out)
                cmd = base_cmd
                findings_policy_disabled = False
                completed = run_subprocess_capped(cmd, cwd=tmpdir, env=os.environ.copy(), timeout=30)

            report_present = os.path.exists(json_out)
            report: Optional[Dict[str, Any]] = None
            report_parsable = False
            if report_present:
                try:
                    with open(json_out, "r", encoding="utf-8") as jf:
                        loaded = json.load(jf)
                    report_parsable = isinstance(loaded, dict)
                    report = loaded if report_parsable else None
                except (OSError, ValueError):
                    report = None
                    report_parsable = False

            outcome = classify_slither_outcome(
                exit_code=completed.returncode,
                report=report,
                report_present=report_present,
                report_parsable=report_parsable,
                timed_out=bool(completed.timed_out),
                findings_policy_disabled=findings_policy_disabled,
            )

            record["slither_exit_code"] = completed.returncode
            record["slither_argv"] = list(cmd)
            record["slither_stdout_tail"] = _log_tail(completed.stdout)
            record["slither_stderr_tail"] = _log_tail(completed.stderr)
            record["slither_timed_out"] = bool(completed.timed_out)
            record["slither_report_present"] = report_present
            record["slither_report_valid"] = outcome["report_valid"]
            record["slither_report_success"] = outcome["report_success"]
            record["slither_report_error"] = outcome["report_error"]
            record["analysis_status"] = outcome["analysis_status"]
            record["exit_code_disposition"] = outcome["exit_code_disposition"]
            record["detector_count"] = outcome["detector_count"]

            if outcome["analysis_status"] == STATUS_COMPLETED:
                extracted = []
                for det in outcome["detectors"][:5]:  # Top 5 most critical detectors
                    extracted.append({
                        "check": det.get("check"),
                        "impact": det.get("impact"),
                        "confidence": det.get("confidence"),
                        "description": det.get("description", "")[:200]
                    })
                record["mode"] = MODE_SLITHER
                record["findings"] = extracted
                record["finding_count"] = len(extracted)
                record["slither_available"] = True
                return record

            # The run did not complete. The findings of an incomplete report are
            # kept as evidence of the partial run, but they are never the findings
            # of the analysis: the deterministic heuristics take over below.
            if outcome["analysis_status"] == STATUS_PARTIAL:
                partial = []
                for det in outcome["detectors"][:5]:
                    partial.append({
                        "check": det.get("check"),
                        "impact": det.get("impact"),
                        "confidence": det.get("confidence"),
                        "description": det.get("description", "")[:200]
                    })
                record["partial_findings"] = partial
                record["partial_finding_count"] = len(partial)

            record["error"] = _describe_incomplete_run(outcome, completed, report)
        except Exception as exc:  # noqa: BLE001 - the failure is the evidence
            record["error"] = f"{type(exc).__name__}: {exc}"
            record["analysis_status"] = STATUS_FALLBACK
            record["exit_code_disposition"] = DISPOSITION_NO_REPORT

    # Fallback AST heuristic detection if Slither cannot run, or if it did not
    # finish the analysis. The mode says so explicitly - a fallback is never
    # passed off as an analysis.
    record["mode"] = MODE_FALLBACK
    record["fallback_reason"] = record["error"] or "slither produced no usable report"
    record["findings"] = _slither_fallback_findings(target.source_code)
    record["finding_count"] = len(record["findings"])
    return record


def _describe_incomplete_run(
    outcome: Dict[str, Any],
    completed: CappedProcessResult,
    report: Optional[Dict[str, Any]],
) -> str:
    """The reason why the run of Slither was not a completed analysis."""
    exit_code = completed.returncode
    stderr = _log_tail(completed.stderr, 800)
    stdout = _log_tail(completed.stdout, 800)
    disposition = outcome["exit_code_disposition"]
    report_error = outcome.get("report_error")

    if disposition == "timed_out":
        return (
            f"slither did not finish within the timeout and was killed "
            f"(exit code {exit_code}): {stderr or stdout}"
        )
    if disposition == "no_valid_report":
        return (
            f"slither produced no report (exit code {exit_code}): "
            f"{stderr or stdout or 'no output'}"
        )
    if disposition == "unparsable_report":
        return (
            f"slither wrote a report that could not be parsed (exit code {exit_code}): "
            f"{stderr or stdout or 'no output'}"
        )
    if disposition == "analysis_error":
        return (
            f"slither reported a failed analysis (exit code {exit_code}): "
            f"{report_error or stderr or stdout}"
        )
    return (
        f"slither left with the code {exit_code} and the disposition of that code is "
        f"unknown: {stderr or stdout or 'no output'}"
    )



def run_slither_analysis(target: TargetProgram) -> list:
    """
    Executes Slither AST / taint analysis on the target contract.
    Returns structured list of static vulnerability warnings to prime reasoning models.

    The findings are the output of the real Slither detectors when Slither can
    run, and the deterministic fallback heuristics of this repository otherwise.
    Callers that report the findings use ``run_slither_analysis_detailed`` so
    that the provenance of the findings is part of the evidence.
    """
    return run_slither_analysis_detailed(target, include_version=False)["findings"]


def run_payload_in_sandbox(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """
    Executes an exploit module against a trusted verification harness in Foundry.
    Zero trust in model-supplied assertions: verification is performed exclusively
    by the immutable test harness in the EVM. Enforces cheatcode isolation.
    """
    start_time = time.time()

    # Target names become filesystem paths; only Solidity identifiers are allowed.
    if not is_safe_target_name(target.name):
        return ExecutionResult(
            return_code=-6,
            stdout="",
            stderr="INFRA_ERROR: target name is not a safe Solidity identifier",
            execution_time_sec=0.0,
            category=ResultCategory.INFRA_ERROR,
            timed_out=False,
            invariant_violated=False,
            verified_by_harness=False,
        )

    # Pre-execution check 1: Reject malformed generation without running Foundry
    if not payload.format_valid:
        return ExecutionResult(
            return_code=-4,
            stdout="",
            stderr=f"GENERATION_FORMAT_ERROR: {payload.format_error_reason}",
            execution_time_sec=0.0,
            category=ResultCategory.GENERATION_FORMAT_ERROR,
            timed_out=False,
            invariant_violated=False,
            cheatcode_detected=False,
            verified_by_harness=False
        )

    # Pre-execution check 2: reject attempts to import or execute Foundry cheatcodes.
    if detect_prohibited_cheatcodes(payload.test_code):
        return ExecutionResult(
            return_code=-3,
            stdout="",
            stderr="Security Violation: ExploitModule attempted to import or execute Foundry cheatcodes (vm.*).",
            execution_time_sec=0.01,
            category=ResultCategory.CHEATCODE_DETECTED,
            timed_out=False,
            invariant_violated=False,
            cheatcode_detected=True,
            verified_by_harness=False,
        )

    # Trusted harness source is loaded from the image-bundled repository directory.
    # TargetProgram.trusted_harness_code is a deprecated untrusted input and is ignored.
    try:
        trusted_harness_source = load_trusted_harness_code(target.name)
    except (ValueError, FileNotFoundError, OSError) as exc:
        return ExecutionResult(
            return_code=-7,
            stdout="",
            stderr=f"INFRA_ERROR: trusted repository harness unavailable: {exc}",
            execution_time_sec=time.time() - start_time,
            category=ResultCategory.INFRA_ERROR,
            timed_out=False,
            invariant_violated=False,
            verified_by_harness=False,
        )

    # Candidate execution begins only after trusted harness resolution succeeds.
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        test_dir = os.path.join(tmpdir, "test")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(test_dir, exist_ok=True)
        
        # Symlink pre-baked libraries in <1ms (zero copying).
        # The library root is the image-baked /opt/foundry_base/lib in the Modal
        # image; FOUNDRY_BASE_LIB_DIR allows a local, non-Linux toolchain to
        # point at the same pre-baked libraries.
        base_lib = os.environ.get("FOUNDRY_BASE_LIB_DIR", "/opt/foundry_base/lib")
        target_lib = os.path.join(tmpdir, "lib")
        if os.path.exists(base_lib):
            try:
                os.symlink(base_lib, target_lib)
            except Exception:
                shutil.copytree(base_lib, target_lib)
        
        # Write foundry.toml
        with open(os.path.join(tmpdir, "foundry.toml"), "w", encoding="utf-8") as f:
            f.write(FOUNDRY_TOML_CONTENT)
            
        # Write target contract into both src/ and test/ so that both:
        # 1. import {Target} from "../src/Target.sol" (src-relative)
        # 2. import {Target} from "./Target.sol" (test-relative)
        # resolve seamlessly across all repository harnesses and candidate exploits.
        target_src_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_src_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        target_test_path = os.path.join(test_dir, f"{target.name}.sol")
        with open(target_test_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        # Write only the repository-owned harness loaded from the immutable Modal image.
        harness_path = os.path.join(test_dir, f"{target.name}Harness.t.sol")
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(trusted_harness_source)
                
        # Write candidate ExploitModule (strictly sanitized filename to prevent path traversal)
        safe_filename = "ExploitModule.sol"
        with open(os.path.join(test_dir, safe_filename), "w", encoding="utf-8") as f:
            f.write(payload.test_code)
        with open(os.path.join(src_dir, safe_filename), "w", encoding="utf-8") as f:
            f.write(payload.test_code)
            
        env = os.environ.copy()
        env["PATH"] = f"/root/.foundry/bin:{env.get('PATH', '')}"
        
        try:
            # Run offline with JSON output and maximum trace detail (-vvvv)
            cmd = ["forge", "test", "--offline", "--json", "-vvvv"]
            proc = run_subprocess_capped(
                cmd,
                cwd=tmpdir,
                timeout=config.SANDBOX_TIMEOUT_SEC,
                env=env,
            )
            elapsed = time.time() - start_time
            raw_stdout, raw_stderr = proc.stdout, proc.stderr
            output_text = raw_stdout + "\\n" + raw_stderr

            # Byte-exact evidence streams (Iteration 14 P0.2). The digests of the
            # evidence chain describe these bytes, never a re-encoded string.
            import base64
            import hashlib as _hashlib
            stdout_bytes = proc.stdout_bytes
            stderr_bytes = proc.stderr_bytes

            # Observed toolchain facts of THIS execution (Iteration 14 P0.3).
            observed_environment = observe_execution_environment(
                argv=cmd,
                working_directory=tmpdir,
                env=env,
                observed_exit_code=proc.returncode if proc.returncode is not None else -1,
            )

            if proc.timed_out:
                return ExecutionResult(
                    return_code=proc.returncode,
                    stdout=raw_stdout,
                    stderr=raw_stderr,
                    execution_time_sec=elapsed,
                    category=ResultCategory.RUNTIME_REVERT,
                    timed_out=True,
                    invariant_violated=False,
                    verified_by_harness=False,
                    observed_environment=observed_environment,
                    stdout_sha256=_hashlib.sha256(stdout_bytes).hexdigest(),
                    stderr_sha256=_hashlib.sha256(stderr_bytes).hexdigest(),
                    stdout_byte_length=len(stdout_bytes),
                    stderr_byte_length=len(stderr_bytes),
                    stdout_bytes_b64=base64.b64encode(stdout_bytes).decode("ascii"),
                    stderr_bytes_b64=base64.b64encode(stderr_bytes).decode("ascii"),
                )

            structured_json, test_status, revert_reason, decoded_logs = parse_forge_output(raw_stdout)

            # ------------------------------------------------------------------
            # TRUSTED EVIDENCE (Reward Specification 2.0.0)
            # ------------------------------------------------------------------
            # The verdict is taken from the STRUCTURED result of the immutable,
            # repository-owned harness suite. Log text is model-controllable and
            # is therefore never used to decide whether an exploit succeeded -
            # `decoded_logs` is kept for diagnostics only.
            harness_verdict, harness_suite, verdict_status, verdict_reason, harness_addr, trusted_raw_logs = extract_trusted_harness_evidence(
                structured_json, target.name
            )

            # Fail-closed on an inconsistent trusted verdict: a breach that is not
            # backed by a clean forge run cannot be trusted.
            if harness_verdict == HARNESS_VERDICT_BREACH and proc.returncode != 0:
                harness_verdict = HARNESS_VERDICT_UNKNOWN
            if (
                harness_verdict == HARNESS_VERDICT_BREACH
                and verdict_status is not None
                and test_status is not None
                and verdict_status != test_status
            ):
                harness_verdict = HARNESS_VERDICT_UNKNOWN

            # The trusted status/reason supersede the global forge parse whenever
            # the trusted suite produced a result of its own.
            effective_test_status = verdict_status if verdict_status is not None else test_status
            effective_revert_reason = verdict_reason if verdict_reason is not None else revert_reason

            # Secondary Oracle evidence is captured for auditability, but does not
            # replace the MiniMax trusted-harness verdict or independently award reward.
            oracle_verification = None
            if harness_verdict == HARNESS_VERDICT_BREACH:
                try:
                    from core.evm_oracle import trusted_oracle
                    oracle_verification = trusted_oracle.verify_execution(
                        target=target,
                        candidate_id=payload.candidate_id or "unknown",
                        return_code=proc.returncode,
                        test_status=effective_test_status,
                        decoded_logs=decoded_logs,
                        stdout_text=raw_stdout,
                        stderr_text=raw_stderr,
                        execution_time_sec=elapsed,
                        revert_reason=effective_revert_reason,
                        cheatcode_detected=False,
                        structured_json=None,
                        raw_logs=trusted_raw_logs,
                        trusted_harness_address=harness_addr,
                    )
                except Exception as oracle_exc:
                    # The authoritative harness result remains intact; preserve a
                    # machine-readable shadow-check failure rather than masking it.
                    from core.schemas import VerificationResult
                    oracle_verification = VerificationResult(
                        execution_success=(proc.returncode == 0 and effective_test_status == "Success"),
                        invariant_breach=False,
                        confidence_status="UNVERIFIED",
                        failure_reason=f"Secondary Oracle diagnostic failed: {type(oracle_exc).__name__}: {oracle_exc}",
                    )

            inv_violated = harness_verdict == HARNESS_VERDICT_BREACH

            # Classify outcome category
            if inv_violated:
                category = ResultCategory.EXPLOIT_CONFIRMED
            elif harness_verdict == HARNESS_VERDICT_NO_BREACH:
                category = ResultCategory.SAFE_RUN
            elif harness_verdict == HARNESS_VERDICT_EXEC_REVERT:
                category = ResultCategory.RUNTIME_REVERT
            elif "Compiler run failed" in output_text or "ParserError" in output_text or "Error (" in output_text:
                category = ResultCategory.COMPILATION_ERROR
            else:
                # Missing trusted harness evidence is an infrastructure error, not SAFE_RUN.
                category = ResultCategory.INFRA_ERROR

            return ExecutionResult(
                return_code=proc.returncode,
                stdout=raw_stdout,
                stderr=raw_stderr,
                execution_time_sec=elapsed,
                category=category,
                timed_out=False,
                invariant_violated=inv_violated,
                structured_json=structured_json,
                test_status=effective_test_status,
                revert_reason=effective_revert_reason,
                decoded_logs=decoded_logs,
                cheatcode_detected=False,
                verified_by_harness=harness_verdict in (
                    HARNESS_VERDICT_BREACH,
                    HARNESS_VERDICT_NO_BREACH,
                    HARNESS_VERDICT_EXEC_REVERT,
                ),
                reproducibility_confirmed=False,
                harness_verdict=harness_verdict,
                harness_suite=harness_suite,
                evidence_source=(
                    "trusted_harness_structured_result" if harness_suite else "none"
                ),
                evidence=oracle_verification.evidence if oracle_verification else None,
                invariant_results=oracle_verification.invariant_results if oracle_verification else [],
                verification_result=oracle_verification,
                observed_environment=observed_environment,
                stdout_sha256=_hashlib.sha256(stdout_bytes).hexdigest(),
                stderr_sha256=_hashlib.sha256(stderr_bytes).hexdigest(),
                stdout_byte_length=len(stdout_bytes),
                stderr_byte_length=len(stderr_bytes),
                stdout_bytes_b64=base64.b64encode(stdout_bytes).decode("ascii"),
                stderr_bytes_b64=base64.b64encode(stderr_bytes).decode("ascii"),
            )
            
        except FileNotFoundError as fnf:
            # forge command not found in environment -> INFRA_ERROR
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-5,
                stdout="",
                stderr=f"INFRA_ERROR: Foundry executable not found: {fnf}",
                execution_time_sec=elapsed,
                category=ResultCategory.INFRA_ERROR,
                timed_out=False,
                invariant_violated=False
            )
        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-1,
                stdout=e.stdout if isinstance(e.stdout, str) else "",
                stderr=e.stderr if isinstance(e.stderr, str) else "",
                execution_time_sec=elapsed,
                category=ResultCategory.RUNTIME_REVERT,
                timed_out=True,
                invariant_violated=False
            )
        except Exception as ex:
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-2,
                stdout="",
                stderr=f"INFRA_ERROR: Unexpected sandbox execution exception: {ex}",
                execution_time_sec=elapsed,
                category=ResultCategory.INFRA_ERROR,
                timed_out=False,
                invariant_violated=False
            )


def verify_independent_replay_result(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """
    Executes an independent second run in a completely fresh ephemeral EVM container.

    The returned result carries its OWN trusted harness verdict, so the replay
    evidence is genuinely independent of the first run and can be credited as a
    separate reward component (no double counting).
    """
    return run_payload_in_sandbox(target, payload)


def verify_independent_replay(target: TargetProgram, payload: ExploitPayload) -> bool:
    """
    Checks whether a second independent run reproduces the trusted harness breach.

    The replay is only accepted when the TRUSTED harness verdict of the second,
    independent execution is a breach. Log text is never consulted.
    """
    replay_result = verify_independent_replay_result(target, payload)
    return (
        replay_result.harness_verdict == HARNESS_VERDICT_BREACH
        and replay_result.invariant_violated
        and replay_result.return_code == 0
        and not replay_result.cheatcode_detected
        and replay_result.category == ResultCategory.EXPLOIT_CONFIRMED
    )
