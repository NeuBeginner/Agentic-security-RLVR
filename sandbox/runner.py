import os
import json
import re
import signal
import threading
import shutil
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram, ResultCategory
from core.config import config
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
    .add_local_dir(LOCAL_TRUSTED_HARNESSES_DIR, remote_path=TRUSTED_HARNESSES_DIR, copy=False)
    .add_local_python_source("core", "sandbox")
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

    root = os.path.realpath(harness_dir or TRUSTED_HARNESSES_DIR)
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

    return CappedProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=decode("stdout"),
        stderr=decode("stderr"),
        timed_out=timed_out,
    )



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


def extract_trusted_harness_verdict(
    structured_data,
    target_name: str
):
    """Read exactly one immutable repository harness and exact testExploit() result."""
    if (
        not is_safe_target_name(target_name)
        or target_name not in TRUSTED_HARNESS_CONTRACTS
        or not isinstance(structured_data, dict)
    ):
        return HARNESS_VERDICT_UNKNOWN, "", None, None

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
                matches.append((path, test_info.get("status"), test_info.get("reason")))

    if len(matches) != 1:
        return HARNESS_VERDICT_UNKNOWN, "", None, None

    suite_path, status, reason = matches[0]
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


def run_slither_analysis(target: TargetProgram) -> list:
    """
    Executes Slither AST / taint analysis on the target contract.
    Returns structured list of static vulnerability warnings to prime reasoning models.
    """
    if not is_safe_target_name(target.name):
        return []
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir, exist_ok=True)
        
        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        json_out = os.path.join(tmpdir, "slither.json")
        cmd = ["slither", target_path, "--json", json_out, "--solc-solcs-select", config.SOLC_VERSION]
        
        try:
            run_subprocess_capped(cmd, cwd=tmpdir, env=os.environ.copy(), timeout=30)
            if os.path.exists(json_out):
                with open(json_out, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                    results = data.get("results", {}).get("detectors", [])
                    extracted = []
                    for det in results[:5]:  # Top 5 most critical detectors
                        extracted.append({
                            "check": det.get("check"),
                            "impact": det.get("impact"),
                            "confidence": det.get("confidence"),
                            "description": det.get("description", "")[:200]
                        })
                    return extracted
        except Exception:
            pass
            
    # Fallback AST heuristic detection if Slither binary is offline
    fallback_detectors = []
    src_lower = target.source_code.lower()
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
        
        # Symlink pre-baked libraries in <1ms (zero copying)
        base_lib = "/opt/foundry_base/lib"
        target_lib = os.path.join(tmpdir, "lib")
        if os.path.exists(base_lib):
            try:
                os.symlink(base_lib, target_lib)
            except Exception:
                shutil.copytree(base_lib, target_lib)
        
        # Write foundry.toml
        with open(os.path.join(tmpdir, "foundry.toml"), "w", encoding="utf-8") as f:
            f.write(FOUNDRY_TOML_CONTENT)
            
        # Write target contract: src/{target.name}.sol
        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
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
                )

            structured_json, test_status, revert_reason, decoded_logs = parse_forge_output(raw_stdout)

            # ------------------------------------------------------------------
            # TRUSTED EVIDENCE (Reward Specification 2.0.0)
            # ------------------------------------------------------------------
            # The verdict is taken from the STRUCTURED result of the immutable,
            # repository-owned harness suite. Log text is model-controllable and
            # is therefore never used to decide whether an exploit succeeded -
            # `decoded_logs` is kept for diagnostics only.
            harness_verdict, harness_suite, verdict_status, verdict_reason = extract_trusted_harness_verdict(
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
                        structured_json=structured_json,
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
