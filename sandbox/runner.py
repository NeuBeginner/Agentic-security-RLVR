import os
import json
import re
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
    """
    Extracts the verdict of the immutable harness suite from forge's structured
    output.

    Only suites that belong to the repository-owned harness file are inspected.
    A suite injected by the candidate (for example `test/ExploitModule.sol`)
    can therefore never produce a verdict.

    The verdict is derived from forge's structured test STATUS and REASON:
      * status == "Success"                     -> BREACH
        (harness contract: the test returns normally only on the breach path)
      * status == "Failure" and the reason is the harness' own EXPLOIT_FAILED
        rejection                                       -> NO_BREACH
      * status == "Failure" with any other reason      -> EXEC_REVERT
      * anything else / missing suite                   -> UNKNOWN (fail-closed)

    Returns: (verdict, suite_path, status, reason)
    """
    verdict = HARNESS_VERDICT_UNKNOWN
    suite_path = ""
    status = None
    reason = None

    if not isinstance(structured_data, dict):
        return verdict, suite_path, status, reason

    prefix = trusted_harness_suite_prefix(target_name)

    for suite_key, suite_val in structured_data.items():
        if not isinstance(suite_val, dict):
            continue

        path = str(suite_key).split(":")[0].replace("\\", "/").strip()
        if not path.startswith(prefix):
            continue
        # Defensive: never accept a suite that carries the candidate's filename.
        if "ExploitModule" in path:
            continue

        test_results = suite_val.get("test_results", {})
        if not isinstance(test_results, dict):
            continue

        for test_sig, test_info in test_results.items():
            if not isinstance(test_info, dict):
                continue
            if HARNESS_TEST_NAME not in str(test_sig):
                continue
            suite_path = path
            status = test_info.get("status")
            reason = test_info.get("reason")
            break

        if suite_path:
            break

    if suite_path and status == "Success":
        verdict = HARNESS_VERDICT_BREACH
    elif suite_path and status == "Failure":
        if reason and str(reason).startswith(HARNESS_NO_BREACH_REASON_PREFIX):
            verdict = HARNESS_VERDICT_NO_BREACH
        else:
            verdict = HARNESS_VERDICT_EXEC_REVERT

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
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir, exist_ok=True)
        
        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        json_out = os.path.join(tmpdir, "slither.json")
        cmd = ["slither", target_path, "--json", json_out, "--solc-solcs-select", config.SOLC_VERSION]
        
        try:
            subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True, timeout=30)
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

    # Pre-execution check 2: Block any exploit attempting to hijack Foundry cheatcodes
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
            verified_by_harness=False
        )
    
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
            
        # Write trusted invariant test harness: test/{target.name}Harness.t.sol
        if target.trusted_harness_code:
            harness_path = os.path.join(test_dir, f"{target.name}Harness.t.sol")
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(target.trusted_harness_code)
                
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
            proc = subprocess.run(
                cmd,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=config.SANDBOX_TIMEOUT_SEC,
                env=env,
            )
            elapsed = time.time() - start_time
            
            output_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
            
            # Parse structured JSON output
            structured_json, test_status, revert_reason, decoded_logs = parse_forge_output(proc.stdout or "")

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

            inv_violated = harness_verdict == HARNESS_VERDICT_BREACH

            # Classify outcome category
            if inv_violated:
                category = ResultCategory.EXPLOIT_CONFIRMED
            elif harness_verdict in (HARNESS_VERDICT_NO_BREACH, HARNESS_VERDICT_EXEC_REVERT):
                category = ResultCategory.RUNTIME_REVERT
            elif proc.returncode == 0:
                category = ResultCategory.SAFE_RUN
            elif "Compiler run failed" in output_text or "ParserError" in output_text or "Error (" in output_text:
                category = ResultCategory.COMPILATION_ERROR
            elif effective_revert_reason is not None or "EVM Runtime Revert" in output_text:
                category = ResultCategory.RUNTIME_REVERT
            else:
                # If forge failed without compiler or test output, it's an infrastructure fault
                category = ResultCategory.INFRA_ERROR

            return ExecutionResult(
                return_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
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
    Confirms 100% deterministic reproducibility before awarding full RLVR reward.

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
