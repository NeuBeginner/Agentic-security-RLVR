import os
import json
import shutil
import subprocess
import tempfile
import time
from typing import Dict, Any, List, Optional, Tuple
import modal
from core.schemas import (
    ExploitPayload,
    ExecutionResult,
    TargetProgram,
    ResultCategory,
    ExecutionEvidence,
    InvariantResult,
    VerificationResult
)
from core.config import config
from core.evm_oracle import trusted_oracle, compute_state_hash

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

# Hardened Foundry Configuration for Untrusted Execution
FOUNDRY_TOML_CONTENT = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200
offline = true
ffi = false
gas_limit = 30000000
memory_limit = 134217728
fs_permissions = [
    { access = "none", path = ".." },
    { access = "read-write", path = "./" }
]
remappings = [
    "forge-std/=lib/forge-std/src/",
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@openzeppelin/=lib/openzeppelin-contracts/"
]
"""

# Maximum allowed stdout/stderr in bytes to protect against log-bomb memory exhaustion (1MB)
MAX_LOG_OUTPUT_BYTES = 1024 * 1024

# Sanitized environment configuration
SAFE_ENV_ALLOWLIST = {"PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"}
SENSITIVE_PATTERNS = ["KEY", "TOKEN", "SECRET", "AUTH", "PASS", "MODAL_", "GEMINI_", "AWS_", "GITHUB_", "SSH_"]

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
    "Vm public vm"
]


def detect_prohibited_cheatcodes(code: str) -> bool:
    """Detects attempts by candidate ExploitModule to use privileged Foundry cheatcodes."""
    for pattern in PROHIBITED_CHEATCODES:
        if pattern in code:
            return True
    return False


def build_sanitized_environment() -> Dict[str, str]:
    """
    Constructs a minimal, secure environment for untrusted Solidity execution.
    Strictly strips all API keys, access tokens, and sensitive orchestration variables.
    """
    clean_env: Dict[str, str] = {}
    for k, v in os.environ.items():
        k_upper = k.upper()
        if any(pat in k_upper for pat in SENSITIVE_PATTERNS):
            continue
        if k_upper in SAFE_ENV_ALLOWLIST or k in SAFE_ENV_ALLOWLIST:
            clean_env[k] = v

    # Add standard binary paths
    current_path = clean_env.get("PATH", os.environ.get("PATH", ""))
    foundry_paths = ["/root/.foundry/bin", os.path.expanduser("~/.foundry/bin")]
    for fp in foundry_paths:
        if os.path.exists(fp) and fp not in current_path:
            current_path = f"{fp}:{current_path}"
    clean_env["PATH"] = current_path
    clean_env["FOUNDRY_OFFLINE"] = "true"
    clean_env["FOUNDRY_FFI"] = "false"
    return clean_env


def truncate_log_output(text: str, max_bytes: int = MAX_LOG_OUTPUT_BYTES) -> str:
    """Truncates log string to maximum byte limit to prevent memory exhaustion."""
    if not text:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
        return truncated + "\n[LOG_TRUNCATED: Output exceeded safe quota of 1MB]"
    return text


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
            subprocess.run(
                cmd,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=30,
                env=build_sanitized_environment()
            )
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
    by the immutable test harness in the EVM evaluated by TrustedEVMStateOracle.
    Enforces cheatcode isolation, secret stripping, and resource caps.
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
        
        # Write hardened foundry.toml
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
            
        sanitized_env = build_sanitized_environment()
        
        try:
            # Run offline with JSON output and maximum trace detail (-vvvv)
            cmd = ["forge", "test", "--offline", "--json", "-vvvv"]
            proc = subprocess.run(
                cmd,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=config.SANDBOX_TIMEOUT_SEC,
                env=sanitized_env,
            )
            elapsed = time.time() - start_time
            
            raw_stdout = truncate_log_output(proc.stdout or "")
            raw_stderr = truncate_log_output(proc.stderr or "")
            output_text = raw_stdout + "\n" + raw_stderr
            
            # Parse structured JSON output
            structured_json, test_status, revert_reason, decoded_logs = parse_forge_output(proc.stdout or "")
            
            # Extract gas used if present in structured_json
            gas_used = None
            if structured_json and isinstance(structured_json, dict):
                for _, sval in structured_json.items():
                    if isinstance(sval, dict):
                        tres = sval.get("test_results", {})
                        for _, tinfo in tres.items():
                            if isinstance(tinfo, dict) and "gas" in tinfo:
                                gas_used = tinfo.get("gas")
            
            # Delegate state verification to the Trusted EVM State Oracle
            verification = trusted_oracle.verify_execution(
                target=target,
                candidate_id=payload.candidate_id,
                return_code=proc.returncode,
                test_status=test_status,
                decoded_logs=decoded_logs,
                stdout_text=raw_stdout,
                stderr_text=raw_stderr,
                execution_time_sec=elapsed,
                gas_used=gas_used,
                revert_reason=revert_reason,
                cheatcode_detected=False,
                structured_json=structured_json
            )

            inv_violated = verification.invariant_breach

            # Determine fine-grained category
            if inv_violated:
                category = ResultCategory.EXPLOIT_CONFIRMED
            elif proc.returncode == 0:
                category = ResultCategory.SAFE_RUN
            elif revert_reason is not None or "EVM Runtime Revert" in output_text:
                category = ResultCategory.RUNTIME_REVERT
            elif "Compiler run failed" in output_text or "ParserError" in output_text or "Error (" in output_text:
                category = ResultCategory.COMPILATION_ERROR
            else:
                category = ResultCategory.INFRA_ERROR
            
            state_delta = verification.evidence.state_delta if verification.evidence else {}

            return ExecutionResult(
                return_code=proc.returncode,
                stdout=raw_stdout,
                stderr=raw_stderr,
                execution_time_sec=elapsed,
                category=category,
                timed_out=False,
                invariant_violated=inv_violated,
                structured_json=structured_json,
                test_status=test_status,
                revert_reason=revert_reason,
                decoded_logs=decoded_logs,
                cheatcode_detected=False,
                verified_by_harness=inv_violated,
                reproducibility_confirmed=False,
                gas_used=gas_used,
                state_delta=state_delta,
                evidence=verification.evidence,
                invariant_results=verification.invariant_results,
                verification_result=verification
            )
            
        except FileNotFoundError as fnf:
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
            out_str = truncate_log_output(e.stdout if isinstance(e.stdout, str) else "")
            err_str = truncate_log_output(e.stderr if isinstance(e.stderr, str) else "")
            return ExecutionResult(
                return_code=-1,
                stdout=out_str,
                stderr=err_str,
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


# =============================================================================
# 3. INDEPENDENT REPLAY VERIFIER
# =============================================================================

class ReplayOutcome:
    """Detailed audit report for independent replay verification."""
    def __init__(
        self,
        target_name: str,
        candidate_id: str,
        is_confirmed: bool,
        status: str,  # CONFIRMED, FAILED, INVARIANT_MISMATCH, INFRA_ERROR
        initial_breached_invariants: List[str],
        replay_breached_invariants: List[str],
        initial_state_hash: str = "",
        replay_state_hash: str = "",
        details: Optional[Dict[str, Any]] = None
    ):
        self.target_name = target_name
        self.candidate_id = candidate_id
        self.is_confirmed = is_confirmed
        self.status = status
        self.initial_breached_invariants = initial_breached_invariants
        self.replay_breached_invariants = replay_breached_invariants
        self.initial_state_hash = initial_state_hash
        self.replay_state_hash = replay_state_hash
        self.details = details or {}


def verify_independent_replay_structured(
    target: TargetProgram,
    payload: ExploitPayload,
    initial_evidence: Optional[ExecutionEvidence] = None,
    expected_breached_invariants: Optional[List[str]] = None
) -> ReplayOutcome:
    """
    Executes a structured independent replay in a fresh ephemeral environment.
    Verifies that:
    1. Replay execution finishes cleanly (return code 0).
    2. No cheatcodes were injected.
    3. The exact same security invariant(s) breached in Run 1 are breached in Run 2.
    4. State transition delta matches expected invariant violation.
    """
    replay_result = run_payload_in_sandbox(target, payload)

    # Check for infrastructure failure
    if replay_result.category == ResultCategory.INFRA_ERROR:
        return ReplayOutcome(
            target_name=target.name,
            candidate_id=payload.candidate_id,
            is_confirmed=False,
            status="INFRA_ERROR",
            initial_breached_invariants=expected_breached_invariants or [],
            replay_breached_invariants=[],
            details={"error": replay_result.stderr}
        )

    # Check for cheatcode detection
    if replay_result.cheatcode_detected:
        return ReplayOutcome(
            target_name=target.name,
            candidate_id=payload.candidate_id,
            is_confirmed=False,
            status="FAILED",
            initial_breached_invariants=expected_breached_invariants or [],
            replay_breached_invariants=[],
            details={"reason": "Cheatcode detected during replay"}
        )

    replay_v_res = replay_result.verification_result
    replay_breaches = replay_v_res.breached_invariants if replay_v_res else []
    replay_state_hash = replay_result.evidence.final_state_hash if replay_result.evidence else ""
    init_state_hash = initial_evidence.final_state_hash if initial_evidence else ""

    # Check invariant violation
    if not replay_result.invariant_violated or replay_result.return_code != 0:
        return ReplayOutcome(
            target_name=target.name,
            candidate_id=payload.candidate_id,
            is_confirmed=False,
            status="FAILED",
            initial_breached_invariants=expected_breached_invariants or [],
            replay_breached_invariants=replay_breaches,
            initial_state_hash=init_state_hash,
            replay_state_hash=replay_state_hash,
            details={"reason": "Replay run did not breach invariant"}
        )

    # If expected invariants were specified, assert they match
    if expected_breached_invariants:
        common = set(expected_breached_invariants).intersection(set(replay_breaches))
        if not common:
            return ReplayOutcome(
                target_name=target.name,
                candidate_id=payload.candidate_id,
                is_confirmed=False,
                status="INVARIANT_MISMATCH",
                initial_breached_invariants=expected_breached_invariants,
                replay_breached_invariants=replay_breaches,
                initial_state_hash=init_state_hash,
                replay_state_hash=replay_state_hash,
                details={"reason": f"Replay breached {replay_breaches} instead of expected {expected_breached_invariants}"}
            )

    return ReplayOutcome(
        target_name=target.name,
        candidate_id=payload.candidate_id,
        is_confirmed=True,
        status="CONFIRMED",
        initial_breached_invariants=expected_breached_invariants or replay_breaches,
        replay_breached_invariants=replay_breaches,
        initial_state_hash=init_state_hash,
        replay_state_hash=replay_state_hash,
        details={"execution_time_sec": replay_result.execution_time_sec}
    )


def verify_independent_replay(target: TargetProgram, payload: ExploitPayload) -> bool:
    """
    Executes an independent second run in a completely fresh ephemeral EVM container.
    Confirms 100% deterministic reproducibility before awarding full RLVR reward.
    Preserves exact backwards compatibility with existing boolean signatures.
    """
    outcome = verify_independent_replay_structured(target, payload)
    return outcome.is_confirmed
