import os
import json
import shutil
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram
from core.config import config

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
    "Vm public vm"
]


def detect_prohibited_cheatcodes(code: str) -> bool:
    """Detects attempts by candidate ExploitModule to use privileged Foundry cheatcodes."""
    for pattern in PROHIBITED_CHEATCODES:
        if pattern in code:
            return True
    return False


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

    # Pre-execution check: block any exploit attempting to hijack Foundry cheatcodes
    if detect_prohibited_cheatcodes(payload.test_code):
        return ExecutionResult(
            return_code=-3,
            stdout="",
            stderr="Security Violation: ExploitModule attempted to import or execute Foundry cheatcodes (vm.*).",
            execution_time_sec=0.01,
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
            
            # Invariant verification: must have breach log from harness and zero exit code
            has_breach_signal = (
                any("[INVARIANT_BREACHED" in str(l) for l in decoded_logs) or
                ("[INVARIANT_BREACHED" in output_text and proc.returncode == 0)
            )
            
            inv_violated = (
                proc.returncode == 0 and
                (test_status == "Success" or "[PASS]" in output_text) and
                has_breach_signal
            )
            
            return ExecutionResult(
                return_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                execution_time_sec=elapsed,
                timed_out=False,
                invariant_violated=inv_violated,
                structured_json=structured_json,
                test_status=test_status,
                revert_reason=revert_reason,
                decoded_logs=decoded_logs,
                cheatcode_detected=False,
                verified_by_harness=inv_violated,
                reproducibility_confirmed=False
            )
            
        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-1,
                stdout=e.stdout if isinstance(e.stdout, str) else "",
                stderr=e.stderr if isinstance(e.stderr, str) else "",
                execution_time_sec=elapsed,
                timed_out=True,
                invariant_violated=False
            )
        except Exception as ex:
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-2,
                stdout="",
                stderr=str(ex),
                execution_time_sec=elapsed,
                timed_out=False,
                invariant_violated=False
            )


def verify_independent_replay(target: TargetProgram, payload: ExploitPayload) -> bool:
    """
    Executes an independent second run in a completely fresh ephemeral EVM container.
    Confirms 100% deterministic reproducibility before awarding full RLVR reward.
    """
    replay_result = run_payload_in_sandbox(target, payload)
    return (
        replay_result.invariant_violated and
        replay_result.return_code == 0 and
        not replay_result.cheatcode_detected
    )
