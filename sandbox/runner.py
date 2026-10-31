import os
import json
import shutil
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram
from core.config import config
from sandbox.harness_registry import get_trusted_harness

# Pinned Foundry Release & Checksum (Point 3)
FOUNDRY_VERSION = "v1.8.7"
FOUNDRY_TARBALL_URL = f"https://github.com/foundry-rs/foundry/releases/download/{FOUNDRY_VERSION}/foundry_{FOUNDRY_VERSION}_linux_amd64.tar.gz"
FOUNDRY_SHA256 = "ba470eb718e779e4b0e3f1520b5284231b1bf98e9a39de07fb8f77ed70525bcf"

PREBAKE_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prebake_solc.py")

# Fully pinned, reproducible Foundry + Solc + OpenZeppelin Execution Image
sandbox_image = (
    modal.Image.debian_slim(python_version="3.10")
    .apt_install("curl", "git", "build-essential", "ca-certificates")
    # Copy verified solc prebake script into image
    .add_local_file(PREBAKE_SCRIPT_PATH, "/opt/prebake_solc.py", copy=True)
    .run_commands(
        # 1. Download and verify PINNED Foundry release v1.8.7 with SHA256 validation (Point 3)
        f"curl -sSfL '{FOUNDRY_TARBALL_URL}' -o /tmp/foundry.tar.gz",
        f"echo '{FOUNDRY_SHA256}  /tmp/foundry.tar.gz' | sha256sum -c -",
        "mkdir -p /root/.foundry/bin && tar -xzf /tmp/foundry.tar.gz -C /root/.foundry/bin && rm /tmp/foundry.tar.gz",
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


def run_payload_in_sandbox(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """
    Executes an exploit module against a trusted verification harness in Foundry.
    MANDATORY: Harness code is resolved strictly on the worker side from harness_registry.
    Arbitrary targets without registered harnesses are rejected immediately (Point 1).
    """
    start_time = time.time()
    
    # 1. Strict Worker-Side Resolution of Immutable Harness (Point 1)
    try:
        trusted_harness_code = get_trusted_harness(target.name)
    except ValueError as err:
        return ExecutionResult(
            return_code=-3,
            stdout="",
            stderr=str(err),
            execution_time_sec=0.0,
            timed_out=False,
            invariant_violated=False
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
            
        # Write mandatory immutable harness: test/{target.name}TrustedHarness.t.sol
        harness_path = os.path.join(test_dir, f"{target.name}TrustedHarness.t.sol")
        with open(harness_path, "w", encoding="utf-8") as f:
            f.write(trusted_harness_code)
                
        # Write candidate ExploitModule (strictly sanitized filename to prevent path traversal)
        safe_filename = "ExploitModule.sol"
        exploit_path = os.path.join(test_dir, safe_filename)
        with open(exploit_path, "w", encoding="utf-8") as f:
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
            
            # Rigorous Invariant Verification:
            # The trusted harness alone emits [INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]
            # upon detecting physical state insolvency in the EVM.
            has_breach_signal = (
                "[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in output_text or
                any("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]" in str(l) for l in decoded_logs)
            )
            
            # Test must pass (asserting breach) with zero return code
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
                decoded_logs=decoded_logs
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
