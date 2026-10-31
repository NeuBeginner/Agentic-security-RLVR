import os
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram
from core.config import config

# Official Foundry + Slither execution image for Modal
sandbox_image = (
    modal.Image.debian_slim(python_version="3.10")
    .apt_install("curl", "git", "build-essential")
    .run_commands(
        "curl -L https://foundry.paradigm.xyz | bash",
        "/root/.foundry/bin/foundryup",
    )
    .env({"PATH": "/root/.foundry/bin:$PATH"})
    .pip_install("pydantic>=2.0.0", "slither-analyzer")
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
fs_permissions = [{ access = "read-write", path = "./" }]
"""


def run_payload_in_sandbox(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """
    Executes a Solidity exploit using Foundry (forge test) inside an isolated Modal container.
    Physical proof of vulnerability execution in a real EVM.
    """
    start_time = time.time()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        test_dir = os.path.join(tmpdir, "test")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(test_dir, exist_ok=True)
        
        # Write foundry.toml
        with open(os.path.join(tmpdir, "foundry.toml"), "w", encoding="utf-8") as f:
            f.write(FOUNDRY_TOML_CONTENT)
            
        # Write target contract: src/Target.sol
        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        # Write exploit test: test/Exploit.t.sol
        exploit_filename = payload.test_filename if payload.test_filename.endswith(".sol") else "Exploit.t.sol"
        exploit_path = os.path.join(test_dir, exploit_filename)
        with open(exploit_path, "w", encoding="utf-8") as f:
            f.write(payload.test_code)
            
        try:
            # Run Foundry test with verbose tracing
            cmd = ["forge", "test", "-vvv"]
            proc = subprocess.run(
                cmd,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=config.SANDBOX_TIMEOUT_SEC,
            )
            elapsed = time.time() - start_time
            
            # Foundry outputs "[PASS]" when a test succeeds
            output_text = (proc.stdout or "") + (proc.stderr or "")
            
            # An exploit is verified if testExploit passes in Foundry
            inv_violated = (
                "[PASS]" in output_text and 
                "testExploit" in output_text and
                proc.returncode == 0
            ) or ("[INVARIANT_BREACHED]" in output_text)
            
            return ExecutionResult(
                return_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                execution_time_sec=elapsed,
                timed_out=False,
                invariant_violated=inv_violated
            )
            
        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            return ExecutionResult(
                return_code=-1,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=e.stderr or "" if isinstance(e.stderr, str) else "",
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
