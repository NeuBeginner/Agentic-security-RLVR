import os
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram
from core.config import config

# Define lightweight, isolated Debian environment for execution
sandbox_image = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install("pydantic>=2.0.0", "pytest")
    .add_local_python_source("core", "sandbox")
)


def run_payload_in_sandbox(target: TargetProgram, payload: ExploitPayload) -> ExecutionResult:
    """
    Executes the generated exploit against the target code inside an isolated container.
    Guarantees no state leakage between separate runs.
    """
    start_time = time.time()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        target_path = os.path.join(tmpdir, f"target_{target.name}.py")
        exploit_path = os.path.join(tmpdir, payload.test_filename)
        
        # Write target code and synthesized exploit
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        with open(exploit_path, "w", encoding="utf-8") as f:
            f.write(payload.test_code)
            
        # Execute in a subprocess with strict timeout
        try:
            cmd = ["python", exploit_path]
            proc = subprocess.run(
                cmd,
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=config.SANDBOX_TIMEOUT_SEC,
            )
            elapsed = time.time() - start_time
            
            # Check for invariant violation signals in execution output
            inv_violated = (
                "[INVARIANT_BREACHED]" in proc.stdout or 
                "[INVARIANT_BREACHED]" in proc.stderr
            )
            
            return ExecutionResult(
                return_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
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
