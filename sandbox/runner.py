import os
import json
import shutil
import subprocess
import tempfile
import time
import modal
from core.schemas import ExploitPayload, ExecutionResult, TargetProgram
from core.config import config

SOLC_PREBAKE_CMD = (
    "python3 -c \""
    "import urllib.request, json, os; "
    "req = urllib.request.Request('https://binaries.soliditylang.org/linux-amd64/list.json', headers={'User-Agent': 'Mozilla/5.0'}); "
    "data = json.loads(urllib.request.urlopen(req, timeout=30).read()); "
    "targets = [f'0.8.{i}' for i in range(19, 29)]; "
    "print('[*] Pre-baking solc versions:', targets); "
    "for b in data.get('builds', []): "
    "    v = b.get('version'); "
    "    if v in targets: "
    "        d = f'/root/.svm/{v}'; os.makedirs(d, exist_ok=True); p = f'{d}/solc-{v}'; "
    "        if not os.path.exists(p): "
    "            url = f'https://binaries.soliditylang.org/linux-amd64/{b[\"path\"]}'; "
    "            r = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}); "
    "            with urllib.request.urlopen(r, timeout=60) as resp, open(p, 'wb') as f: f.write(resp.read()); "
    "            os.chmod(p, 0o755); print(f'[✓] solc {v} cached');"
    "\""
)

# Optimized Foundry + Solc + OpenZeppelin Execution Image for Modal
sandbox_image = (
    modal.Image.debian_slim(python_version="3.10")
    .apt_install("curl", "git", "build-essential", "ca-certificates")
    .run_commands(
        # 1. Install Foundry toolchain (forge, cast, anvil)
        "curl -sSfL https://foundry.paradigm.xyz | bash",
        "/root/.foundry/bin/foundryup",
        # 2. Pre-bake solc compilers (0.8.19 - 0.8.28) directly into ~/.svm
        SOLC_PREBAKE_CMD,
        # 3. Pre-bake standard libraries: forge-std and @openzeppelin/contracts
        "mkdir -p /opt/foundry_base/lib && cd /opt/foundry_base/lib && "
        "git clone --depth 1 https://github.com/foundry-rs/forge-std.git forge-std && "
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
    Executes a Solidity exploit using Foundry (forge test --offline --json -vvvv)
    inside an isolated Modal container.
    """
    start_time = time.time()
    
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
            
        # Write target contract: src/Target.sol
        target_path = os.path.join(src_dir, f"{target.name}.sol")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(target.source_code)
            
        # Write exploit test: test/Exploit.t.sol
        exploit_filename = payload.test_filename if payload.test_filename.endswith(".sol") else "Exploit.t.sol"
        exploit_path = os.path.join(test_dir, exploit_filename)
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
            
            # Substantive checks: prevent dummy / empty tests from gaming RLVR
            has_target_call = target.name in payload.test_code
            has_assert = (
                "assert" in payload.test_code or 
                "require" in payload.test_code or 
                "[INVARIANT_BREACHED]" in payload.test_code
            )
            
            is_exploit_success = (
                (test_status == "Success" or "[PASS]" in output_text) and
                proc.returncode == 0 and
                has_target_call and
                has_assert
            )
            
            is_explicit_log = (
                "[INVARIANT_BREACHED]" in output_text or 
                any("[INVARIANT_BREACHED]" in str(l) for l in decoded_logs)
            ) and proc.returncode == 0
            
            inv_violated = is_exploit_success or is_explicit_log
            
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
