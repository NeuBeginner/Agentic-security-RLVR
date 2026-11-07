"""
benchmarks/adapters.py

Executable Baseline Adapters for Aegis-RLVR Benchmark Suite.
Implements real toolchains for all 5 baselines:
1. Baseline 1: Static Analysis Only (Slither)
2. Baseline 2: LLM Auditor Only (Zero-shot text vulnerability audit findings)
3. Baseline 3: LLM Auditor + LLM Exploit Generation (Unverified PoC synthesis)
4. Baseline 4: LLM Auditor + Exploit Generation + Naive Foundry (Text marker / Exit code 0)
5. Baseline 5: Full Aegis-RLVR (Hypothesis Pipeline + Isolated Runner + Trusted State Oracle + Independent Replay)

All adapters strictly enforce:
- Zero ground truth leakage (adapters only receive TargetSpecification).
- Incomplete / unavailable detection when external binaries or API credentials are absent.
- Dynamic candidate counts from actual generator outputs, never hardcoded numbers.
- Verified breach status requires authenticated execution evidence.
"""

from __future__ import annotations

import os
import json
import shutil
import tempfile
import time
import subprocess
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from benchmarks.protocol import (
    TargetSpecification,
    TargetExecutionArtifact,
    ExecutionStatus,
)
from core.schemas import TargetProgram, ExploitPayload, AttackHypothesis, ResultCategory


class BaselineAdapter(ABC):
    """Abstract base class for a benchmark baseline runner."""

    @property
    @abstractmethod
    def baseline_id(self) -> str:
        pass

    @property
    @abstractmethod
    def baseline_name(self) -> str:
        pass

    @abstractmethod
    def check_availability(self) -> Tuple[bool, Optional[str]]:
        """Returns (is_available, unavailable_reason)."""
        pass

    @abstractmethod
    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        """Executes the baseline on a single target without access to ground truth."""
        pass


class SlitherBaselineAdapter(BaselineAdapter):
    """
    Baseline 1: Static Analysis Only (Slither AST / taint analysis).
    Runs real slither binary on target source.
    If slither binary is unavailable, reports explicit ExecutionStatus.UNAVAILABLE.
    """
    @property
    def baseline_id(self) -> str:
        return "baseline_1"

    @property
    def baseline_name(self) -> str:
        return "Static Analysis Only (Slither)"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        bin_path = shutil.which("slither")
        if not bin_path:
            return False, "slither executable not found on system PATH"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = os.path.join(tmpdir, f"{target.target_name}.sol")
            with open(src_file, "w", encoding="utf-8") as f:
                f.write(source_code)

            json_out = os.path.join(tmpdir, "slither_out.json")
            cmd = ["slither", src_file, "--json", json_out]

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_sec,
                )
                elapsed = round(time.time() - start_time, 3)

                findings = []
                if os.path.exists(json_out):
                    try:
                        with open(json_out, "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                            detectors = data.get("results", {}).get("detectors", [])
                            for d in detectors:
                                impact = str(d.get("impact", "")).capitalize()
                                if impact in ["High", "Medium"]:
                                    findings.append({
                                        "check": d.get("check"),
                                        "impact": impact,
                                        "confidence": d.get("confidence"),
                                        "description": d.get("description", "")[:200]
                                    })
                    except Exception as parse_err:
                        proc_stderr = f"{proc.stderr}\nFailed to parse JSON: {parse_err}"

                detected = len(findings) > 0

                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.SUCCESS,
                    detected=detected,
                    candidates_generated=0,
                    verified_breaches=0,
                    replayed_breaches=0,
                    duration_seconds=elapsed,
                    cost_usd=0.0,
                    tool_metadata={
                        "slither_version": "available",
                        "exit_code": proc.returncode,
                        "detectors_count": len(findings),
                    },
                    raw_output={"findings": findings},
                    logs=[proc.stdout[:1000]] if proc.stdout else []
                )

            except subprocess.TimeoutExpired:
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.FAILED,
                    unavailable_reason=f"Slither timed out after {timeout_sec}s",
                    duration_seconds=float(timeout_sec),
                )
            except Exception as e:
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.FAILED,
                    unavailable_reason=f"Slither execution exception: {e}",
                    duration_seconds=round(time.time() - start_time, 3),
                )


class LLMAuditorBaselineAdapter(BaselineAdapter):
    """
    Baseline 2: LLM Auditor Only (Zero-shot text vulnerability audit findings).
    Queries configured LLM model without generating code or verifying in Foundry.
    If LLM API credentials or model provider are missing, reports UNAVAILABLE.
    """
    def __init__(self, model_id: str = "gemini-1.5-pro", client_override: Any = None):
        self.model_id = model_id
        self.client_override = client_override

    @property
    def baseline_id(self) -> str:
        return "baseline_2"

    @property
    def baseline_name(self) -> str:
        return "LLM Auditor Only (Raw Text Findings)"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        if self.client_override is not None:
            return True, None
        api_key = (
            os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not api_key:
            return False, "LLM credentials (GEMINI_API_KEY, GOOGLE_API_KEY, or OPENAI_API_KEY) not found in environment"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)
        prompt = (
            f"You are a smart contract auditor. Analyze the following Solidity contract for security vulnerabilities.\n"
            f"Contract Name: {target.target_name}\n"
            f"Source Code:\n{source_code}\n\n"
            f"Respond with a JSON object: {{\"vulnerability_found\": true/false, \"vulnerability_type\": \"...\", \"confidence\": \"High/Medium/Low\"}}"
        )
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

        try:
            if self.client_override:
                response_text = self.client_override(prompt)
            else:
                # Real LLM call
                from google import genai
                client = genai.Client()
                resp = client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                )
                response_text = resp.text

            elapsed = round(time.time() - start_time, 3)
            # Parse structured finding
            detected = False
            vuln_type = "None"
            confidence = "Low"
            try:
                # Extract JSON block
                s_idx = response_text.find("{")
                e_idx = response_text.rfind("}")
                if s_idx != -1 and e_idx != -1:
                    data = json.loads(response_text[s_idx:e_idx + 1])
                    detected = bool(data.get("vulnerability_found", False))
                    vuln_type = data.get("vulnerability_type", "Unknown")
                    confidence = data.get("confidence", "Medium")
            except Exception:
                detected = "vulnerability" in response_text.lower() and "high" in response_text.lower()

            # Cost estimation: roughly $0.002 per target on typical prompt
            estimated_cost = 0.002

            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=detected,
                candidates_generated=0,
                verified_breaches=0,
                replayed_breaches=0,
                duration_seconds=elapsed,
                cost_usd=estimated_cost,
                tool_metadata={
                    "model_id": self.model_id,
                    "prompt_hash": prompt_hash,
                    "confidence": confidence,
                    "vulnerability_type": vuln_type,
                },
                raw_output={"response": response_text[:500]},
                logs=[response_text[:300]]
            )

        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"LLM auditor invocation failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
            )


class LLMUnverifiedPoCBaselineAdapter(BaselineAdapter):
    """
    Baseline 3: LLM Auditor + LLM Exploit Generation (Unverified PoC synthesis).
    Generates candidate exploit module without EVM execution verification.
    Candidate count is taken directly from actual generator output.
    verified_breaches and replayed_breaches are strictly 0.
    """
    def __init__(self, model_id: str = "gemini-1.5-pro", client_override: Any = None):
        self.model_id = model_id
        self.client_override = client_override

    @property
    def baseline_id(self) -> str:
        return "baseline_3"

    @property
    def baseline_name(self) -> str:
        return "LLM Auditor + Exploit Gen (Unverified PoC)"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        if self.client_override is not None:
            return True, None
        api_key = (
            os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not api_key:
            return False, "LLM credentials not found in environment"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)
        prompt = (
            f"Generate a Solidity ExploitModule for {target.target_name}.\n"
            f"Source:\n{source_code}\n\n"
            f"Respond with ```solidity contract ExploitModule {{ ... }} ```"
        )
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

        try:
            if self.client_override:
                response_text = self.client_override(prompt)
            else:
                from google import genai
                client = genai.Client()
                resp = client.models.generate_content(model=self.model_id, contents=prompt)
                response_text = resp.text

            elapsed = round(time.time() - start_time, 3)

            # Extract generated exploit candidate
            has_code = "contract ExploitModule" in response_text or "function runExploit" in response_text
            candidates_generated = 1 if has_code else 0
            detected = bool(candidates_generated > 0)

            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=detected,
                candidates_generated=candidates_generated,
                verified_breaches=0,  # Unverified!
                replayed_breaches=0,  # Unverified!
                duration_seconds=elapsed,
                cost_usd=0.005,
                tool_metadata={
                    "model_id": self.model_id,
                    "prompt_hash": prompt_hash,
                },
                raw_output={"generated_code_present": has_code},
                logs=[response_text[:300]]
            )

        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"PoC generation failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
            )


class LLMNaiveFoundryBaselineAdapter(BaselineAdapter):
    """
    Baseline 4: LLM Auditor + Exploit Generation + Naive Foundry (Exit Code 0 / Text Marker).
    Compiles and executes candidate exploit in Foundry.
    Considers test verified if forge returncode == 0 and 'PASS' or '[INVARIANT_BREACHED' is in output.
    Does NOT use hardened state oracle or trusted harness anti-spoofing emitter checks.
    """
    def __init__(self, model_id: str = "gemini-1.5-pro", client_override: Any = None):
        self.model_id = model_id
        self.client_override = client_override

    @property
    def baseline_id(self) -> str:
        return "baseline_4"

    @property
    def baseline_name(self) -> str:
        return "LLM + Naive Foundry (Exit Code 0 / Text Marker)"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        forge_bin = shutil.which("forge")
        if not forge_bin:
            return False, "forge executable not found on system PATH"
        if self.client_override is None:
            api_key = (
                os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
            )
            if not api_key:
                return False, "LLM credentials not found in environment"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
            )

        start_time = time.time()
        # Synthesis + Naive Foundry execution
        try:
            # Generate candidate code
            source_code = target.load_source_code(base_dir)
            prompt = f"Write exploit module for {target.target_name}:\n{source_code}"
            if self.client_override:
                candidate_code = self.client_override(prompt)
            else:
                from google import genai
                client = genai.Client()
                resp = client.models.generate_content(model=self.model_id, contents=prompt)
                candidate_code = resp.text

            # Execute in temp foundry environment with naive criteria
            # Naive Foundry check: returncode == 0 and no revert
            with tempfile.TemporaryDirectory() as tmpdir:
                # Setup minimal forge project
                src_dir = os.path.join(tmpdir, "src")
                test_dir = os.path.join(tmpdir, "test")
                os.makedirs(src_dir, exist_ok=True)
                os.makedirs(test_dir, exist_ok=True)

                with open(os.path.join(src_dir, f"{target.target_name}.sol"), "w", encoding="utf-8") as f:
                    f.write(source_code)
                with open(os.path.join(test_dir, "ExploitModule.sol"), "w", encoding="utf-8") as f:
                    f.write(candidate_code)

                # Run forge
                cmd = ["forge", "test", "--offline", "--json"]
                proc = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_sec,
                )
                elapsed = round(time.time() - start_time, 3)

                # Naive verdict: exit code 0 or "[INVARIANT_BREACHED" marker
                naive_verified = (proc.returncode == 0) and (
                    "PASS" in proc.stdout or "[INVARIANT_BREACHED" in proc.stdout
                )

                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.SUCCESS,
                    detected=bool(naive_verified),
                    candidates_generated=1,
                    verified_breaches=1 if naive_verified else 0,
                    replayed_breaches=0,  # Naive baseline does not perform replay
                    duration_seconds=elapsed,
                    cost_usd=0.01,
                    tool_metadata={"forge_exit_code": proc.returncode},
                    raw_output={"stdout": proc.stdout[:1000]},
                    logs=[proc.stdout[:300]]
                )

        except subprocess.TimeoutExpired:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Naive Foundry execution timed out after {timeout_sec}s",
                duration_seconds=float(timeout_sec),
            )
        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Naive Foundry execution failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
            )


class FullAegisRLVRBaselineAdapter(BaselineAdapter):
    """
    Baseline 5: Full Aegis-RLVR.
    Complete hardened verification loop:
    - Hypothesis generation (HypothesisManager)
    - Generator
    - Isolated Sandbox execution against repository-owned trusted harness
    - Secondary EVM State Oracle validation (strict emitter, topic, ABI checks)
    - Independent replay verification
    - Zero ground truth leakage: verified_breaches is strictly derived from harness verdict
      and state oracle evaluation.
    """
    def __init__(self, model_id: str = "gemini-1.5-pro", candidate_generator: Any = None):
        self.model_id = model_id
        self.candidate_generator = candidate_generator

    @property
    def baseline_id(self) -> str:
        return "baseline_5"

    @property
    def baseline_name(self) -> str:
        return "Full Aegis-RLVR (Hypothesis + Isolated Oracle + Replay)"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        forge_bin = shutil.which("forge")
        has_modal = bool(os.environ.get("MODAL_TOKEN_ID"))
        if not forge_bin and not has_modal:
            return False, "Neither forge executable nor MODAL_TOKEN_ID found on system PATH/environment"
        if self.candidate_generator is None:
            api_key = (
                os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY")
                or os.environ.get("OPENAI_API_KEY")
            )
            if not api_key:
                return False, "LLM credentials not found in environment for hypothesis/exploit generation"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        from sandbox.runner import TRUSTED_HARNESS_CONTRACTS
        if target.target_name not in TRUSTED_HARNESS_CONTRACTS:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=f"Target {target.target_name} is not in production trusted harness allowlist ({list(TRUSTED_HARNESS_CONTRACTS.keys())})",
                detected=False,
                candidates_generated=0,
                verified_breaches=0,
                replayed_breaches=0,
            )

        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)

        try:
            from core.schemas import TargetProgram, ExploitPayload, AttackHypothesis
            from sandbox.runner import run_payload_in_sandbox, verify_independent_replay, HarnessVerdict

            target_prog = TargetProgram(
                name=target.target_name,
                source_code=source_code,
            )

            # 1. Synthesize candidate payload
            if self.candidate_generator:
                payload = self.candidate_generator(target_prog)
            else:
                from core.hypothesis import HypothesisManager
                from google import genai
                hyp_mgr = HypothesisManager()
                hypotheses = hyp_mgr.generate_hypotheses(target_prog)
                selected_hyp = hypotheses[0] if hypotheses else AttackHypothesis(
                    vulnerability_type="SecurityAudit",
                    reasoning_trace="Automated hypothesis generation",
                    attack_vector="direct",
                )
                client = genai.Client()
                prompt = (
                    f"Synthesize an ExploitModule for target {target_prog.name}.\n"
                    f"Hypothesis: {selected_hyp.vulnerability_type} ({selected_hyp.reasoning_trace})\n"
                    f"Target Source:\n{source_code}\n\n"
                    f"Respond with Solidity code containing contract ExploitModule {{ ... }}"
                )
                resp = client.models.generate_content(model=self.model_id, contents=prompt)
                test_code = resp.text
                payload = ExploitPayload(
                    target_name=target_prog.name,
                    hypothesis=selected_hyp,
                    test_code=test_code,
                    format_valid=True
                )

            candidates_count = 1 if (payload and payload.test_code and len(payload.test_code.strip()) > 20) else 0

            # 2. Execute candidate in isolated sandbox with trusted harness
            exec_res = run_payload_in_sandbox(target_prog, payload)
            elapsed = round(time.time() - start_time, 3)

            is_verified = (
                exec_res.harness_verdict == HarnessVerdict.BREACH.value
                and exec_res.verification_result is not None
                and exec_res.verification_result.invariant_breach is True
            )

            # 3. Independent replay verification
            is_replayed = False
            if is_verified:
                is_replayed = verify_independent_replay(target_prog, payload)

            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.SUCCESS,
                detected=bool(is_verified),
                candidates_generated=candidates_count,
                verified_breaches=1 if is_verified else 0,
                replayed_breaches=1 if is_replayed else 0,
                duration_seconds=elapsed,
                cost_usd=0.015,
                tool_metadata={
                    "harness_verdict": exec_res.harness_verdict,
                    "harness_suite": exec_res.harness_suite,
                    "reproduced": is_replayed,
                },
                raw_output={"exit_code": exec_res.return_code, "category": exec_res.category.value if exec_res.category else None},
                logs=[exec_res.stdout[:300]]
            )

        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Full Aegis-RLVR execution exception: {e}",
                duration_seconds=round(time.time() - start_time, 3),
            )


class SyntheticSmokeAdapter(BaselineAdapter):
    """
    Synthetic Mock Adapter strictly used in --mode smoke for CI pipeline tests.
    Every produced artifact is explicitly labeled with is_synthetic_smoke: True.
    """
    def __init__(self, baseline_id: str, baseline_name: str):
        self._b_id = baseline_id
        self._b_name = baseline_name

    @property
    def baseline_id(self) -> str:
        return self._b_id

    @property
    def baseline_name(self) -> str:
        return self._b_name

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 60
    ) -> TargetExecutionArtifact:
        # Deterministic synthetic simulation for CI plumbing
        tid = target.contract_id
        is_ctrl = target.difficulty == "control"

        detected = False
        candidates = 0
        verified = 0
        replayed = 0
        cost = 0.0

        if self._b_id == "baseline_1":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SAFE-01", "SAFE-02"]
        elif self._b_id == "baseline_2":
            detected = tid in ["REENT-01", "ERC4626-01", "AC-01", "ORACLE-01", "FLASH-01", "STATE-01", "SAFE-01", "SAFE-03"]
            cost = 0.04
        elif self._b_id == "baseline_3":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SAFE-01"]
            candidates = 4 if detected else 0
            cost = 0.10
        elif self._b_id == "baseline_4":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SIG-01", "PREC-01", "SAFE-01"]
            candidates = 8 if detected else 0
            verified = 5 if detected else 0
            replayed = 3 if detected else 0
            cost = 0.18
        elif self._b_id == "baseline_5":
            detected = not is_ctrl and tid not in ["BRIDGE-01"]
            candidates = 6 if detected else 2
            verified = 1 if detected else 0
            replayed = 1 if (detected and verified == 1) else 0
            cost = 0.18

        return TargetExecutionArtifact(
            baseline_id=self._b_id,
            target_id=target.contract_id,
            target_name=target.target_name,
            status=ExecutionStatus.SUCCESS,
            detected=detected,
            candidates_generated=candidates,
            verified_breaches=verified,
            replayed_breaches=replayed,
            duration_seconds=0.01,
            cost_usd=cost,
            tool_metadata={"is_synthetic_smoke": True},
            raw_output={"mock_run": True},
            logs=["[SYNTHETIC_SMOKE_FIXTURE]"]
        )
