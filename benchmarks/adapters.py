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
- Zero ground truth leakage (adapters only receive public TargetSpecification).
- Incomplete / unavailable detection when external binaries or API credentials are absent.
- Explicit provider routing: checks and invokes only credentials matching the configured provider.
- Full output preservation (complete stdout/stderr, actual versions, exit codes, config hashes).
- Dynamic candidate counts from actual generator outputs, never hardcoded numbers.
- Verified breach status requires authenticated EVM execution evidence.
- No hardcoded cost estimates: unmeasured runs report cost_usd as None.
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
from contextlib import contextmanager

_MODAL_APP_RUNNING = False


class ModalAppContext:
    """
    Context manager that ensures an active Modal app context exists when invoking
    remote Modal functions from standalone Python scripts or runner entrypoints.
    Handles sequential invocations and nested context entry without stale app_id collisions.
    Fails safely as a no-op when running without Modal credentials (e.g. CI runners).
    Class-based implementation eliminates generator throw-yield protocol collisions.
    """

    def __init__(self):
        self._owned = False
        self._ctx = None

    def __enter__(self):
        global _MODAL_APP_RUNNING
        self._owned = False
        self._ctx = None
        if _MODAL_APP_RUNNING or os.environ.get("MODAL_TASK_ID"):
            return self
        try:
            import modal
            token_id = os.environ.get("MODAL_TOKEN_ID")
            if not token_id:
                try:
                    token_id = modal.config.config.get("token_id")
                except Exception:
                    token_id = None
            if not token_id:
                return self

            from modal_app import app
            self._ctx = app.run()
            self._ctx.__enter__()
            _MODAL_APP_RUNNING = True
            self._owned = True
        except Exception:
            self._ctx = None
            self._owned = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        global _MODAL_APP_RUNNING
        if self._owned and self._ctx is not None:
            try:
                self._ctx.__exit__(exc_type, exc_val, exc_tb)
            finally:
                _MODAL_APP_RUNNING = False
        return False


def ensure_modal_app_context() -> ModalAppContext:
    return ModalAppContext()

from benchmarks.protocol import (
    TargetSpecification,
    TargetExecutionArtifact,
    ExecutionStatus,
)


def check_llm_provider_availability(provider: str) -> Tuple[bool, Optional[str]]:
    """Validates presence of API credentials for the requested provider."""
    prov = provider.lower()
    if prov in ("gemini", "google"):
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            return False, f"Gemini API credentials (GEMINI_API_KEY or GOOGLE_API_KEY) not found for provider '{provider}'"
        return True, None
    elif prov == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            return False, f"OpenAI API credentials (OPENAI_API_KEY) not found for provider '{provider}'"
        return True, None
    else:
        return False, f"Unsupported LLM provider '{provider}'. Supported providers: 'gemini', 'openai'"


def invoke_llm_provider(provider: str, model_id: str, prompt: str) -> str:
    """Invokes configured LLM provider directly."""
    prov = provider.lower()
    if prov in ("gemini", "google"):
        from google import genai
        client = genai.Client()
        resp = client.models.generate_content(model=model_id, contents=prompt)
        return resp.text or ""
    elif prov == "openai":
        from openai import OpenAI
        client = OpenAI()
        resp = client.chat.completions.create(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""
    else:
        raise ValueError(f"Unsupported LLM provider: '{provider}'")


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

    @property
    def timeout_sec(self) -> int:
        return getattr(self, "_timeout_sec", 60)

    @property
    def resource_budget(self) -> Dict[str, Any]:
        return getattr(self, "_resource_budget", {"timeout_sec": self.timeout_sec})

    def get_effective_config_hash(self) -> str:
        """Returns deterministic SHA-256 hash of effective adapter configuration."""
        data = {
            "baseline_id": self.baseline_id,
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> Optional[List[str]]:
        """Returns structured default invocation command line tokens, or None if not subprocess-based."""
        return None

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
    Runs real slither binary on target source in project context with remappings.
    Captures complete stdout/stderr, actual binary version, and exit codes.
    Reports FAILED/INCOMPLETE if execution fails or output is unparseable.
    """
    def __init__(
        self,
        timeout_sec: int = 60,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {
            "timeout_sec": timeout_sec,
            "compiler_context": "@openzeppelin/=lib/openzeppelin-contracts/ forge-std/=lib/forge-std/src/",
        }

    @property
    def baseline_id(self) -> str:
        return "baseline_1"

    @property
    def baseline_name(self) -> str:
        return "Static Analysis Only (Slither)"

    def get_effective_config_hash(self) -> str:
        data = {
            "baseline_id": self.baseline_id,
            "slither_version": self.get_slither_version(),
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "solc_remaps": [
                "@openzeppelin/=lib/openzeppelin-contracts/",
                "forge-std/=lib/forge-std/src/",
            ],
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> List[str]:
        return [
            "slither",
            "<target_path>",
            "--json",
            "slither_out.json",
            "--solc-remaps",
            "@openzeppelin/=lib/openzeppelin-contracts/ forge-std/=lib/forge-std/src/",
        ]

    def get_slither_version(self) -> str:
        try:
            res = subprocess.run(
                ["slither", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return res.stdout.strip() or res.stderr.strip() or "unknown"
        except Exception:
            return "unknown"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        bin_path = shutil.which("slither")
        if not bin_path:
            return False, "slither executable not found on system PATH"
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: Optional[int] = None
    ) -> TargetExecutionArtifact:
        effective_timeout = timeout_sec if timeout_sec is not None else self.timeout_sec
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        start_time = time.time()
        slither_ver = self.get_slither_version()

        # Resolve target source file path
        target_path = Path(target.source_file)
        if not target_path.is_absolute() and base_dir:
            target_path = base_dir / target_path

        if not target_path.exists():
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Target source file {target_path} not found",
                duration_seconds=0.0,
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = os.path.join(tmpdir, "slither_out.json")
            cmd = [
                "slither",
                str(target_path),
                "--json",
                json_out,
                "--solc-remaps",
                "@openzeppelin/=lib/openzeppelin-contracts/ forge-std/=lib/forge-std/src/"
            ]

            cwd = str(base_dir) if base_dir and base_dir.exists() else None

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=effective_timeout,
                )
                elapsed = round(time.time() - start_time, 3)

                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
                stdout_sha256 = hashlib.sha256(stdout_text.encode("utf-8")).hexdigest()
                stderr_sha256 = hashlib.sha256(stderr_text.encode("utf-8")).hexdigest()

                base_tool_metadata = {
                    "slither_version": slither_ver,
                    "exit_code": proc.returncode,
                    "command": " ".join(cmd),
                    "argv": list(cmd),
                    "timeout_sec": effective_timeout,
                    "resource_budget": dict(self.resource_budget),
                    "compiler_context": "@openzeppelin/=lib/openzeppelin-contracts/ forge-std/=lib/forge-std/src/",
                    "project_context_cwd": cwd,
                    "stdout_sha256": stdout_sha256,
                    "stderr_sha256": stderr_sha256,
                    "effective_config_hash": self.get_effective_config_hash(),
                }

                # P0 REQUIREMENT: Non-zero exit code MUST be classified as FAILED.
                # The presence of valid JSON from partial execution must NEVER turn a non-zero exit into SUCCESS.
                if proc.returncode != 0:
                    err_msg = stderr_text.strip() or stdout_text.strip() or "Unknown non-zero exit"
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason=f"Slither failed (exit code {proc.returncode}): {err_msg[:300]}",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [stdout_text[:1000]],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                # Returncode is 0: verify JSON output exists
                if not os.path.exists(json_out):
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason="Slither exited with code 0 but produced no JSON output file",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                # Parse JSON
                try:
                    with open(json_out, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                except Exception as parse_err:
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason=f"Failed to parse Slither JSON output: {parse_err}",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                # Validate JSON structure and expected fields
                if not isinstance(data, dict):
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason="Slither JSON output is not a JSON object/dict",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                if "success" in data and data["success"] is False:
                    err_field = str(data.get("error", "unspecified internal error"))
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason=f"Slither reported internal failure in JSON: {err_field[:300]}",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                if "results" not in data or not isinstance(data.get("results"), dict):
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason="Slither JSON output missing 'results' object",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                results_obj = data["results"]
                if "detectors" not in results_obj or not isinstance(results_obj.get("detectors"), list):
                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason="Slither JSON output missing 'results.detectors' list",
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:1000]] if stderr_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=self.get_effective_config_hash(),
                    )

                findings = []
                for d in results_obj["detectors"]:
                    if not isinstance(d, dict):
                        continue
                    impact = str(d.get("impact", "")).capitalize()
                    if impact in ["High", "Medium"]:
                        findings.append({
                            "check": d.get("check"),
                            "impact": impact,
                            "confidence": d.get("confidence"),
                            "description": str(d.get("description", ""))[:200]
                        })

                detected = len(findings) > 0
                base_tool_metadata["detectors_count"] = len(findings)

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
                    cost_usd=None,
                    tool_metadata=base_tool_metadata,
                    raw_output={
                        "findings": findings,
                        "stdout": stdout_text,
                        "stderr": stderr_text,
                    },
                    logs=[stdout_text[:1000]] if stdout_text else [],
                    argv=list(cmd),
                    timeout_sec=effective_timeout,
                    resource_budget=dict(self.resource_budget),
                    effective_config_hash=self.get_effective_config_hash(),
                )

            except subprocess.TimeoutExpired:
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.FAILED,
                    unavailable_reason=f"Slither timed out after {effective_timeout}s",
                    duration_seconds=float(effective_timeout),
                    cost_usd=None,
                    tool_metadata={"slither_version": slither_ver, "argv": list(cmd)},
                    argv=list(cmd),
                    timeout_sec=effective_timeout,
                    resource_budget=dict(self.resource_budget),
                    effective_config_hash=self.get_effective_config_hash(),
                )
            except Exception as e:
                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.FAILED,
                    unavailable_reason=f"Slither execution exception: {e}",
                    duration_seconds=round(time.time() - start_time, 3),
                    cost_usd=None,
                    tool_metadata={"slither_version": slither_ver, "argv": list(cmd)},
                    argv=list(cmd),
                    timeout_sec=effective_timeout,
                    resource_budget=dict(self.resource_budget),
                    effective_config_hash=self.get_effective_config_hash(),
                )


class LLMAuditorBaselineAdapter(BaselineAdapter):
    """
    Baseline 2: LLM Auditor Only (Zero-shot text vulnerability audit findings).
    Queries configured LLM model without generating code or verifying in Foundry.
    If LLM API credentials or model provider are missing, reports UNAVAILABLE.
    """
    PROMPT_TEMPLATE = (
        "You are a smart contract auditor. Analyze the following Solidity contract for security vulnerabilities.\n"
        "Contract Name: {target_name}\n"
        "Source Code:\n{source_code}\n\n"
        "Respond with a JSON object: {{\"vulnerability_found\": true/false, \"vulnerability_type\": \"...\", \"confidence\": \"High/Medium/Low\"}}"
    )

    def __init__(
        self,
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        client_override: Any = None,
        timeout_sec: int = 60,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self.model_id = model_id
        self.provider = provider
        self.client_override = client_override
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {"timeout_sec": timeout_sec, "temperature": 0.0}

    @property
    def baseline_id(self) -> str:
        return "baseline_2"

    @property
    def baseline_name(self) -> str:
        return "LLM Auditor Only (Raw Text Findings)"

    def get_effective_config_hash(self) -> str:
        data = {
            "baseline_id": self.baseline_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "prompt_template_sha256": hashlib.sha256(self.PROMPT_TEMPLATE.encode("utf-8")).hexdigest(),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> Optional[List[str]]:
        """Returns None because LLM auditor is a direct provider API invocation, not a subprocess."""
        return None

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        if self.client_override is not None:
            return True, None
        return check_llm_provider_availability(self.provider)

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
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)
        prompt = self.PROMPT_TEMPLATE.format(target_name=target.target_name, source_code=source_code)
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        try:
            if self.client_override:
                response_text = self.client_override(prompt)
            else:
                response_text = invoke_llm_provider(self.provider, self.model_id, prompt)

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

            base_tool_metadata = {
                "provider": self.provider,
                "model_id": self.model_id,
                "prompt_hash": prompt_sha256,
                "prompt_sha256": prompt_sha256,
                "confidence": confidence,
                "vulnerability_type": vuln_type,
                "cost_status": "unmeasured",
                "timeout_sec": timeout_sec,
                "resource_budget": dict(self.resource_budget),
                "effective_config_hash": self.get_effective_config_hash(),
                "exit_code": None,
            }

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
                cost_usd=None,  # Unmeasured empirical cost
                tool_metadata=base_tool_metadata,
                raw_output={"response": response_text},
                logs=[response_text[:300]],
                argv=None,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
                prompt_hash=prompt_sha256,
            )

        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"LLM auditor invocation failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
                cost_usd=None,
                tool_metadata={
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "prompt_hash": prompt_sha256,
                    "exit_code": None,
                },
                argv=None,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
                prompt_hash=prompt_sha256,
            )


class LLMUnverifiedPoCBaselineAdapter(BaselineAdapter):
    """
    Baseline 3: LLM Auditor + LLM Exploit Generation (Unverified PoC synthesis).
    Generates candidate exploit module without EVM execution verification.
    Candidate count is taken directly from actual generator output.
    verified_breaches and replayed_breaches are strictly 0.
    """
    PROMPT_TEMPLATE = (
        "Generate a Solidity ExploitModule for {target_name}.\n"
        "Source:\n{source_code}\n\n"
        "Respond with ```solidity contract ExploitModule {{ ... }} ```"
    )

    def __init__(
        self,
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        client_override: Any = None,
        timeout_sec: int = 60,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self.model_id = model_id
        self.provider = provider
        self.client_override = client_override
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {"timeout_sec": timeout_sec, "temperature": 0.0}

    @property
    def baseline_id(self) -> str:
        return "baseline_3"

    @property
    def baseline_name(self) -> str:
        return "LLM Auditor + Exploit Gen (Unverified PoC)"

    def get_effective_config_hash(self) -> str:
        data = {
            "baseline_id": self.baseline_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "prompt_template_sha256": hashlib.sha256(self.PROMPT_TEMPLATE.encode("utf-8")).hexdigest(),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> Optional[List[str]]:
        """Returns None because LLM unverified PoC generation is a direct provider API invocation, not a subprocess."""
        return None

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        if self.client_override is not None:
            return True, None
        return check_llm_provider_availability(self.provider)

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
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)
        prompt = self.PROMPT_TEMPLATE.format(target_name=target.target_name, source_code=source_code)
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        try:
            if self.client_override:
                response_text = self.client_override(prompt)
            else:
                response_text = invoke_llm_provider(self.provider, self.model_id, prompt)

            elapsed = round(time.time() - start_time, 3)

            # Extract generated exploit candidate dynamically
            has_code = "contract ExploitModule" in response_text or "function runExploit" in response_text
            candidates_generated = 1 if has_code else 0
            detected = bool(candidates_generated > 0)

            base_tool_metadata = {
                "provider": self.provider,
                "model_id": self.model_id,
                "prompt_hash": prompt_sha256,
                "prompt_sha256": prompt_sha256,
                "cost_status": "unmeasured",
                "timeout_sec": timeout_sec,
                "resource_budget": dict(self.resource_budget),
                "effective_config_hash": self.get_effective_config_hash(),
                "exit_code": None,
            }

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
                cost_usd=None,  # Unmeasured empirical cost
                tool_metadata=base_tool_metadata,
                raw_output={"response": response_text, "generated_code_present": has_code},
                logs=[response_text[:300]],
                argv=None,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
                prompt_hash=prompt_sha256,
            )

        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"PoC generation failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
                cost_usd=None,
                tool_metadata={
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "prompt_hash": prompt_sha256,
                    "exit_code": None,
                },
                argv=None,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
                prompt_hash=prompt_sha256,
            )


class LLMNaiveFoundryBaselineAdapter(BaselineAdapter):
    """
    Baseline 4: LLM Auditor + Exploit Generation + Naive Foundry (Exit Code 0 / Text Marker).
    Compiles and executes candidate exploit in Foundry.
    Considers test passing if forge returncode == 0 and structured JSON test results indicate Success.
    Does NOT use hardened EVM state oracle or trusted harness anti-spoofing emitter checks.
    Separates naive test pass signal from verified invariant breach (verified_breaches is strictly 0).
    """
    PROMPT_TEMPLATE = (
        "Write exploit module for {target_name}:\n{source_code}"
    )

    def __init__(
        self,
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        client_override: Any = None,
        timeout_sec: int = 60,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self.model_id = model_id
        self.provider = provider
        self.client_override = client_override
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {"timeout_sec": timeout_sec, "offline": True}

    @property
    def baseline_id(self) -> str:
        return "baseline_4"

    @property
    def baseline_name(self) -> str:
        return "LLM + Naive Foundry (Exit Code 0 / Text Marker)"

    def get_effective_config_hash(self) -> str:
        prompt_tmpl_sha = hashlib.sha256(self.PROMPT_TEMPLATE.encode("utf-8")).hexdigest()
        data = {
            "baseline_id": self.baseline_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "forge_version": self.get_forge_version(),
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "prompt_template_sha256": prompt_tmpl_sha,
            "foundry_args": ["test", "--offline", "--json"],
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> List[str]:
        return ["forge", "test", "--offline", "--json"]

    def get_forge_version(self) -> str:
        try:
            res = subprocess.run(
                ["forge", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return res.stdout.strip() or res.stderr.strip() or "unknown"
        except Exception:
            return "unknown"

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        forge_bin = shutil.which("forge")
        if not forge_bin:
            return False, "forge executable not found on system PATH"
        if self.client_override is None:
            return check_llm_provider_availability(self.provider)
        return True, None

    @staticmethod
    def _parse_forge_json(stdout_text: str) -> Tuple[int, int, List[str], Dict[str, Any]]:
        """
        Parses structured Forge JSON output.
        Returns:
            (total_tests_run, passed_tests, suites_found, parsed_data)
        """
        total_tests = 0
        passed_tests = 0
        suites_found: List[str] = []
        parsed: Dict[str, Any] = {}

        if not stdout_text.strip():
            return 0, 0, [], {}

        # 1. Try direct JSON parse
        try:
            parsed = json.loads(stdout_text)
        except Exception:
            # 2. Try substring JSON extraction if output has preamble
            start = stdout_text.find("{")
            end = stdout_text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    parsed = json.loads(stdout_text[start:end + 1])
                except Exception:
                    parsed = {}

        if not isinstance(parsed, dict):
            return 0, 0, [], {}

        # Structure A: direct {"test_results": {...}}
        if "test_results" in parsed and isinstance(parsed["test_results"], dict):
            suites_found.append("default")
            for t_name, t_info in parsed["test_results"].items():
                total_tests += 1
                status = str(t_info.get("status", "")).lower() if isinstance(t_info, dict) else str(t_info).lower()
                if status in ("success", "passed", "pass", "ok"):
                    passed_tests += 1
        else:
            # Structure B: {"suite_file:ContractName": {"test_results": {...}}}
            for suite_name, suite_data in parsed.items():
                if isinstance(suite_data, dict) and "test_results" in suite_data:
                    suites_found.append(str(suite_name))
                    t_results = suite_data.get("test_results", {})
                    if isinstance(t_results, dict):
                        for t_name, t_info in t_results.items():
                            total_tests += 1
                            status = str(t_info.get("status", "")).lower() if isinstance(t_info, dict) else str(t_info).lower()
                            if status in ("success", "passed", "pass", "ok"):
                                passed_tests += 1

        return total_tests, passed_tests, suites_found, parsed

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: Optional[int] = None
    ) -> TargetExecutionArtifact:
        effective_timeout = timeout_sec if timeout_sec is not None else self.timeout_sec
        default_cmd = ["forge", "test", "--offline", "--json"]
        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        start_time = time.time()
        forge_ver = self.get_forge_version()

        try:
            source_code = target.load_source_code(base_dir)
            prompt = self.PROMPT_TEMPLATE.format(target_name=target.target_name, source_code=source_code)
            prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

            if self.client_override:
                candidate_code = self.client_override(prompt)
            else:
                candidate_code = invoke_llm_provider(self.provider, self.model_id, prompt)

            candidate_code_sha256 = hashlib.sha256(candidate_code.encode("utf-8")).hexdigest()

            # Execute in temp foundry environment with naive criteria
            with tempfile.TemporaryDirectory() as tmpdir:
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
                effective_cfg_hash = self.get_effective_config_hash()

                proc = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=effective_timeout,
                )
                elapsed = round(time.time() - start_time, 3)

                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
                stdout_sha256 = hashlib.sha256(stdout_text.encode("utf-8")).hexdigest()
                stderr_sha256 = hashlib.sha256(stderr_text.encode("utf-8")).hexdigest()

                total_tests, passed_tests, suites_found, parsed_json = self._parse_forge_json(stdout_text)

                base_tool_metadata = {
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "forge_version": forge_ver,
                    "exit_code": proc.returncode,
                    "forge_exit_code": proc.returncode,
                    "command": " ".join(cmd),
                    "argv": list(cmd),
                    "config_hash": effective_cfg_hash,
                    "effective_config_hash": effective_cfg_hash,
                    "timeout_sec": effective_timeout,
                    "resource_budget": dict(self.resource_budget),
                    "stdout_sha256": stdout_sha256,
                    "stderr_sha256": stderr_sha256,
                    "prompt_sha256": prompt_sha256,
                    "candidate_code_sha256": candidate_code_sha256,
                    "total_tests_run": total_tests,
                    "passed_tests": passed_tests,
                    "suites_found": suites_found,
                    "cost_status": "unmeasured",
                }

                # Evaluate execution signals:
                # 1. Non-zero exit code: compilation failure or test assertion failure
                if proc.returncode != 0:
                    err_msg = stderr_text.strip() or stdout_text.strip() or "Non-zero exit code"
                    is_compile_failure = (total_tests == 0)
                    base_tool_metadata["naive_signal"] = False
                    base_tool_metadata["test_pass"] = False
                    base_tool_metadata["is_compile_failure"] = is_compile_failure

                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED if is_compile_failure else ExecutionStatus.SUCCESS,
                        unavailable_reason=f"Forge compilation/execution failed (exit code {proc.returncode}): {err_msg[:300]}" if is_compile_failure else None,
                        detected=False,
                        candidates_generated=1,
                        verified_breaches=0,
                        replayed_breaches=0,
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stderr_text[:500]] if stderr_text else [stdout_text[:500]],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=effective_cfg_hash,
                        prompt_hash=prompt_sha256,
                    )

                # 2. Exit code 0, but no tests were executed (e.g. empty test suite)
                if total_tests == 0:
                    base_tool_metadata["naive_signal"] = False
                    base_tool_metadata["test_pass"] = False
                    base_tool_metadata["is_empty_suite"] = True

                    return TargetExecutionArtifact(
                        baseline_id=self.baseline_id,
                        target_id=target.contract_id,
                        target_name=target.target_name,
                        status=ExecutionStatus.FAILED,
                        unavailable_reason="Forge exited with code 0 but executed 0 test cases (no tests run)",
                        detected=False,
                        candidates_generated=1,
                        verified_breaches=0,
                        replayed_breaches=0,
                        duration_seconds=elapsed,
                        cost_usd=None,
                        tool_metadata=base_tool_metadata,
                        raw_output={"stdout": stdout_text, "stderr": stderr_text},
                        logs=[stdout_text[:500]] if stdout_text else [],
                        argv=list(cmd),
                        timeout_sec=effective_timeout,
                        resource_budget=dict(self.resource_budget),
                        effective_config_hash=effective_cfg_hash,
                        prompt_hash=prompt_sha256,
                    )

                # 3. Tests were executed and completed:
                test_pass = (passed_tests > 0)
                base_tool_metadata["test_pass"] = bool(test_pass)
                base_tool_metadata["naive_signal"] = bool(test_pass)

                return TargetExecutionArtifact(
                    baseline_id=self.baseline_id,
                    target_id=target.contract_id,
                    target_name=target.target_name,
                    status=ExecutionStatus.SUCCESS,
                    detected=bool(test_pass),
                    candidates_generated=1,
                    # P0 INVARIANT: A naive test pass without invariant verification is NOT a verified breach
                    verified_breaches=0,
                    replayed_breaches=0,
                    duration_seconds=elapsed,
                    cost_usd=None,
                    tool_metadata=base_tool_metadata,
                    raw_output={"stdout": stdout_text, "stderr": stderr_text},
                    logs=[stdout_text[:500]] if stdout_text else [],
                    argv=list(cmd),
                    timeout_sec=effective_timeout,
                    resource_budget=dict(self.resource_budget),
                    effective_config_hash=effective_cfg_hash,
                    prompt_hash=prompt_sha256,
                )

        except subprocess.TimeoutExpired:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Naive Foundry execution timed out after {effective_timeout}s",
                duration_seconds=float(effective_timeout),
                cost_usd=None,
                tool_metadata={
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "forge_version": forge_ver,
                    "exit_code": None,
                },
                argv=None,
                timeout_sec=effective_timeout,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
            )
        except Exception as e:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Naive Foundry execution failed: {e}",
                duration_seconds=round(time.time() - start_time, 3),
                cost_usd=None,
                tool_metadata={
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "forge_version": forge_ver,
                    "exit_code": None,
                },
                argv=None,
                timeout_sec=effective_timeout,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
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
    def __init__(
        self,
        model_id: str = "gemini-1.5-pro",
        provider: str = "gemini",
        candidate_generator: Any = None,
        max_hypotheses: int = 3,
        timeout_sec: int = 120,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self.model_id = model_id
        self.provider = provider
        self.candidate_generator = candidate_generator
        self.max_hypotheses = max_hypotheses
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {
            "timeout_sec": timeout_sec,
            "max_hypotheses": max_hypotheses,
            "allowlist": ["Vault", "ERC4626Vault"],
        }

    @property
    def baseline_id(self) -> str:
        return "baseline_5"

    @property
    def baseline_name(self) -> str:
        if self.provider == "modal_h100":
            return "Full Aegis-RLVR (Modal H100 Reasoning + Modal CPU EVM Replay)"
        elif self.provider == "modal_t4":
            return "Full Aegis-RLVR (Modal T4 Reasoning + Modal CPU EVM Replay)"
        elif self.provider == "gemini":
            return "Full Aegis-RLVR (Gemini Frontier API Reasoning + Modal CPU EVM Replay)"
        elif self.provider == "openai":
            return "Full Aegis-RLVR (OpenAI API Reasoning + Modal CPU EVM Replay)"
        return f"Full Aegis-RLVR ({self.provider} + Modal CPU EVM Replay)"

    def get_effective_config_hash(self) -> str:
        data = {
            "baseline_id": self.baseline_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "max_hypotheses": self.max_hypotheses,
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "allowlist": ["Vault", "ERC4626Vault"],
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> List[str]:
        return [
            "modal",
            "run",
            "modal_app.py",
            f"--hypotheses={self.max_hypotheses}",
            f"--provider={self.provider}",
            f"--model={self.model_id}",
        ]

    def check_availability(self) -> Tuple[bool, Optional[str]]:
        has_modal = False
        try:
            import modal
            has_modal = bool(modal.config.config.get("token_id"))
        except Exception:
            has_modal = bool(os.environ.get("MODAL_TOKEN_ID"))
        if not has_modal:
            return False, "Modal authentication not configured (missing token_id in ~/.modal.toml or MODAL_TOKEN_ID env)"
        if self.candidate_generator is None:
            if self.provider in ("modal_h100", "modal_t4"):
                return True, None
            return check_llm_provider_availability(self.provider)
        return True, None

    def execute_target(
        self,
        target: TargetSpecification,
        base_dir: Optional[Path] = None,
        timeout_sec: int = 120
    ) -> TargetExecutionArtifact:
        from core.config import config
        from sandbox.runner import TRUSTED_HARNESS_CONTRACTS
        cmd = [
            "modal",
            "run",
            "modal_app.py",
            "--target-name",
            target.target_name,
            f"--hypotheses={self.max_hypotheses}",
            f"--provider={self.provider}",
            f"--model={self.model_id}",
        ]

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
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        is_avail, reason = self.check_availability()
        if not is_avail:
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.UNAVAILABLE,
                unavailable_reason=reason,
                argv=None,
                timeout_sec=None,
                resource_budget={},
                effective_config_hash=None,
            )

        start_time = time.time()
        source_code = target.load_source_code(base_dir)

        try:
            from core.schemas import TargetProgram, ExploitPayload, AttackHypothesis, ResultCategory, VerificationVerdict
            from modal_app import verify_exploit_remote, verify_replay_remote, record_trajectory_remote

            # Resolve trusted verification harness
            solidity_dir = (
                base_dir / "benchmarks" / "targets" / "solidity"
                if base_dir
                else Path(__file__).parent / "targets" / "solidity"
            )
            if not solidity_dir.exists():
                solidity_dir = Path(__file__).parent.parent / "benchmarks" / "targets" / "solidity"

            harness_file = solidity_dir / f"{target.target_name}Harness.t.sol"
            harness_source = ""
            if harness_file.exists():
                harness_source = harness_file.read_text(encoding="utf-8")
            else:
                harness_name = TRUSTED_HARNESS_CONTRACTS.get(target.target_name)
                if harness_name:
                    hf = solidity_dir / f"{harness_name}.t.sol"
                    if hf.exists():
                        harness_source = hf.read_text(encoding="utf-8")

            invariants_map = {
                "Vault": ["address(vault).balance >= balances[victim] (Depositor Solvency)"],
                "ERC4626Vault": [
                    "victimShares > 0 (No zero-share deposit robbery)",
                    "vault.convertToAssets(victimShares) >= 0.95 * VICTIM_DEPOSIT (Dilution Protection)"
                ]
            }
            target_invariants = invariants_map.get(target.target_name, ["Security invariant intact"])

            target_prog = TargetProgram(
                name=target.target_name,
                source_code=source_code,
                language="solidity",
                invariants=target_invariants,
                trusted_harness_code=harness_source
            )

            # 1. Synthesize candidate payload inside Modal app context
            with ensure_modal_app_context():
                payload = None
                if self.candidate_generator:
                    payload = self.candidate_generator(target_prog)
                elif self.provider == "modal_h100":
                    from modal_app import ProductionAuditAgent
                    agent = ProductionAuditAgent()
                    p_dict = agent.generate_solidity_exploit.remote(target_prog.model_dump())
                    payload = ExploitPayload(**p_dict)
                elif self.provider == "modal_t4":
                    from modal_app import DevReasoningAgent
                    agent = DevReasoningAgent()
                    p_dict = agent.generate_solidity_exploit.remote(target_prog.model_dump())
                    payload = ExploitPayload(**p_dict)
                else:
                    from core.hypothesis import HypothesisManager
                    hyp_mgr = HypothesisManager()
                    hypotheses = hyp_mgr.generate_hypotheses(target_prog)
                    selected_hyp = hypotheses[0] if hypotheses else AttackHypothesis(
                        vulnerability_type="SecurityAudit",
                        reasoning_trace="Automated hypothesis generation",
                        attack_vector="direct",
                    )
                    prompt = (
                        f"Synthesize an ExploitModule for target {target_prog.name}.\n"
                        f"Hypothesis: {selected_hyp.vulnerability_type} ({selected_hyp.reasoning_trace})\n"
                        f"Target Source:\n{source_code}\n\n"
                        f"Respond with Solidity code containing contract ExploitModule {{ ... }}"
                    )
                    test_code = invoke_llm_provider(self.provider, self.model_id, prompt)
                    from core.llm_generator import parse_model_response
                    payload = parse_model_response(target_prog, test_code, hypothesis=selected_hyp)

                candidates_count = 1 if (payload and payload.test_code and len(payload.test_code.strip()) > 20) else 0

                # 2. Execute candidate remotely on Modal EVM sandbox
                target_dict = target_prog.model_dump()
                payload_dict = payload.model_dump() if payload else {}

                verdict_dict = verify_exploit_remote.remote(target_dict, payload_dict)
                verdict = VerificationVerdict(**verdict_dict)
                elapsed = round(time.time() - start_time, 3)

                # 3. Independent remote replay verification on fresh Modal container
                is_replayed = False
                replay_attempted = False
                if verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
                    replay_attempted = True
                    try:
                        is_replayed = bool(verify_replay_remote.remote(target_dict, payload_dict))
                    except Exception as exc:
                        # Remote replay infrastructure error: MUST fail closed as FAILED, NEVER SUCCESS
                        is_timeout = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()
                        return TargetExecutionArtifact(
                            baseline_id=self.baseline_id,
                            target_id=target.contract_id,
                            target_name=target.target_name,
                            status=ExecutionStatus.FAILED,
                            unavailable_reason=f"Modal remote replay {'timed out' if is_timeout else 'infrastructure failure'}: {type(exc).__name__}: {exc}",
                            duration_seconds=round(time.time() - start_time, 3),
                            cost_usd=None,
                            tool_metadata={
                                "remote_backend": "modal",
                                "modal_app": config.APP_NAME,
                                "modal_functions": ["verify_exploit_remote", "verify_replay_remote"],
                                "remote_stages": {
                                    "inference": "remote_gpu" if self.provider in ("modal_h100", "modal_t4") else "api_or_local",
                                    "evm_sandbox": "modal_cpu_worker",
                                    "independent_replay": "modal_cpu_worker_failed",
                                    "trajectory_persistence": "not_eligible",
                                },
                                "error_type": type(exc).__name__,
                                "stage_failed": "independent_replay",
                                "command": " ".join(cmd),
                                "argv": cmd,
                            },
                            argv=cmd,
                            timeout_sec=timeout_sec,
                            resource_budget=dict(self.resource_budget),
                            effective_config_hash=self.get_effective_config_hash(),
                        )

                is_verified = bool(replay_attempted and is_replayed and verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED)
                if is_verified:
                    verdict.category = ResultCategory.EXPLOIT_CONFIRMED
                    verdict.is_verified = True
                    verdict.reproducible = True
                    verdict.replay_status = "CONFIRMED"
                    verdict.reward_score = config.REWARD_INVARIANT_BREACH

                # 4. Remote trajectory persistence on Modal volume
                persisted_path = None
                persistence_status = "not_eligible"
                persistence_error = None
                if is_verified:
                    try:
                        from core.evaluator import create_trajectory_record
                        traj = create_trajectory_record(
                            target_prog, payload, verdict,
                            prompt_used=payload.prompt_text or "",
                            dataset_split="test",
                            dataset_partition="test",
                            is_synthetic=False,
                            trainable=False
                        )
                        persisted_res = record_trajectory_remote.remote(traj.model_dump())
                        if isinstance(persisted_res, str) and persisted_res:
                            persisted_path = persisted_res
                            persistence_status = "persisted"
                        else:
                            persistence_status = "unknown_response"
                    except Exception as p_exc:
                        persistence_status = "failed"
                        persistence_error = f"{type(p_exc).__name__}: {p_exc}"

            modal_functions = []
            if self.provider == "modal_h100":
                modal_functions.append("ProductionAuditAgent.generate_solidity_exploit")
            elif self.provider == "modal_t4":
                modal_functions.append("DevReasoningAgent.generate_solidity_exploit")
            modal_functions.append("verify_exploit_remote")
            if replay_attempted:
                modal_functions.append("verify_replay_remote")
            if persistence_status == "persisted":
                modal_functions.append("record_trajectory_remote")

            base_tool_metadata = {
                "remote_backend": "modal",
                "modal_app": config.APP_NAME,
                "modal_functions": modal_functions,
                "remote_stages": {
                    "inference": "remote_gpu" if self.provider in ("modal_h100", "modal_t4") else "api_or_local",
                    "evm_sandbox": "modal_cpu_worker",
                    "independent_replay": "modal_cpu_worker" if replay_attempted else "not_attempted",
                    "trajectory_persistence": "modal_volume" if persistence_status == "persisted" else persistence_status,
                },
                "inference_backend": "modal_h100" if self.provider == "modal_h100" else ("modal_t4" if self.provider == "modal_t4" else f"{self.provider}_api"),
                "evm_sandbox_backend": "modal_cpu_worker",
                "replay_backend": "modal_cpu_worker" if replay_attempted else "not_attempted",
                "trajectory_persistence_backend": "modal_volume" if persistence_status == "persisted" else persistence_status,
                "persisted_trajectory_path": persisted_path,
                "persistence_status": persistence_status,
                "persistence_error": persistence_error,
                "gpu_allocated": config.AUDIT_GPU_TYPE if self.provider == "modal_h100" else (config.DEV_GPU_TYPE if self.provider == "modal_t4" else None),
                "cpu_cores": config.SANDBOX_CPU_CORES,
                "memory_mb": config.SANDBOX_MEMORY_MB,
                "provider": self.provider,
                "model_id": self.model_id,
                "token_provenance": (
                    "model_generate" if (payload and payload.generated_token_ids)
                    else ("synthetic" if (payload and getattr(payload, "is_synthetic", False)) else "external_text")
                ),
                "generated_tokens_count": len(payload.generated_token_ids) if (payload and payload.generated_token_ids) else 0,
                "harness_verdict": verdict.category.value,
                "reward_score": verdict.reward_score,
                "reward_components": verdict.reward_components,
                "reproduced": is_replayed,
                "cost_status": "unmeasured",
                "command": " ".join(cmd),
                "argv": cmd,
                "timeout_sec": timeout_sec,
                "resource_budget": dict(self.resource_budget),
                "effective_config_hash": self.get_effective_config_hash(),
            }

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
                cost_usd=None,
                tool_metadata=base_tool_metadata,
                raw_output={"category": verdict.category.value, "reward_score": verdict.reward_score},
                logs=[verdict.feedback[:300]] if verdict.feedback else [],
                argv=cmd,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
            )

        except Exception as e:
            is_timeout = isinstance(e, TimeoutError) or "timed out" in str(e).lower()
            return TargetExecutionArtifact(
                baseline_id=self.baseline_id,
                target_id=target.contract_id,
                target_name=target.target_name,
                status=ExecutionStatus.FAILED,
                unavailable_reason=f"Full Aegis-RLVR Modal remote execution {'timed out' if is_timeout else 'failed'}: {type(e).__name__}: {e}",
                duration_seconds=round(time.time() - start_time, 3),
                cost_usd=None,
                tool_metadata={
                    "remote_backend": "modal",
                    "modal_app": config.APP_NAME,
                    "modal_functions": ["verify_exploit_remote"],
                    "provider": self.provider,
                    "model_id": self.model_id,
                    "command": " ".join(cmd),
                    "argv": cmd,
                },
                argv=cmd,
                timeout_sec=timeout_sec,
                resource_budget=dict(self.resource_budget),
                effective_config_hash=self.get_effective_config_hash(),
            )


class SyntheticSmokeAdapter(BaselineAdapter):
    """
    Synthetic Mock Adapter strictly used in --mode smoke for CI pipeline tests.
    Every produced artifact is explicitly labeled with is_synthetic_smoke: True.
    """
    def __init__(
        self,
        baseline_id: str,
        baseline_name: str,
        timeout_sec: int = 5,
        resource_budget: Optional[Dict[str, Any]] = None,
    ):
        self._b_id = baseline_id
        self._b_name = baseline_name
        self._timeout_sec = timeout_sec
        self._resource_budget = resource_budget or {"timeout_sec": timeout_sec, "mode": "synthetic_smoke"}

    @property
    def baseline_id(self) -> str:
        return self._b_id

    @property
    def baseline_name(self) -> str:
        return self._b_name

    def get_effective_config_hash(self) -> str:
        data = {
            "baseline_id": self._b_id,
            "baseline_name": self._b_name,
            "timeout_sec": self.timeout_sec,
            "resource_budget": self.resource_budget,
            "is_synthetic_smoke": True,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()

    def get_default_argv(self) -> List[str]:
        return ["synthetic_smoke_runner", "--baseline", self._b_id]

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
        cmd = ["synthetic_smoke_runner", "--baseline", self._b_id, "--target", target.contract_id]

        detected = False
        candidates = 0
        verified = 0
        replayed = 0

        if self._b_id == "baseline_1":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SAFE-01", "SAFE-02"]
        elif self._b_id == "baseline_2":
            detected = tid in ["REENT-01", "ERC4626-01", "AC-01", "ORACLE-01", "FLASH-01", "STATE-01", "SAFE-01", "SAFE-03"]
        elif self._b_id == "baseline_3":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SAFE-01"]
            candidates = 4 if detected else 0
        elif self._b_id == "baseline_4":
            detected = tid in ["REENT-01", "AC-01", "DOS-01", "SIG-01", "PREC-01", "SAFE-01"]
            candidates = 8 if detected else 0
            verified = 5 if detected else 0
            replayed = 3 if detected else 0
        elif self._b_id == "baseline_5":
            detected = not is_ctrl and tid not in ["BRIDGE-01"]
            candidates = 6 if detected else 2
            verified = 1 if detected else 0
            replayed = 1 if (detected and verified == 1) else 0

        tool_metadata = {
            "is_synthetic_smoke": True,
            "command": " ".join(cmd),
            "argv": list(cmd),
            "exit_code": 0,
            "stdout_sha256": hashlib.sha256(b"mock stdout").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "timeout_sec": self.timeout_sec,
            "resource_budget": dict(self.resource_budget),
            "effective_config_hash": self.get_effective_config_hash(),
        }

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
            cost_usd=None,  # No synthetic fabricated dollar amounts
            tool_metadata=tool_metadata,
            raw_output={"mock_run": True},
            logs=["[SYNTHETIC_SMOKE_FIXTURE]"],
            argv=cmd,
            timeout_sec=self.timeout_sec,
            resource_budget=dict(self.resource_budget),
            effective_config_hash=self.get_effective_config_hash(),
        )
