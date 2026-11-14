"""
tests/test_cpu_audit_contract.py

The offline contract tests of the CPU-only Modal audit service
(``modal_cpu_audit_app.py``) and of its driver (``benchmarks/run_cpu_audit.py``).

Nothing in this file performs a provider call, a deployment, a volume operation or a
model download: the whole suite is local and deterministic, exactly like the other
suites of this repository. The live behaviour of the service is proven by the evidence
of the end-to-end run (``benchmarks/evidence/cpu_audit/``), not by these tests.

What is proven here:
1. The application declares **no GPU** and explicit, conservative CPU resources.
2. The application is **separate** from the GPU production application and does not
   import the R1 dispatch registry, so it cannot weaken the fail-closed approval
   mechanism of the benchmark.
3. The repository-owned candidate registry is valid, and its candidates satisfy the
   repository's own format gate and cheatcode policy.
4. The request validation is **fail-closed**: an unsafe name, a target without a
   trusted harness, an oversized payload or a malformed run id is refused explicitly.
5. A target without a candidate ends in the explicit status ``CANDIDATE_UNAVAILABLE``
   - the service never invents a verdict.
6. The model cache is mounted read-only and the artifacts are written into the
   dedicated results volume only.
7. The driver refuses the live invocation without an explicit approval.
8. The **authorisation of the service is enforced on the server side**: a direct
   call to any of the three public functions without the shared token is refused
   before any work is done - it does not depend on the environment of the caller.
9. The expectation evaluation of the driver detects a **false confirmation** - the
   control target must not be reported as a confirmed exploit - and it detects the
   contradictions of the evidence instead of accepting them.
"""

from __future__ import annotations

import ast
import importlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest

_ROOT = Path(__file__).resolve().parent.parent

import modal_cpu_audit_app as app_module  # noqa: E402
from benchmarks.run_cpu_audit import (  # noqa: E402
    APPROVAL_ENV_VAR,
    AUTH_TOKEN_ENV_VAR,
    AuditNotAuthorised,
    _assert_authorised,
    _auth_token,
    _evaluate_expectations,
    _scan_for_secrets,
)
from core.llm_generator import validate_exploit_format  # noqa: E402
from sandbox.runner import (  # noqa: E402
    TRUSTED_HARNESS_CONTRACTS,
    detect_prohibited_cheatcodes,
)

APP_SOURCE = (_ROOT / "modal_cpu_audit_app.py").read_text(encoding="utf-8")
REGISTRY_PATH = _ROOT / "benchmarks" / "cpu_audit_pocs" / "registry.json"

#: A token that is long enough to pass the length check of the service. It is a
#: test value, never a real token.
TEST_TOKEN = "t" * 40


# ---------------------------------------------------------------------------
# 1. The declared resources
# ---------------------------------------------------------------------------


def test_the_application_declares_no_gpu_and_explicit_cpu_resources():
    """No GPU is requested, so none can be allocated."""
    resources = app_module.DECLARED_RESOURCES
    assert resources["gpu"] is None
    assert resources["cpu"] == 2.0
    assert resources["memory"] == 2048
    assert resources["timeout"] == 600
    assert resources["retries"] == 0
    assert resources["block_network"] is True


def test_the_application_name_is_separate_from_the_gpu_application():
    """The CPU service is its own application, not a class of the GPU one."""
    from core.config import config

    assert app_module.APP_NAME != config.APP_NAME
    assert app_module.APP_NAME == "aegis-rlvr-cpu-audit"


# ---------------------------------------------------------------------------
# 2. The separation from the GPU path and from the R1 dispatch registry
# ---------------------------------------------------------------------------


def test_the_application_never_imports_the_gpu_production_app():
    """The CPU application cannot reach the H100 class of the production app."""
    tree = ast.parse(APP_SOURCE)

    imported_modules: List[str] = []
    referenced_names: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported_modules.append(module)
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            referenced_names.append(node.id)
        elif isinstance(node, ast.Attribute):
            referenced_names.append(node.attr)

    assert "modal_app" not in imported_modules
    assert "ProductionAuditAgent" not in referenced_names
    assert "DevReasoningAgent" not in referenced_names
    assert "H100" not in imported_modules


def test_the_application_never_imports_the_r1_dispatch_registry():
    """
    The R1 registry decides which call sites are authorised. A module that imports
    and mutates it could weaken the fail-closed gate, so the CPU service does not
    touch it at all.
    """
    assert not re.search(r"^\s*import\s+core\.r1_bounds", APP_SOURCE, re.MULTILINE)
    assert not re.search(r"^\s*from\s+core\.r1_bounds\s+import", APP_SOURCE, re.MULTILINE)
    assert not re.search(r"^\s*from\s+core\s+import\s+r1_bounds", APP_SOURCE, re.MULTILINE)
    assert not re.search(r"^\s*import\s+benchmarks\.r1_dispatch", APP_SOURCE, re.MULTILINE)


def test_the_r1_gate_still_refuses_every_unapproved_call_site():
    """
    The fail-closed behaviour of the benchmark is unchanged by this workstream.

    The repository pins no approval key, so no provider dispatch can be authorised -
    this is the state the project expects, and the CPU service does not change it.
    """
    from core import r1_approval

    assert r1_approval.PINNED_PUBLIC_KEY is None
    assert r1_approval.pinned_public_key() is None
    with pytest.raises(r1_approval.ApprovalNotVerified):
        r1_approval.verify_approval({"step_id": "x"}, b"signature")


# ---------------------------------------------------------------------------
# 3. The candidate registry
# ---------------------------------------------------------------------------


def _registry() -> Dict[str, Any]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_the_candidate_registry_is_valid():
    registry = _registry()
    assert registry["schema_version"] == "aegis-cpu-audit-poc-registry/1.0.0"
    entries = registry["entries"]
    assert entries, "the registry holds no candidate"

    for entry in entries:
        assert entry["target_name"] in TRUSTED_HARNESS_CONTRACTS, (
            "the registry references a target without a trusted harness: "
            f"{entry['target_name']}"
        )
        poc_path = _ROOT / "benchmarks" / "cpu_audit_pocs" / entry["poc_file"]
        assert poc_path.is_file(), f"the candidate file is missing: {poc_path}"
        assert entry["expected_outcome"] in ("BREACH", "NO_BREACH")


def test_the_registry_covers_a_vulnerable_target_and_its_safe_control():
    """A candidate that only ever confirms a breach would be worthless as evidence."""
    outcomes = {
        entry["target_name"]: entry["expected_outcome"]
        for entry in _registry()["entries"]
    }
    assert "BREACH" in outcomes.values(), "no target expects a breach"
    assert "NO_BREACH" in outcomes.values(), "no negative control in the registry"


@pytest.mark.parametrize("entry", _registry()["entries"])
def test_every_repository_candidate_passes_the_repository_format_gate(entry):
    """The candidates satisfy the format gate of the repository itself."""
    poc_path = _ROOT / "benchmarks" / "cpu_audit_pocs" / entry["poc_file"]
    code = poc_path.read_text(encoding="utf-8")

    is_valid, reason = validate_exploit_format(code)
    assert is_valid, f"the candidate does not satisfy the format gate: {reason}"
    assert not detect_prohibited_cheatcodes(code), "the candidate uses a prohibited cheatcode"


def test_the_registry_resolves_the_candidate_of_a_target():
    resolved = app_module.resolve_registry_candidate("Vault")
    assert resolved is not None
    assert resolved["candidate_origin"] == "repository_registry"
    assert "contract ExploitModule" in resolved["candidate_code"]


def test_a_target_without_a_candidate_resolves_to_nothing():
    """No candidate is invented for a target the registry does not cover."""
    assert app_module.resolve_registry_candidate("ERC4626Vault") is None


# ---------------------------------------------------------------------------
# 4. The fail-closed request validation
# ---------------------------------------------------------------------------


def test_a_valid_request_is_accepted():
    validation = app_module.validate_request(
        {"target_name": "Vault", "source_code": "contract Vault { }"}
    )
    assert validation["ok"] is True
    assert validation["target_name"] == "Vault"
    assert validation["candidate_origin"] == "repository_registry"
    assert validation["run_id"]


def test_an_unsafe_target_name_is_refused():
    validation = app_module.validate_request(
        {"target_name": "../../etc/passwd", "source_code": "contract X { }"}
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "TARGET_NAME_UNSAFE"


def test_a_target_without_a_trusted_harness_is_refused():
    """Without an immutable harness there is no verdict that could be trusted."""
    validation = app_module.validate_request(
        {"target_name": "NotAllowlisted", "source_code": "contract X { }"}
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "TARGET_NOT_ALLOWED"


def test_a_missing_source_is_refused():
    validation = app_module.validate_request({"target_name": "Vault"})
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "SOURCE_CODE_MISSING"


def test_an_oversized_source_is_refused():
    oversized = "a" * (app_module.MAX_TARGET_SOURCE_BYTES + 1)
    validation = app_module.validate_request(
        {"target_name": "Vault", "source_code": oversized}
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "SOURCE_CODE_TOO_LARGE"


def test_an_oversized_request_is_refused():
    oversized = "a" * (app_module.MAX_REQUEST_BYTES + 1)
    validation = app_module.validate_request(
        {"target_name": "Vault", "source_code": oversized}
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] in ("REQUEST_TOO_LARGE", "SOURCE_CODE_TOO_LARGE")


def test_a_malformed_run_id_is_refused():
    validation = app_module.validate_request(
        {"target_name": "Vault", "source_code": "contract X { }", "run_id": "../escape"}
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "RUN_ID_INVALID"


def test_a_request_that_is_not_a_mapping_is_refused():
    validation = app_module.validate_request(["not", "a", "mapping"])
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "REQUEST_NOT_A_MAPPING"


def test_a_target_without_a_candidate_ends_explicitly_and_invents_nothing():
    """No verdict is produced when the synthesis stage did not run."""
    validation = app_module.validate_request(
        {"target_name": "ERC4626Vault", "source_code": "contract X { }"}
    )
    assert validation["status"] == "CANDIDATE_UNAVAILABLE"
    assert validation["error"]["code"] == "CANDIDATE_UNAVAILABLE"
    assert "verdict" not in validation
    assert "reward_score" not in validation


def test_an_oversized_candidate_is_refused():
    oversized = "a" * (app_module.MAX_CANDIDATE_BYTES + 1)
    validation = app_module.validate_request(
        {
            "target_name": "Vault",
            "source_code": "contract X { }",
            "candidate_code": oversized,
        }
    )
    assert validation["status"] == "REJECTED"
    assert validation["error"]["code"] == "CANDIDATE_CODE_TOO_LARGE"


# ---------------------------------------------------------------------------
# 5. The volumes
# ---------------------------------------------------------------------------


def test_the_model_cache_is_mounted_read_only():
    """The cache is requested read-only; the results live in a dedicated volume."""
    assert app_module.MODEL_VOLUME_NAME == "aegis-model-cache"
    assert app_module.RESULTS_VOLUME_NAME == "aegis-cpu-audit-results"
    assert app_module.MODEL_VOLUME_MOUNT_PATH != app_module.RESULTS_VOLUME_MOUNT_PATH
    assert "read_only=True" in APP_SOURCE


def test_the_artifacts_are_written_into_the_dedicated_volume_only():
    """The service never writes into the model cache."""
    run_dir = re.search(
        r"run_dir\s*=\s*os\.path\.join\(\s*(.*?)\)\s*\n", APP_SOURCE, re.DOTALL
    )
    assert run_dir is not None, "the run directory of the service was not found"
    assert "RESULTS_VOLUME_MOUNT_PATH" in run_dir.group(1)
    assert "MODEL_VOLUME_MOUNT_PATH" not in run_dir.group(1)


def test_the_existing_cache_is_never_created_by_the_service():
    """``create_if_missing`` would create an empty cache - the service must not."""
    volume_declaration = re.search(
        r"modal\.Volume\.from_name\(MODEL_VOLUME_NAME[^)]*\)", APP_SOURCE
    )
    assert volume_declaration is not None
    assert "create_if_missing" not in volume_declaration.group(0)


# ---------------------------------------------------------------------------
# 6. The authorisation of the driver
# ---------------------------------------------------------------------------


def test_the_driver_refuses_the_live_invocation_without_an_approval(monkeypatch):
    monkeypatch.delenv(APPROVAL_ENV_VAR, raising=False)
    with pytest.raises(AuditNotAuthorised):
        _assert_authorised()


def test_the_driver_accepts_an_explicit_approval(monkeypatch):
    monkeypatch.setenv(APPROVAL_ENV_VAR, "1")
    _assert_authorised()


def test_the_driver_refuses_to_start_without_the_authorisation_token(monkeypatch):
    """Without the token of the service every call would be refused anyway."""
    monkeypatch.delenv(AUTH_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setattr("benchmarks.run_cpu_audit._token_from_env_file", lambda: "")
    with pytest.raises(AuditNotAuthorised):
        _auth_token()


def test_the_driver_reads_the_authorisation_token(monkeypatch):
    monkeypatch.setenv(AUTH_TOKEN_ENV_VAR, TEST_TOKEN)
    assert _auth_token() == TEST_TOKEN


def test_the_driver_reads_the_token_from_the_local_env_file(monkeypatch):
    """The token may live in the local .env file, which is excluded from git."""
    monkeypatch.delenv(AUTH_TOKEN_ENV_VAR, raising=False)
    monkeypatch.setattr(
        "benchmarks.run_cpu_audit._token_from_env_file", lambda: TEST_TOKEN
    )
    assert _auth_token() == TEST_TOKEN


def test_the_env_file_is_excluded_from_git():
    """The token of the service must never reach the repository."""
    gitignore = (_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore.splitlines()


# ---------------------------------------------------------------------------
# 7. The authorisation of the service (server side)
# ---------------------------------------------------------------------------


def test_every_public_function_carries_the_authorisation_secret():
    """The token has to reach the container, otherwise every call is refused."""
    assert app_module.AUTH_SECRET_NAME == "aegis-cpu-audit-auth"
    assert app_module.AUTH_TOKEN_ENV_VAR == "AEGIS_CPU_AUDIT_TOKEN"
    # The secret is mounted into the container of every public function.
    assert APP_SOURCE.count("secrets=[auth_secret]") == 3


def test_the_authorisation_is_checked_before_any_work():
    """
    The check has to come before the work of the function.

    The order is read from the source: the authorisation call precedes the
    validation, the static analysis, the EVM and every access to a volume.
    """
    tree = ast.parse(APP_SOURCE)
    work_calls = {
        "validate_request",
        "run_slither_analysis_detailed",
        "run_payload_in_sandbox",
        "verify_independent_replay_result",
        "save_result_artifact",
        "observed_runtime_facts",
    }
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("audit_contract", "read_saved_result", "probe_environment")
    }
    assert set(functions) == {"audit_contract", "read_saved_result", "probe_environment"}

    for name, node in functions.items():
        statements = node.body
        auth_index = None
        for index, statement in enumerate(statements):
            called = [
                child.func.id
                for child in ast.walk(statement)
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
            ]
            if "assert_authorised" in called:
                auth_index = index
                break
            assert not (set(called) & work_calls), (
                f"{name} calls {sorted(set(called) & work_calls)} before the authorisation"
            )
        assert auth_index is not None, f"{name} does not check the authorisation"


def test_a_call_without_the_token_is_refused(monkeypatch):
    """
    A DIRECT call without the token is refused by the service itself.

    The call goes to the real function of the application - there is no local
    gate in between - and it is refused before any work is done.
    """
    monkeypatch.setenv(AUTH_TOKEN_ENV_VAR, TEST_TOKEN)

    audit = app_module.audit_contract.local(
        {"target_name": "Vault", "source_code": "contract Vault { }"}
    )
    assert audit["status"] == "UNAUTHORIZED"
    assert audit["error"]["code"] == "NOT_AUTHORISED"

    probe = app_module.probe_environment.local("")
    assert probe["status"] == "UNAUTHORIZED"
    assert probe["error"]["code"] == "NOT_AUTHORISED"

    read_back = app_module.read_saved_result.local("some-run", "wrong-token")
    assert read_back["status"] == "UNAUTHORIZED"
    assert read_back["error"]["code"] == "NOT_AUTHORISED"


def test_a_call_with_a_wrong_token_is_refused(monkeypatch):
    monkeypatch.setenv(AUTH_TOKEN_ENV_VAR, TEST_TOKEN)

    audit = app_module.audit_contract.local(
        {
            "target_name": "Vault",
            "source_code": "contract Vault { }",
            "auth_token": "x" * 40,
        }
    )
    assert audit["status"] == "UNAUTHORIZED"
    assert audit["error"]["code"] == "NOT_AUTHORISED"


def test_the_service_refuses_every_call_when_the_secret_is_missing(monkeypatch):
    """
    Without the secret in the container the service is closed.

    A missing secret must not open the service - it closes it.
    """
    monkeypatch.delenv(AUTH_TOKEN_ENV_VAR, raising=False)

    audit = app_module.audit_contract.local(
        {
            "target_name": "Vault",
            "source_code": "contract Vault { }",
            "auth_token": TEST_TOKEN,
        }
    )
    assert audit["status"] == "UNAUTHORIZED"
    assert audit["error"]["code"] == "NOT_AUTHORISED"


def test_the_authorisation_comparison_is_constant_time():
    """The token is compared with hmac.compare_digest, never with ==."""
    assert "hmac.compare_digest" in APP_SOURCE
    assert "presented_token ==" not in APP_SOURCE


def test_the_authorisation_token_is_never_echoed():
    """The token of the caller must not travel into the result."""
    refusal = app_module.refuse_unauthorised("audit_contract", "a reason")
    assert "auth_token" not in json.dumps(refusal)


# ---------------------------------------------------------------------------
# 8. The expectation evaluation of the driver
# ---------------------------------------------------------------------------


def _consistent_results(control_category: str = "SAFE_RUN") -> Dict[str, Any]:
    """
    A run that satisfies every expectation of the end-to-end test.

    The shape is the shape of the real result of the service, so the
    evaluation is exercised against the structure it will actually see.
    """
    breach_confirmed = control_category == "EXPLOIT_CONFIRMED"

    vulnerable_verdict = {
        "category": "EXPLOIT_CONFIRMED",
        "is_verified": True,
        "reproducible": True,
        "replay_status": "CONFIRMED",
        "replay_confirmed": True,
        "reward_score": 1.0,
        "state_delta_verified": False,
        "breach_evidence_basis": "trusted_harness_event",
        "verification_result": {
            "replay_confirmed": True,
            "confidence_status": "CONFIRMED",
        },
        "evidence": {
            "state_delta": {
                "has_real_snapshot": False,
                "state_changed": False,
                "trace_context": {"verified_event": True},
            }
        },
    }
    control_verdict = {
        "category": control_category,
        "is_verified": breach_confirmed,
        "reproducible": breach_confirmed,
        "replay_status": "CONFIRMED" if breach_confirmed else "NOT_ELIGIBLE",
        "replay_confirmed": breach_confirmed,
        "reward_score": 1.0 if breach_confirmed else -0.1,
        "state_delta_verified": False,
        "breach_evidence_basis": "none",
        "verification_result": {
            "replay_confirmed": breach_confirmed,
            "confidence_status": "CONFIRMED" if breach_confirmed else "UNVERIFIED",
        },
        "evidence": {"state_delta": {"has_real_snapshot": False, "state_changed": False}},
    }

    return {
        "environment_probe": {
            "declared_resources": {"gpu": None},
            "model_cache": {
                "write_probe": {"result": "READ_ONLY_ENFORCED"},
                "readable_files": [{"path": "trees/x.json"}],
            },
            "runtime": {"gpu_device_exposed": False, "nvidia_device_nodes": []},
            "toolchain": {
                "solc": (
                    "the `solc` on the PATH is the solc-select shim; it needs an "
                    "active version selection and therefore prints a traceback "
                    "instead of a version."
                ),
                "solc_on_path_is_a_shim": True,
                "pinned_solc": {
                    "requested_version": "0.8.20",
                    "path": "/root/.svm/0.8.20/solc-0.8.20",
                    "version_output": "solc, the solidity compiler commandline interface\nVersion: 0.8.20",
                    "error": None,
                },
            },
        },
        "vulnerable_target": {
            "status": "COMPLETED",
            "verdict": vulnerable_verdict,
            "reward": {
                "score": 1.0,
                "components": {
                    "generation": 0.05,
                    "compilation": 0.1,
                    "verification": 0.1,
                    "invariant": 0.25,
                    "replay": 0.5,
                },
                "penalty": 0.0,
                "spec_version": "2.0.0",
                "is_verified": True,
                "reproducible": True,
                "replay_status": "CONFIRMED",
                "replay_confirmed": True,
            },
            "consistency": {"all_consistent": True, "checks": {}},
            "stages": {
                "static_analysis": {
                    "analysis_mode": "slither",
                    "slither_version": "slither-analyzer 0.10.4",
                    "fallback_reason": None,
                    "finding_count": 5,
                },
                "hypothesis": {"count": 3},
                "verification": {
                    "execution": {
                        "return_code": 0,
                        "test_status": "Success",
                        "harness_verdict": "BREACH",
                        "harness_suite": "test/VaultHarness.t.sol",
                    }
                },
                "replay": {
                    "executed": True,
                    "reproduced": True,
                    "harness_verdict": "BREACH",
                    "return_code": 0,
                    "first_execution_id": "exec_aaaaaaaa",
                    "replay_execution_id": "exec_bbbbbbbb",
                    "independent_execution": True,
                    "independence_basis": "distinct_execution_id",
                },
            },
        },
        "safe_control": {
            "status": "COMPLETED",
            "verdict": control_verdict,
            "consistency": {"all_consistent": True, "checks": {}},
            "stages": {
                "replay": {
                    "executed": True,
                    "reproduced": breach_confirmed,
                    "harness_verdict": "BREACH" if breach_confirmed else "NO_BREACH",
                    "return_code": 0,
                }
            },
        },
        "invalid_contract": {"status": "REJECTED", "error": {"code": "TARGET_NOT_ALLOWED"}},
        "read_back": {"status": "READ_BACK", "parsed": True},
        "unauthorised_audit_contract": {
            "status": "UNAUTHORIZED",
            "error": {"code": "NOT_AUTHORISED"},
        },
        "unauthorised_probe_environment": {
            "status": "UNAUTHORIZED",
            "error": {"code": "NOT_AUTHORISED"},
        },
        "unauthorised_read_saved_result": {
            "status": "UNAUTHORIZED",
            "error": {"code": "NOT_AUTHORISED"},
        },
    }


def test_the_evaluation_passes_a_consistent_run():
    evaluation = _evaluate_expectations(_consistent_results("SAFE_RUN"))
    assert evaluation["failed"] == 0, [
        c for c in evaluation["checks"] if c["status"] != "PASS"
    ]
    assert evaluation["all_passed"] is True


def test_the_evaluation_detects_a_false_confirmation():
    """A breach reported for the safe control is a failure, not a pass."""
    evaluation = _evaluate_expectations(
        _consistent_results("EXPLOIT_CONFIRMED")
    )
    assert evaluation["all_passed"] is False
    failing = [c for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert any(c["check"] == "safe_control_not_confirmed" for c in failing)


def test_the_evaluation_does_not_accept_a_claim_of_reproducibility_alone():
    """
    ``reproducible=True`` alone is not a pass.

    A result that claims a confirmed exploit without an independent replay is
    a failure, even when every other flag looks perfect.
    """
    results = _consistent_results("SAFE_RUN")
    results["vulnerable_target"]["stages"]["replay"]["independent_execution"] = False
    results["vulnerable_target"]["stages"]["replay"]["replay_execution_id"] = (
        results["vulnerable_target"]["stages"]["replay"]["first_execution_id"]
    )

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "independent_replay_executed" in failing


def test_the_evaluation_detects_contradictory_verdict_fields():
    """A verdict whose fields disagree is a failure."""
    results = _consistent_results("SAFE_RUN")
    results["vulnerable_target"]["verdict"]["replay_status"] = "NOT_ELIGIBLE"

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "verdict_fields_are_consistent" in failing


def test_the_evaluation_detects_a_wrong_reward():
    """The reward has to be the sum of its own components."""
    results = _consistent_results("SAFE_RUN")
    results["vulnerable_target"]["reward"]["score"] = 1.0
    results["vulnerable_target"]["reward"]["components"]["replay"] = 0.0

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "reward_is_correctly_awarded" in failing


def test_the_evaluation_detects_a_state_delta_claim_without_a_snapshot():
    """``state_delta_verified`` may not be claimed without a real snapshot."""
    results = _consistent_results("SAFE_RUN")
    results["vulnerable_target"]["verdict"]["state_delta_verified"] = True

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "state_delta_claim_matches_the_evidence" in failing


def test_the_evaluation_detects_a_fallback_static_analysis():
    """A fallback must never be accepted as the analysis of the run."""
    results = _consistent_results("SAFE_RUN")
    results["vulnerable_target"]["stages"]["static_analysis"]["analysis_mode"] = (
        "fallback_heuristics"
    )

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "static_analysis_used_the_real_slither" in failing


def test_the_evaluation_requires_the_refusal_of_an_unauthorised_call():
    """A run that does not prove the refusal of a direct call is not complete."""
    results = _consistent_results("SAFE_RUN")
    results["unauthorised_audit_contract"] = {
        "status": "COMPLETED",
        "error": {"code": "NOT_AUTHORISED"},
    }

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "unauthorised_call_refused:audit_contract" in failing


def test_the_evaluation_requires_the_pinned_compiler_to_be_reported():
    """The probe has to report the pinned compiler, not a bare `solc`."""
    results = _consistent_results("SAFE_RUN")
    results["environment_probe"]["toolchain"]["pinned_solc"]["version_output"] = None

    evaluation = _evaluate_expectations(results)
    assert evaluation["all_passed"] is False
    failing = [c["check"] for c in evaluation["checks"] if c["status"] == "FAIL"]
    assert "pinned_compiler_reported" in failing


# ---------------------------------------------------------------------------
# 8. The secret scan
# ---------------------------------------------------------------------------


def test_the_secret_scan_reports_a_leaked_key():
    findings = _scan_for_secrets('the key is "AIzaSyA0123456789abcdefghijklmnopqrstuv"')
    assert findings


def test_the_secret_scan_is_quiet_on_ordinary_payloads():
    findings = _scan_for_secrets(json.dumps({"category": "SAFE_RUN", "reward": -0.1}))
    assert not findings
