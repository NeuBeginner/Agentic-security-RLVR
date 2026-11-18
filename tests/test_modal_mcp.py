"""
tests/test_modal_mcp.py
=======================

The tests of the Modal MCP server.

The tests are hermetic: they need neither a Modal account nor a network. The
Modal access layer is replaced by a fake that records the calls, so that the
tests prove the *policy* of the server - what it allows, what it refuses and
what it never returns - and not the behaviour of the API of Modal.

The covered rules are the ones that matter for the security of the
integration:

* only the allowlisted applications, functions and environments are reachable;
* a request without a valid credential is refused before it reaches a tool;
* a request that was already executed cannot be executed twice;
* a write operation needs both the write switch and the confirmation value;
* no result carries a credential.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from integrations.modal_mcp.config import Settings  # noqa: E402
from integrations.modal_mcp.modal_access import AccessError  # noqa: E402
from integrations.modal_mcp.oauth import OAuthServer  # noqa: E402
from integrations.modal_mcp.policy import Policy, PolicyError, request_fingerprint  # noqa: E402
from integrations.modal_mcp.server import build_app  # noqa: E402
from integrations.modal_mcp.state import MemoryStateStore  # noqa: E402
from integrations.modal_mcp.tools import ToolBox  # noqa: E402

ACCESS_TOKEN = "test-access-token-0123456789abcdef"
ENROLLMENT_CODE = "test-enrollment-code-9876543210"
WRITE_CONFIRMATION = "test-write-confirmation-secret-xyz"


def _extract_csrf(html_text: str) -> str:
    import re as _re

    match = _re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    assert match is not None, "csrf_token hidden input missing from /authorize page"
    return match.group(1)


class FakeAccess:
    """A fake access layer that records the calls of the tools."""

    def __init__(self, cpu_audit_token: str = "cpu-audit-token") -> None:
        self.calls: list[tuple] = []
        self.cpu_audit_token = cpu_audit_token

    def list_apps(self, environment=None):
        self.calls.append(("list_apps", environment))
        return [
            {
                "app_id": "ap-aaaaaaaaaaaaaaaaaaaa",
                "name": "aegis-rlvr-cpu-audit",
                "description": "aegis-rlvr-cpu-audit",
                "state": "APP_STATE_DEPLOYED",
                "created_at": "2026-11-14 17:23:37",
                "stopped_at": None,
                "running_tasks": 0,
            },
            {
                "app_id": "ap-bbbbbbbbbbbbbbbbbbbb",
                "name": "something-else",
                "description": "something-else",
                "state": "APP_STATE_STOPPED",
                "created_at": "2026-11-14 17:20:45",
                "stopped_at": "2026-11-14 17:20:50",
                "running_tasks": 0,
            },
        ]

    def app_status(self, app):
        self.calls.append(("app_status", app))
        return {
            "app_id": "ap-aaaaaaaaaaaaaaaaaaaa",
            "name": app,
            "state": "APP_STATE_DEPLOYED",
            "environment": "main",
        }

    def function_status(self, app, function):
        self.calls.append(("function_status", app, function))
        return {
            "app_name": app,
            "function_name": function,
            "function_id": "fu-test",
            "timeout_sec": 600,
            "app_state": "APP_STATE_DEPLOYED",
        }

    def logs(self, app, limit=50):
        self.calls.append(("logs", app, limit))
        return [{"timestamp": 1.0, "message": "line"}]

    def billing(self):
        self.calls.append(("billing",))
        return {"metered_cost": 6.08, "billed_cost": 0.0}

    def call_function(self, app, function, payload):
        self.calls.append(("call_function", app, function, payload))
        if not self.cpu_audit_token:
            raise AccessError(
                "CPU_AUTH_TOKEN_MISSING",
                "the server carries no authorisation token for the CPU audit service",
            )
        return {"status": "COMPLETED", "function": function, "payload": payload}

    def list_volume(self, volume, path):
        self.calls.append(("list_volume", volume, path))
        return [{"path": "runs/run-0001", "type": "DIRECTORY", "size": 0}]

    def read_volume_file(self, volume, path):
        self.calls.append(("read_volume_file", volume, path))
        if path.endswith("run-0001/result.json"):
            return b'{"status": "COMPLETED", "reward": 1.0}'
        return None

    def stop_app(self, app_id):
        self.calls.append(("stop_app", app_id))
        return {"app_id": app_id, "stopped": True}


def make_settings(**overrides) -> Settings:
    base = dict(
        modal_token_id="ak-test",
        modal_token_secret="as-test",
        access_token=ACCESS_TOKEN,
        enrollment_code=ENROLLMENT_CODE,
        write_confirmation_secret=WRITE_CONFIRMATION,
        cpu_audit_token="cpu-audit-token",
        allowed_apps=("aegis-rlvr-cpu-audit",),
        allowed_functions=(
            "aegis-rlvr-cpu-audit:audit_contract",
            "aegis-rlvr-cpu-audit:read_saved_result",
            "aegis-rlvr-cpu-audit:probe_environment",
        ),
        allowed_environments=("main",),
        write_enabled=False,
        require_auth=True,
        targets_dir=str(_ROOT / "benchmarks" / "targets" / "solidity"),
        pocs_dir=str(_ROOT / "benchmarks" / "cpu_audit_pocs"),
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture()
def settings() -> Settings:
    return make_settings()


@pytest.fixture()
def toolbox(settings: Settings):
    access = FakeAccess()
    box = ToolBox(settings, Policy(settings), access, MemoryStateStore())
    box.access = access
    return box


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------


def test_environment_outside_the_allowlist_is_refused(settings):
    policy = Policy(settings)
    with pytest.raises(PolicyError) as error:
        policy.check_environment("production")
    assert error.value.code == "ENVIRONMENT_NOT_ALLOWED"


def test_application_outside_the_allowlist_is_refused(settings):
    policy = Policy(settings)
    with pytest.raises(PolicyError) as error:
        policy.check_app("aegis-rlvr-security")
    assert error.value.code == "APP_NOT_ALLOWED"


def test_function_outside_the_allowlist_is_refused(settings):
    policy = Policy(settings)
    with pytest.raises(PolicyError) as error:
        policy.check_function("aegis-rlvr-cpu-audit", "production_dispatch")
    assert error.value.code == "FUNCTION_NOT_ALLOWED"


def test_write_operation_is_refused_while_the_switch_is_off(settings):
    policy = Policy(settings)
    with pytest.raises(PolicyError) as error:
        policy.check_write("modal_stop_app", ACCESS_TOKEN)
    assert error.value.code == "WRITE_DISABLED"


def test_write_operation_needs_the_confirmation_value(settings):
    policy = Policy(make_settings(write_enabled=True))
    with pytest.raises(PolicyError) as error:
        policy.check_write("modal_stop_app", "wrong-value")
    assert error.value.code == "CONFIRMATION_REQUIRED"
    with pytest.raises(PolicyError) as error_token:
        policy.check_write("modal_stop_app", ACCESS_TOKEN)
    assert error_token.value.code == "CONFIRMATION_REQUIRED"
    policy.check_write("modal_stop_app", WRITE_CONFIRMATION)


def test_request_id_has_to_be_bounded(settings):
    policy = Policy(settings)
    with pytest.raises(PolicyError) as error:
        policy.check_request_id("short")
    assert error.value.code == "REQUEST_ID_INVALID"


def test_the_fingerprint_binds_the_tool_and_the_arguments():
    first = request_fingerprint("modal_run_cpu_audit", {"target_name": "Vault"})
    same = request_fingerprint("modal_run_cpu_audit", {"target_name": "Vault"})
    other = request_fingerprint("modal_run_cpu_audit", {"target_name": "SecureVault"})
    other_tool = request_fingerprint("modal_run_tests", {"target_name": "Vault"})
    assert first == same
    assert first != other
    assert first != other_tool


# ---------------------------------------------------------------------------
# The replay ledger
# ---------------------------------------------------------------------------


def test_the_same_request_is_executed_once(toolbox):
    first = toolbox.modal_run_tests("probe", "req-replay-0001")
    assert first["status"] == "OK"
    second = toolbox.modal_run_tests("probe", "req-replay-0001")
    assert second["status"] == "REFUSED"
    assert second["error"]["code"] == "REPLAY_DETECTED"


def test_a_request_id_cannot_be_reused_for_another_request(toolbox):
    toolbox.modal_run_tests("probe", "req-reuse-0001")
    again = toolbox.modal_run_tests("candidate_registry", "req-reuse-0001")
    assert again["status"] == "REFUSED"
    assert again["error"]["code"] == "REQUEST_ID_REUSED"


def test_a_replayed_fingerprint_is_refused_under_another_identifier(toolbox):
    toolbox.modal_run_tests("probe", "req-first-0001")
    # The same request under a different identifier: the fingerprint of the
    # request is the same, so the ledger refuses it as well.
    again = toolbox.modal_run_tests("probe", "req-second-0001")
    assert again["status"] == "REFUSED"
    assert again["error"]["code"] == "REPLAY_DETECTED"


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


def test_the_status_tool_reports_the_configuration_without_a_secret(toolbox):
    result = toolbox.modal_status()
    assert result["status"] == "OK"
    assert result["server"]["modal_credentials_present"] is True
    assert result["server"]["access_token_present"] is True
    serialised = json.dumps(result)
    assert ACCESS_TOKEN not in serialised
    assert "cpu-audit-token" not in serialised


def test_the_list_of_applications_marks_the_allowlisted_one(toolbox):
    result = toolbox.modal_list_apps()
    names = {app["name"]: app["allowlisted"] for app in result["applications"]}
    assert names == {"aegis-rlvr-cpu-audit": True}


def test_a_tool_of_an_unknown_application_is_refused(toolbox):
    result = toolbox.modal_app_status("something-else")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "APP_NOT_ALLOWED"


def test_the_logs_of_an_unknown_application_are_refused(toolbox):
    result = toolbox.modal_logs("something-else")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "APP_NOT_ALLOWED"


def test_the_audit_service_is_called_with_the_shared_token(toolbox):
    result = toolbox.modal_run_cpu_audit("Vault", "req-audit-0001")
    assert result["status"] == "OK"
    call = [c for c in toolbox.access.calls if c[0] == "call_function"][-1]
    assert call[1] == "aegis-rlvr-cpu-audit"
    assert call[2] == "audit_contract"
    assert call[3]["target_name"] == "Vault"
    assert "contract" in call[3]["source_code"].lower()


def test_the_audit_of_a_target_without_a_harness_is_refused(toolbox):
    result = toolbox.modal_run_cpu_audit("NotAllowlisted", "req-audit-0002")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "TARGET_SOURCE_UNAVAILABLE"


def test_the_control_target_is_read_from_the_controls_directory(toolbox):
    result = toolbox.modal_run_cpu_audit("SecureVault", "req-audit-0003")
    assert result["status"] == "OK"
    call = [c for c in toolbox.access.calls if c[0] == "call_function"][-1]
    assert call[3]["target_name"] == "SecureVault"


def test_the_evidence_is_read_from_the_committed_state_of_the_volume(toolbox):
    result = toolbox.modal_read_evidence("run-0001")
    assert result["status"] == "OK"
    artifact = result["artifact"]
    assert artifact["parsed"] is True
    assert artifact["result"]["reward"] == 1.0
    assert len(artifact["sha256"]) == 64
    assert artifact["byte_length"] > 0
    assert ("read_volume_file", "aegis-cpu-audit-results", "runs/run-0001/result.json") in toolbox.access.calls


def test_the_evidence_of_an_unknown_run_is_refused(toolbox):
    result = toolbox.modal_read_evidence("run-unknown")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "ARTIFACT_NOT_FOUND"


def test_an_unknown_test_suite_is_refused(toolbox):
    result = toolbox.modal_run_tests("pytest -k everything", "req-suite-0001")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "SUITE_NOT_ALLOWED"


def test_the_stop_tool_is_refused_while_the_write_switch_is_off(toolbox):
    result = toolbox.modal_stop_app("aegis-rlvr-cpu-audit", ACCESS_TOKEN, "req-stop-0001")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "WRITE_DISABLED"
    assert not [c for c in toolbox.access.calls if c[0] == "stop_app"]


def test_the_stop_tool_stops_the_application_with_the_confirmation(settings):
    box = ToolBox(
        make_settings(write_enabled=True),
        Policy(make_settings(write_enabled=True)),
        FakeAccess(),
        MemoryStateStore(),
    )
    result = box.modal_stop_app("aegis-rlvr-cpu-audit", WRITE_CONFIRMATION, "req-stop-0002")
    assert result["status"] == "OK"
    assert [c for c in box.access.calls if c[0] == "stop_app"]


def test_the_deploy_tool_is_refused_in_the_first_stage(toolbox):
    result = toolbox.modal_deploy_dev("main", ACCESS_TOKEN, "req-deploy-0001")
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] in ("WRITE_DISABLED", "DEPLOY_NOT_IMPLEMENTED")


def test_a_missing_cpu_token_is_a_clear_refusal(settings):
    box = ToolBox(
        make_settings(cpu_audit_token=""),
        Policy(make_settings(cpu_audit_token="")),
        FakeAccess(cpu_audit_token=""),
        MemoryStateStore(),
    )
    result = box.modal_environment_probe()
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "CPU_AUTH_TOKEN_MISSING"


def test_the_access_error_is_turned_into_a_refusal(settings):
    class FailingAccess(FakeAccess):
        def call_function(self, app, function, payload):
            raise AccessError("CPU_AUTH_TOKEN_MISSING", "the token is missing")

    box = ToolBox(settings, Policy(settings), FailingAccess(), MemoryStateStore())
    result = box.modal_environment_probe()
    assert result["status"] == "REFUSED"
    assert result["error"]["code"] == "CPU_AUTH_TOKEN_MISSING"


# ---------------------------------------------------------------------------
# The authorisation of the HTTP endpoint
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(settings):
    from starlette.testclient import TestClient

    box = ToolBox(settings, Policy(settings), FakeAccess(), MemoryStateStore())
    app = build_app(settings, Policy(settings), FakeAccess(), MemoryStateStore())
    with TestClient(app) as test_client:
        yield test_client


def _mcp_post(client, payload, token=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post("/mcp", json=payload, headers=headers)


def test_the_endpoint_refuses_a_request_without_a_credential(client):
    response = _mcp_post(
        client,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}},
    )
    assert response.status_code == 401
    assert "resource_metadata" in response.headers.get("www-authenticate", "")


def test_the_endpoint_refuses_a_wrong_credential(client):
    response = _mcp_post(
        client,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}},
        token="not-the-token",
    )
    assert response.status_code == 401


def test_the_endpoint_accepts_the_access_token_of_the_owner(client):
    response = _mcp_post(
        client,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}},
        token=ACCESS_TOKEN,
    )
    assert response.status_code == 200


def test_the_metadata_of_the_authorization_server_is_public(client):
    response = client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    payload = response.json()
    assert payload["response_types_supported"] == ["code"]
    assert payload["code_challenge_methods_supported"] == ["S256"]
    assert payload["registration_endpoint"].endswith("/register")


def test_the_metadata_of_the_protected_resource_is_public(client):
    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    assert response.json()["bearer_methods_supported"] == ["header"]


# ---------------------------------------------------------------------------
# The OAuth flow
# ---------------------------------------------------------------------------


def _pkce_pair():
    import base64
    import hashlib
    import os as _os

    verifier = base64.urlsafe_b64encode(_os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def test_the_full_oauth_flow_issues_a_working_token(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    oauth = OAuthServer(settings, state)
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        # 1. the client registers itself
        registration = client.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert registration.status_code == 201
        client_id = registration.json()["client_id"]
        assert "client_secret" not in registration.json()

        # 2. the owner approves the client
        verifier, challenge = _pkce_pair()
        redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect"
        page = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-1",
            },
        )
        assert page.status_code == 200
        csrf_token = _extract_csrf(page.text)
        approval = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-1",
                "csrf_token": csrf_token,
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        assert approval.status_code == 302
        location = approval.headers["location"]
        assert location.startswith(redirect_uri)
        code = location.split("code=")[1].split("&")[0]

        # 3. the client exchanges the code for a token
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200
        access_token = token.json()["access_token"]
        refresh_token = token.json()["refresh_token"]

        # 4. the token opens the MCP endpoint
        response = _mcp_post(
            client,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "chatgpt", "version": "1"}}},
            token=access_token,
        )
        assert response.status_code == 200

        # 5. the refresh token issues a new access token
        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["access_token"] != access_token


def test_the_consent_page_refuses_a_wrong_enrolment_code(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        registration = client.post(
            "/register",
            json={
                "client_name": "attacker",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = registration.json()["client_id"]
        verifier, challenge = _pkce_pair()
        approval = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "enrollment_code": "wrong",
            },
            follow_redirects=False,
        )
        assert approval.status_code == 403


def test_the_code_is_refused_without_the_matching_verifier(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        registration = client.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = registration.json()["client_id"]
        _, challenge = _pkce_pair()
        page = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert page.status_code == 200
        csrf_token = _extract_csrf(page.text)
        approval = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "csrf_token": csrf_token,
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        code = approval.headers["location"].split("code=")[1].split("&")[0]
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_verifier": "a-wrong-verifier-that-is-long-enough",
            },
        )
        assert token.status_code == 400
        assert token.json()["error"] == "invalid_grant"


def test_an_unregistered_redirect_uri_is_refused(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        registration = client.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = registration.json()["client_id"]
        _, challenge = _pkce_pair()
        response = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://evil.example/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Hardening regression tests (P0, P1, P2)
# ---------------------------------------------------------------------------


def test_modal_run_cpu_audit_rejects_source_code_and_candidate_code(toolbox):
    import inspect

    params = inspect.signature(toolbox.modal_run_cpu_audit).parameters
    assert "source_code" not in params
    assert "candidate_code" not in params
    with pytest.raises(TypeError):
        toolbox.modal_run_cpu_audit("Vault", "req-inject-0001", source_code="contract Evil {}")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        toolbox.modal_run_cpu_audit("Vault", "req-inject-0002", candidate_code="contract PoC {}")  # type: ignore[call-arg]


def test_invalid_target_and_run_id_do_not_poison_replay_guard(toolbox):
    bad_target = toolbox.modal_run_cpu_audit("NonExistentTarget", "req-poison-0001")
    assert bad_target["status"] == "REFUSED"
    assert bad_target["error"]["code"] == "TARGET_SOURCE_UNAVAILABLE"

    bad_run = toolbox.modal_run_cpu_audit("Vault", "req-poison-0001", run_id="../escape")
    assert bad_run["status"] == "REFUSED"
    assert bad_run["error"]["code"] == "RUN_ID_INVALID"

    # Because neither invalid call wrote to _replay_guard, the same request_id
    # still succeeds for a valid request.
    good = toolbox.modal_run_cpu_audit("Vault", "req-poison-0001", run_id="run-valid-01")
    assert good["status"] == "OK"


def test_env_cannot_override_cpu_only_apps_or_functions(monkeypatch):
    monkeypatch.setenv("MODAL_MCP_ALLOWED_APPS", "aegis-rlvr-security,aegis-rlvr-cpu-audit")
    monkeypatch.setenv(
        "MODAL_MCP_ALLOWED_FUNCTIONS",
        "aegis-rlvr-security:verify_exploit_remote,aegis-rlvr-cpu-audit:audit_contract",
    )
    resolved = Settings.from_env()
    assert resolved.allowed_apps == ("aegis-rlvr-cpu-audit",)
    assert resolved.allowed_functions == ("aegis-rlvr-cpu-audit:audit_contract",)

    # Even direct Settings construction intersects with CPU_ONLY_APPS / CPU_ONLY_FUNCTIONS.
    direct = make_settings(
        allowed_apps=("aegis-rlvr-security",),
        allowed_functions=("aegis-rlvr-security:verify_exploit_remote",),
    )
    assert direct.allowed_apps == ()
    assert direct.allowed_functions == ()


def test_modal_access_call_function_blocks_r1_and_non_cpu_call_sites():
    from integrations.modal_mcp.modal_access import ModalAccess

    access = ModalAccess("ak-test", "as-test", cpu_audit_token="cpu-token")
    with pytest.raises(AccessError) as err_r1:
        access.call_function("aegis-rlvr-security", "verify_exploit_remote", {})
    assert err_r1.value.code == "CALL_SITE_NOT_ALLOWED"

    with pytest.raises(AccessError) as err_other:
        access.call_function("aegis-rlvr-cpu-audit", "train_grpo_remote", {})
    assert err_other.value.code == "CALL_SITE_NOT_ALLOWED"


def test_rate_limits_and_audit_quotas_are_enforced():
    limited = make_settings(audit_hourly_limit=1, audit_daily_limit=2, tool_rate_limit_per_min=1)
    box = ToolBox(limited, Policy(limited), FakeAccess(), MemoryStateStore())

    first = box.modal_run_cpu_audit("Vault", "req-quota-0001", run_id="run-q-1")
    assert first["status"] == "OK"
    second = box.modal_run_cpu_audit("Vault", "req-quota-0002", run_id="run-q-2")
    assert second["status"] == "REFUSED"
    assert second["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Hourly cap
    hourly_box = ToolBox(
        make_settings(audit_hourly_limit=1, audit_daily_limit=10, tool_rate_limit_per_min=10),
        Policy(make_settings(audit_hourly_limit=1, audit_daily_limit=10, tool_rate_limit_per_min=10)),
        FakeAccess(),
        MemoryStateStore(),
    )
    assert hourly_box.modal_run_cpu_audit("Vault", "req-hr-0001", run_id="run-h-1")["status"] == "OK"
    hr2 = hourly_box.modal_run_cpu_audit("Vault", "req-hr-0002", run_id="run-h-2")
    assert hr2["status"] == "REFUSED"
    assert hr2["error"]["code"] == "AUDIT_QUOTA_EXCEEDED"

    # Probe and read_evidence rate-limited too
    probe_box = ToolBox(
        make_settings(tool_rate_limit_per_min=1),
        Policy(make_settings(tool_rate_limit_per_min=1)),
        FakeAccess(),
        MemoryStateStore(),
    )
    assert probe_box.modal_environment_probe()["status"] == "OK"
    assert probe_box.modal_environment_probe()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert probe_box.modal_read_evidence("run-0001")["status"] == "OK"
    assert probe_box.modal_read_evidence("run-0001")["error"]["code"] == "RATE_LIMIT_EXCEEDED"


def test_tool_timeout_sec_and_max_result_bytes_are_enforced():
    import time as _time

    class SlowAccess(FakeAccess):
        def call_function(self, app, function, payload):
            _time.sleep(0.3)
            return super().call_function(app, function, payload)

    timeout_settings = make_settings(tool_timeout_sec=0.05)  # type: ignore[arg-type]
    box = ToolBox(timeout_settings, Policy(timeout_settings), SlowAccess(), MemoryStateStore())
    res = box.modal_environment_probe()
    assert res["status"] == "REFUSED"
    assert res["error"]["code"] == "TOOL_TIMEOUT"

    small_settings = make_settings(max_result_bytes=120)
    small_box = ToolBox(small_settings, Policy(small_settings), FakeAccess(), MemoryStateStore())
    status_res = small_box.modal_status()
    assert status_res["truncated"] is True
    assert len(json.dumps(status_res).encode("utf-8")) <= 120


def test_oauth_redirect_uri_rejects_localhost_subdomain_trick(settings):
    from starlette.testclient import TestClient

    app = build_app(settings, Policy(settings), FakeAccess(), MemoryStateStore())
    with TestClient(app) as client:
        bad = client.post(
            "/register",
            json={
                "client_name": "evil",
                "redirect_uris": ["http://localhost.evil.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert bad.status_code == 400
        assert bad.json()["error"] == "invalid_redirect_uri"

        good_local = client.post(
            "/register",
            json={
                "client_name": "local",
                "redirect_uris": ["http://127.0.0.1:8080/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert good_local.status_code == 201


def test_oauth_enrollment_code_is_one_time_and_csrf_and_headers_enforced(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        reg = client.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = reg.json()["client_id"]
        _, challenge = _pkce_pair()

        page = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert page.status_code == 200
        assert page.headers.get("x-frame-options") == "DENY"
        assert "frame-ancestors 'none'" in page.headers.get("content-security-policy", "")
        csrf = _extract_csrf(page.text)

        # Missing CSRF is refused
        no_csrf = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        assert no_csrf.status_code == 403

        # First valid use succeeds
        ok = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "csrf_token": csrf,
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        assert ok.status_code == 302

        # Second use of the same enrollment_code is refused
        page2 = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        csrf2 = _extract_csrf(page2.text)
        reused = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "csrf_token": csrf2,
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        assert reused.status_code == 403


def test_oauth_register_and_authorize_rate_limits(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        for i in range(10):
            r = client.post(
                "/register",
                json={
                    "client_name": f"c-{i}",
                    "redirect_uris": ["https://chatgpt.com/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201
            client_id = r.json()["client_id"]
        limited = client.post(
            "/register",
            json={
                "client_name": "c-over",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert limited.status_code == 429

        _, challenge = _pkce_pair()
        for _ in range(5):
            p = client.get(
                "/authorize",
                params={
                    "client_id": client_id,
                    "redirect_uri": "https://chatgpt.com/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
            csrf = _extract_csrf(p.text)
            bad = client.post(
                "/authorize",
                data={
                    "client_id": client_id,
                    "redirect_uri": "https://chatgpt.com/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "csrf_token": csrf,
                    "enrollment_code": "wrong-code",
                },
                follow_redirects=False,
            )
            assert bad.status_code == 403
        locked = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        assert locked.status_code == 429


def test_oauth_token_redirect_uri_required_refresh_rotation_and_revoke(settings):
    from starlette.testclient import TestClient

    state = MemoryStateStore()
    app = build_app(settings, Policy(settings), FakeAccess(), state)
    with TestClient(app) as client:
        reg = client.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        client_id = reg.json()["client_id"]
        verifier, challenge = _pkce_pair()
        page = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        csrf = _extract_csrf(page.text)
        ok = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "csrf_token": csrf,
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        code = ok.headers["location"].split("code=")[1].split("&")[0]

        # Omitting redirect_uri on /token is refused
        missing_redir = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        assert missing_redir.status_code == 400

        # Valid exchange
        page2_code_state = client.post(
            "/register",
            json={
                "client_name": "chatgpt2",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert page2_code_state.status_code == 201

    # Fresh store for clean authorization code test
    state2 = MemoryStateStore()
    app2 = build_app(settings, Policy(settings), FakeAccess(), state2)
    with TestClient(app2) as client2:
        reg2 = client2.post(
            "/register",
            json={
                "client_name": "chatgpt",
                "redirect_uris": ["https://chatgpt.com/cb"],
                "token_endpoint_auth_method": "none",
            },
        )
        cid2 = reg2.json()["client_id"]
        v2, c2 = _pkce_pair()
        p2 = client2.get(
            "/authorize",
            params={
                "client_id": cid2,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": c2,
                "code_challenge_method": "S256",
            },
        )
        ok2 = client2.post(
            "/authorize",
            data={
                "client_id": cid2,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_challenge": c2,
                "code_challenge_method": "S256",
                "csrf_token": _extract_csrf(p2.text),
                "enrollment_code": ENROLLMENT_CODE,
            },
            follow_redirects=False,
        )
        auth_code = ok2.headers["location"].split("code=")[1].split("&")[0]
        tok = client2.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": cid2,
                "redirect_uri": "https://chatgpt.com/cb",
                "code_verifier": v2,
            },
        )
        assert tok.status_code == 200
        rt1 = tok.json()["refresh_token"]

        # Refresh token rotation: rt1 works once, then is revoked
        ref = client2.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": rt1, "client_id": cid2},
        )
        assert ref.status_code == 200
        at2 = ref.json()["access_token"]
        rt2 = ref.json()["refresh_token"]
        assert rt2 != rt1

        reused_rt = client2.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": rt1, "client_id": cid2},
        )
        assert reused_rt.status_code == 400

        # /revoke invalidates at2
        rev = client2.post("/revoke", data={"token": at2})
        assert rev.status_code == 200
        after_rev = _mcp_post(
            client2,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "chatgpt", "version": "1"}}},
            token=at2,
        )
        assert after_rev.status_code == 401


def test_host_header_injection_is_blocked(settings):
    from starlette.testclient import TestClient

    app = build_app(settings, Policy(settings), FakeAccess(), MemoryStateStore())
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"Host": 'evil.com",foo="bar'},
        )
        assert resp.status_code == 401
        www = resp.headers.get("www-authenticate", "")
        assert "evil.com" not in www
        assert "https://localhost/.well-known/oauth-protected-resource" in www


def test_modal_dict_state_store_ttl_none_and_fail_closed():
    from integrations.modal_mcp.state import ModalDictStateStore

    class FakeModalDict:
        def __init__(self):
            self.data = {}
            self.fail_on_get = False

        def get(self, key):
            if self.fail_on_get:
                raise ConnectionError("modal network down")
            if key not in self.data:
                raise KeyError(key)
            return self.data[key]

        def __setitem__(self, key, value):
            self.data[key] = value

        def pop(self, key):
            if key not in self.data:
                raise KeyError(key)
            return self.data.pop(key)

    store = ModalDictStateStore.__new__(ModalDictStateStore)
    store._dict_name = "test"
    store._client = None
    store._dict = FakeModalDict()

    # ttl_sec=None must not crash with float(None)
    store.put_json("perm", {"ok": True}, ttl_sec=None)
    assert store.get_json("perm") == {"ok": True}
    assert store.get_json("missing") is None

    # Network error must propagate (fail-closed), not return None
    store._dict.fail_on_get = True
    with pytest.raises(ConnectionError):
        store.get_json("perm")


def test_logs_redaction_and_volume_read_limits_and_client_cache():
    from integrations.modal_mcp.modal_access import ModalAccess, _CLIENT_HOLDER, _redact_log_text

    redacted = _redact_log_text("Authorization: Bearer at_secret123456 ak-1234567890 as-abcdefghij rt_xyz987654")
    assert "at_secret123456" not in redacted
    assert "ak-1234567890" not in redacted
    assert "as-abcdefghij" not in redacted
    assert "rt_xyz987654" not in redacted

    access = ModalAccess("ak-test", "as-test", cpu_audit_token="tok")
    with pytest.raises(AccessError) as err_vol:
        access.read_volume_file("other-volume", "runs/run-1/result.json")
    assert err_vol.value.code == "VOLUME_NOT_ALLOWED"

    with pytest.raises(AccessError) as err_path:
        access.read_volume_file("aegis-cpu-audit-results", "runs/../../etc/passwd")
    assert err_path.value.code == "VOLUME_PATH_INVALID"

    _CLIENT_HOLDER.clear()


def test_audit_redacts_confirmation_and_context_sets_request_id(capsys):
    from integrations.modal_mcp.context import get_request_id, set_request_id
    from integrations.modal_mcp.policy import audit

    set_request_id("req-audit-ctx-01")
    assert get_request_id() == "req-audit-ctx-01"
    audit("write_attempt", confirmation="super-secret-value", app="aegis-rlvr-cpu-audit")
    captured = capsys.readouterr().out
    assert "super-secret-value" not in captured
    assert '"confirmation": "[redacted]"' in captured
