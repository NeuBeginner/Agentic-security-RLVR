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


class FakeAccess:
    """A fake access layer that records the calls of the tools."""

    def __init__(self, cpu_audit_token: str = "cpu-audit-token") -> None:
        self.calls: list[tuple] = []
        self.cpu_audit_token = cpu_audit_token

    def list_apps(self):
        self.calls.append(("list_apps",))
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
    policy.check_write("modal_stop_app", ACCESS_TOKEN)


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
    assert names["aegis-rlvr-cpu-audit"] is True
    assert names["something-else"] is False


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
    result = box.modal_stop_app("aegis-rlvr-cpu-audit", ACCESS_TOKEN, "req-stop-0002")
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
        approval = client.post(
            "/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state-1",
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
        approval = client.post(
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
