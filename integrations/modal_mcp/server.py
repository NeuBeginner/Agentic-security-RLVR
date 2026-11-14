"""
modal_mcp.server
================

The assembly of the server: the MCP tools, the OAuth endpoints and the
authorisation in front of them.

The server speaks the **Streamable HTTP** transport of the MCP protocol. The
endpoint is ``/mcp``; the OAuth endpoints sit next to it.

Authorisation
-------------
Every request for the MCP endpoint needs a credential:

* the static bearer token of the owner - the way to call the server from a
  script, from ``curl`` or from the MCP Inspector; or
* an access token of the OAuth authorization server - the way a chat client
  such as ChatGPT calls it.

A request without a valid credential is refused with ``401`` before it
reaches a tool. The refusal names the metadata of the authorization server,
so that a client that supports OAuth can start the flow by itself.
"""

from __future__ import annotations

import hmac
import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings
from .context import set_principal
from .modal_access import ModalAccess
from .oauth import OAuthServer
from .policy import Policy
from .state import StateStore
from .tools import EXECUTES, MUTATES, READ_ONLY, ToolBox

#: The name of the server, as it is shown to a chat client.
SERVER_NAME = "aegis-modal-mcp"

#: The instructions of the server. They are the text that a model reads when
#: it decides which tool to call, so they state the boundary of the server
#: instead of advertising it.
SERVER_INSTRUCTIONS = """
This server exposes the Modal workspace of the Aegis-RLVR Solidity audit
service. It is a CPU-only service: it never allocates a GPU, it never changes
the configuration of the workspace and it never touches the production
dispatch of the benchmark.

Use the diagnostics (modal_status, modal_list_apps, modal_app_status,
modal_function_status, modal_logs, modal_billing) to answer questions about
the state of the deployment. Use modal_run_cpu_audit, modal_read_evidence,
modal_list_evidence, modal_environment_probe and modal_run_tests to work with
the audit service itself. Every call that starts work needs a unique
request_id, so that a captured request cannot be executed twice.

The management tools (modal_deploy_dev, modal_stop_app) change the workspace.
They are switched off unless the owner switched them on, and they need the
confirmation value of the owner.
""".strip()


class AuthenticatedApp:
    """
    The ASGI wrapper that checks the credential of every MCP request.

    The check happens before the request reaches a tool, so that an
    unauthenticated request can never trigger a side effect.
    """

    def __init__(self, app: ASGIApp, settings: Settings, oauth: OAuthServer) -> None:
        self.app = app
        self.settings = settings
        self.oauth = oauth

    def _bearer(self, headers: List[Tuple[bytes, bytes]]) -> str:
        for name, value in headers:
            if name.lower() == b"authorization":
                raw = value.decode("latin-1")
                if raw.lower().startswith("bearer "):
                    return raw[7:].strip()
                return ""
        return ""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        headers = [(key.lower(), value) for key, value in scope.get("headers", [])]
        token = self._bearer(headers)
        principal: Optional[str] = None

        if token:
            if self.settings.access_token and hmac.compare_digest(token, self.settings.access_token):
                principal = "bearer"
            else:
                principal = self.oauth.verify_bearer(token)

        if principal is None and self.settings.require_auth:
            host = ""
            for name, value in headers:
                if name == b"host":
                    host = value.decode("latin-1")
            resource = f"https://{host}/.well-known/oauth-protected-resource"
            body = json.dumps(
                {
                    "error": "unauthorized",
                    "error_description": "this server needs a bearer token or an OAuth access token",
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", f'Bearer resource_metadata="{resource}"'.encode("latin-1")),
                        (b"content-length", str(len(body)).encode("latin-1")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        set_principal(principal or "anonymous")
        await self.app(scope, receive, send)


def build_mcp(box: ToolBox) -> FastMCP:
    """Build the MCP server and register the tools of the toolbox."""
    from mcp.server.transport_security import TransportSecuritySettings

    mcp = FastMCP(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        stateless_http=True,
        # The DNS-rebinding protection of the SDK accepts only the hosts of
        # the local machine. The endpoint of this server is public and its
        # host changes with the deployment, so the protection is switched off
        # deliberately: every request for the MCP endpoint needs a credential
        # anyway, and the refusal of a request without one happens before a
        # tool is reached. The authorisation of the requests is the boundary
        # of this server, not the name of the host.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    mcp.tool(name="modal_status", annotations=READ_ONLY)(box.modal_status)
    mcp.tool(name="modal_list_apps", annotations=READ_ONLY)(box.modal_list_apps)
    mcp.tool(name="modal_app_status", annotations=READ_ONLY)(box.modal_app_status)
    mcp.tool(name="modal_function_status", annotations=READ_ONLY)(box.modal_function_status)
    mcp.tool(name="modal_logs", annotations=READ_ONLY)(box.modal_logs)
    mcp.tool(name="modal_billing", annotations=READ_ONLY)(box.modal_billing)

    mcp.tool(name="modal_run_cpu_audit", annotations=EXECUTES)(box.modal_run_cpu_audit)
    mcp.tool(name="modal_read_evidence", annotations=READ_ONLY)(box.modal_read_evidence)
    mcp.tool(name="modal_list_evidence", annotations=READ_ONLY)(box.modal_list_evidence)
    mcp.tool(name="modal_environment_probe", annotations=READ_ONLY)(box.modal_environment_probe)
    mcp.tool(name="modal_run_tests", annotations=EXECUTES)(box.modal_run_tests)

    mcp.tool(name="modal_deploy_dev", annotations=MUTATES)(box.modal_deploy_dev)
    mcp.tool(name="modal_stop_app", annotations=MUTATES)(box.modal_stop_app)

    return mcp


def build_app(
    settings: Settings,
    policy: Policy,
    access: ModalAccess,
    state: StateStore,
) -> ASGIApp:
    """Build the ASGI application of the server."""
    box = ToolBox(settings, policy, access, state)
    mcp = build_mcp(box)
    inner = mcp.streamable_http_app()

    oauth = OAuthServer(settings, state)
    routes = [
        Route("/.well-known/oauth-authorization-server", oauth.metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", oauth.resource_metadata, methods=["GET"]),
        Route("/register", oauth.register, methods=["POST"]),
        Route("/authorize", oauth.authorize_page, methods=["GET"]),
        Route("/authorize", oauth.authorize, methods=["POST"]),
        Route("/token", oauth.token, methods=["POST"]),
        *inner.routes,
    ]

    app = Starlette(routes=routes, lifespan=inner.router.lifespan_context)
    return AuthenticatedApp(app, settings, oauth)


def describe(settings: Settings) -> Dict[str, Any]:
    """A short description of the configuration of the server (no secrets)."""
    return {
        "server": SERVER_NAME,
        "settings": settings.public_view(),
    }
