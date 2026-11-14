"""
integrations/modal_mcp/__main__.py
==================================

The local runner of the MCP server.

The local run exists for the development and for the verification of the
server without a deployment: it serves the same ASGI application on
``127.0.0.1``, with the same authorisation, so that a call against the local
endpoint proves the same thing as a call against the deployed one.

Examples::

    python -m integrations.modal_mcp --port 8765
    python -m integrations.modal_mcp --use-local-profile --require-auth false
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from integrations.modal_mcp.config import Settings  # noqa: E402
from integrations.modal_mcp.modal_access import ModalAccess  # noqa: E402
from integrations.modal_mcp.policy import Policy  # noqa: E402
from integrations.modal_mcp.server import build_app  # noqa: E402
from integrations.modal_mcp.state import MemoryStateStore  # noqa: E402


def _local_profile_credentials() -> tuple[str, str]:
    """
    The credentials of the active local Modal profile.

    They are used only by a local run that was started with
    ``--use-local-profile``. The deployed server never falls back to them: it
    uses the dedicated credential of its own secret.
    """
    from modal.config import config

    token_id = config.get("token_id")
    token_secret = config.get("token_secret")
    if not token_id or not token_secret:
        raise RuntimeError(
            "the active local Modal profile has no credential; log in with "
            "`modal token set` or start the server with the dedicated credential"
        )
    return token_id, token_secret


def main(argv: list[str] | None = None) -> int:
    """Run the server locally."""
    parser = argparse.ArgumentParser(description="run the Modal MCP server locally")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--use-local-profile",
        action="store_true",
        help="use the credential of the active local Modal profile instead of the "
        "dedicated credential of the environment",
    )
    parser.add_argument(
        "--require-auth",
        choices=("true", "false"),
        help="require a credential on the MCP endpoint (default: true)",
    )
    args = parser.parse_args(argv)

    if args.require_auth is not None:
        os.environ["MODAL_MCP_REQUIRE_AUTH"] = args.require_auth

    settings = Settings.from_env()
    if args.use_local_profile:
        token_id, token_secret = _local_profile_credentials()
        settings = Settings.from_env()
        object.__setattr__(settings, "modal_token_id", token_id)
        object.__setattr__(settings, "modal_token_secret", token_secret)

    if not settings.has_modal_credentials:
        print(
            "the dedicated Modal credential is missing: set MODAL_MCP_TOKEN_ID and "
            "MODAL_MCP_TOKEN_SECRET, or start the server with --use-local-profile",
            file=sys.stderr,
        )
        return 2

    policy = Policy(settings)
    access = ModalAccess(
        settings.modal_token_id,
        settings.modal_token_secret,
        environment=settings.allowed_environments[0],
        cpu_audit_token=settings.cpu_audit_token,
    )
    state = MemoryStateStore()
    app = build_app(settings, policy, access, state)

    import uvicorn

    print(
        f"the Modal MCP server listens on http://{args.host}:{args.port}/mcp "
        f"(require_auth={settings.require_auth}, write_enabled={settings.write_enabled})",
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
