"""
modal_mcp.config
================

The settings of the Modal MCP server.

Every setting is read from the environment, because the deployed server gets
its credentials from a Modal Secret and its switch positions from the
environment of the app. Nothing is read from a file that could be committed.

The defaults are the *safe* ones: authentication is required, the write
operations are disabled, and only the CPU audit application of this repository
is reachable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import FrozenSet, Tuple

#: The CPU-only audit application of this repository. It is the only
#: application the server is allowed to look at or call.
DEFAULT_CPU_APP = "aegis-rlvr-cpu-audit"

#: The functions of the CPU audit application that the server may call. Every
#: one of them is CPU-only - the application declares no GPU at all.
DEFAULT_CPU_FUNCTIONS: Tuple[str, ...] = (
    "audit_contract",
    "read_saved_result",
    "probe_environment",
)

#: The environment of the workspace the server may work in.
DEFAULT_ENVIRONMENTS: Tuple[str, ...] = ("main",)

#: The volume that holds the artifacts of the CPU audit service.
DEFAULT_RESULTS_VOLUME = "aegis-cpu-audit-results"

#: The Modal Dict that holds the OAuth clients, the issued tokens and the
#: replay-protection ledger of this server.
DEFAULT_STATE_DICT = "aegis-modal-mcp-state"

#: The maximum size of a tool result. A result that is larger is truncated -
#: a chat client cannot use a 50 MB answer anyway.
DEFAULT_MAX_RESULT_BYTES = 200_000

#: The maximum wall-clock time of one tool call, in seconds.
DEFAULT_TOOL_TIMEOUT_SEC = 900


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, "").lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = _env(name, "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_tuple(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
    raw = _env(name, "")
    if not raw:
        return default
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    return items or default


@dataclass(frozen=True)
class Settings:
    """The resolved configuration of one running MCP server."""

    #: The dedicated Modal credential. It arrives through the environment of
    #: the container, because a Modal Secret is mounted as environment
    #: variables. It is never logged and never returned by a tool.
    #:
    #: The names are deliberately *not* ``MODAL_TOKEN_ID`` and
    #: ``MODAL_TOKEN_SECRET``: a Modal container already carries the
    #: credentials of its own workspace under those names, and the server has
    #: to use the dedicated credential it was configured with - not the
    #: ambient one.
    modal_token_id: str = ""
    modal_token_secret: str = ""

    #: The static bearer token that the owner uses for a direct call (curl,
    #: MCP Inspector, a local script). The value itself is a secret; only the
    #: tool that *verifies* a token ever sees it.
    access_token: str = ""

    #: The shared authorisation token of the CPU audit service. The service
    #: checks it on its own side, before it does any work, so a call without
    #: it is refused by the service itself. The value is the token of the
    #: Modal secret ``aegis-cpu-audit-auth`` and it never leaves the
    #: container of this server.
    cpu_audit_token: str = ""

    #: The public URL of the server, used as the issuer of the OAuth
    #: authorization server. It is configured at deploy time, because the
    #: label of the endpoint makes the URL stable.
    issuer: str = ""

    #: The one-time code that the owner has to type on the consent page before
    #: an OAuth client may obtain a token. Without it, the consent page
    #: refuses: an unauthenticated visitor cannot enrol a client.
    enrollment_code: str = ""

    #: The applications that may be inspected or called.
    allowed_apps: Tuple[str, ...] = (DEFAULT_CPU_APP,)

    #: The functions that may be called, as ``app:function`` pairs.
    allowed_functions: Tuple[str, ...] = field(
        default_factory=lambda: tuple(
            f"{DEFAULT_CPU_APP}:{name}" for name in DEFAULT_CPU_FUNCTIONS
        )
    )

    #: The environments that may be used.
    allowed_environments: Tuple[str, ...] = DEFAULT_ENVIRONMENTS

    #: Whether the write operations (deploy, stop) may be used at all.
    write_enabled: bool = False

    #: Whether a request without a valid credential is refused.
    require_auth: bool = True

    #: The maximum size of a tool result, in bytes.
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    #: The maximum wall-clock time of one tool call, in seconds.
    tool_timeout_sec: int = DEFAULT_TOOL_TIMEOUT_SEC

    #: The volume that holds the artifacts of the CPU audit service.
    results_volume: str = DEFAULT_RESULTS_VOLUME

    #: The Modal Dict that holds the state of the server.
    state_dict: str = DEFAULT_STATE_DICT

    #: The directory with the trusted target sources of the repository.
    targets_dir: str = "/opt/aegis/targets/solidity"

    #: The directory with the repository-owned candidate registry.
    pocs_dir: str = "/opt/aegis/cpu_audit_pocs"

    @property
    def has_modal_credentials(self) -> bool:
        """Whether a dedicated Modal credential is present."""
        return bool(self.modal_token_id and self.modal_token_secret)

    @property
    def function_allowlist(self) -> FrozenSet[str]:
        """The ``app:function`` pairs that may be called."""
        return frozenset(self.allowed_functions)

    @classmethod
    def from_env(cls) -> "Settings":
        """Build the settings from the environment."""
        allowed_apps = _env_tuple("MODAL_MCP_ALLOWED_APPS", (DEFAULT_CPU_APP,))
        raw_functions = _env_tuple(
            "MODAL_MCP_ALLOWED_FUNCTIONS",
            tuple(f"{app}:{name}" for app in allowed_apps for name in DEFAULT_CPU_FUNCTIONS),
        )
        return cls(
            modal_token_id=_env("MODAL_MCP_TOKEN_ID"),
            modal_token_secret=_env("MODAL_MCP_TOKEN_SECRET"),
            access_token=_env("MODAL_MCP_ACCESS_TOKEN"),
            cpu_audit_token=_env("AEGIS_CPU_AUDIT_TOKEN"),
            enrollment_code=_env("MODAL_MCP_ENROLLMENT_CODE"),
            issuer=_env("MODAL_MCP_ISSUER"),
            allowed_apps=allowed_apps,
            allowed_functions=raw_functions,
            allowed_environments=_env_tuple(
                "MODAL_MCP_ALLOWED_ENVIRONMENTS", DEFAULT_ENVIRONMENTS
            ),
            write_enabled=_env_bool("MODAL_MCP_WRITE_ENABLED", False),
            require_auth=_env_bool("MODAL_MCP_REQUIRE_AUTH", True),
            max_result_bytes=_env_int("MODAL_MCP_MAX_RESULT_BYTES", DEFAULT_MAX_RESULT_BYTES),
            tool_timeout_sec=_env_int("MODAL_MCP_TOOL_TIMEOUT_SEC", DEFAULT_TOOL_TIMEOUT_SEC),
            results_volume=_env("MODAL_MCP_RESULTS_VOLUME", DEFAULT_RESULTS_VOLUME),
            state_dict=_env("MODAL_MCP_STATE_DICT", DEFAULT_STATE_DICT),
            targets_dir=_env("MODAL_MCP_TARGETS_DIR", "/opt/aegis/targets/solidity"),
            pocs_dir=_env("MODAL_MCP_POCS_DIR", "/opt/aegis/cpu_audit_pocs"),
        )

    def public_view(self) -> dict:
        """
        The settings as they may be shown to a caller.

        The credential, the access token and the enrolment code are reduced to
        a boolean: a tool result says *whether* a credential is configured, and
        never *what* it is.
        """
        return {
            "allowed_apps": list(self.allowed_apps),
            "allowed_functions": list(self.allowed_functions),
            "allowed_environments": list(self.allowed_environments),
            "write_enabled": self.write_enabled,
            "require_auth": self.require_auth,
            "max_result_bytes": self.max_result_bytes,
            "tool_timeout_sec": self.tool_timeout_sec,
            "results_volume": self.results_volume,
            "modal_credentials_present": self.has_modal_credentials,
            "access_token_present": bool(self.access_token),
            "enrollment_code_present": bool(self.enrollment_code),
            "cpu_audit_token_present": bool(self.cpu_audit_token),
        }
