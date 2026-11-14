"""
modal_mcp.policy
================

The policy of the Modal MCP server: what may be looked at, what may be called,
what may be changed and how a repeated or forged request is refused.

The policy is deliberately separate from the tools and from the Modal access
layer, so that it can be tested on its own: every check is a pure function of
the settings and of the arguments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Dict, Optional

from .config import Settings

#: The identifier of an application. Modal application names are lower case
#: words and dashes; the identifier of a deployment is ``ap-`` plus digits.
_APP_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_APP_ID_RE = re.compile(r"^ap-[A-Za-z0-9]{16,32}$")

#: The identifier of a run. The same rule as in the CPU audit service.
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: The identifier of a request. A UUID without dashes is accepted as well.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")

#: The operations that change something. They are refused unless the write
#: switch is on *and* the caller passes the confirmation value.
WRITE_OPERATIONS = frozenset({"modal_deploy_dev", "modal_stop_app"})


class PolicyError(Exception):
    """
    A refusal of the policy.

    The refusal is a value, not an accident: the tools turn it into a
    structured answer that names the rule that refused the request.
    """

    def __init__(self, code: str, reason: str, **extra: Any) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason
        self.extra = extra

    def to_dict(self) -> Dict[str, Any]:
        """The structured form of the refusal."""
        return {"status": "REFUSED", "error": {"code": self.code, "reason": self.reason, **self.extra}}


def audit(event: str, **fields: Any) -> None:
    """
    Write one structured record into the journal of the server.

    The record is one JSON object per line. It never carries a secret: the
    caller passes names, states, digests and measurements only. The helper
    removes the keys that look like a credential before the record is written,
    so that a careless caller cannot leak one into the log.
    """
    forbidden = ("token", "secret", "password", "authorization", "code", "key")
    safe = {}
    for name, value in fields.items():
        lowered = name.lower()
        if any(word in lowered for word in forbidden):
            safe[name] = "[redacted]"
            continue
        safe[name] = value
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
    }
    record.update(safe)
    print(json.dumps(record, default=str, ensure_ascii=False), flush=True)


class Policy:
    """
    The allowlist of the server.

    A policy answers four questions: may this environment be used, may this
    application be looked at, may this function be called and may this
    operation change something. Every answer is fail-closed: an unknown value
    is refused.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- environments --------------------------------------------------------

    def check_environment(self, environment: str) -> None:
        """Refuse an environment that is not on the allowlist."""
        if environment not in self.settings.allowed_environments:
            raise PolicyError(
                "ENVIRONMENT_NOT_ALLOWED",
                "the environment is not on the allowlist of this server",
                environment=environment,
                allowed=list(self.settings.allowed_environments),
            )

    # -- applications --------------------------------------------------------

    def check_app(self, app: str) -> None:
        """
        Refuse an application that is not on the allowlist.

        Both the name of an application and the identifier of a deployment are
        accepted; the identifier is resolved to a name by the caller before the
        check, so that the allowlist stays a list of names.
        """
        if not app or not _APP_NAME_RE.match(app):
            raise PolicyError(
                "APP_NAME_INVALID",
                "the application name is not a bounded Modal application name",
                app=str(app)[:80],
            )
        if app not in self.settings.allowed_apps:
            raise PolicyError(
                "APP_NOT_ALLOWED",
                "the application is not on the allowlist of this server",
                app=app,
                allowed=list(self.settings.allowed_apps),
            )

    def check_app_id(self, app_id: str) -> None:
        """Refuse an application identifier that does not look like one."""
        if not app_id or not _APP_ID_RE.match(app_id):
            raise PolicyError(
                "APP_ID_INVALID",
                "the application identifier is not a Modal application identifier",
                app_id=str(app_id)[:64],
            )

    # -- functions -----------------------------------------------------------

    def check_function(self, app: str, function: str) -> None:
        """Refuse a function that is not on the allowlist of the application."""
        self.check_app(app)
        pair = f"{app}:{function}"
        if pair not in self.settings.function_allowlist:
            raise PolicyError(
                "FUNCTION_NOT_ALLOWED",
                "the function is not on the allowlist of this server",
                app=app,
                function=function,
                allowed=list(self.settings.allowed_functions),
            )

    # -- write operations ----------------------------------------------------

    def check_write(self, operation: str, confirmation: Optional[str]) -> None:
        """
        Refuse a write operation that may not run.

        Two independent conditions have to hold: the write switch of the
        server has to be on, and the caller has to pass the confirmation value
        that the owner holds. A missing confirmation is refused even when the
        switch is on.
        """
        if operation not in WRITE_OPERATIONS:
            raise PolicyError(
                "OPERATION_UNKNOWN",
                "the operation is not a write operation of this server",
                operation=operation,
            )
        if not self.settings.write_enabled:
            raise PolicyError(
                "WRITE_DISABLED",
                "the write operations of this server are switched off",
                operation=operation,
            )
        if not confirmation or not hmac.compare_digest(confirmation, self.settings.access_token):
            raise PolicyError(
                "CONFIRMATION_REQUIRED",
                "the write operation needs the confirmation value of the owner",
                operation=operation,
            )

    # -- run and request identifiers ----------------------------------------

    def check_run_id(self, run_id: str) -> None:
        """Refuse a run identifier that is not a bounded identifier."""
        if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
            raise PolicyError(
                "RUN_ID_INVALID",
                "the run identifier is not a bounded identifier",
                run_id=str(run_id)[:64],
            )

    def check_request_id(self, request_id: str) -> str:
        """
        Check the identifier of a request and return it.

        The identifier is the key of the replay ledger: a request that carries
        an identifier that was already seen is refused, so that a captured
        request cannot be replayed.
        """
        if not isinstance(request_id, str) or not _REQUEST_ID_RE.match(request_id):
            raise PolicyError(
                "REQUEST_ID_INVALID",
                "the request identifier must be a unique identifier of at least "
                "8 characters of letters, digits, dots, dashes and underscores",
            )
        return request_id


def request_fingerprint(tool: str, arguments: Dict[str, Any]) -> str:
    """
    The fingerprint of one request.

    The fingerprint binds the tool and its arguments, and deliberately *not*
    the identifier of the request: two requests with the same arguments are
    the same work, so the second one is a replay even when it carries another
    identifier. The identifier of the request is checked separately, so that a
    request that carries the identifier of another one is refused as well.
    """
    payload = json.dumps(
        {"tool": tool, "arguments": arguments},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking their content through the time."""
    if not left or not right:
        return False
    return hmac.compare_digest(left, right)


def local_dir_fingerprint(path: str) -> Optional[str]:
    """
    A short digest of a local directory listing.

    It is used to prove in a result that the repository copy of the target
    sources is the one the server actually read - without shipping the files
    themselves into the result.
    """
    if not os.path.isdir(path):
        return None
    names = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if not os.path.isfile(full):
                continue
            with open(full, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            names.append(f"{name}:{digest[:16]}")
    except OSError:
        return None
    if not names:
        return None
    return hashlib.sha256("|".join(names).encode("utf-8")).hexdigest()[:32]
