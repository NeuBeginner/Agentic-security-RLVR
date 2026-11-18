"""
modal_mcp.context
=================

The identity of the caller of the current request.

The authorisation middleware of the server writes the identity of the caller
into a context variable, so that every tool - and every journal record - knows
*who* asked. The identity is a label, never a secret: a bearer token is
recorded as ``bearer``, a token of the OAuth authorization server as
``oauth:<client id>``.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_PRINCIPAL: ContextVar[Optional[str]] = ContextVar("modal_mcp_principal", default=None)
_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("modal_mcp_request_id", default=None)


def set_principal(principal: str) -> None:
    """Remember who is calling."""
    _PRINCIPAL.set(principal)


def get_principal() -> str:
    """The identity of the caller, or ``anonymous``."""
    return _PRINCIPAL.get() or "anonymous"


def set_request_id(request_id: str) -> None:
    """Remember the identifier of the current request."""
    _REQUEST_ID.set(request_id)


def get_request_id() -> Optional[str]:
    """The identifier of the current request, if the caller supplied one."""
    return _REQUEST_ID.get()
