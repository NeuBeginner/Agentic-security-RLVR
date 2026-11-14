"""
modal_mcp.state
===============

The state of the server: the registered OAuth clients, the issued tokens and
the replay ledger.

The deployed server keeps this state in a Modal Dict, so that it survives the
replacement of a container and is shared by every replica. The tests use the
in-memory implementation, so that they need neither a Modal account nor a
network.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class StateStore(ABC):
    """The interface of the state of the server."""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Read one value, or ``None`` when the key is unknown."""

    @abstractmethod
    def put(self, key: str, value: Any, ttl_sec: Optional[int] = None) -> None:
        """Write one value, optionally with a time to live."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove one value. Removing an unknown key is not an error."""

    def get_json(self, key: str) -> Optional[Any]:
        """Read one JSON value."""
        raw = self.get(key)
        if raw is None:
            return None
        if isinstance(raw, (dict, list)):
            return raw
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    def put_json(self, key: str, value: Any, ttl_sec: Optional[int] = None) -> None:
        """Write one JSON value."""
        self.put(key, json.dumps(value, default=str), ttl_sec=ttl_sec)


class MemoryStateStore(StateStore):
    """
    The in-memory state.

    The values expire with their time to live. The store is used by the tests
    and by a local run of the server.
    """

    def __init__(self) -> None:
        self._values: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}

    def _purge(self) -> None:
        now = time.time()
        expired = [key for key, deadline in self._expiry.items() if deadline <= now]
        for key in expired:
            self._values.pop(key, None)
            self._expiry.pop(key, None)

    def get(self, key: str) -> Optional[Any]:
        self._purge()
        return self._values.get(key)

    def put(self, key: str, value: Any, ttl_sec: Optional[int] = None) -> None:
        self._purge()
        self._values[key] = value
        if ttl_sec:
            self._expiry[key] = time.time() + ttl_sec

    def delete(self, key: str) -> None:
        self._values.pop(key, None)
        self._expiry.pop(key, None)


class ModalDictStateStore(StateStore):
    """
    The state in a Modal Dict.

    The Dict is a key-value store of the workspace; it holds nothing but the
    bookkeeping of this server. The time to live is implemented on top of the
    Dict: a value that has expired is treated as absent and is removed.
    """

    def __init__(self, dict_name: str, client: Any = None) -> None:
        import modal  # imported lazily, so that the tests need no Modal account

        self._dict_name = dict_name
        self._client = client
        self._dict = modal.Dict.from_name(dict_name, create_if_missing=True, client=client)

    def get(self, key: str) -> Optional[Any]:
        try:
            value = self._dict.get(key)
        except Exception:  # noqa: BLE001 - a missing key must not break a tool
            return None
        if value is None:
            return None
        try:
            record = json.loads(value)
        except (TypeError, ValueError):
            return value
        if isinstance(record, dict) and "expires_at" in record and "value" in record:
            if float(record["expires_at"]) <= time.time():
                self.delete(key)
                return None
            return record["value"]
        return value

    def put(self, key: str, value: Any, ttl_sec: Optional[int] = None) -> None:
        record = {"value": value, "expires_at": time.time() + ttl_sec if ttl_sec else None}
        self._dict[key] = json.dumps(record, default=str)

    def delete(self, key: str) -> None:
        try:
            self._dict.pop(key)
        except Exception:  # noqa: BLE001 - removing an unknown key is not an error
            pass
