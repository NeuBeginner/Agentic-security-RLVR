"""
modal_mcp.modal_access
=======================

The access layer: the thin, well defined set of Modal operations that the
tools of this server are allowed to perform.

Two rules shape this module:

* the credential is **explicit** - the access layer builds its own client from
  a token id and a token secret that it is given, and never from an ambient
  environment, so that the server runs on exactly the credential it was
  configured with;
* the operations are **bounded** - every method takes its arguments from the
  policy-checked allowlist and returns a plain dictionary that carries no
  secret.

The raw calls go through the asynchronous stub of the Modal SDK. They are
wrapped in ``synchronize_api`` so that they run on the loop of the SDK itself;
running them on an own event loop deadlocks, because the client of the SDK is
bound to its own loop.

Three RPCs of the SDK are *not* implemented by the server of Modal and are
therefore not used here: ``AppLookup``, ``AppGetObjects`` and ``AppCountLogs``.
The identifier of an application is resolved through ``AppList`` instead.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .policy import audit

_CLIENT_HOLDER: Dict[str, Any] = {}

#: The functions of the CPU audit service that take the shared authorisation
#: token inside the request.
TOKEN_IN_REQUEST = frozenset({"audit_contract"})

#: The functions of the CPU audit service that take the shared authorisation
#: token as a second argument.
TOKEN_AS_SECOND_ARGUMENT = frozenset({"read_saved_result", "probe_environment"})


class AccessError(Exception):
    """A refusal of the access layer."""

    def __init__(self, code: str, reason: str, **extra: Any) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason
        self.extra = extra

    def to_dict(self) -> Dict[str, Any]:
        """The structured form of the refusal."""
        return {
            "status": "REFUSED",
            "error": {"code": self.code, "reason": self.reason, **self.extra},
        }


def _reset_client_cache() -> None:
    """Forget the cached asynchronous client (used by the tests)."""
    _CLIENT_HOLDER.pop("client", None)


async def _async_client(token_id: str, token_secret: str):
    """The asynchronous client of the SDK, created once per process."""
    from modal.client import _Client

    client = _CLIENT_HOLDER.get("client")
    if client is None:
        client = await _Client.from_credentials(token_id, token_secret)
        _CLIENT_HOLDER["client"] = client
    return client


def _to_dict(message: Any) -> Dict[str, Any]:
    """Convert a protobuf message into a plain dictionary."""
    from google.protobuf.json_format import MessageToDict

    return MessageToDict(message, preserving_proto_field_name=True)


def _app_state_name(state: int) -> str:
    """The name of the state of an application."""
    names = {
        0: "APP_STATE_UNSPECIFIED",
        1: "APP_STATE_EPHEMERAL",
        2: "APP_STATE_DETACHED",
        3: "APP_STATE_DEPLOYED",
        4: "APP_STATE_STOPPING",
        5: "APP_STATE_STOPPED",
        6: "APP_STATE_INITIALIZING",
        7: "APP_STATE_DISABLED",
        8: "APP_STATE_DETACHED_DISCONNECTED",
        9: "APP_STATE_DERIVED",
    }
    return names.get(int(state), f"APP_STATE_{state}")


def _month_start_timestamp() -> Any:
    """The first day of the current month, in UTC.

    The billing summary of Modal only accepts a UTC month boundary as the
    start of the interval.
    """
    from google.protobuf.timestamp_pb2 import Timestamp

    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    return Timestamp(seconds=int(start.timestamp()))


class ModalAccess:
    """
    The Modal operations of the server.

    The class holds the credential of the server and the shared authorisation
    token of the CPU audit service. Neither of them is ever written into a
    result, a log record or an exception message.
    """

    def __init__(
        self,
        token_id: str,
        token_secret: str,
        environment: str = "main",
        cpu_audit_token: str = "",
    ) -> None:
        if not token_id or not token_secret:
            raise ValueError("the Modal credential is incomplete")
        self._token_id = token_id
        self._token_secret = token_secret
        self._environment = environment
        self._cpu_audit_token = (cpu_audit_token or "").strip()
        self._sync_client: Any = None

    # -- the clients ---------------------------------------------------------

    @property
    def client(self):
        """The synchronous client, built from the explicit credential."""
        if self._sync_client is None:
            import modal

            self._sync_client = modal.Client.from_credentials(
                self._token_id, self._token_secret
            )
        return self._sync_client

    # -- diagnostics ---------------------------------------------------------

    def list_apps(self) -> List[Dict[str, Any]]:
        """The applications of the environment of the server."""
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        token_id, token_secret, environment = (
            self._token_id,
            self._token_secret,
            self._environment,
        )

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            response = await client.stub.AppList(
                api_pb2.AppListRequest(environment_name=environment)
            )
            apps = []
            for item in response.apps:
                apps.append(
                    {
                        "app_id": item.app_id,
                        "name": item.name or item.description,
                        "description": item.description,
                        "state": _app_state_name(item.state),
                        "created_at": str(item.created_at),
                        "stopped_at": str(item.stopped_at) if item.stopped_at else None,
                        "running_tasks": int(item.n_running_tasks),
                    }
                )
            return apps

        return _call()

    def _app_id(self, app_name: str) -> str:
        """The identifier of the newest deployment of one application."""
        candidates = [app for app in self.list_apps() if app["name"] == app_name]
        if not candidates:
            raise AccessError(
                "APP_NOT_FOUND",
                "the application is not deployed in this environment",
                app=app_name,
            )
        deployed = [app for app in candidates if app["state"] == "APP_STATE_DEPLOYED"]
        pool = deployed or candidates
        pool.sort(key=lambda app: app["created_at"], reverse=True)
        return pool[0]["app_id"]

    def app_status(self, app_name: str) -> Dict[str, Any]:
        """The state of one application."""
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        app_id = self._app_id(app_name)
        token_id, token_secret = self._token_id, self._token_secret

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            lifecycle = await client.stub.AppGetLifecycle(
                api_pb2.AppGetLifecycleRequest(app_id=app_id)
            )
            return lifecycle.lifecycle

        lifecycle = _call()
        return {
            "app_id": app_id,
            "name": app_name,
            "environment": self._environment,
            "state": _app_state_name(lifecycle.app_state),
            "created_at": str(lifecycle.created_at),
            "deployed_at": str(lifecycle.deployed_at),
            "version": lifecycle.version,
            "created_by": lifecycle.created_by,
            "deployed_by": lifecycle.deployed_by,
        }

    def function_status(self, app_name: str, function_name: str) -> Dict[str, Any]:
        """
        The state of one function of one application.

        The SDK does not expose the resources of a deployed function, so the
        answer carries what Modal knows: the identifier of the function, its
        timeout, its type and its schema. The resources of the CPU audit
        service - in particular the absence of a GPU - are the evidence of
        the probe of the service itself.
        """
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        token_id, token_secret, environment = (
            self._token_id,
            self._token_secret,
            self._environment,
        )

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            response = await client.stub.FunctionGet(
                api_pb2.FunctionGetRequest(
                    app_name=app_name,
                    object_tag=function_name,
                    environment_name=environment,
                )
            )
            return response

        response = _call()
        function = response.function
        arguments = [argument.name for argument in function.function_schema.arguments]
        return {
            "app_name": app_name,
            "function_name": function_name,
            "function_id": response.function_id,
            "function_type": str(function.function_type),
            "timeout_sec": int(function.timeout_secs),
            "arguments": arguments,
            "app_state": self.app_status(app_name)["state"],
            "resources_note": (
                "Modal does not expose the resources of a deployed function; the "
                "declared resources of the service are the evidence of its own "
                "environment probe (modal_environment_probe)"
            ),
        }

    def logs(self, app_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """The last log entries of one application."""
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        app_id = self._app_id(app_name)
        token_id, token_secret = self._token_id, self._token_secret
        bounded = max(1, min(int(limit), 500))

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            response = await client.stub.AppFetchLogs(
                api_pb2.AppFetchLogsRequest(app_id=app_id, limit=bounded)
            )
            entries: List[Dict[str, Any]] = []
            for batch in response.batches:
                for item in batch.items:
                    data = item.data
                    if isinstance(data, bytes):
                        text = data.decode("utf-8", errors="replace")
                    else:
                        text = str(data)
                    entries.append(
                        {
                            "timestamp": item.timestamp,
                            "message": text.rstrip("\n"),
                        }
                    )
            return entries

        return _call()

    def billing(self) -> Dict[str, Any]:
        """The billing summary of the workspace for the current month."""
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        token_id, token_secret = self._token_id, self._token_secret

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            response = await client.stub.WorkspaceBillingSummary(
                api_pb2.WorkspaceBillingSummaryRequest(
                    start_timestamp=_month_start_timestamp()
                )
            )
            return response

        response = _call()
        summary = {
            "start": str(response.start_timestamp),
            "end": str(response.end_timestamp),
            "metered_cost": float(response.metered_cost),
            "billed_cost": float(response.billed_cost),
            "metered_cost_breakdown": {
                name: float(value)
                for name, value in response.metered_cost_breakdown.items()
            },
            "adjustments": len(response.adjustments),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return summary

    # -- the CPU audit service ----------------------------------------------

    def _require_cpu_token(self, function_name: str) -> str:
        """The shared authorisation token of the CPU audit service."""
        if not self._cpu_audit_token:
            raise AccessError(
                "CPU_AUTH_TOKEN_MISSING",
                "the server carries no authorisation token for the CPU audit "
                "service, so every call to that service would be refused on its "
                "own side. Store the token of the Modal secret "
                "'aegis-cpu-audit-auth' in the secret of this server under the "
                "key AEGIS_CPU_AUDIT_TOKEN.",
                function=function_name,
            )
        return self._cpu_audit_token

    def call_function(self, app_name: str, function_name: str, payload: Any) -> Any:
        """
        Call one function of one application and return its result.

        The call runs on the CPU of the application itself; the server never
        starts a GPU and never passes a GPU request on. The shared
        authorisation token of the CPU audit service travels with the call,
        because that service checks it on its own side before it does any
        work.
        """
        import modal

        function = modal.Function.from_name(
            app_name,
            function_name,
            environment_name=self._environment,
            client=self.client,
        )
        if function_name in TOKEN_IN_REQUEST:
            if not isinstance(payload, dict):
                raise AccessError(
                    "REQUEST_SHAPE_INVALID",
                    "the request of this function has to be a JSON object",
                    function=function_name,
                )
            token = self._require_cpu_token(function_name)
            return function.remote({**payload, "auth_token": token})
        if function_name in TOKEN_AS_SECOND_ARGUMENT:
            token = self._require_cpu_token(function_name)
            return function.remote(payload, token)
        return function.remote(payload)

    def list_volume(self, volume_name: str, path: str) -> List[Dict[str, Any]]:
        """The entries of a directory of a volume."""
        import modal

        volume = modal.Volume.from_name(
            volume_name,
            environment_name=self._environment,
            client=self.client,
        )
        entries = []
        for entry in volume.listdir(path):
            entries.append(
                {
                    "path": entry.path,
                    "type": str(entry.type),
                    "size": int(getattr(entry, "size", 0) or 0),
                }
            )
        return entries

    # -- write operations ----------------------------------------------------

    def stop_app(self, app_id: str) -> Dict[str, Any]:
        """Stop one application. Only the policy may call this."""
        from modal._utils.async_utils import synchronize_api
        from modal_proto import api_pb2

        token_id, token_secret = self._token_id, self._token_secret

        @synchronize_api
        async def _call():
            client = await _async_client(token_id, token_secret)
            await client.stub.AppStop(api_pb2.AppStopRequest(app_id=app_id))
            return {"app_id": app_id, "stopped": True}

        result = _call()
        audit("app_stopped", app_id=app_id)
        return result
