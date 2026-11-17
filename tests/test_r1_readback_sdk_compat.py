"""The Modal SDK 1.5.5 compatibility of the D27 autoscaler read-back.

The read-back used to await the **synchronous** public client
(``await Client.from_env()``). In Modal SDK 1.5.5 ``Client`` is the synchronous
wrapper the SDK builds with ``Client = synchronize_api(_Client)``
(``modal/client.py:532``), so that expression raises
``TypeError: object Client can't be used in 'await' expression`` and the
read-back failed closed against every deployment, independently of the
deployment state.

These tests pin the corrected arrangement:

* the **asynchronous** client is the one that is used, and the public
  synchronous client is never awaited;
* the RPC runs on the **Modal synchronizer's own loop** - a private loop
  deadlocks as soon as the public synchronous client has been created in the
  process, which the provider does when it resolves a Modal object;
* every failure is **fail closed** and never a partial read;
* the mutating ``update_autoscaler`` RPC is never issued.

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download. The Modal client is replaced by a double.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, List, Optional

import pytest

from benchmarks import r1_dispatch

from modal.client import Client, _Client
from modal_proto import api_pb2


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


class _FakeStub:
    """The read-only RPC double: it records the request and the running loop."""

    def __init__(self, response: Any, error: Optional[BaseException] = None) -> None:
        self.response = response
        self.error = error
        self.requests: List[Any] = []
        self.loops: List[Any] = []

    async def FunctionGet(self, request: Any) -> Any:  # noqa: N802 - the RPC name
        self.requests.append(request)
        self.loops.append(asyncio.get_running_loop())
        if self.error is not None:
            raise self.error
        return self.response


class _FakeClient:
    def __init__(self, stub: _FakeStub) -> None:
        self.stub = stub


def _complete_response() -> Any:
    return api_pb2.FunctionGetResponse(
        function=api_pb2.FunctionData(
            autoscaler_settings=api_pb2.AutoscalerSettings(
                min_containers=0,
                max_containers=32,
                buffer_containers=4,
                scaledown_window=60,
            )
        )
    )


@pytest.fixture
def fake_client(monkeypatch):
    """Install a double for the asynchronous client and forbid the public one.

    The public synchronous client raises when it is touched: the read-back must
    not use it, and it must not await it either.
    """
    stub = _FakeStub(_complete_response())
    client = _FakeClient(stub)

    async def fake_from_env():
        return client

    def forbidden_public_client(*args, **kwargs):
        raise AssertionError(
            "the read-back must not use the synchronous public client "
            "(modal.client.Client)"
        )

    monkeypatch.setattr(_Client, "from_env", fake_from_env)
    monkeypatch.setattr(Client, "from_env", forbidden_public_client)
    monkeypatch.setenv("R1_ENABLE_PROVIDER_READBACK", "1")
    return stub


# --------------------------------------------------------------------------------------
# the SDK fact that caused the defect
# --------------------------------------------------------------------------------------


def test_the_public_modal_client_is_synchronous_and_the_private_one_is_not():
    """Modal SDK 1.5.5: ``Client`` is the sync wrapper, ``_Client`` is async."""
    assert not inspect.iscoroutinefunction(Client.from_env)
    assert inspect.iscoroutinefunction(_Client.from_env)


def test_the_read_back_source_does_not_await_the_synchronous_public_client():
    """The source of the reader must not contain the defective expression."""
    source = inspect.getsource(r1_dispatch.provider_autoscaler_reader)
    assert "await Client.from_env()" not in source
    assert "_run_coroutine_blocking" not in source


# --------------------------------------------------------------------------------------
# the corrected client construction
# --------------------------------------------------------------------------------------


def test_the_read_back_uses_the_asynchronous_client(fake_client):
    """The four effective settings are read through the asynchronous client."""
    settings = r1_dispatch.provider_autoscaler_reader(
        None, "ProductionAuditAgent.generate_solidity_exploit"
    )
    assert settings == {
        "min_containers": 0,
        "max_containers": 32,
        "buffer_containers": 4,
        "scaledown_window": 60,
    }


def test_the_read_back_never_uses_the_synchronous_public_client(fake_client):
    """The double of the public client raises when touched - the read must pass."""
    r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    assert fake_client.requests, "the read-back issued no FunctionGet request"


def test_the_read_back_sends_the_authoritative_function_get_request(fake_client):
    """The request carries the app, the object tag and the environment."""
    r1_dispatch.provider_autoscaler_reader(None, "ProductionAuditAgent.generate_solidity_exploit")
    request = fake_client.requests[-1]
    assert request.object_tag == "ProductionAuditAgent.*"
    assert request.environment_name == "main"
    assert request.app_version == 0
    assert request.app_name


def test_the_read_back_runs_the_rpc_on_the_modal_synchronizer_loop(fake_client):
    """The RPC must run on the SDK's own loop, not on a private one.

    A private loop deadlocks as soon as the public synchronous client has been
    created in the process, because the client singleton then belongs to the
    synchronizer's loop.
    """
    from modal._utils.async_utils import synchronizer

    r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    running = fake_client.loops[-1]
    assert running is not None
    assert running is synchronizer._loop


def test_the_read_back_can_be_repeated_in_one_process(fake_client):
    """A second read-back in the same process must not fail on the client state."""
    for _ in range(2):
        settings = r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
        assert settings["max_containers"] == 32
    assert len(fake_client.requests) == 2


# --------------------------------------------------------------------------------------
# fail closed
# --------------------------------------------------------------------------------------


def test_a_client_failure_fails_closed(monkeypatch):
    """A client that cannot be built is an unavailable read, never a partial one."""

    async def failing_from_env():
        raise RuntimeError("no credentials")

    monkeypatch.setattr(_Client, "from_env", failing_from_env)
    monkeypatch.setenv("R1_ENABLE_PROVIDER_READBACK", "1")
    with pytest.raises(r1_dispatch.AutoscalerReadbackUnavailable) as excinfo:
        r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    assert "RuntimeError" in str(excinfo.value)


def test_an_rpc_failure_fails_closed(monkeypatch):
    """An RPC that fails is an unavailable read, and the gate refuses the step."""
    stub = _FakeStub(None, error=RuntimeError("transport closed"))

    async def fake_from_env():
        return _FakeClient(stub)

    monkeypatch.setattr(_Client, "from_env", fake_from_env)
    monkeypatch.setenv("R1_ENABLE_PROVIDER_READBACK", "1")
    with pytest.raises(r1_dispatch.AutoscalerReadbackUnavailable) as excinfo:
        r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    assert "transport closed" in str(excinfo.value)

    with pytest.raises(r1_dispatch.DispatchRefusal) as refusal:
        r1_dispatch.read_back_autoscaler(
            None,
            function_name="verify_exploit_remote",
            reader=r1_dispatch.provider_autoscaler_reader,
        )
    assert refusal.value.reason == "autoscaler_readback_unavailable"


def test_the_read_back_is_refused_without_the_explicit_opt_in(monkeypatch):
    """Without the opt-in the read is unavailable and the provider is not touched."""

    async def forbidden_from_env():
        raise AssertionError("the provider must not be contacted without the opt-in")

    monkeypatch.setattr(_Client, "from_env", forbidden_from_env)
    monkeypatch.delenv("R1_ENABLE_PROVIDER_READBACK", raising=False)
    with pytest.raises(r1_dispatch.AutoscalerReadbackUnavailable):
        r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")


# --------------------------------------------------------------------------------------
# the mutating RPC is never used as a read
# --------------------------------------------------------------------------------------


def test_the_read_back_never_issues_the_mutating_autoscaler_rpc(fake_client, monkeypatch):
    """``FunctionUpdateSchedulingParams`` is the mutating RPC - it is never built."""

    def forbidden_update_request(*args, **kwargs):
        raise AssertionError(
            "the mutating autoscaler RPC (FunctionUpdateSchedulingParams) was issued"
        )

    monkeypatch.setattr(
        api_pb2, "FunctionUpdateSchedulingParams", forbidden_update_request, raising=False
    )
    r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    assert fake_client.requests


def test_the_provider_object_is_never_asked_to_update_its_autoscaler(fake_client):
    """The provider object of the call site is only read, never mutated."""

    class FakeTarget:
        def __init__(self) -> None:
            self.update_autoscaler_calls = 0

        def update_autoscaler(self, **kwargs) -> None:
            self.update_autoscaler_calls += 1
            raise AssertionError("update_autoscaler() must never be called")

    target = FakeTarget()
    r1_dispatch.provider_autoscaler_reader(target, "verify_exploit_remote")
    assert target.update_autoscaler_calls == 0
