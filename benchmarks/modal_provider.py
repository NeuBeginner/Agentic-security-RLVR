"""
benchmarks/modal_provider.py
============================

The client's access to the **Modal provider** (Iteration 21).

The review of Iteration 20 established that a function container has no
supported source of a provider-issued container id. The provider-issued
container id of an invocation is a **client-side** fact, and this module is
the single place where the client asks the provider for it.

The three answers the client needs, and what each one proves:

``call_graph_inputs(function_call_id)``
    The provider's own record of the inputs of a function call. Every entry
    carries the **function-call id** it belongs to and the **container id**
    (``task_id``) that executed it. The public API is
    ``modal.FunctionCall.from_id(fc).get_call_graph()``, which returns the
    public ``modal.types.InputInfo`` records.

``containers_of_app(app_id)``
    The provider's container listing of an application. The SDK's own
    ``modal container list`` prints exactly this record - the column heading
    is *"Container ID"* and the value is the provider's ``TaskStats.task_id``
    (``modal/cli/container.py``). The SDK itself calls that very field
    ``get_old_container_ids()`` (``modal/runner.py``): **the provider's task id
    is the container id**.

``task_app_id(container_id)``
    The provider's own record of the application a container belongs to. It is
    the second, independent cross-check of the app↔container relation.

Nothing here decides what is *true*: the module only asks. The decision - and
the refusal to attach a container that cannot be correlated to the very
invocation - belongs to ``benchmarks/adapters.py``, which turns the answers
into a typed fact.

**No live call is required to read this module.** The provider is an
injectable collaborator, so the tests can drive the whole path with a fake
provider - a simulation, and always called one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List, Optional


class ModalProviderError(RuntimeError):
    """The provider could not be asked, or answered something unusable."""


@dataclass(frozen=True)
class ProviderCallGraphInput:
    """One input of a function call, as the provider's call graph reports it."""

    input_id: str
    function_call_id: str
    container_id: str


@dataclass(frozen=True)
class ProviderContainer:
    """One container of an application, as the provider's listing reports it."""

    container_id: str
    app_id: str
    started_at: Optional[float] = None


class ModalProvider:
    """
    The provider's answers, read on the client side.

    The provider is reached through the public Modal SDK:

    * the call graph through ``modal.FunctionCall.from_id(...).get_call_graph()``;
    * the container listing and the task record through the provider's own
      gRPC stub - the very stub the SDK's own ``modal container list`` uses.

    The class holds no state of its own beyond the injected client, so a test
    can replace the provider with a fake one without touching the network.
    """

    def __init__(self, client: Any = None) -> None:
        """
        ``client`` is an optional ``modal.Client``. Without one the SDK's own
        ``Client.from_env()`` is used, exactly as the SDK's command line does.
        """
        self._client = client

    # -- the client ---------------------------------------------------------

    def _modal_client(self) -> Any:
        """The Modal client the provider is reached through."""
        if self._client is not None:
            return self._client
        from modal import Client

        return Client.from_env()

    # -- the provider's call graph ------------------------------------------

    def call_graph_inputs(self, function_call_id: str) -> List[ProviderCallGraphInput]:
        """
        The inputs of a function call, as the provider's call graph reports them.

        The SDK documents the call graph as best-effort and not populated in
        real time (``modal/_functions.py``). An empty list is therefore a
        normal answer, not an error - it means the provider holds no record of
        this call, and the container id of the call is then simply unavailable.
        """
        from modal import FunctionCall

        call = FunctionCall.from_id(function_call_id, client=self._client)
        graph = call.get_call_graph() or []

        inputs: List[ProviderCallGraphInput] = []
        for info in graph:
            input_id = getattr(info, "input_id", None)
            call_id = getattr(info, "function_call_id", None)
            container_id = getattr(info, "task_id", None)
            if not call_id or not container_id:
                continue
            inputs.append(
                ProviderCallGraphInput(
                    input_id=str(input_id or ""),
                    function_call_id=str(call_id),
                    container_id=str(container_id),
                )
            )
        return inputs

    # -- the provider's container listing -----------------------------------

    def containers_of_app(self, app_id: str) -> List[ProviderContainer]:
        """The containers the provider lists for an application."""
        from modal_proto import api_pb2

        response = self._stub_call(
            "TaskList",
            api_pb2.TaskListRequest(app_id=app_id),
        )
        containers: List[ProviderContainer] = []
        for task in getattr(response, "tasks", ()):
            container_id = getattr(task, "task_id", None)
            if not container_id:
                continue
            containers.append(
                ProviderContainer(
                    container_id=str(container_id),
                    app_id=str(getattr(task, "app_id", "") or ""),
                    started_at=getattr(task, "started_at", None),
                )
            )
        return containers

    # -- the provider's task record -----------------------------------------

    def task_app_id(self, container_id: str) -> Optional[str]:
        """The application the provider's own record names for a container."""
        from modal_proto import api_pb2

        response = self._stub_call(
            "TaskGetInfo",
            api_pb2.TaskGetInfoRequest(task_id=container_id),
        )
        app_id = getattr(response, "app_id", None)
        return str(app_id) if app_id else None

    # -- the provider's stub ------------------------------------------------

    def _stub_call(self, method_name: str, request: Any) -> Any:
        """
        Call one method of the provider's gRPC stub from synchronous code.

        The SDK's own command line reaches the very same stub. The call is
        executed in the SDK's own event loop, so the connection the stub was
        opened with stays usable.
        """
        from modal._utils.async_utils import synchronizer

        stub = self._modal_client().stub
        method: Optional[Callable[..., Any]] = getattr(stub, method_name, None)
        if method is None:
            raise ModalProviderError(
                f"The Modal provider stub has no method {method_name!r}"
            )

        async def _call() -> Any:
            return await method(request)

        return synchronizer.wrap(_call)()
