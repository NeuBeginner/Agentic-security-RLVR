"""The client-side identity of a run against the **deployed** application.

The tests of this module prove five facts:

* a run that addresses the deployed application by name observes the
  **provider-issued** application id and the provider's own dashboard URL of
  that very application - not the local app object, which was never run;
* a run that does **not** address the deployed application keeps its own
  observation and never asks the provider for an application;
* the provider's call graph that holds the input of a call but names no
  container for it is an explicit absence with that exact reason;
* the container id of an invocation is correlated **while the container is
  alive** - right after the call returned - and the fact is kept for the rest
  of the run; and
* the provider's lookup of an application never creates one.

Everything here is local: no provider call, no deployment, no paid
computation.
"""

from __future__ import annotations

import pytest

from benchmarks import adapters
from benchmarks.adapters import (
    _client_observed_app_id,
    _client_observed_app_page_url,
    _client_observed_block,
    _runtime_function_call_id,
    deployed_app_addressing,
    observe_container_id_of_call,
)
from benchmarks.evidence_integrity import (
    OBSERVATION_SIDE_CLIENT,
    OBSERVED,
    NOT_AVAILABLE,
)
from benchmarks.modal_provider import ModalProvider

APP_ID = "ap-P2HqbucGX4wdyBQc3287g7"
APP_NAME = "aegis-rlvr-security"
FUNCTION_CALL_ID = "fc-01M7MGKM2JAN091V4RNBC7ACBA"
CONTAINER_ID = "ta-01M7MGKM2RXFMAKKZPA9ZTFGFQ"
OTHER_CONTAINER_ID = "ta-01M7MGKM2RXFMAKKZPA9ZTGGH"


@pytest.fixture(autouse=True)
def _clean_client_observations():
    """Every test starts with an empty client-side observation cache."""
    adapters._CLIENT_OBSERVED_CONTAINER_IDS.clear()
    adapters._DEPLOYED_APP_HANDLE = None
    yield
    adapters._CLIENT_OBSERVED_CONTAINER_IDS.clear()
    adapters._DEPLOYED_APP_HANDLE = None


class _FakeProvider:
    """The provider's answers, read on the client side."""

    def __init__(self, *, inputs=None, containers=None, task_app_ids=None) -> None:
        self._inputs = list(inputs or [])
        self._containers = list(containers or [])
        self._task_app_ids = dict(task_app_ids or {})
        self.asked: list = []

    def call_graph_inputs(self, function_call_id: str):
        self.asked.append(("call_graph_inputs", function_call_id))
        return list(self._inputs)

    def containers_of_app(self, app_id: str):
        self.asked.append(("containers_of_app", app_id))
        return list(self._containers)

    def task_app_id(self, container_id: str):
        self.asked.append(("task_app_id", container_id))
        return self._task_app_ids.get(container_id)


class _FakeAppHandle:
    """The handle of a deployed application."""

    def __init__(self, app_id: str = APP_ID) -> None:
        self.app_id = app_id

    def get_dashboard_url(self) -> str:
        return "https://modal.com/id/%s" % self.app_id


class _FakeAppHandleWithoutId(_FakeAppHandle):
    """A handle the provider resolved without an id."""

    def __init__(self) -> None:
        self.app_id = None


# --------------------------------------------------------------------------------------
# the application id and the dashboard URL of the deployed application
# --------------------------------------------------------------------------------------


def test_the_deployed_run_observes_the_provider_issued_application_id(monkeypatch):
    """The deployed run reads the id of the deployed app from the provider."""
    monkeypatch.setattr(adapters, "_deployed_app_id", lambda: (APP_ID, ""))

    with deployed_app_addressing(True):
        fact = _client_observed_app_id()

    assert fact["status"] == OBSERVED
    assert fact["value"] == APP_ID
    assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT


def test_the_deployed_run_observes_the_provider_dashboard_url(monkeypatch):
    """The dashboard URL is the provider's URL of the deployed app."""
    monkeypatch.setattr(adapters, "_deployed_app_handle", lambda: (_FakeAppHandle(), ""))

    with deployed_app_addressing(True):
        fact = _client_observed_app_page_url()

    assert fact["status"] == OBSERVED
    assert fact["value"] == "https://modal.com/id/%s" % APP_ID
    assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT


def test_the_deployed_run_never_fabricates_an_application_id(monkeypatch):
    """A provider that names no application yields an explicit absence."""
    monkeypatch.setattr(adapters, "_deployed_app_id", lambda: (None, ": RuntimeError: no app"))

    with deployed_app_addressing(True):
        fact = _client_observed_app_id()

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "no app" in fact["reason"]


def test_a_local_run_never_asks_the_provider_for_an_application(monkeypatch):
    """The local run keeps its own observation - the provider is not asked.

    The local observation is the one of the local app object, and it is
    whatever that object holds: an id when the app ran in this process, an
    explicit absence when it did not. What it never is: a lookup of the
    provider.
    """
    asked: list = []

    def _asked() -> tuple:
        asked.append("asked")
        return APP_ID, ""

    monkeypatch.setattr(adapters, "_deployed_app_id", _asked)

    fact = _client_observed_app_id()

    assert asked == []
    assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT
    assert fact["status"] in (OBSERVED, NOT_AVAILABLE)


def test_the_deployed_lookup_falls_back_to_the_provider_when_the_handle_has_no_id(
    monkeypatch,
):
    """The provider's own lookup names the app when the handle names none."""
    monkeypatch.setattr(adapters, "_deployed_app_handle", lambda: (_FakeAppHandleWithoutId(), ""))

    class _Provider:
        def app_id_of_app_name(self, app_name: str, environment_name: str = "") -> str:
            assert app_name == APP_NAME
            return APP_ID

    monkeypatch.setattr(adapters, "_deployed_app_id", lambda: (APP_ID, ""))
    monkeypatch.setattr("benchmarks.modal_provider.ModalProvider", _Provider)

    assert adapters._deployed_app_id()[0] == APP_ID


# --------------------------------------------------------------------------------------
# the container id of an invocation
# --------------------------------------------------------------------------------------


def test_the_provider_names_no_container_for_a_finished_input(monkeypatch):
    """The call graph holds the input but names no container for it."""
    from benchmarks.modal_provider import ProviderCallGraphInput

    provider = _FakeProvider(
        inputs=[
            ProviderCallGraphInput(
                input_id="in-01M7MGKM2RXFMAKKZPA9ZTFGFQ",
                function_call_id=FUNCTION_CALL_ID,
                container_id="",
            )
        ]
    )
    monkeypatch.setattr(adapters, "_client_observed_app_id", lambda: _observed(APP_ID))

    fact = observe_container_id_of_call(FUNCTION_CALL_ID, provider=provider)

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "names no container" in fact["reason"]
    assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT


def test_the_container_id_is_correlated_once_and_kept(monkeypatch):
    """The correlation is made once - while the container is alive."""
    from benchmarks.modal_provider import ProviderCallGraphInput, ProviderContainer

    provider = _FakeProvider(
        inputs=[
            ProviderCallGraphInput(
                input_id="in-01M7MGKM2RXFMAKKZPA9ZTFGFQ",
                function_call_id=FUNCTION_CALL_ID,
                container_id=CONTAINER_ID,
            )
        ],
        containers=[ProviderContainer(container_id=CONTAINER_ID, app_id=APP_ID)],
        task_app_ids={CONTAINER_ID: APP_ID},
    )
    monkeypatch.setattr(adapters, "_client_observed_app_id", lambda: _observed(APP_ID))

    first = observe_container_id_of_call(FUNCTION_CALL_ID, provider=provider)
    assert first["status"] == OBSERVED
    assert first["value"] == CONTAINER_ID

    asked_after_first = list(provider.asked)
    second = observe_container_id_of_call(FUNCTION_CALL_ID, provider=provider)

    assert second["value"] == CONTAINER_ID
    # the provider is not asked a second time: the container of that call is
    # named to nobody once it is gone
    assert provider.asked == asked_after_first


def test_the_client_block_reuses_the_correlation_of_the_stage(monkeypatch):
    """The report reuses the correlation made right after the call."""
    from benchmarks.modal_provider import ProviderCallGraphInput, ProviderContainer

    provider = _FakeProvider(
        inputs=[
            ProviderCallGraphInput(
                input_id="in-01M7MGKM2RXFMAKKZPA9ZTFGFQ",
                function_call_id=FUNCTION_CALL_ID,
                container_id=CONTAINER_ID,
            )
        ],
        containers=[ProviderContainer(container_id=CONTAINER_ID, app_id=APP_ID)],
        task_app_ids={CONTAINER_ID: APP_ID},
    )
    monkeypatch.setattr(adapters, "_client_observed_app_id", lambda: _observed(APP_ID))

    observe_container_id_of_call(FUNCTION_CALL_ID, provider=provider)
    asked_after_correlation = list(provider.asked)

    block = _client_observed_block(
        {"function_call_id": _observed(FUNCTION_CALL_ID)}, provider=provider
    )

    assert block["container_id"]["status"] == OBSERVED
    assert block["container_id"]["value"] == CONTAINER_ID
    assert provider.asked == asked_after_correlation


def test_an_uncorrelated_container_of_the_same_app_is_never_attached(monkeypatch):
    """A container the provider does not tie to the call is not attached."""
    from benchmarks.modal_provider import ProviderCallGraphInput, ProviderContainer

    provider = _FakeProvider(
        inputs=[
            ProviderCallGraphInput(
                input_id="in-01M7MGKM2RXFMAKKZPA9ZTFGFQ",
                function_call_id=FUNCTION_CALL_ID,
                container_id=OTHER_CONTAINER_ID,
            )
        ],
        containers=[ProviderContainer(container_id=CONTAINER_ID, app_id=APP_ID)],
        task_app_ids={OTHER_CONTAINER_ID: APP_ID, CONTAINER_ID: APP_ID},
    )
    monkeypatch.setattr(adapters, "_client_observed_app_id", lambda: _observed(APP_ID))

    fact = observe_container_id_of_call(FUNCTION_CALL_ID, provider=provider)

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert CONTAINER_ID not in fact["reason"]


# --------------------------------------------------------------------------------------
# the anchor of the envelope
# --------------------------------------------------------------------------------------


def test_the_runtime_envelope_names_the_function_call():
    """The anchor of the envelope is the real function-call id of the worker."""
    assert (
        _runtime_function_call_id(
            {"function_call_id": {"status": OBSERVED, "value": FUNCTION_CALL_ID}}
        )
        == FUNCTION_CALL_ID
    )


def test_a_runtime_envelope_without_an_observed_call_names_no_call():
    """An unobserved envelope names no call - and never an invented one."""
    assert _runtime_function_call_id({"function_call_id": {"status": NOT_AVAILABLE}}) is None
    assert _runtime_function_call_id({}) is None
    assert _runtime_function_call_id(None) is None
    assert _runtime_function_call_id("fc-not-an-envelope") is None


# --------------------------------------------------------------------------------------
# the provider's lookup of an application
# --------------------------------------------------------------------------------------


def test_the_provider_lookup_never_creates_an_application():
    """The lookup of an app name asks the provider without the creation type."""
    from modal_proto import api_pb2

    recorded: list = []

    class _Response:
        app_id = APP_ID

    class _Stub:
        async def AppGetOrCreate(self, request):  # noqa: N802 - the provider's own name
            recorded.append(request)
            return _Response()

    class _Client:
        stub = _Stub()

    provider = ModalProvider(client=_Client())
    app_id = provider.app_id_of_app_name(APP_NAME)

    assert app_id == APP_ID
    assert len(recorded) == 1
    request = recorded[0]
    assert request.app_name == APP_NAME
    # the creation type stays unset: the provider resolves the existing app
    # record and never creates one
    assert request.object_creation_type != api_pb2.OBJECT_CREATION_TYPE_CREATE_IF_MISSING


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _observed(value: str) -> dict:
    """An observed client-side fact."""
    return {
        "status": OBSERVED,
        "value": value,
        "source": "the test",
        "observed_by": OBSERVATION_SIDE_CLIENT,
    }
