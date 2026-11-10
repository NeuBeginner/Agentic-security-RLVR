"""
tests/test_iteration21_evidence_integrity.py
============================================

Iteration 21 (PR #12 follow-up) - the **provider-backed** container identity.

The Iteration 20 review kept the container-identity path of the production
provenance open as a P0:

* ``modal_app.py::capture_modal_runtime_identity()`` treated ``MODAL_WORKER_ID``
  or ``HOSTNAME`` as an observed Modal container id, although neither is a
  provider-issued identifier - ``MODAL_WORKER_ID`` is the SDK's ``worker_id``
  **configuration setting** (documented in the SDK source as internal
  debugging use) and ``HOSTNAME`` is a generic container hostname;
* the tests proved only that the producer *copies* an environment string, not
  that the string is a provider-issued container id;
* the client-observed block held no container identity at all.

This suite checks the fix:

* the source of the producer reads **no** environment variable for the
  container identity - a spoofed ``MODAL_WORKER_ID`` / ``HOSTNAME`` /
  ``MODAL_TASK_ID`` stays an absence;
* every observed value names a **registered** observation source - a
  free-form source string is no longer enough;
* the worker envelope holds no observed container id, ever;
* the client-side container id is provider-observed, carries a correlation
  record, and is tied to the very invocation the worker observed - a container
  of the same app that cannot be correlated is refused;
* the producer -> serialized response -> stage evidence -> provenance consumer
  path holds, and the digests are recomputed in the tampering tests;
* the historical evidence of Iterations 14-20 stays valid.

The tests that need the committed capture skip - with an explicit reason -
while the artifacts of the capture are not committed yet. The tests of the
contract itself always run.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    OBSERVATION_SIDE_CLIENT,
    OBSERVATION_SIDE_WORKER,
    PROVIDER_OBSERVATION_SOURCES,
    SOURCE_CLIENT_APP_ID,
    SOURCE_CLIENT_APP_PAGE_URL,
    SOURCE_CLIENT_CONTAINER_ID,
    SOURCE_WORKER_FUNCTION_CALL_ID,
    StageResponseCapture,
    build_stage_identity_facts,
    observed,
    not_available,
    sha256_bytes,
    validate_client_observed_facts,
    validate_modal_invocation_provenance,
    validate_provider_observation_source,
    validate_runtime_identity_envelope,
    validate_stage_evidence_artifact,
)
from benchmarks.validate_iteration21_evidence import (  # noqa: E402
    DEFAULT_EVIDENCE_DIR,
    DEFAULT_REPORT,
    FORBIDDEN_ENVIRONMENT_NAMES,
    PRODUCER_SOURCE,
    STAGE,
    TARGET_ID,
    _validate_iteration21,
    find_environment_lookups,
    main,
)

EVIDENCE_DIR = _ROOT / DEFAULT_EVIDENCE_DIR
RECORD_PATH = EVIDENCE_DIR / "capture_record.json"
ARTIFACT_PATH = EVIDENCE_DIR / f"{TARGET_ID}_stage_evidence_{STAGE}.json"
VALIDATION_EVIDENCE = _ROOT / DEFAULT_REPORT
CHANGE_IMPACT_MATRIX = _ROOT / "benchmarks" / "evidence" / "iteration21_change_impact_matrix.md"
CI_WORKFLOW = _ROOT / ".github" / "workflows" / "ci.yml"

#: The provider-issued identifiers the tests work with.
FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y3"
OTHER_FUNCTION_CALL_ID = "fc-01M71H7789CATYCWNEG05916Y4"
APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oJ"
OTHER_APP_ID = "ap-gW7GDdh9OlSqjL2tRnB1oK"
CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRR"
OTHER_CONTAINER_ID = "ta-01M71H78SAWD0JF71CFPA0QTRS"

#: The fake values the hostile environment holds.
SPOOFED_WORKER_ID = "ta-SpoofedWorkerId0000000000"
SPOOFED_HOSTNAME = "spoofed-host"
SPOOFED_TASK_ID = "ta-SpoofedTaskId00000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _committed_capture() -> Dict[str, Any]:
    """The committed artifacts of the capture - or an explicit skip."""
    if not RECORD_PATH.is_file() or not ARTIFACT_PATH.is_file():
        pytest.skip(
            "the capture of Iteration 21 is not committed yet - the artifacts are published "
            "with the evidence commit"
        )
    return {
        "record": json.loads(RECORD_PATH.read_text(encoding="utf-8")),
        "artifact": json.loads(ARTIFACT_PATH.read_text(encoding="utf-8")),
    }


def _producer_envelope(monkeypatch: pytest.MonkeyPatch, **environment: str) -> Dict[str, Any]:
    """
    Run the **real** production producer and return the envelope it built.

    ``environment`` sets the container environment of the simulated container:
    ``function_call_id`` is what ``modal.current_function_call_id()`` returns,
    ``worker_id``, ``hostname`` and ``task_id`` are the container's environment
    variables - the very ones the producer must not read.
    """
    import modal
    import modal_app

    function_call_id = environment.get("function_call_id")
    monkeypatch.setattr(
        modal,
        "current_function_call_id",
        lambda: function_call_id,
        raising=False,
    )
    for name in ("MODAL_WORKER_ID", "HOSTNAME", "MODAL_TASK_ID"):
        monkeypatch.delenv(name, raising=False)
    if "worker_id" in environment:
        monkeypatch.setenv("MODAL_WORKER_ID", environment["worker_id"])
    if "hostname" in environment:
        monkeypatch.setenv("HOSTNAME", environment["hostname"])
    if "task_id" in environment:
        monkeypatch.setenv("MODAL_TASK_ID", environment["task_id"])

    return modal_app.capture_modal_runtime_identity()


class _FakeProvider:
    """
    A **fake** provider - a simulation, and always called one.

    It answers exactly the three questions the real provider answers, so the
    whole client path can be driven without a network. It is never a proof of
    a live Modal identity.
    """

    def __init__(
        self,
        *,
        inputs: Optional[List[Any]] = None,
        containers: Optional[List[Any]] = None,
        task_app_ids: Optional[Dict[str, str]] = None,
        raises: bool = False,
    ) -> None:
        self._inputs = inputs or []
        self._containers = containers or []
        self._task_app_ids = task_app_ids or {}
        self._raises = raises

    def call_graph_inputs(self, function_call_id: str) -> List[Any]:
        if self._raises:
            raise RuntimeError("the provider could not be asked")
        return list(self._inputs)

    def containers_of_app(self, app_id: str) -> List[Any]:
        if self._raises:
            raise RuntimeError("the provider could not be asked")
        return list(self._containers)

    def task_app_id(self, container_id: str) -> Optional[str]:
        if self._raises:
            raise RuntimeError("the provider could not be asked")
        return self._task_app_ids.get(container_id)


def _graph_input(
    *,
    input_id: str = "in-01M71H7789CATYCWNEG05916Y3",
    function_call_id: str = FUNCTION_CALL_ID,
    container_id: str = CONTAINER_ID,
) -> Any:
    from benchmarks.modal_provider import ProviderCallGraphInput

    return ProviderCallGraphInput(
        input_id=input_id,
        function_call_id=function_call_id,
        container_id=container_id,
    )


def _container(
    *,
    container_id: str = CONTAINER_ID,
    app_id: str = APP_ID,
) -> Any:
    from benchmarks.modal_provider import ProviderContainer

    return ProviderContainer(container_id=container_id, app_id=app_id)


def _correlated_container_fact(
    *,
    value: str = CONTAINER_ID,
    function_call_id: str = FUNCTION_CALL_ID,
    app_id: str = APP_ID,
    source: str = SOURCE_CLIENT_CONTAINER_ID,
    with_correlation: bool = True,
) -> Dict[str, Any]:
    """A client-side container id with a correlation record."""
    fact = observed(
        value,
        source=source,
        observed_by=OBSERVATION_SIDE_CLIENT,
    )
    if with_correlation:
        fact["correlation"] = {
            "function_call_id": function_call_id,
            "app_id": app_id,
            "container_id": value,
            "provider_records": {
                "call_graph_input": {
                    "input_id": "in-01M71H7789CATYCWNEG05916Y3",
                    "function_call_id": function_call_id,
                    "task_id": value,
                },
                "app_container_listing": {
                    "container_id": value,
                    "app_id": app_id,
                },
                "task_record": {
                    "container_id": value,
                    "app_id": app_id,
                },
            },
        }
    return fact


def _client_block(container_fact: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The client-observed block of a run."""
    return {
        "app_id": observed(
            APP_ID,
            source=SOURCE_CLIENT_APP_ID,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "app_page_url": observed(
            f"https://modal.com/id/{APP_ID}",
            source=SOURCE_CLIENT_APP_PAGE_URL,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
        "container_id": (
            container_fact
            if container_fact is not None
            else _correlated_container_fact()
        ),
    }


def _check_by_name(outcome: Dict[str, Any], name: str) -> Dict[str, Any]:
    for check in outcome["checks"]:
        if check["check"] == name:
            return check
    raise AssertionError(f"the validator does not run the check {name!r}")


def _revalidate(
    tmp_path: Path,
    *,
    record_mutator: Optional[Callable[[Dict[str, Any]], None]] = None,
    artifact_mutator: Optional[Callable[[Dict[str, Any]], None]] = None,
    keep_recorded_digest: bool = False,
) -> Dict[str, Any]:
    """
    Run the Iteration 21 validator over a copy of the committed capture.

    The copy may be mutated - that is how the adversarial tests prove that the
    validator really rejects a broken artifact and does not merely accept the
    published one.
    """
    committed = _committed_capture()
    record = json.loads(json.dumps(committed["record"]))
    artifact = json.loads(json.dumps(committed["artifact"]))

    if record_mutator is not None:
        record_mutator(record)
    if artifact_mutator is not None:
        artifact_mutator(artifact)

    copy_dir = tmp_path / "capture"
    copy_dir.mkdir(parents=True, exist_ok=True)
    artifact_copy = copy_dir / ARTIFACT_PATH.name
    artifact_copy.write_bytes(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )
    record["evidence_artifact"]["path"] = str(
        artifact_copy.relative_to(_ROOT)
    ).replace("\\", "/") if _ROOT in artifact_copy.parents else str(artifact_copy)
    if not keep_recorded_digest:
        record["evidence_artifact"]["sha256"] = sha256_bytes(artifact_copy.read_bytes())
    (copy_dir / "capture_record.json").write_bytes(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    )

    return _validate_iteration21(
        evidence_dir=copy_dir,
        code_sha=record.get("source", {}).get("code_sha"),
    )


# ===========================================================================
# 1) The producer source
# ===========================================================================

def test_iteration21_the_producer_source_reads_no_environment_variable_for_the_container_id():
    """The producer must not read MODAL_WORKER_ID, HOSTNAME or MODAL_TASK_ID."""
    assert PRODUCER_SOURCE.is_file()
    lookups = find_environment_lookups(PRODUCER_SOURCE)
    forbidden = [hit for hit in lookups if hit["name"] in FORBIDDEN_ENVIRONMENT_NAMES]
    assert forbidden == [], (
        f"the producer source still reads the environment variable(s) "
        f"{[hit['name'] for hit in forbidden]} at line(s) "
        f"{[hit['line'] for hit in forbidden]}"
    )


def test_iteration21_a_producer_that_reads_the_hostname_is_detected(tmp_path):
    """The check must find a lookup in a source that has one."""
    broken = tmp_path / "broken_producer.py"
    broken.write_text(
        "import os\n"
        "\n"
        "def capture():\n"
        "    return os.environ.get('HOSTNAME')\n",
        encoding="utf-8",
    )
    hits = find_environment_lookups(broken)
    assert len(hits) == 1
    assert hits[0]["name"] == "HOSTNAME"


def test_iteration21_a_docstring_that_mentions_the_hostname_is_not_a_lookup(tmp_path):
    """A mention of the variable in a docstring is not a lookup."""
    harmless = tmp_path / "harmless.py"
    harmless.write_text(
        '"""The producer reads neither MODAL_WORKER_ID nor HOSTNAME."""\n'
        "\n"
        "def capture():\n"
        "    return {'note': 'HOSTNAME is not provider-issued'}\n",
        encoding="utf-8",
    )
    assert find_environment_lookups(harmless) == []


def test_iteration21_the_producer_never_touches_the_running_app_module(monkeypatch):
    """The real producer must not even touch the unsupported module."""
    import modal
    import modal_app

    class _Sentinel:
        def __init__(self) -> None:
            self.accesses: list = []

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            self.accesses.append("call")
            raise AssertionError("modal.running_app was called")

        def __getattr__(self, name: str) -> Any:
            if name.startswith("__") and name.endswith("__"):
                raise AttributeError(name)
            self.accesses.append(name)
            raise AssertionError("modal.running_app was read")

    sentinel = _Sentinel()
    monkeypatch.setattr(modal, "running_app", sentinel, raising=False)
    for name in ("MODAL_WORKER_ID", "HOSTNAME", "MODAL_TASK_ID"):
        monkeypatch.delenv(name, raising=False)

    envelope = modal_app.capture_modal_runtime_identity()

    assert sentinel.accesses == [], f"the producer touched modal.running_app: {sentinel.accesses}"
    assert isinstance(envelope, dict)


# ===========================================================================
# 2) The spoofed environment
# ===========================================================================

def test_iteration21_a_spoofed_environment_does_not_become_an_observed_container_id(monkeypatch):
    """Well-formed fake values in the environment stay an absence."""
    import modal_app

    envelope = _producer_envelope(
        monkeypatch,
        worker_id=SPOOFED_WORKER_ID,
        hostname=SPOOFED_HOSTNAME,
        task_id=SPOOFED_TASK_ID,
    )

    fact = envelope["container_id"]
    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert envelope["container_id_value"] is None
    assert SPOOFED_WORKER_ID not in str(fact)
    assert SPOOFED_HOSTNAME not in str(fact)
    assert modal_app.MODAL_CONTAINER_ID_NOT_ATTESTABLE_REASON == fact["reason"]


def test_iteration21_the_container_id_is_an_explicit_absence_with_the_precise_reason(monkeypatch):
    """The container id is NOT_AVAILABLE with the exact reason of the producer."""
    import modal_app

    envelope = _producer_envelope(monkeypatch)
    fact = envelope["container_id"]

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert fact["reason"] == modal_app.MODAL_CONTAINER_ID_NOT_ATTESTABLE_REASON
    assert fact["observed_by"] == OBSERVATION_SIDE_WORKER
    assert "MODAL_WORKER_ID" in fact["reason"]
    assert "HOSTNAME" in fact["reason"]
    assert envelope["container_id_value"] is None


def test_iteration21_the_function_call_id_keeps_its_exact_source(monkeypatch):
    """The function-call id is the worker's provider-issued anchor."""
    envelope = _producer_envelope(monkeypatch, function_call_id=FUNCTION_CALL_ID)

    fact = envelope["function_call_id"]
    assert fact["status"] == OBSERVED
    assert fact["value"] == FUNCTION_CALL_ID
    assert fact["source"] == SOURCE_WORKER_FUNCTION_CALL_ID
    assert fact["observed_by"] == OBSERVATION_SIDE_WORKER


def test_iteration21_the_worker_envelope_holds_no_observed_container_id(monkeypatch):
    """The real producer never reports an observed container id."""
    envelope = _producer_envelope(
        monkeypatch,
        function_call_id=FUNCTION_CALL_ID,
        worker_id=SPOOFED_WORKER_ID,
        hostname=SPOOFED_HOSTNAME,
        task_id=SPOOFED_TASK_ID,
    )

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if field_name == "container_id":
            assert fact["status"] == NOT_AVAILABLE


# ===========================================================================
# 3) The registry of the allowed observation sources
# ===========================================================================

def test_iteration21_the_registered_sources_are_accepted():
    """A well-formed envelope passes the strict source mode."""
    envelope = {
        "app_id": not_available(
            "no application id in the container",
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
        "function_call_id": observed(
            FUNCTION_CALL_ID,
            source=SOURCE_WORKER_FUNCTION_CALL_ID,
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
        "container_id": not_available(
            "no container id in the container",
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
    }
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert ok, error


def test_iteration21_an_unregistered_source_is_rejected():
    """A free-form source string is not enough."""
    envelope = {
        "function_call_id": observed(
            FUNCTION_CALL_ID,
            source="somewhere in the container",
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
    }
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "registered observation source" in (error or "")


def test_iteration21_a_worker_side_observed_container_id_is_rejected():
    """The old, defective source is not a registered one."""
    envelope = {
        "container_id": observed(
            CONTAINER_ID,
            source="MODAL_WORKER_ID/HOSTNAME of the running container",
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
    }
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "registered observation source" in (error or "")


def test_iteration21_a_synthetic_container_id_is_rejected():
    """A synthetic value is not a provider-issued container id."""
    envelope = {
        "container_id": observed(
            "modal-cpu-0123456789ab",
            source=SOURCE_CLIENT_CONTAINER_ID,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
    }
    ok, error = validate_provider_observation_source("container_id", envelope["container_id"])
    assert not ok
    assert "not a provider-issued identifier" in (error or "")


def test_iteration21_a_malformed_function_call_id_is_rejected():
    """A malformed provider id is rejected."""
    envelope = {
        "function_call_id": observed(
            "fc-guess",
            source=SOURCE_WORKER_FUNCTION_CALL_ID,
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
    }
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "not a provider-issued identifier" in (error or "")


def test_iteration21_the_registry_covers_every_identity_field():
    """Every identity field has a registered source."""
    for field_name in ("function_call_id", "app_id", "app_page_url", "container_id"):
        assert field_name in PROVIDER_OBSERVATION_SOURCES
    assert (
        PROVIDER_OBSERVATION_SOURCES["container_id"]["side"] == OBSERVATION_SIDE_CLIENT
    )
    assert (
        PROVIDER_OBSERVATION_SOURCES["function_call_id"]["side"] == OBSERVATION_SIDE_WORKER
    )


# ===========================================================================
# 4) The client-side container identity
# ===========================================================================

def test_iteration21_the_client_side_container_id_is_provider_observed():
    """The client resolves the container of the very invocation."""
    from benchmarks.adapters import _client_observed_container_id

    provider = _FakeProvider(
        inputs=[_graph_input()],
        containers=[_container()],
        task_app_ids={CONTAINER_ID: APP_ID},
    )
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == OBSERVED
    assert fact["value"] == CONTAINER_ID
    assert fact["source"] == SOURCE_CLIENT_CONTAINER_ID
    assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT
    correlation = fact["correlation"]
    assert correlation["function_call_id"] == FUNCTION_CALL_ID
    assert correlation["app_id"] == APP_ID
    assert correlation["container_id"] == CONTAINER_ID


def test_iteration21_the_client_side_container_id_is_correlated_to_the_invocation():
    """The strict client validation accepts the correlated container id."""
    block = _client_block()
    ok, error = validate_client_observed_facts(
        block,
        strict_sources=True,
        expected_function_call_id=FUNCTION_CALL_ID,
        expected_app_id=APP_ID,
    )
    assert ok, error


def test_iteration21_a_client_side_container_id_of_another_invocation_is_rejected():
    """A container of another invocation is refused."""
    block = _client_block(_correlated_container_fact(function_call_id=OTHER_FUNCTION_CALL_ID))
    ok, error = validate_client_observed_facts(
        block,
        strict_sources=True,
        expected_function_call_id=FUNCTION_CALL_ID,
        expected_app_id=APP_ID,
    )
    assert not ok
    assert "another invocation" in (error or "")


def test_iteration21_a_client_side_container_id_of_another_app_is_rejected():
    """A container of another application is refused."""
    block = _client_block(_correlated_container_fact(app_id=OTHER_APP_ID))
    ok, error = validate_client_observed_facts(
        block,
        strict_sources=True,
        expected_function_call_id=FUNCTION_CALL_ID,
        expected_app_id=APP_ID,
    )
    assert not ok
    assert "another application" in (error or "")


def test_iteration21_a_client_side_container_id_without_the_provider_source_is_rejected():
    """A free-form source string does not make a container id provider-backed."""
    block = _client_block(
        _correlated_container_fact(source="the container of the last run")
    )
    ok, error = validate_client_observed_facts(block, strict_sources=True)
    assert not ok
    assert "registered observation source" in (error or "")


def test_iteration21_a_client_side_container_id_without_a_correlation_is_rejected():
    """A container id that is not tied to the invocation is refused."""
    block = _client_block(_correlated_container_fact(with_correlation=False))
    ok, error = validate_client_observed_facts(block, strict_sources=True)
    assert not ok
    assert "correlation record" in (error or "")


def test_iteration21_an_uncorrelated_container_of_the_same_app_is_rejected():
    """A container the provider does not list for the app is never attached."""
    from benchmarks.adapters import _client_observed_container_id

    # The call graph names a container that the provider's listing of this
    # application does NOT hold: an unrelated container of the same app.
    provider = _FakeProvider(
        inputs=[_graph_input(container_id=OTHER_CONTAINER_ID)],
        containers=[_container(container_id=CONTAINER_ID)],
        task_app_ids={OTHER_CONTAINER_ID: APP_ID, CONTAINER_ID: APP_ID},
    )
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "container listing" in fact["reason"]


def test_iteration21_a_container_listed_for_the_app_is_accepted():
    """The provider's listing is what makes the container belong to the app."""
    from benchmarks.adapters import _client_observed_container_id

    provider = _FakeProvider(
        inputs=[_graph_input()],
        containers=[_container(), _container(container_id=OTHER_CONTAINER_ID, app_id=APP_ID)],
        task_app_ids={CONTAINER_ID: APP_ID},
    )
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == OBSERVED
    assert fact["value"] == CONTAINER_ID


def test_iteration21_a_mismatched_task_record_is_rejected():
    """The provider's own task record is the second cross-check."""
    from benchmarks.adapters import _client_observed_container_id

    provider = _FakeProvider(
        inputs=[_graph_input()],
        containers=[_container()],
        task_app_ids={CONTAINER_ID: OTHER_APP_ID},
    )
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "task record" in fact["reason"]


def test_iteration21_a_missing_provider_response_is_an_explicit_absence():
    """A provider that answers nothing yields an explicit absence."""
    from benchmarks.adapters import _client_observed_container_id

    provider = _FakeProvider(inputs=[], containers=[], task_app_ids={})
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "call graph" in fact["reason"]


def test_iteration21_an_unreachable_provider_is_an_explicit_absence():
    """A provider that cannot be asked yields an explicit absence."""
    from benchmarks.adapters import _client_observed_container_id

    provider = _FakeProvider(raises=True)
    fact = _client_observed_container_id(
        function_call_id=FUNCTION_CALL_ID,
        app_id=APP_ID,
        provider=provider,
    )

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert "could not be read" in fact["reason"]


def test_iteration21_without_a_function_call_id_the_container_id_is_unavailable():
    """Without the worker's anchor there is nothing to correlate."""
    from benchmarks.adapters import _client_observed_container_id

    fact = _client_observed_container_id(
        function_call_id=not_available("no function call id"),
        app_id=APP_ID,
        provider=_FakeProvider(),
    )

    assert fact["status"] == NOT_AVAILABLE
    assert "function-call id" in fact["reason"]


def test_iteration21_a_client_observation_inside_the_worker_envelope_is_rejected():
    """A client fact may never sit inside the worker envelope."""
    envelope = {
        "container_id": observed(
            CONTAINER_ID,
            source=SOURCE_CLIENT_CONTAINER_ID,
            observed_by=OBSERVATION_SIDE_CLIENT,
        ),
    }
    ok, error = validate_runtime_identity_envelope(envelope, strict_sources=True)
    assert not ok
    assert "worker" in (error or "")
    assert "side" in (error or "")


# ===========================================================================
# 5) The producer -> response -> stage evidence -> provenance path
# ===========================================================================

def _capture_and_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """Run the real producer and write its stage evidence artifact."""
    import modal_app

    envelope = _producer_envelope(monkeypatch, function_call_id=FUNCTION_CALL_ID)
    response = {
        "stage": STAGE,
        "modal_runtime": envelope,
        "worker_observed": {"note": "the response of the production producer"},
    }
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of the production producer",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    from benchmarks.evidence_integrity import write_stage_evidence_artifact

    artifact_path, artifact_ref = write_stage_evidence_artifact(
        tmp_path,
        capture,
        target_id=TARGET_ID,
        correlation_id="corr-iteration21-test",
    )
    return {
        "envelope": envelope,
        "capture": capture,
        "artifact_path": artifact_path,
        "artifact_ref": artifact_ref,
        "producer": modal_app,
    }


def test_iteration21_the_producer_response_satisfies_the_evidence_contract(tmp_path, monkeypatch):
    """The whole path holds: producer -> response -> artifact -> validator."""
    from benchmarks.evidence_integrity import (
        build_modal_stage_provenance,
        build_stage_identity_facts,
    )

    captured = _capture_and_artifact(tmp_path, monkeypatch)
    artifact = json.loads(captured["artifact_path"].read_text(encoding="utf-8"))

    ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    assert ok, error

    ok, error = validate_runtime_identity_envelope(
        artifact["runtime_identity"],
        strict_sources=True,
    )
    assert ok, error

    stage_facts = build_stage_identity_facts(
        captured["capture"],
        evidence_ref=captured["artifact_ref"],
    )
    provenance = {
        "modal_invocation_provenance": {
            "modal_app_id": stage_facts["app_id"],
            "client_observed": {
                "app_id": observed(
                    APP_ID,
                    source=SOURCE_CLIENT_APP_ID,
                    observed_by=OBSERVATION_SIDE_CLIENT,
                ),
                "container_id": not_available(
                    "the provider was not asked in this test",
                    observed_by=OBSERVATION_SIDE_CLIENT,
                ),
            },
            "target_id": TARGET_ID,
            "correlation_id": "corr-iteration21-test",
            "stages": {
                STAGE: build_modal_stage_provenance(
                    function_name="verify_exploit_remote",
                    resource="CPU",
                    attempted=True,
                    evidence_ref=captured["artifact_ref"],
                    **stage_facts,
                ),
            },
        }
    }
    ok, error = validate_modal_invocation_provenance(
        provenance,
        evidence_root=tmp_path,
        strict_sources=True,
    )
    assert ok, error


def test_iteration21_a_detached_envelope_is_rejected(tmp_path, monkeypatch):
    """An envelope that is not the one of the response is refused."""
    captured = _capture_and_artifact(tmp_path, monkeypatch)
    artifact = json.loads(captured["artifact_path"].read_text(encoding="utf-8"))

    artifact["runtime_identity"]["function_call_id"]["value"] = OTHER_FUNCTION_CALL_ID

    ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    assert not ok
    assert "runtime-identity" in (error or "").lower()


def test_iteration21_the_stage_facts_keep_the_side_of_the_envelope(monkeypatch):
    """The side survives the producer -> facts path."""
    envelope = _producer_envelope(monkeypatch, function_call_id=FUNCTION_CALL_ID)
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of the production producer",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    facts = build_stage_identity_facts(capture)

    for field_name, fact in facts.items():
        # An observed fact names the side it was observed from; an absence may
        # leave the side unnamed.
        side = fact.get("observed_by")
        assert side in (None, OBSERVATION_SIDE_WORKER), field_name
    assert facts["function_call_id"]["status"] == OBSERVED
    assert facts["function_call_id"]["observed_by"] == OBSERVATION_SIDE_WORKER
    assert facts["container_id"]["status"] == NOT_AVAILABLE


# ===========================================================================
# 6) The published evidence
# ===========================================================================

def test_iteration21_the_artifact_digest_matches_the_bytes_on_disk():
    """The digest of the artifact is the digest of the bytes on disk."""
    committed = _committed_capture()
    from benchmarks.evidence_integrity import file_sha256

    recorded = committed["record"]["evidence_artifact"]["sha256"]
    assert file_sha256(ARTIFACT_PATH) == recorded


def test_iteration21_a_tampered_artifact_is_rejected(tmp_path):
    """A tampered artifact is refused."""
    outcome = _revalidate(
        tmp_path,
        artifact_mutator=lambda artifact: artifact["provider_response"].update(
            {"tampered": True}
        ),
        keep_recorded_digest=True,
    )
    check = _check_by_name(outcome, "P3.9.artifact_digest_matches_the_bytes_on_disk")
    assert check["status"] == "FAILED"


def test_iteration21_the_validator_accepts_the_committed_capture():
    """The committed capture passes every check of the validator."""
    outcome = _validate_iteration21(
        evidence_dir=EVIDENCE_DIR,
        code_sha=json.loads(RECORD_PATH.read_text(encoding="utf-8"))["source"]["code_sha"],
    )
    assert outcome["errors"] == [], outcome["errors"]
    assert len(outcome["checks"]) >= 13


def test_iteration21_the_validator_rejects_a_producer_that_reads_the_hostname(tmp_path):
    """A capture whose producer read the hostname is refused."""
    def _mutate(record: Dict[str, Any]) -> None:
        record["runtime_identity"]["container_id"] = observed(
            SPOOFED_WORKER_ID,
            source="MODAL_WORKER_ID/HOSTNAME of the running container",
            observed_by=OBSERVATION_SIDE_WORKER,
        )

    outcome = _revalidate(tmp_path, record_mutator=_mutate)
    check = _check_by_name(
        outcome,
        "P3.6.the_worker_holds_no_observed_container_id",
    )
    assert check["status"] == "FAILED"


def test_iteration21_the_capture_declares_no_live_invocation_and_no_deployment():
    """The capture states its own boundary."""
    committed = _committed_capture()
    invocation = committed["record"]["invocation"]

    assert invocation["live_modal_invocation"] is False
    assert invocation["provider_queried"] is False
    assert invocation["deployment"] == "none"
    assert invocation["gpu"] == "none"


def test_iteration21_the_capture_holds_no_provider_issued_identifier():
    """The capture is local: it holds no provider-issued identifier."""
    committed = _committed_capture()
    envelope = committed["record"]["runtime_identity"]

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope.get(field_name)
        if isinstance(fact, dict):
            assert fact["status"] == NOT_AVAILABLE, field_name


def test_iteration21_the_validation_evidence_is_bound_to_the_code_sha():
    """The published report is bound to the commit it was made from."""
    if not VALIDATION_EVIDENCE.is_file():
        pytest.skip(
            "the validation evidence of Iteration 21 is not committed yet - it is published "
            "with the evidence commit"
        )
    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    bound = report.get("code_sha")
    assert isinstance(bound, str) and len(bound) == 40

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    assert head
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", bound, head],
        cwd=_ROOT,
        capture_output=True,
        check=False,
    )
    assert ancestor.returncode == 0, (
        f"the validation evidence is bound to {bound}, which is not an ancestor of {head}"
    )


def test_iteration21_the_check_mode_detects_a_foreign_code_sha(tmp_path):
    """``--check`` refuses a report that belongs to another commit."""
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps({"code_sha": "0" * 40, "summary": {"overall_status": "PASSED"}}),
        encoding="utf-8",
    )
    exit_code = main(
        ["--check", "--report", str(report_path), "--code-sha", "1" * 40]
    )
    assert exit_code == 1


def test_iteration21_the_historical_evidence_stays_valid():
    """The artifacts of Iteration 20 still satisfy their own validator."""
    from benchmarks.validate_iteration20_evidence import (
        DEFAULT_EVIDENCE_DIR as ITER20_DIR,
        _validate_iteration20,
    )

    evidence_dir = _ROOT / ITER20_DIR
    if not (evidence_dir / "capture_record.json").is_file():
        pytest.skip("the capture of Iteration 20 is not committed")

    outcome = _validate_iteration20(evidence_dir=evidence_dir, code_sha=None)
    assert outcome["errors"] == [], outcome["errors"]


def test_iteration21_the_ci_workflow_runs_the_new_suite_and_the_new_validator():
    """The workflow runs the Iteration 21 suite and the Iteration 21 validator."""
    if not CI_WORKFLOW.is_file():
        pytest.skip("the CI workflow is not committed")
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "tests/test_iteration21_evidence_integrity.py" in workflow
    assert "python -m benchmarks.validate_iteration21_evidence --check" in workflow


def test_iteration21_the_change_impact_matrix_documents_the_iteration():
    """The matrix states the boundary of the iteration."""
    if not CHANGE_IMPACT_MATRIX.is_file():
        pytest.skip("the change impact matrix of Iteration 21 is not committed")
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "Iteration 21" in matrix
    assert "no live modal call" in matrix.lower()
    assert "MODAL_WORKER_ID" in matrix
    assert "HOSTNAME" in matrix
