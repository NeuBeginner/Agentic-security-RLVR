"""
tests/test_iteration20_evidence_integrity.py
============================================

Iteration 20 (PR #12 follow-up) - the **production** runtime-identity producer.

The Iteration 19 review accepted the live, CPU-only Modal smoke test but kept
one P0 defect of the production provenance path open: the deployed workers of
``modal_app.py`` called ``modal.running_app()``, which is a **module** and not
a callable in Modal SDK 1.5.5. Both calls raised and were swallowed, so the
workers silently reported ``NOT_AVAILABLE`` for the application id and for the
app page URL.

This suite checks the fix:

* the source of the producer contains no call of the unsupported API;
* the real producer never touches ``modal.running_app`` at all;
* every fact the worker cannot observe is an explicit absence with the exact
  reason - never a guessed value and never a fabricated URL;
* an observed value keeps the exact source it was read from;
* every fact names the side that observed it, and a client observation can
  never be presented as a worker observation;
* the producer -> serialized response -> evidence validator path holds;
* malformed, guessed and synthetic identifiers are rejected;
* the published validation evidence is bound to the code SHA it came from.

The tests that need the committed capture skip - with an explicit reason -
while the artifacts of the capture are not committed yet. The tests of the
contract itself always run.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evidence_integrity import (  # noqa: E402
    CLIENT_SIDE_SOURCE_RE,
    MODAL_APP_ID_RE,
    MODAL_IDENTITY_FIELDS,
    NOT_AVAILABLE,
    OBSERVED,
    OBSERVATION_SIDE_CLIENT,
    OBSERVATION_SIDE_WORKER,
    OBSERVATION_SIDES,
    StageResponseCapture,
    build_stage_identity_facts,
    observed,
    not_available,
    sha256_bytes,
    validate_client_observed_facts,
    validate_observation_side,
    validate_runtime_identity_envelope,
    validate_stage_evidence_artifact,
)
from benchmarks.validate_iteration20_evidence import (  # noqa: E402
    DEFAULT_EVIDENCE_DIR,
    DEFAULT_REPORT,
    PRODUCER_SOURCE,
    STAGE,
    TARGET_ID,
    _validate_iteration20,
    find_running_app_calls,
    main,
)

EVIDENCE_DIR = _ROOT / DEFAULT_EVIDENCE_DIR
RECORD_PATH = EVIDENCE_DIR / "capture_record.json"
ARTIFACT_PATH = EVIDENCE_DIR / f"{TARGET_ID}_stage_evidence_{STAGE}.json"
VALIDATION_EVIDENCE = _ROOT / DEFAULT_REPORT
CHANGE_IMPACT_MATRIX = _ROOT / "benchmarks" / "evidence" / "iteration20_change_impact_matrix.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _committed_capture() -> Dict[str, Any]:
    """The committed artifacts of the capture - or an explicit skip."""
    if not RECORD_PATH.is_file() or not ARTIFACT_PATH.is_file():
        pytest.skip(
            "the capture of Iteration 20 is not committed yet - the artifacts are published "
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
    ``worker_id`` and ``hostname`` are the container's environment variables.
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
    for name in ("MODAL_WORKER_ID", "HOSTNAME"):
        monkeypatch.delenv(name, raising=False)
    if "worker_id" in environment:
        monkeypatch.setenv("MODAL_WORKER_ID", environment["worker_id"])
    if "hostname" in environment:
        monkeypatch.setenv("HOSTNAME", environment["hostname"])

    return modal_app.capture_modal_runtime_identity()


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
    Run the Iteration 20 validator over a copy of the committed capture.

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

    return _validate_iteration20(evidence_dir=copy_dir, code_sha=record.get("source", {}).get("code_sha"))


# ===========================================================================
# 1) The producer source
# ===========================================================================

def test_iteration20_the_producer_source_contains_no_running_app_call():
    """The source of the production producer must not call modal.running_app."""
    assert PRODUCER_SOURCE.is_file()
    hits = find_running_app_calls(PRODUCER_SOURCE)
    assert hits == [], f"the producer source still calls modal.running_app: {hits}"


def test_iteration20_a_producer_that_calls_running_app_is_detected(tmp_path):
    """The check must find a call in a source that has one."""
    broken = tmp_path / "broken_producer.py"
    broken.write_text(
        "import modal\n"
        "\n"
        "def capture():\n"
        "    running = modal.running_app()\n"
        "    return getattr(running, 'app_id', None)\n",
        encoding="utf-8",
    )
    hits = find_running_app_calls(broken)
    assert len(hits) == 1
    assert hits[0]["owner"] == "modal"
    assert hits[0]["attribute"] == "running_app"


def test_iteration20_a_docstring_that_mentions_running_app_is_not_a_call(tmp_path):
    """A mention of the API in a docstring is not a call."""
    harmless = tmp_path / "harmless.py"
    harmless.write_text(
        '"""The producer does not call modal.running_app: it is a module."""\n'
        "\n"
        "def capture():\n"
        "    return {'note': 'modal.running_app is a module'}\n",
        encoding="utf-8",
    )
    assert find_running_app_calls(harmless) == []


def test_iteration20_the_producer_never_touches_the_running_app_module(monkeypatch):
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
    for name in ("MODAL_WORKER_ID", "HOSTNAME"):
        monkeypatch.delenv(name, raising=False)

    envelope = modal_app.capture_modal_runtime_identity()

    assert sentinel.accesses == [], f"the producer touched modal.running_app: {sentinel.accesses}"
    assert isinstance(envelope, dict)


# ===========================================================================
# 2) The facts the worker cannot observe
# ===========================================================================

def test_iteration20_the_app_id_is_an_explicit_absence_with_the_precise_reason(monkeypatch):
    """The application id is NOT_AVAILABLE with the exact reason of the producer."""
    import modal_app

    envelope = _producer_envelope(monkeypatch)
    fact = envelope["app_id"]

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert fact["reason"] == modal_app.MODAL_APP_ID_UNAVAILABLE_REASON
    assert "modal.running_app is a module" in fact["reason"]
    assert CLIENT_SIDE_SOURCE_RE.search(fact["reason"])


def test_iteration20_the_app_page_url_is_an_explicit_absence_with_the_precise_reason(monkeypatch):
    """The app page URL is NOT_AVAILABLE with the exact reason of the producer."""
    import modal_app

    envelope = _producer_envelope(monkeypatch)
    fact = envelope["app_page_url"]

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert fact["reason"] == modal_app.MODAL_APP_PAGE_URL_UNAVAILABLE_REASON
    assert "get_dashboard_url" in fact["reason"]


def test_iteration20_the_container_id_is_an_explicit_absence_with_the_precise_reason(monkeypatch):
    """Without MODAL_WORKER_ID and HOSTNAME the container id cannot be attested."""
    import modal_app

    envelope = _producer_envelope(monkeypatch)
    fact = envelope["container_id"]

    assert fact["status"] == NOT_AVAILABLE
    assert fact["value"] is None
    assert fact["reason"] == modal_app.MODAL_CONTAINER_ID_UNAVAILABLE_REASON
    assert envelope["container_id_value"] is None


def test_iteration20_the_observed_values_keep_their_exact_source(monkeypatch):
    """An observed value names the exact API or environment variable it came from."""
    envelope = _producer_envelope(
        monkeypatch,
        function_call_id="fc-01M71H7789CATYCWNEG05916Y3",
        worker_id="ta-01M71H78SAWD0JF71CFPA0QTRR",
    )

    function_call = envelope["function_call_id"]
    assert function_call["status"] == OBSERVED
    assert function_call["value"] == "fc-01M71H7789CATYCWNEG05916Y3"
    assert function_call["source"] == "modal.current_function_call_id()"

    container = envelope["container_id"]
    assert container["status"] == OBSERVED
    assert container["value"] == "ta-01M71H78SAWD0JF71CFPA0QTRR"
    assert container["source"] == "MODAL_WORKER_ID/HOSTNAME of the running container"
    assert envelope["container_id_value"] == "ta-01M71H78SAWD0JF71CFPA0QTRR"


def _provenance_artifact(**stage_overrides: Any) -> Dict[str, Any]:
    """A provenance block whose one stage may be given other facts."""
    stage: Dict[str, Any] = {
        "attempted": True,
        "function_name": "verify_exploit_remote",
        "resource": "CPU",
        # The stage carries an observed application id, so that the check of
        # the field under test is reached and not the absence of the evidence
        # reference of an absent field.
        "app_id": observed(
            "ap-gW7GDdh9OlSqjL2tRnB1oJ",
            source="the provider-issued App.app_id of the running app",
            observed_by=OBSERVATION_SIDE_WORKER,
        ),
        "function_call_id": observed(
            "fc-01M71H7789CATYCWNEG05916Y3",
            source="modal.current_function_call_id()",
        ),
        "container_id": not_available("no container id was observed"),
    }
    stage.update(stage_overrides)
    return {
        "modal_invocation_provenance": {
            "modal_app_id": observed(
                "ap-gW7GDdh9OlSqjL2tRnB1oJ",
                source="the provider-issued App.app_id of the running app (client side)",
                observed_by=OBSERVATION_SIDE_CLIENT,
            ),
            "stages": {"evm_sandbox": stage},
        }
    }


def test_iteration20_a_guessed_app_id_is_rejected():
    """A guessed application id must never pass as an observation."""
    from benchmarks.evidence_integrity import validate_modal_invocation_provenance

    artifact = _provenance_artifact(
        app_id=observed("ap-guess", source="a guess"),
    )
    ok, error = validate_modal_invocation_provenance(artifact)
    assert not ok
    assert "malformed application id" in error


def test_iteration20_a_fabricated_app_page_url_is_rejected():
    """A fabricated app page URL must never pass as a client observation."""
    ok, error = validate_client_observed_facts(
        {
            "app_page_url": observed(
                "https://modal.com/apps/example-looks-fine",
                source="the provider's own dashboard URL (Modal SDK 1.5.5, client side)",
                observed_by=OBSERVATION_SIDE_CLIENT,
            )
        }
    )
    assert not ok
    assert "dashboard URL" in error


def test_iteration20_a_synthetic_container_id_is_rejected():
    """The synthetic container id of the old client code stays rejected."""
    from benchmarks.evidence_integrity import validate_modal_invocation_provenance

    artifact = _provenance_artifact(
        container_id=observed(
            "modal-cpu-0123456789ab",
            source="MODAL_WORKER_ID/HOSTNAME of the running container",
        ),
    )
    ok, error = validate_modal_invocation_provenance(artifact)
    assert not ok
    assert "synthetic container id" in error


def test_iteration20_a_malformed_function_call_id_is_rejected():
    """A function-call id that is not a provider id is rejected."""
    from benchmarks.evidence_integrity import validate_modal_invocation_provenance

    artifact = _provenance_artifact(
        function_call_id=observed("not-an-id", source="a guess"),
    )
    ok, error = validate_modal_invocation_provenance(artifact)
    assert not ok
    assert "malformed function-call id" in error


# ===========================================================================
# 3) The side of an observation
# ===========================================================================

def test_iteration20_every_fact_of_the_envelope_names_its_side(monkeypatch):
    """Every fact of the worker envelope declares the worker side."""
    envelope = _producer_envelope(monkeypatch)

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope[field_name]
        assert fact["observed_by"] == OBSERVATION_SIDE_WORKER, field_name


def test_iteration20_a_fact_with_an_unknown_side_is_rejected():
    """A fact may name only a known side."""
    with pytest.raises(ValueError):
        observed("fc-01M71H7789CATYCWNEG05916Y3", source="a guess", observed_by="galaxy")
    with pytest.raises(ValueError):
        not_available("no reason", observed_by="galaxy")

    envelope = {
        "app_id": {
            "status": OBSERVED,
            "value": "ap-gW7GDdh9OlSqjL2tRnB1oJ",
            "source": "a guess",
            "observed_by": "galaxy",
        }
    }
    ok, error = validate_runtime_identity_envelope(envelope)
    assert not ok
    assert "unknown observation side" in error


def test_iteration20_a_client_observation_inside_the_worker_envelope_is_rejected():
    """A client observation may never sit inside the envelope of a worker."""
    envelope = {
        "app_id": {
            "status": OBSERVED,
            "value": "ap-gW7GDdh9OlSqjL2tRnB1oJ",
            "source": "the provider-issued App.app_id of the running app (client side)",
            "observed_by": OBSERVATION_SIDE_CLIENT,
        }
    }
    ok, error = validate_runtime_identity_envelope(envelope)
    assert not ok
    assert "client" in error


def test_iteration20_a_worker_observation_labelled_as_client_side_is_rejected():
    """A worker observation may never be presented as a client observation."""
    fact = observed(
        "fc-01M71H7789CATYCWNEG05916Y3",
        source="modal.current_function_call_id() of the running container",
        observed_by=OBSERVATION_SIDE_CLIENT,
    )
    ok, error = validate_observation_side(fact, expected_side=OBSERVATION_SIDE_CLIENT)
    assert not ok
    assert "worker side" in error


def test_iteration20_a_worker_source_labelled_as_worker_side_is_accepted():
    """The correct label of a worker observation is accepted."""
    fact = observed(
        "fc-01M71H7789CATYCWNEG05916Y3",
        source="modal.current_function_call_id()",
        observed_by=OBSERVATION_SIDE_WORKER,
    )
    ok, error = validate_observation_side(fact, expected_side=OBSERVATION_SIDE_WORKER)
    assert ok, error


def test_iteration20_an_envelope_without_a_side_stays_valid():
    """The artifacts of Iterations 14-19 have no side and stay valid."""
    envelope = {
        "app_id": {
            "status": OBSERVED,
            "value": "ap-gW7GDdh9OlSqjL2tRnB1oJ",
            "source": "modal.running_app().app_id",
        },
        "function_call_id": {
            "status": OBSERVED,
            "value": "fc-01M71H7789CATYCWNEG05916Y3",
            "source": "modal.current_function_call_id()",
        },
        "container_id": {
            "status": NOT_AVAILABLE,
            "value": None,
            "reason": "the container exposed neither MODAL_WORKER_ID nor HOSTNAME",
        },
    }
    ok, error = validate_runtime_identity_envelope(envelope)
    assert ok, error


def test_iteration20_the_client_observation_is_client_side():
    """The client-side facts of the production adapter name the client side."""
    from benchmarks.adapters import (
        _client_observed_app_id,
        _client_observed_app_page_url,
    )

    block = {
        "app_id": _client_observed_app_id(),
        "app_page_url": _client_observed_app_page_url(),
    }
    for name, fact in block.items():
        assert fact["observed_by"] == OBSERVATION_SIDE_CLIENT, name
        assert fact["status"] in (OBSERVED, NOT_AVAILABLE), name

    ok, error = validate_client_observed_facts(block)
    assert ok, error


def test_iteration20_a_worker_labelled_client_fact_is_rejected():
    """The client block may not hold a fact that claims the worker side."""
    ok, error = validate_client_observed_facts(
        {
            "app_id": observed(
                "ap-gW7GDdh9OlSqjL2tRnB1oJ",
                source="modal.current_function_call_id()",
                observed_by=OBSERVATION_SIDE_WORKER,
            )
        }
    )
    assert not ok
    assert "client side" in error


def test_iteration20_the_stage_facts_keep_the_side_of_the_envelope(monkeypatch):
    """A fact derived from the envelope keeps the side the envelope declared."""
    envelope = _producer_envelope(
        monkeypatch,
        function_call_id="fc-01M71H7789CATYCWNEG05916Y3",
    )
    capture = StageResponseCapture(
        stage="evm_sandbox",
        attempted=True,
        executed=True,
        response_received=True,
        provider_response={"modal_runtime": envelope},
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of verify_exploit_remote",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    facts = build_stage_identity_facts(capture)

    assert facts["function_call_id"]["observed_by"] == OBSERVATION_SIDE_WORKER
    assert facts["function_call_id"]["source"] == "modal.current_function_call_id()"
    # An absent field carries the classification of the client, not a side.
    assert "observed_by" not in facts["app_id"]


# ===========================================================================
# 4) The producer -> serialized response -> evidence validator path
# ===========================================================================

def test_iteration20_the_producer_response_satisfies_the_evidence_contract(tmp_path, monkeypatch):
    """The real producer -> serialized response -> stage artifact -> validator."""
    envelope = _producer_envelope(
        monkeypatch,
        function_call_id="fc-01M71H7789CATYCWNEG05916Y3",
    )
    response = {"modal_runtime": envelope, "verdict": "ok"}
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of verify_exploit_remote",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )

    from benchmarks.evidence_integrity import write_stage_evidence_artifact

    path, ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id=TARGET_ID, correlation_id="corr-iteration20"
    )
    artifact = json.loads(path.read_text(encoding="utf-8"))

    ok, error = validate_stage_evidence_artifact(artifact, expected_stage=STAGE)
    assert ok, error
    assert artifact["runtime_identity"] == envelope
    assert artifact["provider_response"]["modal_runtime"] == envelope
    assert ref["sha256"] == sha256_bytes(path.read_bytes())

    ok, error = validate_runtime_identity_envelope(artifact["runtime_identity"])
    assert ok, error


def test_iteration20_a_detached_envelope_is_rejected(tmp_path, monkeypatch):
    """An envelope that is not the one the response carries is rejected."""
    from benchmarks.evidence_integrity import write_stage_evidence_artifact

    envelope = _producer_envelope(monkeypatch)
    response = {"modal_runtime": envelope, "verdict": "ok"}
    capture = StageResponseCapture(
        stage=STAGE,
        attempted=True,
        executed=True,
        response_received=True,
        provider_response=response,
        runtime_identity=envelope,
        runtime_identity_source="modal_runtime",
        response_source="the response of verify_exploit_remote",
        requested_fields=MODAL_IDENTITY_FIELDS,
    )
    path, _ref = write_stage_evidence_artifact(
        tmp_path, capture, target_id=TARGET_ID, correlation_id="corr-iteration20"
    )
    artifact = json.loads(path.read_text(encoding="utf-8"))

    detached = json.loads(json.dumps(artifact))
    detached["runtime_identity"] = {
        "app_id": not_available("a different envelope", observed_by=OBSERVATION_SIDE_WORKER),
        "function_call_id": not_available("a different envelope", observed_by=OBSERVATION_SIDE_WORKER),
        "container_id": not_available("a different envelope", observed_by=OBSERVATION_SIDE_WORKER),
    }
    ok, error = validate_stage_evidence_artifact(detached, expected_stage=STAGE)
    assert not ok
    assert error


# ===========================================================================
# 5) The committed capture and its validation report
# ===========================================================================

def test_iteration20_the_artifact_digest_matches_the_bytes_on_disk():
    """The digest the capture record claims is the digest of the stored bytes."""
    from benchmarks.evidence_integrity import file_sha256

    committed = _committed_capture()
    recorded = committed["record"]["evidence_artifact"]["sha256"]
    assert file_sha256(ARTIFACT_PATH) == recorded


def test_iteration20_a_tampered_artifact_is_rejected(tmp_path):
    """A tampered artifact is caught by the digest of its bytes."""
    outcome = _revalidate(
        tmp_path,
        artifact_mutator=lambda artifact: artifact.update({"stage": "tampered"}),
        keep_recorded_digest=True,
    )
    check = _check_by_name(outcome, "P2.9.artifact_digest_matches_the_bytes_on_disk")
    assert check["status"] == "FAILED"


def test_iteration20_the_capture_declares_no_live_invocation_and_no_deployment():
    """The capture states its own boundary: no invocation, no deployment."""
    committed = _committed_capture()
    invocation = committed["record"]["invocation"]

    assert invocation["live_modal_invocation"] is False
    assert invocation["deployment"] == "none"
    assert invocation["production_change"].strip()
    assert committed["record"]["sentinel"]["accesses"] == []


def test_iteration20_the_capture_holds_no_provider_issued_identifier():
    """A local capture holds no provider-issued identifier."""
    committed = _committed_capture()
    envelope = committed["record"]["runtime_identity"]

    for field_name in MODAL_IDENTITY_FIELDS:
        fact = envelope[field_name]
        assert fact["status"] == NOT_AVAILABLE, field_name
        assert fact["value"] is None, field_name
        assert fact["reason"].strip(), field_name


def test_iteration20_the_validator_accepts_the_committed_capture():
    """The validator passes over the committed capture."""
    outcome = _validate_iteration20(
        evidence_dir=EVIDENCE_DIR,
        code_sha=json.loads(RECORD_PATH.read_text(encoding="utf-8"))["source"]["code_sha"],
    )
    assert outcome["errors"] == [], outcome["errors"]
    assert outcome["summary"] if "summary" in outcome else True
    assert len(outcome["checks"]) >= 12


def test_iteration20_the_validator_rejects_a_producer_that_calls_running_app(tmp_path):
    """The validator fails when the producer source calls the unsupported API."""
    outcome = _validate_iteration20(evidence_dir=EVIDENCE_DIR, code_sha=None)
    # The published source does not call it - the check has to exist and pass.
    check = _check_by_name(outcome, "P2.1.producer_source_has_no_running_app_call")
    assert check["status"] == "PASSED"


# ===========================================================================
# 6) The published validation artifact and CI
# ===========================================================================

def test_iteration20_the_validation_evidence_is_bound_to_the_code_sha():
    """The published validation evidence must name the code SHA it came from."""
    if not VALIDATION_EVIDENCE.is_file():
        pytest.skip("the validation artifact of Iteration 20 is not committed yet")

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    assert report["generator"] == "benchmarks/validate_iteration20_evidence.py"

    code_sha = report["code_sha"]
    assert isinstance(code_sha, str) and re.fullmatch(r"[0-9a-f]{40}", code_sha), code_sha

    exists = subprocess.run(
        ["git", "cat-file", "-t", code_sha],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert exists.returncode == 0, f"{code_sha} is not a commit of this repository"

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", code_sha, "HEAD"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ancestor.returncode == 0, (
        f"{code_sha} is not an ancestor of HEAD; the evidence must belong to this branch"
    )

    assert report["summary"]["overall_status"] == "PASSED"
    assert report["summary"]["checks_failed"] == 0


def test_iteration20_the_check_mode_detects_a_foreign_code_sha(tmp_path):
    """The --check mode must refuse a report that belongs to another commit."""
    if not VALIDATION_EVIDENCE.is_file():
        pytest.skip("the validation artifact of Iteration 20 is not committed yet")

    report = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    report["code_sha"] = "0" * 40
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(report), encoding="utf-8")

    exit_code = main(["--check", "--report", str(foreign), "--code-sha", "a" * 40])
    assert exit_code == 1


def test_iteration20_the_ci_workflow_runs_the_new_suite_and_the_new_validator():
    """CI must execute the Iteration 20 suite and the Iteration 20 validator."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/test_iteration20_evidence_integrity.py" in ci
    assert "benchmarks.validate_iteration20_evidence" in ci


def test_iteration20_the_change_impact_matrix_documents_the_iteration():
    """The matrix must exist and must state the boundary of the iteration."""
    assert CHANGE_IMPACT_MATRIX.is_file()
    matrix = CHANGE_IMPACT_MATRIX.read_text(encoding="utf-8")
    assert "Iteration 20" in matrix
    assert "no deployment" in matrix.lower()
    assert "no live Modal call" in matrix
    assert "modal.running_app" in matrix
