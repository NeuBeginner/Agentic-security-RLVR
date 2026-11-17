"""The approved run (R4) - the runner under a signed approval artifact.

The tests of this module prove four facts:

* an ordinary run - without an approval artifact - behaves exactly as it always
  did: no gate, no ledger, no deployed addressing;
* an approved run resolves its provider callables **by name** against the
  deployed application and installs the **client-side guard** on them, so the
  raw provider callable is not reachable through the guard;
* an approved run runs **no ephemeral app**: the deployed application is the
  one that is called;
* an approval artifact that is not signed by the approval authority authorises
  nothing: the run is refused before a single provider call.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from benchmarks import r1_dispatch
from benchmarks.adapters import (
    deployed_addressing_enabled,
    deployed_app_addressing,
    provider_call_context,
    provider_class_method,
    provider_function,
)
from benchmarks.benchmark_runner import (
    AegisBenchmarkSuite,
    _step_policy_from_payload,
    approved_step_run,
)
from core import r1_approval
from core import r1_bounds as r1

#: The payload of the R4 step - the shape the approval authority signs.
R4_PAYLOAD = {
    "step_id": "R4",
    "approved_by": "owner",
    "approved_at": "2026-11-17T09:31:43Z",
    "call_sites": [
        "ProductionAuditAgent.generate_solidity_exploit",
        "ProductionAuditAgent.refine_solidity_exploit",
        "record_trajectory_remote",
        "verify_exploit_remote",
        "verify_replay_remote",
    ],
    "policy": {
        "step_id": "R4",
        "invocation_budgets": {"gpu": 32, "persistence": 16, "sandbox_cpu": 48},
        "concurrency_caps": {"gpu": 32, "persistence": 16, "sandbox_cpu": 48},
        "wall_clock_budget_sec": 14400,
        "post_execution_deadline_sec": 86400,
        "monetary_ceiling_usd": 12.987788400000001,
        "estimate_usd": 12.987788400000001,
        "approved_by": "owner",
        "approved_at": "2026-11-17T09:31:43Z",
    },
    "dispatch_envelope": {"schema": "r1-dispatch-envelope/1"},
}


class _FakeProviderObject:
    """A provider object with the shape the guard expects."""

    def __init__(self) -> None:
        self.calls: list = []

    def remote(self, *args, **kwargs):  # pragma: no cover - never called here
        self.calls.append((args, kwargs))
        return {"ok": True}


class _FakeProviderClass:
    """A provider class whose instances hand out a fresh method per access."""

    def __init__(self) -> None:
        self.instances: list = []

    def __call__(self, *args, **kwargs):
        instance = _FakeProviderInstance()
        self.instances.append(instance)
        return instance


class _FakeProviderMethod:
    """A provider method of a class instance - the SDK's shape."""

    def __init__(self, name: str) -> None:
        self._name = name

    def remote(self, *args, **kwargs):  # pragma: no cover - never called here
        return {"method": self._name}


class _FakeProviderInstance:
    def __getattr__(self, item):
        return _FakeProviderMethod(item)


def _write_artifact(tmp_path: Path, payload: dict, signature: str = "c2lnbmF0dXJl") -> Path:
    """Write a signed artifact - the payload plus its base64 signature."""
    body = dict(payload)
    body["signature"] = signature
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


# --------------------------------------------------------------------------------------
# the addressing of the provider callables
# --------------------------------------------------------------------------------------


def test_the_deployed_addressing_resolves_the_function_by_name(monkeypatch):
    """The deployed function is resolved by name and guarded on the client side."""
    import modal

    resolved: dict = {}

    def fake_from_name(app_name: str, name: str):
        resolved["app_name"] = app_name
        resolved["name"] = name
        return _FakeProviderObject()

    monkeypatch.setattr(modal.Function, "from_name", staticmethod(fake_from_name))
    # The guard is installed on the provider object and registers it under its
    # call-site name: the registry is restored after the test, so the test does
    # not change the call site of any other test.
    monkeypatch.setitem(
        r1._INSTALLED_OBJECTS,
        "verify_exploit_remote",
        r1._INSTALLED_OBJECTS.get("verify_exploit_remote"),
    )

    from core.config import config

    with deployed_app_addressing():
        guarded = provider_function("verify_exploit_remote")

    assert resolved["app_name"] == config.APP_NAME
    assert resolved["name"] == "verify_exploit_remote"
    # The guard is installed on the provider object itself: the raw callable is
    # reachable only through the private registry of the guard.
    assert isinstance(guarded, r1.GuardedRemote)
    assert guarded.function_name == "verify_exploit_remote"


def test_the_deployed_addressing_guards_the_class_method(monkeypatch):
    """The deployed class method is a guarded method - no bypass of the gate."""
    import modal

    resolved: dict = {}

    def fake_from_name(app_name: str, name: str):
        resolved["app_name"] = app_name
        resolved["name"] = name
        return _FakeProviderClass()

    monkeypatch.setattr(modal.Cls, "from_name", staticmethod(fake_from_name))
    monkeypatch.setitem(
        r1.DEPLOYED_FUNCTIONS,
        "ProductionAuditAgent",
        r1.DEPLOYED_FUNCTIONS.get("ProductionAuditAgent"),
    )

    with deployed_app_addressing():
        method = provider_class_method("ProductionAuditAgent", "generate_solidity_exploit")

    assert resolved["name"] == "ProductionAuditAgent"
    assert isinstance(method, r1.GuardedClassMethod)
    assert method.function_name == "ProductionAuditAgent.generate_solidity_exploit"


def test_the_local_addressing_is_the_default():
    """Without an approval the run keeps the local addressing of the repository."""
    assert deployed_addressing_enabled() is False
    with deployed_app_addressing():
        assert deployed_addressing_enabled() is True
    assert deployed_addressing_enabled() is False


def test_the_deployed_run_starts_no_ephemeral_app(monkeypatch):
    """An approved run runs nothing locally: the deployed app is the one called."""
    from benchmarks import adapters

    started: list = []

    def fake_context():
        started.append(True)
        raise AssertionError("an approved run must not start an ephemeral app")

    monkeypatch.setattr(adapters, "ensure_modal_app_context", fake_context)

    with deployed_app_addressing():
        with provider_call_context():
            pass

    assert started == []


# --------------------------------------------------------------------------------------
# the approved step
# --------------------------------------------------------------------------------------


class _FakeClaims:
    step_id = "R4"
    approved_by = "owner"
    approved_at = "2026-11-17T09:31:43Z"
    policy_digest = "policy-digest"
    dispatch_envelope_digest = "envelope-digest"
    artifact_digest = "artifact-digest"


def test_the_approved_run_opens_the_gate_the_ledger_and_the_deployed_addressing(
    tmp_path, monkeypatch
):
    """The approved run executes under the signed artifact, the ledger and the gate."""
    monkeypatch.setattr(r1_approval, "verify_artifact", lambda artifact: _FakeClaims())
    artifact = _write_artifact(tmp_path, R4_PAYLOAD)
    ledger_path = tmp_path / "ledger.sqlite3"

    with approved_step_run(
        str(artifact), step_id="R4", budget_ledger_path=str(ledger_path)
    ) as step:
        assert deployed_addressing_enabled() is True
        assert step.gate.policy.step_id == "R4"
        assert step.gate.approval is not None
        assert step.gate.budget_ledger is step.ledger
        assert step.ledger.path == ledger_path
        assert step.ledger.cap_usd == 20.0
        assert step.policy.estimate_usd == R4_PAYLOAD["policy"]["estimate_usd"]
        assert sum(step.policy.invocation_budgets.values()) == 96
        assert step.policy.missing_fields() == []
        # The gate is the active gate of the run.
        assert r1_dispatch.current_gate() is step.gate

    assert deployed_addressing_enabled() is False


def test_an_unsigned_artifact_authorises_nothing(tmp_path):
    """An artifact without a signature is refused before a single provider call."""
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(R4_PAYLOAD), encoding="utf-8")

    with pytest.raises(r1_approval.ApprovalNotVerified):
        with approved_step_run(str(path), step_id="R4"):
            pass


def test_a_tampered_artifact_is_refused(tmp_path, monkeypatch):
    """A signature that does not match the payload authorises nothing."""
    artifact = _write_artifact(tmp_path, R4_PAYLOAD)
    monkeypatch.setattr(
        r1_approval,
        "verify_artifact",
        lambda artifact: (_ for _ in ()).throw(
            r1_approval.ApprovalNotVerified("the signature does not match the payload")
        ),
    )

    with pytest.raises(r1_approval.ApprovalNotVerified):
        with approved_step_run(str(artifact), step_id="R4"):
            pass


def test_the_ledger_of_the_approved_run_keeps_the_cap_of_the_cycle(tmp_path, monkeypatch):
    """The cap of the cycle is a hard ceiling: it may be lowered, never raised."""
    monkeypatch.setattr(r1_approval, "verify_artifact", lambda artifact: _FakeClaims())
    artifact = _write_artifact(tmp_path, R4_PAYLOAD)

    with pytest.raises(ValueError):
        with approved_step_run(
            str(artifact),
            step_id="R4",
            budget_ledger_path=str(tmp_path / "ledger.sqlite3"),
            budget_cap_usd=25.0,
        ):
            pass

    with approved_step_run(
        str(artifact),
        step_id="R4",
        budget_ledger_path=str(tmp_path / "ledger.sqlite3"),
        budget_cap_usd=15.0,
    ) as step:
        assert step.ledger.cap_usd == 15.0


def test_the_policy_of_the_run_comes_from_the_signed_payload():
    """The policy is the record of the approved caps - never a command line value."""
    policy = _step_policy_from_payload(R4_PAYLOAD["policy"])
    assert policy.step_id == "R4"
    assert policy.invocation_budgets["sandbox_cpu"] == 48
    assert policy.concurrency_caps["gpu"] == 32
    assert policy.estimate_usd == policy.monetary_ceiling_usd
    assert policy.missing_fields() == []

    with pytest.raises(r1_approval.ApprovalNotVerified):
        _step_policy_from_payload({"step_id": "R4"})


def test_an_unset_bound_of_the_policy_keeps_its_reason():
    """An unset bound of the signed policy keeps the reason of the approval."""
    payload = json.loads(json.dumps(R4_PAYLOAD))
    payload["policy"]["monetary_ceiling_usd"] = {"unset": "not approved yet"}
    policy = _step_policy_from_payload(payload["policy"])
    assert r1.is_unset(policy.monetary_ceiling_usd)
    assert policy.missing_fields() == ["monetary_ceiling_usd"]


def test_the_record_states_the_addressing_of_the_run(tmp_path, monkeypatch):
    """The record states the addressing **of the run**, not of the moment it is written.

    The record is written after the run, when the addressing context has already
    left: a record that asked the mode at that moment would state the opposite
    of what the run did.
    """
    monkeypatch.setattr(r1_approval, "verify_artifact", lambda artifact: _FakeClaims())
    artifact = _write_artifact(tmp_path, R4_PAYLOAD)

    with approved_step_run(
        str(artifact), step_id="R4", budget_ledger_path=str(tmp_path / "ledger.sqlite3")
    ) as step:
        record = step.to_record()
        assert record["provider_addressing"] == (
            "deployed app by name (modal.Function.from_name / modal.Cls.from_name)"
        )

    # The record of the run, written after the run: the same fact.
    assert step.to_record()["provider_addressing"] == record["provider_addressing"]


# --------------------------------------------------------------------------------------
# the runner
# --------------------------------------------------------------------------------------


def test_a_run_without_an_approval_keeps_the_old_behaviour(tmp_path):
    """No artifact, no gate, no ledger: the runner behaves exactly as before."""
    suite = AegisBenchmarkSuite(artifacts_dir=tmp_path / "artifacts")
    report = suite.run_benchmark(mode="smoke", save_results=False)

    assert report["approval"] is None
    assert report["is_synthetic_smoke"] is True
    assert report["total_targets_evaluated"] == 16


def test_an_approval_artifact_requires_the_real_mode(tmp_path):
    """A smoke run starts no provider container: there is nothing to authorise."""
    suite = AegisBenchmarkSuite(artifacts_dir=tmp_path / "artifacts")
    with pytest.raises(ValueError):
        suite.run_benchmark(
            mode="smoke",
            save_results=False,
            approval_artifact=str(tmp_path / "artifact.json"),
        )
