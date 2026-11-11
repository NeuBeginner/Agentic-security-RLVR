"""The R1 contract: the declared bounds, the dispatch gate and the estimator.

The proofs this file carries are the ones the maintainer asked for:

* missing bounds block the dispatch;
* configured bounds are enforced;
* the cumulative cold-container accounting is correct;
* the estimator includes the full storage interval.

Everything here is local: no test performs a provider call, a deployment or a
volume operation.
"""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import r1_dispatch
from benchmarks import r1_estimator
from core import r1_bounds as r1

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _approved_profile(base: r1.ResourceProfile, **overrides) -> r1.ResourceProfile:
    """The same class with every required bound approved."""
    values = {
        "cpu_request_cores": 2.0,
        "cpu_limit_cores": 4.0,
        "memory_request_mb": 2048,
        "memory_limit_mb": 4096,
        "timeout_sec": 60,
        "startup_timeout_sec": 120,
        "scaledown_window_sec": 60,
    }
    values.update(overrides)
    return dataclasses.replace(base, **values)


def _approved_egress(policy: r1.EgressPolicy, **overrides) -> r1.EgressPolicy:
    values = {"payload_cap_bytes": 0, "protocol_allowance_bytes": 1024 * 1024}
    values.update(overrides)
    return dataclasses.replace(policy, **values)


def _approved_world() -> dict:
    """Approved profiles and egress policies for the three container classes."""
    profiles = {
        r1.SANDBOX_CPU: _approved_profile(r1.SANDBOX_CPU_PROFILE),
        r1.GPU_CLASS: _approved_profile(
            r1.GPU_PROFILE, cpu_request_cores=8.0, cpu_limit_cores=16.0, memory_request_mb=32768, memory_limit_mb=65536
        ),
        r1.PERSISTENCE: _approved_profile(
            r1.PERSISTENCE_PROFILE, cpu_request_cores=0.5, cpu_limit_cores=1.0, memory_request_mb=512, memory_limit_mb=1024
        ),
    }
    egress = {
        name: _approved_egress(policy)
        for name, policy in r1.EGRESS_POLICIES.items()
    }
    return {"profiles": profiles, "egress_policies": egress}


def _policy(**overrides) -> r1_dispatch.StepPolicy:
    values = {
        "step_id": "R3",
        "invocation_budgets": {r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        "concurrency_caps": {r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        "wall_clock_budget_sec": 1200.0,
        "post_execution_deadline_sec": 3600.0,
        "monetary_ceiling_usd": 5.0,
        "estimate_usd": 0.5,
        "approved_by": "test",
        "approved_at": "2026-11-11",
    }
    values.update(overrides)
    return r1_dispatch.StepPolicy(**values)


class FakeProviderCallable:
    """A provider callable double: the gate treats it as a billable call."""

    def __init__(self, settings: dict | None = None):
        self.calls = []
        self.readback_calls = []
        self._settings = settings or {
            "min_containers": 0,
            "max_containers": 48,
            "buffer_containers": 0,
            "scaledown_window": 60,
        }
        setattr(self, r1.PROVIDER_CALLABLE_MARKER, True)

    def update_autoscaler(self, **kwargs):
        self.readback_calls.append(kwargs)
        return SimpleNamespace(**self._settings)

    def remote(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


class LocalDouble:
    """A local double: no container, no cost."""

    def __init__(self):
        self.calls = []

    def remote(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


# --------------------------------------------------------------------------------------
# the declarations (D26, D27)
# --------------------------------------------------------------------------------------


def test_every_unapproved_bound_is_visible_and_named():
    missing = r1.missing_deployment_bounds()
    assert set(missing) == {r1.SANDBOX_CPU, r1.GPU_CLASS, r1.PERSISTENCE}
    for container_class, fields in missing.items():
        assert fields, f"{container_class} must declare its unapproved bounds explicitly"
    record = r1.declaration_record()
    assert record["missing_bounds"] == missing
    assert record["max_trajectory_payload_bytes"] is None
    assert record["pinned_model"]["bytes_total"] > 0


def test_the_declared_autoscaler_policy_never_keeps_a_container_warm():
    for container_class, profile in r1.PROFILES.items():
        assert profile.min_containers == 0, container_class
        assert profile.buffer_containers == 0, container_class
    assert r1.PROFILES[r1.SANDBOX_CPU].max_containers == 48
    assert r1.PROFILES[r1.GPU_CLASS].max_containers == 32
    assert r1.PROFILES[r1.PERSISTENCE].max_containers == 16


def test_an_unapproved_limit_is_never_replaced_by_a_permissive_default():
    kwargs = r1.SANDBOX_CPU_PROFILE.modal_kwargs()
    # The request is the published configuration value; the limit is absent because
    # it is not approved - never a silent default.
    assert kwargs["cpu"] == r1.config.SANDBOX_CPU_CORES
    assert kwargs["memory"] == r1.config.SANDBOX_MEMORY_MB
    assert "startup_timeout" not in kwargs
    assert "scaledown_window" not in kwargs
    assert kwargs["min_containers"] == 0 and kwargs["buffer_containers"] == 0


def test_the_sandbox_class_declares_the_network_blocking_and_the_volume_class_does_not():
    sandbox = r1.modal_function_kwargs(r1.SANDBOX_CPU, "verify_exploit_remote")
    persistence = r1.modal_function_kwargs(r1.PERSISTENCE, "record_trajectory_remote")
    assert sandbox["block_network"] is True
    # The persistence function mounts the volume: the provider does not allow the
    # blocking declaration there, its zero comes from its own construction.
    assert persistence["block_network"] is False
    assert r1.EGRESS_POLICIES["record_trajectory_remote"].payload_cap_bytes == 0
    assert r1.EGRESS_POLICIES["verify_exploit_remote"].payload_cap_bytes == 0


def test_the_gpu_container_is_offline_and_verifies_its_cache():
    assert r1.OFFLINE_ENV["HF_HUB_OFFLINE"] == "1"
    assert r1.OFFLINE_ENV["TRANSFORMERS_OFFLINE"] == "1"
    manifest = {"files": [{"path": "model.safetensors", "size": 10}]}
    listing = {"model.safetensors"}
    passed = r1.verify_model_cache_manifest(
        "/cache", manifest, listdir=lambda _path: listing, getsize=lambda _path: 10
    )
    assert passed["status"] == "PASSED"
    failed = r1.verify_model_cache_manifest(
        "/cache", manifest, listdir=lambda _path: set(), getsize=lambda _path: 10
    )
    assert failed["status"] == "FAILED"
    assert failed["missing"] == ["model.safetensors"]
    empty = r1.verify_model_cache_manifest("/cache", {}, listdir=lambda _path: set())
    assert empty["status"] == "FAILED"


def test_the_repository_contains_no_mutating_autoscaler_call():
    pattern = re.compile(r"update_autoscaler\s*\([^)]", re.DOTALL)
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if path.resolve() == Path(__file__).resolve():
            # This file carries the patterns themselves.
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "autoscaler.update(" in text:
            offenders.append(f"{path}: autoscaler.update(")
        for match in pattern.finditer(text):
            offenders.append(f"{path}: {match.group(0)}")
    assert offenders == []


def test_the_producer_dispatches_only_through_the_r1_gate():
    text = (REPO_ROOT / "benchmarks" / "adapters.py").read_text(encoding="utf-8")
    direct_calls = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"\.remote\(", line) and "dispatch_via_r1_gate" not in line
    ]
    assert direct_calls == []


# --------------------------------------------------------------------------------------
# missing bounds block the dispatch (D26, D27, D29)
# --------------------------------------------------------------------------------------


def test_a_provider_dispatch_without_an_approved_policy_is_refused():
    gate = r1_dispatch.DispatchGate(policy=None)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "no_approved_step_policy"
    assert fake.calls == []


def test_unapproved_bounds_block_the_dispatch_even_with_an_approved_policy():
    gate = r1_dispatch.DispatchGate(policy=_policy())
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "bounds_not_approved"
    assert fake.calls == []


def test_an_unapproved_egress_bound_blocks_the_dispatch():
    world = _approved_world()
    world["egress_policies"]["verify_exploit_remote"] = r1.EGRESS_POLICIES["verify_exploit_remote"]
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "egress_bound_not_approved"
    assert fake.calls == []


def test_a_function_without_an_egress_declaration_is_refused():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.GPU_CLASS, "DevReasoningAgent.generate_solidity_exploit", fake, {})
    assert excinfo.value.reason == "no_egress_declaration"
    assert fake.calls == []


def test_the_policy_must_declare_the_post_execution_deadline_and_the_ceiling():
    policy = _policy(post_execution_deadline_sec=r1.Unset("not approved"))
    assert "post_execution_deadline_sec" in policy.missing_fields()
    gate = r1_dispatch.DispatchGate(policy=policy)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "policy_incomplete"


def test_an_estimate_above_the_ceiling_is_refused():
    policy = _policy(estimate_usd=10.0, monetary_ceiling_usd=5.0)
    gate = r1_dispatch.DispatchGate(policy=policy)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "estimate_above_ceiling"


def test_the_guard_refuses_a_provider_call_while_the_bounds_are_unapproved():
    fake = FakeProviderCallable()
    guarded = r1.GuardedRemote(fake, "verify_exploit_remote")
    with pytest.raises(r1.BoundsNotApproved):
        guarded.remote({})
    assert fake.calls == []


def test_the_producer_enforced_payload_cap_refuses_an_unapproved_cap():
    with pytest.raises(r1.BoundsNotApproved):
        r1.assert_payload_within_cap(10, "record_trajectory_remote")


# --------------------------------------------------------------------------------------
# configured bounds are enforced (D26, D27, D28, D29)
# --------------------------------------------------------------------------------------


def test_a_configured_dispatch_is_performed_and_the_autoscaler_is_read_back():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)
    fake = FakeProviderCallable()
    result = gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {"a": 1})
    assert result == {"ok": True}
    assert len(fake.calls) == 1
    # The read-back is the NO-argument call: it never mutates the settings.
    assert fake.readback_calls == [{}]
    assert gate.dispatched() and not gate.refused()


def test_the_invocation_budget_is_enforced():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(invocation_budgets={r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}), **world)
    fake = FakeProviderCallable()
    gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "invocation_budget_exhausted"
    assert len(fake.calls) == 2
    assert len(gate.refused()) == 1


def test_a_cap_above_the_deployed_ceiling_is_refused():
    world = _approved_world()
    policy = _policy(concurrency_caps={r1.SANDBOX_CPU: 49, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1})
    gate = r1_dispatch.DispatchGate(policy=policy, **world)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "deployed_ceiling_too_low"
    assert fake.calls == []


def test_the_autoscaler_readback_must_match_the_declaration():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)
    fake = FakeProviderCallable(settings={"min_containers": 0, "max_containers": 999, "buffer_containers": 0, "scaledown_window": 60})
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "autoscaler_readback_mismatch"
    assert fake.calls == []


def test_a_class_without_a_readback_is_not_dispatchable():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)

    class NoReadback:
        def remote(self, *args, **kwargs):  # pragma: no cover - never reached
            raise AssertionError("the dispatch must be refused before the call")

    no_readback = NoReadback()
    setattr(no_readback, r1.PROVIDER_CALLABLE_MARKER, True)
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", no_readback, {})
    assert excinfo.value.reason == "autoscaler_readback_unavailable"


def test_the_payload_byte_cap_is_enforced_on_the_volume_writing_function():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(), **world)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.PERSISTENCE, "record_trajectory_remote", fake, {"payload": "x" * 10})
    # The cap itself is not approved in the repository, so the write is refused.
    assert excinfo.value.reason == "payload_byte_cap"
    assert fake.calls == []


def test_a_local_double_is_passed_through_and_counted():
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=_policy(invocation_budgets={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}), **world)
    double = LocalDouble()
    gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", double, {})
    assert len(double.calls) == 1
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", double, {})
    assert excinfo.value.reason == "invocation_budget_exhausted"


# --------------------------------------------------------------------------------------
# the cumulative cold-container accounting (D27, D29)
# --------------------------------------------------------------------------------------


def _rate_card() -> r1_estimator.RateCard:
    return r1_estimator.RateCard(
        cpu_per_core_sec=0.0000131,
        memory_per_gib_sec=0.00000222,
        gpu_per_sec=0.001097,
        volume_per_gib_month=0.09,
        egress_per_gib=0.04,
        source="modal.com/pricing",
        read_at="2026-11-11",
        approved_by="test",
    )


def _step(**overrides) -> r1_estimator.StepInputs:
    values = {
        "step_id": "R4",
        "invocations": {r1.SANDBOX_CPU: 96},
        "concurrency_caps": {r1.SANDBOX_CPU: 48},
        "baseline_gib": 0.0,
        "incremental_gib": 0.001,
        "t_exec_sec": 3600.0,
        "t_post_exec_to_publication_sec": 3600.0,
        "egress_functions": {r1.SANDBOX_CPU: ["verify_exploit_remote"]},
    }
    values.update(overrides)
    return r1_estimator.StepInputs(**values)


def test_the_cumulative_cold_containers_are_bounded_by_the_invocations_not_by_the_ceiling():
    world = _approved_world()
    step = _step()
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"], world["egress_policies"])
    assert estimate.available, estimate.unavailable_reasons
    sandbox = estimate.quantities[r1.SANDBOX_CPU]
    # 96 invocations, a deployed ceiling of 48: the cumulative bound is the
    # invocation count. A concurrency cap may never clamp a cumulative quantity.
    assert sandbox["cold_containers_bound"] == 96
    assert sandbox["deployed_max_containers"] == 48
    assert sandbox["concurrent_containers"] == 48


def test_the_egress_is_summed_over_the_cumulative_cold_containers():
    world = _approved_world()
    step = _step()
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"], world["egress_policies"])
    assert estimate.available, estimate.unavailable_reasons
    sandbox = estimate.quantities[r1.SANDBOX_CPU]
    # payload cap 0 + the protocol allowance, once per cold container.
    assert sandbox["egress_bytes"] == 96 * (1024 * 1024)
    assert estimate.terms_usd["egress_sandbox_cpu"] == pytest.approx(
        96 * (1024 * 1024) / (1024 ** 3) * 0.04
    )

def test_the_cpu_and_memory_terms_use_the_explicit_limits():
    world = _approved_world()
    step = _step(invocations={r1.SANDBOX_CPU: 2}, concurrency_caps={r1.SANDBOX_CPU: 2})
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"])
    sandbox = estimate.quantities[r1.SANDBOX_CPU]
    t_billable = 120 + 60 + 60
    assert sandbox["t_billable_sec"] == t_billable
    assert sandbox["cpu_core_seconds"] == 4.0 * t_billable * 2
    assert sandbox["memory_gib_seconds"] == 4.0 * t_billable * 2


def test_a_cap_above_the_deployed_ceiling_makes_the_estimate_unavailable():
    world = _approved_world()
    step = _step(concurrency_caps={r1.SANDBOX_CPU: 49})
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"])
    assert not estimate.available
    assert any("deployed ceiling" in reason for reason in estimate.unavailable_reasons)


# --------------------------------------------------------------------------------------
# the storage interval (D28)
# --------------------------------------------------------------------------------------


def test_the_storage_interval_is_execution_plus_post_execution_plus_retention():
    world = _approved_world()
    day = 86400.0
    step = _step(
        invocations={r1.SANDBOX_CPU: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1},
        baseline_gib=10.0,
        incremental_gib=1.0,
        t_exec_sec=6 * 3600.0,
        t_post_exec_to_publication_sec=4 * 3600.0,
        t_retention_sec=30 * day,
    )
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"], world["egress_policies"])
    assert estimate.available, estimate.unavailable_reasons
    volume = estimate.quantities["volume"]
    assert volume["t_store_sec"] == 6 * 3600.0 + 4 * 3600.0 + 30 * day
    assert volume["t_store_days"] == pytest.approx(30 + 10 / 24)
    # 1 + ceil(30.4166 / 28) = 3 calendar months
    assert volume["months"] == 3
    assert volume["volume_gib_months"] == 11.0 * 3


def test_the_boundary_case_of_the_omitted_interval_is_covered():
    world = _approved_world()
    day = 86400.0
    step = _step(
        invocations={r1.SANDBOX_CPU: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1},
        baseline_gib=10.0,
        incremental_gib=1.0,
        t_exec_sec=26 * day,
        t_post_exec_to_publication_sec=2 * day,
        t_retention_sec=30 * day,
    )
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"], world["egress_policies"])
    volume = estimate.quantities["volume"]
    assert volume["t_store_days"] == pytest.approx(58.0)
    # Without the post-execution interval the total would be 56 days - exactly on the
    # 28-day boundary - and the formula would return 3 months instead of 4.
    assert volume["months"] == 4


def test_an_unbounded_storage_duration_makes_the_estimate_unavailable():
    world = _approved_world()
    step = _step(t_post_exec_to_publication_sec=r1.Unset("not approved"))
    estimate = r1_estimator.estimate_step(step, _rate_card(), world["profiles"])
    assert not estimate.available
    assert any("post-execution deadline" in reason for reason in estimate.unavailable_reasons)


def test_an_unapproved_bound_makes_the_estimate_unavailable():
    estimate = r1_estimator.estimate_step(_step(), _rate_card(), None)
    assert not estimate.available
    assert any("bounds not approved" in reason for reason in estimate.unavailable_reasons)


def test_an_unapproved_rate_card_makes_the_estimate_unavailable():
    rate_card = r1_estimator.RateCard(
        cpu_per_core_sec=0.0000131,
        memory_per_gib_sec=0.00000222,
        gpu_per_sec=0.001097,
        volume_per_gib_month=0.09,
        egress_per_gib=0.04,
        source="modal.com/pricing",
        read_at="2026-11-11",
        approved_by=None,
    )
    estimate = r1_estimator.estimate_step(_step(), rate_card, _approved_world()["profiles"])
    assert not estimate.available
    assert any("not approved" in reason for reason in estimate.unavailable_reasons)


def test_the_cycle_aggregate_prices_the_shared_storage_once():
    world = _approved_world()
    steps = [
        r1_estimator.StepInputs(
            step_id="R3",
            invocations={r1.SANDBOX_CPU: 1},
            concurrency_caps={r1.SANDBOX_CPU: 1},
            baseline_gib=56.9,
            incremental_gib=0.0,
            t_exec_sec=600.0,
            t_post_exec_to_publication_sec=600.0,
        ),
        r1_estimator.StepInputs(
            step_id="R4",
            invocations={r1.SANDBOX_CPU: 48},
            concurrency_caps={r1.SANDBOX_CPU: 48},
            baseline_gib=56.9,
            incremental_gib=0.0,
            t_exec_sec=3600.0,
            t_post_exec_to_publication_sec=3600.0,
        ),
    ]
    estimates = [
        r1_estimator.estimate_step(step, _rate_card(), world["profiles"], world["egress_policies"])
        for step in steps
    ]
    assert all(estimate.available for estimate in estimates)
    aggregate = r1_estimator.aggregate_cycle(
        estimates,
        _rate_card(),
        baseline_gib=56.9,
        total_incremental_gib=0.0,
        total_t_exec_sec=4200.0,
        max_t_post_exec_sec=3600.0,
        cycle_cap_usd=20.0,
    )
    assert aggregate["storage_window"]["months"] == 3
    assert aggregate["cycle_storage_usd"] == pytest.approx(56.9 * 3 * 0.09)
    # The naive sum of the per-step storage terms prices the same standing bytes
    # once per step; the aggregate prices them once over the cycle's window.
    assert aggregate["naive_sum_of_per_step_storage_usd"] > aggregate["cycle_storage_usd"]
