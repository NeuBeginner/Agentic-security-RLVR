"""The R1 dispatch contract: the call-site inventory, the guards, the autoscaler
read-back, the network policy and the invocation budget.

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download. The provider read-back is exercised through
an injected reader, and the provider reader itself is opt-in.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from benchmarks import r1_dispatch
from benchmarks import r1_estimator
from core import r1_bounds as r1

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = REPO_ROOT / "benchmarks" / "evidence" / "r1_call_site_inventory.json"

_SKIP_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _approved_profile(base: r1.ResourceProfile, **overrides) -> r1.ResourceProfile:
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


def _approved_world() -> dict:
    profiles = {
        r1.SANDBOX_CPU: _approved_profile(r1.SANDBOX_CPU_PROFILE),
        r1.GPU_CLASS: _approved_profile(
            r1.GPU_PROFILE,
            cpu_request_cores=8.0,
            cpu_limit_cores=16.0,
            memory_request_mb=32768,
            memory_limit_mb=65536,
        ),
        r1.PERSISTENCE: _approved_profile(
            r1.PERSISTENCE_PROFILE,
            cpu_request_cores=0.5,
            cpu_limit_cores=1.0,
            memory_request_mb=512,
            memory_limit_mb=1024,
        ),
    }
    egress = {
        name: dataclasses.replace(policy, payload_cap_bytes=0, protocol_allowance_bytes=1024 * 1024)
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


def _settings(settings: dict | None = None) -> dict:
    """The four effective autoscaler settings of the approved declaration."""
    return dict(
        settings
        or {
            "min_containers": 0,
            "max_containers": 48,
            "buffer_containers": 0,
            "scaledown_window": 60,
        }
    )


def _reader(settings: dict | None = None):
    """A read-only autoscaler reader double - no provider call, no mutation."""
    values = _settings(settings)

    def reader(target, function_name=""):
        return dict(values)

    return reader


class FakeProviderCallable:
    """A provider callable double: the gate treats it as a billable call."""

    def __init__(self) -> None:
        self.calls = []
        setattr(self, r1.PROVIDER_CALLABLE_MARKER, True)

    def remote(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


def _provider_call_sites(path: Path) -> List[Tuple[str, str, str]]:
    """Every call chain of the file that reaches a provider's ``remote``.

    The result is a list of ``(enclosing function, callee, source)`` triples.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    sites: List[Tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        current: Any = node.func
        remote_attribute = None
        while isinstance(current, ast.Attribute):
            if current.attr == "remote":
                remote_attribute = current
            current = current.value
        if remote_attribute is None:
            continue
        scope: Any = node
        while scope is not None and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            scope = parents.get(id(scope))
        function_name = getattr(scope, "name", "<module>")
        callee = ast.unparse(remote_attribute.value)
        sites.append((function_name, callee, ast.unparse(node)[:120]))
    return sites


def _scanned_inventory() -> Dict[str, int]:
    """The inventory of the repository, as the scanner sees it."""
    counted: Dict[str, int] = {}
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if any(part in _SKIP_DIRECTORIES for part in path.parts):
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative.startswith("tests/"):
            continue
        try:
            sites = _provider_call_sites(path)
        except SyntaxError:  # pragma: no cover - the repository parses
            continue
        for function_name, callee, _source in sites:
            key = f"{relative}::{function_name}::{callee}"
            counted[key] = counted.get(key, 0) + 1
    return counted


# --------------------------------------------------------------------------------------
# A - the repo-wide inventory of the provider call sites
# --------------------------------------------------------------------------------------


def test_the_repository_call_site_inventory_is_complete_and_current():
    """Every provider call site of the repository is classified.

    A new call site that is not classified in the inventory fails this test: the
    inventory cannot silently go stale.
    """
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    declared = {
        key: entry["count"] for key, entry in inventory["dispositions"].items()
    }
    scanned = _scanned_inventory()
    assert scanned == declared, (
        "the provider call sites of the repository and the inventory disagree; "
        f"only in the inventory: {sorted(set(declared) - set(scanned))}; "
        f"only in the repository: {sorted(set(scanned) - set(declared))}"
    )


def test_every_inventory_entry_carries_a_disposition_and_a_reason():
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    allowed = {
        "gated",
        "refused",
        "guarded_class_method",
        "gate",
        "declared_out_of_scope",
    }
    for key, entry in inventory["dispositions"].items():
        assert entry["disposition"] in allowed, key
        assert entry["reason"].strip(), key
        assert entry["count"] >= 1, key


def test_every_gated_call_site_is_a_function_of_the_authorised_trace():
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    gated = [
        entry
        for entry in inventory["dispositions"].values()
        if entry["disposition"] == "gated"
    ]
    assert gated, "the inventory must name the gated call sites"
    for entry in gated:
        for call_site in entry["call_sites"]:
            assert call_site in r1.FUNCTION_CLASS, call_site


def test_every_refused_call_site_is_in_the_refusal_registry():
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    refused = [
        entry
        for entry in inventory["dispositions"].values()
        if entry["disposition"] == "refused"
    ]
    assert refused, "the inventory must name the refused call sites"
    for entry in refused:
        for call_site in entry["call_sites"]:
            assert call_site in r1.UNAUTHORISED_CALL_SITES, call_site
            assert r1.UNAUTHORISED_CALL_SITES[call_site].strip()


def test_every_guarded_class_method_resolves_to_a_known_call_site():
    """A class method resolves to an authorised or to a refused call site."""
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    for entry in inventory["dispositions"].values():
        if entry["disposition"] != "guarded_class_method":
            continue
        assert entry["call_sites"]
        for call_site in entry["call_sites"]:
            assert (
                call_site in r1.FUNCTION_CLASS
                or call_site in r1.UNAUTHORISED_CALL_SITES
            ), call_site


def test_the_refusal_registry_names_every_unauthorised_path_of_the_deployment():
    """The refused surface is the one the review named, and nothing is missing."""
    for callee in (
        "run_slither_remote",
        "verify_replay_fault_injection_remote",
        "audit_volume_trajectories_remote",
        "diagnostic_grpo_forward_remote",
        "train_grpo_remote",
        "DevReasoningAgent.generate_solidity_exploit",
        "DevReasoningAgent.refine_solidity_exploit",
        "ProductionAuditAgent.audit_target_contract",
    ):
        assert callee in r1.UNAUTHORISED_CALL_SITES, callee


def test_the_deployment_installs_the_guard_on_the_functions_and_on_the_classes():
    """The module-level names are guarded - functions *and* Modal classes."""
    import modal_app

    assert isinstance(modal_app.verify_exploit_remote, r1.GuardedRemote)
    assert isinstance(modal_app.verify_replay_remote, r1.GuardedRemote)
    assert isinstance(modal_app.record_trajectory_remote, r1.GuardedRemote)
    assert isinstance(modal_app.run_slither_remote, r1.GuardedRemote)
    # The class methods were the bypass: the class is guarded as well.
    assert isinstance(modal_app.ProductionAuditAgent, r1.GuardedClass)
    assert isinstance(modal_app.DevReasoningAgent, r1.GuardedClass)

    agent = modal_app.ProductionAuditAgent()
    assert isinstance(agent.generate_solidity_exploit, r1.GuardedClassMethod)
    assert isinstance(agent.audit_target_contract, r1.GuardedClassMethod)


def test_a_class_method_call_is_refused_while_the_bounds_are_unapproved():
    """The class-method bypass is closed: the call never reaches the provider."""
    import modal_app

    agent = modal_app.ProductionAuditAgent()
    with pytest.raises(r1.BoundsNotApproved):
        agent.generate_solidity_exploit.remote({"name": "x"})


def test_the_guard_refuses_an_unauthorised_call_site_with_its_reason():
    import modal_app

    with pytest.raises(r1.UnauthorisedCallSite) as excinfo:
        modal_app.run_slither_remote.remote({"name": "x"})
    assert "Slither" in excinfo.value.reason


def test_the_guard_refuses_a_mutating_autoscaler_call():
    """The guard makes the mutating autoscaler accessor unreachable.

    The attribute is fetched, never called: the fetch itself is refused.
    """
    import modal_app

    with pytest.raises(r1.UnauthorisedCallSite):
        getattr(modal_app.verify_exploit_remote, "update_autoscaler")
    with pytest.raises(r1.UnauthorisedCallSite):
        getattr(modal_app.ProductionAuditAgent, "update_autoscaler")
    with pytest.raises(r1.UnauthorisedCallSite):
        getattr(modal_app.ProductionAuditAgent().generate_solidity_exploit, "update_autoscaler")


def test_the_producer_dispatches_only_through_the_r1_gate():
    text = (REPO_ROOT / "benchmarks" / "adapters.py").read_text(encoding="utf-8")
    direct_calls = [
        line.strip()
        for line in text.splitlines()
        if ".remote(" in line and "dispatch_via_r1_gate" not in line
    ]
    assert direct_calls == []


# --------------------------------------------------------------------------------------
# B - the autoscaler read-back is fail-closed and covers all four fields
# --------------------------------------------------------------------------------------


def test_the_read_back_covers_all_four_autoscaler_fields():
    assert r1.AUTOSCALER_FIELDS == (
        "min_containers",
        "max_containers",
        "buffer_containers",
        "scaledown_window",
    )
    for container_class, profile in r1.PROFILES.items():
        declared = r1.declared_autoscaler_settings(profile)
        assert set(declared) == set(r1.AUTOSCALER_FIELDS), container_class


@pytest.mark.parametrize("field_name", r1.AUTOSCALER_FIELDS)
def test_a_missing_field_in_the_read_back_is_refused(field_name):
    settings = _reader()
    payload = settings(None)
    payload.pop(field_name)
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        r1_dispatch.read_back_autoscaler(None, function_name="verify_exploit_remote", reader=lambda *_: payload)
    assert excinfo.value.reason == "autoscaler_readback_missing_field"
    assert field_name in excinfo.value.detail


@pytest.mark.parametrize("field_name", r1.AUTOSCALER_FIELDS)
def test_a_none_field_in_the_read_back_is_refused(field_name):
    payload = _settings()
    payload[field_name] = None
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        r1_dispatch.read_back_autoscaler(None, function_name="verify_exploit_remote", reader=lambda *_: payload)
    assert excinfo.value.reason == "autoscaler_readback_missing_field"
    assert field_name in excinfo.value.detail


@pytest.mark.parametrize("field_name", r1.AUTOSCALER_FIELDS)
def test_a_malformed_field_in_the_read_back_is_refused(field_name):
    payload = _settings()
    payload[field_name] = "60" if field_name != "scaledown_window" else 0
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        r1_dispatch.read_back_autoscaler(None, function_name="verify_exploit_remote", reader=lambda *_: payload)
    assert excinfo.value.reason == "autoscaler_readback_malformed"
    assert field_name in excinfo.value.detail


@pytest.mark.parametrize("field_name", r1.AUTOSCALER_FIELDS)
def test_a_mismatching_field_in_the_read_back_is_refused(field_name):
    world = _approved_world()
    payload = _settings()
    payload[field_name] = payload[field_name] + 1 if field_name != "scaledown_window" else 61
    gate = r1_dispatch.DispatchGate(
        policy=_policy(), autoscaler_reader=lambda *_: payload, **world
    )
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "autoscaler_readback_mismatch"
    assert field_name in excinfo.value.detail
    assert fake.calls == []


def test_a_partial_read_back_is_never_accepted():
    """A read-back that carries only some of the fields is refused."""
    world = _approved_world()
    payload = {"min_containers": 0, "max_containers": 48}
    gate = r1_dispatch.DispatchGate(
        policy=_policy(), autoscaler_reader=lambda *_: payload, **world
    )
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "autoscaler_readback_missing_field"
    assert fake.calls == []


def test_the_read_back_never_uses_the_mutating_update_autoscaler():
    """The read-back is read-only: the mutating accessor is never called."""
    for relative in ("benchmarks/r1_dispatch.py", "core/r1_bounds.py"):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        callers = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update_autoscaler"
        ]
        assert callers == [], f"{relative} calls update_autoscaler at {callers}"


def test_the_provider_read_back_is_opt_in():
    """Without the explicit opt-in the provider read is unavailable, not attempted."""
    assert "R1_ENABLE_PROVIDER_READBACK" not in os.environ
    with pytest.raises(r1_dispatch.AutoscalerReadbackUnavailable):
        r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")


def test_an_unavailable_read_back_refuses_the_dispatch():
    world = _approved_world()

    def unavailable(target, function_name=""):
        raise r1_dispatch.AutoscalerReadbackUnavailable("no read-only read available")

    gate = r1_dispatch.DispatchGate(policy=_policy(), autoscaler_reader=unavailable, **world)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "autoscaler_readback_unavailable"
    assert fake.calls == []


# --------------------------------------------------------------------------------------
# C - the network policy of the deployed functions
# --------------------------------------------------------------------------------------


def test_the_gpu_class_declares_the_provider_level_network_blocking():
    assert r1.class_network_policy(r1.GPU_CLASS) is True
    for name in (
        "ProductionAuditAgent.generate_solidity_exploit",
        "ProductionAuditAgent.refine_solidity_exploit",
        "ProductionAuditAgent.audit_target_contract",
    ):
        policy = r1.egress_policy(name)
        assert policy is not None, name
        assert policy.block_network is True, name
        assert policy.payload_cap_bytes == 0, name


def test_the_deployed_gpu_class_carries_the_declared_network_policy():
    """The decorator of the deployed class declares the policy of the record."""
    source = (REPO_ROOT / "modal_app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ProductionAuditAgent":
            found = node
    assert found is not None
    keywords: Dict[str, ast.AST] = {}
    for decorator in found.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        for keyword in decorator.keywords:
            keywords[keyword.arg] = keyword.value
    assert "block_network" in keywords, "the GPU class must declare its network policy"
    assert ast.unparse(keywords["block_network"]) == "r1.class_network_policy(r1.GPU_CLASS)"


def test_the_protocol_allowance_is_declared_separately_and_is_mandatory():
    """The provider's control-plane overhead is a separate, mandatory bound."""
    for name, policy in r1.EGRESS_POLICIES.items():
        assert policy.protocol_allowance_bytes is not None, name
        assert "payload_cap_bytes" in {field.name for field in dataclasses.fields(policy)}
    # The declared protocol allowance of the record is unset: an unset allowance
    # makes the step not dispatchable, it is never silently zero.
    assert r1.is_unset(r1.EGRESS_POLICIES["verify_exploit_remote"].protocol_allowance_bytes)


def test_a_gpu_payload_cap_of_zero_is_only_possible_with_the_provider_blocking():
    """A zero payload cap is only a bound if the provider enforces the blocking."""
    policy = r1.egress_policy("ProductionAuditAgent.generate_solidity_exploit")
    assert policy is not None
    assert policy.payload_cap_bytes == 0
    assert policy.block_network is True
    assert "block_network" in policy.basis
    # The GPU class is the only class deployment, so its policy is a class policy.
    assert r1.CLASS_CONTAINER_CLASSES == (r1.GPU_CLASS,)


# --------------------------------------------------------------------------------------
# D - the invocation allowance
# --------------------------------------------------------------------------------------


def test_the_invocation_allowance_is_consumed_atomically_under_concurrency():
    """Two concurrent dispatches may never both pass the same remaining allowance."""
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=_policy(
            invocation_budgets={r1.SANDBOX_CPU: 3, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
            concurrency_caps={r1.SANDBOX_CPU: 8, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        ),
        autoscaler_reader=_reader(),
        **world,
    )
    fake = FakeProviderCallable()
    outcomes: List[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        try:
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
            outcome = "dispatched"
        except r1_dispatch.DispatchRefusal as exc:
            outcome = exc.reason
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("dispatched") == 3
    assert outcomes.count("invocation_budget_exhausted") == 5
    assert len(fake.calls) == 3
    assert gate.used_allowance(r1.SANDBOX_CPU) == 3


def test_a_refused_attempt_does_not_consume_the_invocation_allowance():
    """The policy of the concurrency-refused attempt: it costs no invocation.

    A dispatch that the concurrency gate refuses starts no container, so it may
    not cost an invocation: the allowance stays intact for the next attempt.
    """
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=_policy(
            invocation_budgets={r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
            concurrency_caps={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
            wall_clock_budget_sec=1.0,
        ),
        autoscaler_reader=_reader(),
        **world,
    )
    release = threading.Event()
    entered = threading.Event()

    class SlowCallable(FakeProviderCallable):
        def remote(self, *args, **kwargs):
            entered.set()
            release.wait(10)
            return super().remote(*args, **kwargs)

    slow = SlowCallable()
    holder = threading.Thread(target=lambda: gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", slow, {}))
    holder.start()
    assert entered.wait(5)

    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", slow, {})
    assert excinfo.value.reason == "concurrency_gate_timeout"
    # The refused attempt consumed nothing.
    assert gate.used_allowance(r1.SANDBOX_CPU) == 1

    release.set()
    holder.join(10)
    # The allowance is intact: the next attempt may still be dispatched.
    assert gate.used_allowance(r1.SANDBOX_CPU) == 1
    gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", slow, {})
    assert gate.used_allowance(r1.SANDBOX_CPU) == 2


@pytest.mark.parametrize(
    "reason",
    [
        "unauthorised_call_site",
        "no_approved_step_policy",
        "bounds_not_approved",
        "deployed_ceiling_too_low",
        "invocation_budget_exhausted",
        "autoscaler_readback_mismatch",
    ],
)
def test_every_refusal_leaves_the_invocation_allowance_untouched(reason):
    """No refusal consumes an invocation: only a real dispatch does."""
    world = _approved_world()
    policy = _policy(
        invocation_budgets={r1.SANDBOX_CPU: 5, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}
    )
    payload = _settings()
    if reason == "autoscaler_readback_mismatch":
        payload["max_containers"] = payload["max_containers"] + 1
    gate = r1_dispatch.DispatchGate(
        policy=policy, autoscaler_reader=lambda *_: payload, **world
    )
    fake = FakeProviderCallable()

    if reason == "unauthorised_call_site":
        call = lambda: gate.dispatch(r1.GPU_CLASS, "DevReasoningAgent.generate_solidity_exploit", fake, {})
    elif reason == "no_approved_step_policy":
        gate_no_policy = r1_dispatch.DispatchGate(
            policy=None, autoscaler_reader=lambda *_: payload, **world
        )
        call = lambda: gate_no_policy.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    elif reason == "bounds_not_approved":
        gate_unbounded = r1_dispatch.DispatchGate(
            policy=policy, autoscaler_reader=lambda *_: payload
        )
        call = lambda: gate_unbounded.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    elif reason == "deployed_ceiling_too_low":
        gate_high = r1_dispatch.DispatchGate(
            policy=_policy(
                invocation_budgets={r1.SANDBOX_CPU: 5, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
                concurrency_caps={r1.SANDBOX_CPU: 49, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
            ),
            autoscaler_reader=lambda *_: payload,
            **world,
        )
        call = lambda: gate_high.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    elif reason == "invocation_budget_exhausted":
        gate_small = r1_dispatch.DispatchGate(
            policy=_policy(
                invocation_budgets={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}
            ),
            autoscaler_reader=lambda *_: payload,
            **world,
        )
        gate_small.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
        call = lambda: gate_small.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
        with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
            call()
        assert excinfo.value.reason == reason
        assert gate_small.used_allowance(r1.SANDBOX_CPU) == 1
        return
    else:
        call = lambda: gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})

    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        call()
    assert excinfo.value.reason == reason
    assert gate.used_allowance(r1.SANDBOX_CPU) == 0
    assert fake.calls == []
