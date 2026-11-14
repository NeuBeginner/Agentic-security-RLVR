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


def _signed_approval(signer, policy, world=None):
    """Sign the exact effective envelope used by the gate in this test."""
    options = dict(world or {})
    gate = r1_dispatch.DispatchGate(policy=policy, **options)
    return signer(policy, dispatch_envelope=gate.dispatch_envelope_payload())


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

    Two shapes reach the provider:

    * an attribute call of ``remote`` - the shape of the call sites of the
      repository; and
    * a call of ``_call_provider_entry_point`` - the boundary of the workflow.
      The entry point of the provider is no longer reached through a ``remote``
      attribute: it is resolved from the provider object's own class, so the
      resolver is the call site and the scanner has to know it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    def enclosing(node: ast.AST) -> str:
        scope: Any = node
        while scope is not None and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            scope = parents.get(id(scope))
        return getattr(scope, "name", "<module>")

    sites: List[Tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "_call_provider_entry_point":
            callee = ast.unparse(node.args[0]) if node.args else "<unknown>"
            sites.append((enclosing(node), callee, ast.unparse(node)[:120]))
            continue
        current: Any = node.func
        remote_attribute = None
        while isinstance(current, ast.Attribute):
            if current.attr == "remote":
                remote_attribute = current
            current = current.value
        if remote_attribute is None:
            continue
        function_name = enclosing(node)
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
    }
    for key, entry in inventory["dispositions"].items():
        assert entry["disposition"] in allowed, key
        assert entry["reason"].strip(), key
        assert entry["count"] >= 1, key


def test_no_provider_call_site_is_classified_out_of_scope():
    """An unguarded provider call may not pass as complete.

    "Declared out of scope" is not a disposition: a provider call that is not
    gated has to be **refused** with the reason of the refusal registry. The
    Iteration 19 CPU smoke was classified that way and the R1 review named it
    as an unguarded invocation.
    """
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    out_of_scope = [
        key
        for key, entry in inventory["dispositions"].items()
        if entry["disposition"] == "declared_out_of_scope"
    ]
    assert out_of_scope == []
    # Every provider call site of the repository is either gated or refused.
    for key, entry in inventory["dispositions"].items():
        assert entry["disposition"] in {"gated", "refused", "guarded_class_method", "gate"}, key


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
        "cpu_smoke",
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
# F - the raw provider objects are not reachable through the guards
# --------------------------------------------------------------------------------------
#
# The R1 review named four bypasses: the guard wrappers kept the raw Modal objects
# in their own instance dictionaries, so a caller could reach the raw provider
# callable and call it without the gate. Every one of them is closed here: the
# attribute does not exist any more, and the guard is installed on the provider
# object itself, so the raw object is gated too.


class FakeProviderObject:
    """A double of a provider *object* - its 'remote' is the provider entry point.

    The entry point is a **class** attribute, exactly as in the provider SDK:
    the guard resolves the entry point from the object's own class, so a double
    has to declare it there.
    """

    def __init__(self) -> None:
        self.calls = []

    def remote(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


def test_the_guard_of_a_module_function_exposes_no_raw_provider_function():
    import modal_app

    guarded = modal_app.verify_exploit_remote
    assert isinstance(guarded, r1.GuardedRemote)
    # The bypass the review named: the raw Modal function in the instance dict.
    assert not hasattr(guarded, "_fn")
    assert "_fn" not in guarded.__dict__
    with pytest.raises(AttributeError):
        guarded._fn  # noqa: B018 - the attribute access is the assertion
    # No attribute of the guard yields the raw provider object.
    for value in guarded.__dict__.values():
        assert value is not r1._INSTALLED_OBJECTS["verify_exploit_remote"]


def test_the_guard_of_a_class_exposes_no_raw_class():
    import modal_app

    guarded = modal_app.ProductionAuditAgent
    assert isinstance(guarded, r1.GuardedClass)
    assert not hasattr(guarded, "_cls")
    assert "_cls" not in guarded.__dict__
    with pytest.raises(AttributeError):
        guarded._cls  # noqa: B018 - the attribute access is the assertion


def test_the_guarded_instance_exposes_no_raw_instance():
    import modal_app

    agent = modal_app.ProductionAuditAgent()
    assert isinstance(agent, r1.GuardedClassInstance)
    assert not hasattr(agent, "_obj")
    assert "_obj" not in agent.__dict__
    with pytest.raises(AttributeError):
        agent._obj  # noqa: B018 - the attribute access is the assertion
    # The raw class of the instance is not reachable either.
    assert not hasattr(agent, "_cls")


def test_the_guarded_class_method_exposes_no_raw_method():
    import modal_app

    agent = modal_app.ProductionAuditAgent()
    method = agent.generate_solidity_exploit
    assert isinstance(method, r1.GuardedClassMethod)
    assert not hasattr(method, "_fn")
    assert "_fn" not in method.__dict__
    with pytest.raises(AttributeError):
        method._fn  # noqa: B018 - the attribute access is the assertion


@pytest.mark.parametrize(
    "attribute",
    ["_fn", "_obj", "_cls", "_provider", "_remote", "__wrapped__"],
)
def test_no_guard_hands_out_an_underscore_attribute(attribute):
    """Not one guard object carries an attribute that could hold a provider object."""
    import modal_app

    agent = modal_app.ProductionAuditAgent()
    for guarded in (
        modal_app.verify_exploit_remote,
        modal_app.ProductionAuditAgent,
        agent,
        agent.generate_solidity_exploit,
    ):
        assert attribute not in guarded.__dict__
        with pytest.raises(AttributeError):
            getattr(guarded, attribute)


def test_the_raw_provider_object_is_itself_guarded():
    """The guard is installed on the provider object, not only on its name.

    A caller that gets hold of the raw object - from wherever - reaches the
    gate, not the provider.
    """
    import modal_app

    raw = r1._INSTALLED_OBJECTS["verify_exploit_remote"]
    assert isinstance(raw.remote, r1.GuardedProviderRemote)
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        raw.remote({"target": {}})
    assert excinfo.value.reason == "no_approved_step_policy"


def test_a_fake_provider_object_is_never_reached_while_the_bounds_are_unset():
    """The installation gates the object itself: the fake's remote is never reached."""
    fake = FakeProviderObject()
    guarded = r1.install_provider_guard("r1_test_fake_provider_object", fake)

    assert isinstance(fake.remote, r1.GuardedProviderRemote)
    with pytest.raises(r1.UnauthorisedCallSite):
        fake.remote({"x": 1})
    assert fake.calls == []

    with pytest.raises(r1.UnauthorisedCallSite):
        guarded.remote({"x": 1})
    assert fake.calls == []


def test_the_guard_of_a_provider_object_is_installed_on_the_object_itself():
    """The installation replaces the object's own 'remote' with the guard."""
    fake = FakeProviderObject()
    original = fake.remote
    r1.install_provider_guard("r1_test_fake_provider_object_2", fake)

    assert fake.remote is not original
    assert isinstance(fake.remote, r1.GuardedProviderRemote)
    # The entry point is not held by the module: it stays in the object's own
    # class and is resolved from there at the moment of the call. The module
    # keeps no callable of it - not in a registry, not in a closure.
    assert original not in vars(r1).values()
    for registry in vars(r1).values():
        if isinstance(registry, dict):
            assert original not in registry.values()


def test_a_local_double_substituted_on_a_guard_is_called_instead_of_the_provider():
    """A substituted 'remote' is a local function: it starts no container."""
    import modal_app

    calls = []

    def local_double(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True}

    modal_app.verify_exploit_remote.remote = local_double
    try:
        # The local double is not a provider call: the bounds of the class are
        # unset, and the call is passed through instead of being refused.
        result = modal_app.verify_exploit_remote.remote({"target": {}})
        assert result == {"ok": True}
        assert len(calls) == 1
    finally:
        del modal_app.verify_exploit_remote.__dict__["remote"]

    # Without the substitution the same call is refused (fail closed).
    with pytest.raises(r1.BoundsNotApproved):
        modal_app.verify_exploit_remote.remote({"target": {}})


def _install_fake_provider(monkeypatch, name: str) -> FakeProviderObject:
    """Install a fake provider object under a call-site name, reversibly."""
    fake = FakeProviderObject()
    monkeypatch.setitem(r1._INSTALLED_OBJECTS, name, fake)
    r1.install_provider_guard(name, fake)
    return fake


def test_an_approved_dispatch_reaches_the_provider_exactly_once(monkeypatch, signed_approval):
    """The whole path - guard, gate, provider - runs once and is billed once.

    This is the end-to-end proof of the reworked guard: the guarded call is
    dispatched through the single gate, the provider's entry point is reached
    exactly once, and the invocation allowance is consumed exactly once.
    """
    world = _approved_world()
    fake = _install_fake_provider(monkeypatch, "verify_exploit_remote")
    wrapper = r1.GuardedRemote(fake, "verify_exploit_remote")
    policy = _policy(invocation_budgets={r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1})

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        **world,
    ) as gate:
        result = gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", wrapper, {"a": 1})

    assert result == {"ok": True}
    assert len(fake.calls) == 1
    assert gate.used_allowance(r1.SANDBOX_CPU) == 1
    assert len(gate.dispatched()) == 1


def test_the_boundary_guard_dispatches_through_the_same_gate(monkeypatch, signed_approval):
    """The guard on the provider object's own 'remote' uses the single gate."""
    world = _approved_world()
    fake = _install_fake_provider(monkeypatch, "verify_exploit_remote")
    policy = _policy(invocation_budgets={r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1})

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        **world,
    ) as gate:
        result = fake.remote({"a": 1})

    assert result == {"ok": True}
    assert len(fake.calls) == 1
    assert gate.used_allowance(r1.SANDBOX_CPU) == 1


# --------------------------------------------------------------------------------------
# F2 - the provider entry point is not reachable
# --------------------------------------------------------------------------------------
#
# The R1 re-review named the public accessor 'original_entrypoint' as a direct
# bypass: it returned the provider entry point that had been captured before
# the guard was installed, so a caller could invoke it and start a billable
# container without the gate, without the invocation budget and without the
# declared bounds.
#
# The correction goes further than removing the accessor: the repository holds
# **no** provider entry point at all. The entry point stays in the provider
# object's own class, and it is resolved from there at the moment of the call -
# by the R1 gate and by nothing else. The rule these tests state: **no route of
# the repository reaches an invocable provider entry point**.


def _install_bare_fake_provider(name: str) -> Tuple[FakeProviderObject, Any]:
    """Install a fake provider object and return it with its original entry point."""
    fake = FakeProviderObject()
    original = fake.remote
    r1.install_provider_guard(name, fake)
    return fake, original


def test_no_public_route_reaches_the_captured_provider_entry_point():
    """The bypass of the re-review: retrieve the raw entry point and invoke it.

    Every route the repository offers is tried - the accessor that was named,
    the guard installed on the provider object, the module-level guard and the
    gate - and the fake provider must record **zero** calls.
    """
    name = "r1_test_raw_entrypoint_route"
    fake, _original = _install_bare_fake_provider(name)

    routes = []
    accessor = getattr(r1, "original_entrypoint", None)
    if accessor is not None:
        routes.append(("original_entrypoint", lambda: accessor(name)))
    routes.append(("the installed provider object", lambda: fake.remote({"x": 1})))
    routes.append(
        ("the module-level guard", lambda: r1.DEEPLOYED_FUNCTIONS[name].remote({"x": 1}))
    )

    for label, route in routes:
        try:
            entry = route()
        except Exception:
            # A refusal is the expected outcome of a gated route.
            assert fake.calls == [], f"the route '{label}' reached the provider"
            continue
        if callable(entry):
            try:
                entry({"x": 1})
            except Exception:
                pass
        assert fake.calls == [], f"the route '{label}' reached the provider"


def test_the_module_has_no_accessor_for_the_captured_entry_point():
    """The accessor itself must not exist any more - not renamed, not hidden."""
    assert not hasattr(r1, "original_entrypoint")
    assert "original_entrypoint" not in r1.__all__
    assert not hasattr(r1, "_ORIGINAL_ENTRYPOINTS")


def test_the_module_holds_no_dispatch_primitive():
    """The primitive of the old design is gone: there is nothing to capture."""
    assert not hasattr(r1, "_CAPTURED_ENTRYPOINTS")
    assert not hasattr(r1, "_make_captured_entrypoint")


def test_no_public_function_of_the_guard_module_returns_a_provider_object():
    """No public function of the module may hand a provider object to a caller.

    The check is static: a public function that *returns* an entry of a
    provider registry - or the result of a helper that resolves one - is an
    accessor for the raw provider object. The registries are the trust
    boundary of the guard, so only the gate may read them, and the gate lives
    in another module.
    """
    source = (REPO_ROOT / "core" / "r1_bounds.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    registries = {
        "_GUARDED_OBJECTS",
        "_INSTALLED_OBJECTS",
        "_ORIGINAL_ENTRYPOINTS",
        "_CAPTURED_ENTRYPOINTS",
    }
    resolvers = {
        "_guarded_object",
        "_unwrap_guard",
        "_perform_provider_call",
        "_call_provider_entry_point",
        "_raw_class_method",
    }
    offenders = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_"):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Return) or child.value is None:
                continue
            value = child.value
            if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name):
                if value.value.id in registries:
                    offenders.append((node.name, value.value.id, child.lineno))
            elif isinstance(value, ast.Call):
                if isinstance(value.func, ast.Attribute) and isinstance(
                    value.func.value, ast.Name
                ):
                    if value.func.value.id in registries:
                        offenders.append((node.name, value.func.value.id, child.lineno))
                elif isinstance(value.func, ast.Name) and value.func.id in resolvers:
                    offenders.append((node.name, value.func.id, child.lineno))
    assert offenders == [], f"public functions hand out provider objects: {offenders}"


def test_the_provider_call_primitive_refuses_a_call_outside_the_gate():
    """The innermost provider call is the gate's - not the repository's."""
    name = "r1_test_raw_entrypoint_perform"
    fake, _original = _install_bare_fake_provider(name)

    with pytest.raises(r1.UnauthorisedCallSite):
        r1._perform_provider_call(name, fake, {"x": 1})
    assert fake.calls == []


def test_the_entry_point_resolver_refuses_a_call_outside_the_gate():
    """The resolver of the provider entry point is the gate's - not the repository's."""
    name = "r1_test_raw_entrypoint_resolver"
    fake, _original = _install_bare_fake_provider(name)

    with pytest.raises(r1.UnauthorisedCallSite):
        r1._call_provider_entry_point(fake, {"x": 1})
    assert fake.calls == []


def test_the_unwrap_helper_is_not_a_public_accessor():
    """The unwrap helper handed out the raw provider method of a class.

    It was a public function of the module: a caller could unwrap a guarded
    class method and call the raw provider method it returned. It is private
    now, and only the gate may call it.
    """
    assert "unwrap_guard" not in r1.__all__
    assert not hasattr(r1, "unwrap_guard")


# --------------------------------------------------------------------------------------
# G - the Iteration 19 CPU smoke is refused, not classified out of scope
# --------------------------------------------------------------------------------------


class FakeSmokeRemote:
    """The provider entry point of the smoke function - a double, never called."""

    def __init__(self) -> None:
        self.calls = []

    async def aio(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


class FakeSmokeFunction:
    def __init__(self) -> None:
        self.remote = FakeSmokeRemote()


class FakeSmokeApp:
    """The ephemeral app of the smoke - it must not even start for a refusal."""

    def __init__(self) -> None:
        self.run_calls = 0
        self.app_id = "ap-fake"

    def run(self):
        self.run_calls += 1
        raise AssertionError(
            "the ephemeral app must not start for a refused invocation"
        )


def test_the_iteration19_cpu_smoke_invocation_is_refused_before_the_provider_is_reached():
    """The refusal happens before ``.remote.aio()`` - the provider is never reached."""
    import asyncio

    from benchmarks import run_iteration19_cpu_smoke as smoke

    monkey = pytest.MonkeyPatch()
    monkey.delenv(smoke.APPROVAL_ENV_VAR, raising=False)
    try:
        function = FakeSmokeFunction()
        app = FakeSmokeApp()
        with pytest.raises(smoke.SmokeNotAuthorised):
            asyncio.run(smoke._invoke(function, app, "iteration19", "neubeginner"))
        assert function.remote.calls == []
        assert app.run_calls == 0
    finally:
        monkey.undo()


def test_the_iteration19_cpu_smoke_run_refuses_before_it_writes_evidence(tmp_path):
    """A refused run writes no evidence: it is not an attempted invocation."""
    import argparse

    from benchmarks import run_iteration19_cpu_smoke as smoke

    monkey = pytest.MonkeyPatch()
    monkey.delenv(smoke.APPROVAL_ENV_VAR, raising=False)
    try:
        args = argparse.Namespace(
            profile="neubeginner",
            seed="iteration19",
            evidence_dir=str(tmp_path / "evidence"),
        )
        with pytest.raises(smoke.SmokeNotAuthorised):
            smoke.run(args)
        assert not (tmp_path / "evidence").exists()
    finally:
        monkey.undo()


def test_the_iteration19_cpu_smoke_approval_is_explicit(monkeypatch):
    """Only an explicit approval lifts the refusal - and it starts no container."""
    from benchmarks import run_iteration19_cpu_smoke as smoke

    monkeypatch.delenv(smoke.APPROVAL_ENV_VAR, raising=False)
    with pytest.raises(smoke.SmokeNotAuthorised):
        smoke._assert_authorised()

    monkeypatch.setenv(smoke.APPROVAL_ENV_VAR, "1")
    smoke._assert_authorised()  # does not raise - and calls nothing


def test_the_iteration19_cpu_smoke_is_in_the_refusal_registry():
    """The refused surface names the smoke function and its reason."""
    assert "cpu_smoke" in r1.UNAUTHORISED_CALL_SITES
    reason = r1.UNAUTHORISED_CALL_SITES["cpu_smoke"]
    assert "refused" in reason
    assert "approval" in reason


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
def test_a_mismatching_field_in_the_read_back_is_refused(field_name, signed_approval):
    world = _approved_world()
    payload = _settings()
    payload[field_name] = payload[field_name] + 1 if field_name != "scaledown_window" else 61
    policy = _policy()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=lambda *_: payload,
        **world,
    )
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "autoscaler_readback_mismatch"
    assert field_name in excinfo.value.detail
    assert fake.calls == []


def test_a_partial_read_back_is_never_accepted(signed_approval):
    """A read-back that carries only some of the fields is refused."""
    world = _approved_world()
    payload = {"min_containers": 0, "max_containers": 48}
    policy = _policy()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=lambda *_: payload,
        **world,
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


def test_object_tag_matches_modal_sdk_1_5_5_registration_tags():
    """Module functions use their name; @app.cls service functions use 'ClassName.*'."""
    import modal_app
    from modal._utils.async_utils import synchronizer

    raw_app = synchronizer._translate_in(modal_app.app)
    registered_tags = set(raw_app._local_state.functions.keys())
    assert "verify_exploit_remote" in registered_tags
    assert "verify_replay_remote" in registered_tags
    assert "record_trajectory_remote" in registered_tags
    assert "ProductionAuditAgent.*" in registered_tags
    assert "ProductionAuditAgent" not in registered_tags

    assert r1_dispatch._object_tag("verify_exploit_remote") == "verify_exploit_remote"
    assert (
        r1_dispatch._object_tag("ProductionAuditAgent.generate_solidity_exploit")
        == "ProductionAuditAgent.*"
    )
    assert (
        r1_dispatch._object_tag("ProductionAuditAgent.refine_solidity_exploit")
        == "ProductionAuditAgent.*"
    )


def test_provider_autoscaler_reader_enforces_protobuf_has_field_presence(monkeypatch):
    """Unset protobuf fields in FunctionGetResponse must fail closed, never read as 0."""
    from modal.client import _Client
    from modal_proto import api_pb2

    monkeypatch.setenv("R1_ENABLE_PROVIDER_READBACK", "1")
    captured_requests = []
    next_response = [api_pb2.FunctionGetResponse()]

    class FakeStub:
        async def FunctionGet(self, request):
            captured_requests.append(request)
            return next_response[0]

    class FakeClient:
        stub = FakeStub()

    async def fake_from_env():
        return FakeClient()

    # The read-back uses the *asynchronous* client of Modal SDK 1.5.5; the public
    # synchronous client is never used (see tests/test_r1_readback_sdk_compat.py).
    monkeypatch.setattr(_Client, "from_env", fake_from_env)

    # 1. Empty FunctionGetResponse (unset 'function' submessage) -> unavailable
    next_response[0] = api_pb2.FunctionGetResponse()
    with pytest.raises(r1_dispatch.AutoscalerReadbackUnavailable, match="no FunctionData"):
        r1_dispatch.provider_autoscaler_reader(
            None, "ProductionAuditAgent.generate_solidity_exploit"
        )
    assert captured_requests[-1].object_tag == "ProductionAuditAgent.*"

    # 2. FunctionData with unset 'autoscaler_settings' submessage -> unavailable
    next_response[0] = api_pb2.FunctionGetResponse(function=api_pb2.FunctionData())
    with pytest.raises(
        r1_dispatch.AutoscalerReadbackUnavailable, match="no autoscaler settings"
    ):
        r1_dispatch.provider_autoscaler_reader(None, "verify_exploit_remote")
    assert captured_requests[-1].object_tag == "verify_exploit_remote"

    # 3. Partial AutoscalerSettings (scaledown_window unset) -> None, refused by read_back_autoscaler
    next_response[0] = api_pb2.FunctionGetResponse(
        function=api_pb2.FunctionData(
            autoscaler_settings=api_pb2.AutoscalerSettings(
                min_containers=0,
                max_containers=32,
                buffer_containers=0,
            )
        )
    )
    partial = r1_dispatch.provider_autoscaler_reader(
        None, "ProductionAuditAgent.generate_solidity_exploit"
    )
    assert partial == {
        "min_containers": 0,
        "max_containers": 32,
        "buffer_containers": 0,
        "scaledown_window": None,
    }
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        r1_dispatch.read_back_autoscaler(
            None,
            function_name="ProductionAuditAgent.generate_solidity_exploit",
            reader=r1_dispatch.provider_autoscaler_reader,
        )
    assert excinfo.value.reason == "autoscaler_readback_missing_field"
    assert "scaledown_window" in excinfo.value.detail

    # 4. Complete AutoscalerSettings -> all four integers returned
    next_response[0] = api_pb2.FunctionGetResponse(
        function=api_pb2.FunctionData(
            autoscaler_settings=api_pb2.AutoscalerSettings(
                min_containers=0,
                max_containers=32,
                buffer_containers=0,
                scaledown_window=60,
            )
        )
    )
    complete = r1_dispatch.read_back_autoscaler(
        None,
        function_name="ProductionAuditAgent.generate_solidity_exploit",
        reader=r1_dispatch.provider_autoscaler_reader,
    )
    assert complete == {
        "min_containers": 0,
        "max_containers": 32,
        "buffer_containers": 0,
        "scaledown_window": 60,
    }


def test_the_gpu_class_service_function_carries_the_exact_modal_sdk_deployment_kwargs():
    """Verify the actual Modal SDK 1.5.5 _Function closure formed for ProductionAuditAgent.*."""
    import modal_app
    from modal._utils.async_utils import synchronizer

    raw_app = synchronizer._translate_in(modal_app.app)
    gpu_service_fn = raw_app._local_state.functions["ProductionAuditAgent.*"]
    assert gpu_service_fn._tag_ == "ProductionAuditAgent.*"

    load_fn = gpu_service_fn._load
    cells = {
        name: cell.cell_contents
        for name, cell in zip(load_fn.__code__.co_freevars, load_fn.__closure__)
    }
    assert cells["block_network"] is True
    assert cells["gpu"] == "H100"
    assert cells["timeout"] == 1200
    assert cells["min_containers"] == 0
    assert cells["buffer_containers"] == 0
    assert cells["max_containers"] == 32
    # Unapproved bounds are absent (None), never replaced by permissive defaults.
    assert cells["cpu"] is None
    assert cells["memory"] is None
    assert cells["scaledown_window"] is None
    volumes = dict(cells["validated_volumes_no_cloud_buckets"])
    assert "/vol/models" in volumes
    assert cells["secrets"] and len(cells["secrets"]) == 1


def test_an_unavailable_read_back_refuses_the_dispatch(signed_approval):
    world = _approved_world()

    def unavailable(target, function_name=""):
        raise r1_dispatch.AutoscalerReadbackUnavailable("no read-only read available")

    policy = _policy()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=unavailable,
        **world,
    )
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


def test_the_class_semaphore_is_initialized_once_under_concurrency():
    """The first-time membership check must not race across dispatch threads."""
    gate = r1_dispatch.DispatchGate(policy=_policy())
    barrier = threading.Barrier(2)
    returned: List[Any] = []
    errors: List[BaseException] = []

    class _BarrierDict(dict):
        def __contains__(self, key):
            # The old unsynchronised implementation checked membership outside
            # a lock. Force both callers past that check before either can insert.
            barrier.wait(timeout=5)
            return super().__contains__(key)

    gate._semaphores = _BarrierDict()

    def worker() -> None:
        try:
            returned.append(gate._semaphore(r1.SANDBOX_CPU))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert len(returned) == 2
    assert returned[0] is returned[1]


def test_the_invocation_allowance_is_consumed_atomically_under_concurrency(signed_approval):
    """Two concurrent dispatches may never both pass the same remaining allowance."""
    world = _approved_world()
    policy = _policy(
        invocation_budgets={r1.SANDBOX_CPU: 3, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        concurrency_caps={r1.SANDBOX_CPU: 8, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
    )
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
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


def test_a_refused_attempt_does_not_consume_the_invocation_allowance(signed_approval):
    """The policy of the concurrency-refused attempt: it costs no invocation.

    A dispatch that the concurrency gate refuses starts no container, so it may
    not cost an invocation: the allowance stays intact for the next attempt.
    """
    world = _approved_world()
    policy = _policy(
        invocation_budgets={r1.SANDBOX_CPU: 2, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        wall_clock_budget_sec=1.0,
    )
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
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
def test_every_refusal_leaves_the_invocation_allowance_untouched(reason, signed_approval):
    """No refusal consumes an invocation: only a real dispatch does."""
    world = _approved_world()
    policy = _policy(
        invocation_budgets={r1.SANDBOX_CPU: 5, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}
    )
    payload = _settings()
    if reason == "autoscaler_readback_mismatch":
        payload["max_containers"] = payload["max_containers"] + 1
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=lambda *_: payload,
        **world,
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
            policy=policy, approval=_signed_approval(signed_approval, policy), autoscaler_reader=lambda *_: payload
        )
        call = lambda: gate_unbounded.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    elif reason == "deployed_ceiling_too_low":
        high_policy = _policy(
            invocation_budgets={r1.SANDBOX_CPU: 5, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
            concurrency_caps={r1.SANDBOX_CPU: 49, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        )
        gate_high = r1_dispatch.DispatchGate(
            policy=high_policy,
            approval=_signed_approval(signed_approval, high_policy, world),
            autoscaler_reader=lambda *_: payload,
            **world,
        )
        call = lambda: gate_high.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    elif reason == "invocation_budget_exhausted":
        small_policy = _policy(
            invocation_budgets={r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1}
        )
        gate_small = r1_dispatch.DispatchGate(
            policy=small_policy,
            approval=_signed_approval(signed_approval, small_policy, world),
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



@pytest.mark.parametrize("filename", ["r1_rate_card.json", "r1_cost_scenario.json"])
def test_signed_envelope_binds_cost_scenario_and_rate_card_bytes(filename, signed_approval, monkeypatch):
    """A rate-card or scenario edit invalidates the signature even if Python objects stay unchanged."""
    policy = _policy()
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=policy, **world)
    artifact = _signed_approval(signed_approval, policy, world)
    gate.approval = artifact

    original_read_bytes = Path.read_bytes

    def altered_cost_file(path):
        raw = original_read_bytes(path)
        if path.name == filename:
            return raw + b"\n# changed rate-card input\n"
        return raw

    monkeypatch.setattr(Path, "read_bytes", altered_cost_file)
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_envelope_mismatch"
    assert fake.calls == []
