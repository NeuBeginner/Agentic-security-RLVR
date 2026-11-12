"""The boundary tests of the R1 guard.

Three properties, each of them a regression test of the R1 re-review:

* **P0.1** - the guard module captures **no** provider entry point. The closure
  of a dispatch primitive holds no callable that reaches the provider, and no
  registry of the module holds one either.
* **P0.2** - the **class-method boundary** is guarded. The provider method of
  the *raw* class instance - the one a caller reaches through the module's
  private registry - is guarded as well, for every method of the class and not
  only for the method the wrapper handed out.
* **P0.3** - the gate is **not self-authorising**. A step policy that a caller
  constructs in-process - with an ``approved_by`` of its own choosing and with
  permissive profile and read-back doubles - does not authorise a provider
  dispatch.

Everything here is local: no test performs a provider call, a deployment, a
volume operation or a model download. The doubles below record every call they
receive, so "the provider was reached" is an observable fact and not an
assumption.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import inspect
import json
from typing import Any, Dict, List, Tuple

import pytest

from benchmarks import r1_dispatch
from core import r1_bounds as r1

REPO_ROOT = r1.__file__.rsplit("\\", 2)[0] if "\\" in r1.__file__ else "/".join(
    r1.__file__.split("/")[:-2]
)


# --------------------------------------------------------------------------------------
# doubles
# --------------------------------------------------------------------------------------


class FakeProviderObject:
    """A double of a provider *object*.

    The entry point is a **class** attribute, exactly as in the provider SDK:
    the guard resolves the entry point from the object's own class, so a double
    has to declare it there.
    """

    def __init__(self) -> None:
        self.calls: List[Tuple[Any, Any]] = []

    def remote(self, *args: Any, **kwargs: Any):
        self.calls.append((args, kwargs))
        return {"ok": True}


class FakeProviderCallable:
    """A provider callable double: the gate treats it as a billable call."""

    def __init__(self) -> None:
        self.calls: List[Tuple[Any, Any]] = []
        setattr(self, r1.PROVIDER_CALLABLE_MARKER, True)

    def remote(self, *args: Any, **kwargs: Any):
        self.calls.append((args, kwargs))
        return {"ok": True}


class FakeClassProviderMethod:
    """A provider method of a fake class instance."""

    def __init__(self, sink: List[Tuple[Any, Any]]) -> None:
        self.calls = sink

    def remote(self, *args: Any, **kwargs: Any):
        self.calls.append((args, kwargs))
        return {"ok": True}


class FakeClassProviderInstance:
    """A double of a Modal class **instance**.

    Every attribute access produces a **fresh** provider method - exactly what
    the SDK does (``modal/cls.py:442``). A guard that covers only the method it
    handed out leaves the next access unguarded, and that is the bypass the
    re-review named.
    """

    def __init__(self) -> None:
        self.calls: List[Tuple[Any, Any]] = []
        self.methods: List[FakeClassProviderMethod] = []

    def __getattr__(self, name: str) -> Any:
        method = FakeClassProviderMethod(self.calls)
        self.methods.append(method)
        return method


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


def _reader():
    def reader(target, function_name=""):
        return {
            "min_containers": 0,
            "max_containers": 48,
            "buffer_containers": 0,
            "scaledown_window": 60,
        }

    return reader


# --------------------------------------------------------------------------------------
# P0.1 - the guard module captures no provider entry point
# --------------------------------------------------------------------------------------


def _install_fake_provider(name: str) -> FakeProviderObject:
    fake = FakeProviderObject()
    r1.install_provider_guard(name, fake)
    return fake


def test_the_guard_module_holds_no_captured_provider_entry_point():
    """P0.1: there is no captured entry point left to reach the provider."""
    _install_fake_provider("r1_boundary_captured_entrypoint")

    primitives = getattr(r1, "_CAPTURED_ENTRYPOINTS", None) or {}
    assert primitives == {}, (
        "the guard module still holds captured provider entry points: "
        f"{sorted(primitives)}"
    )


def test_the_closure_of_a_dispatch_primitive_hands_out_no_provider_callable():
    """P0.1: the closure of a primitive is inspected and nothing is extracted.

    The re-review named this route: the primitive is retrieved, its closure is
    inspected, the raw provider callable is extracted from the closure cell and
    invoked. The fake provider must record **zero** calls.
    """
    fake = _install_fake_provider("r1_boundary_closure")

    primitives = getattr(r1, "_CAPTURED_ENTRYPOINTS", None) or {}
    for name, primitive in primitives.items():
        for cell in getattr(primitive, "__closure__", None) or ():
            content = cell.cell_contents
            if callable(content):
                with contextlib.suppress(Exception):
                    content({"x": 1})
        assert fake.calls == [], (
            f"the closure of the dispatch primitive of '{name}' reaches the provider"
        )
    assert fake.calls == []


def test_no_registry_of_the_guard_module_holds_a_provider_callable():
    """P0.1: no registry of the module holds a callable entry point.

    A registry of raw callables is a bypass with a name: a caller that reads it
    gets an invocable provider entry point. Only the provider *objects* may be
    registered - their entry point is resolved from their own class.
    """
    offenders = []
    for registry_name, registry in vars(r1).items():
        if not isinstance(registry, dict):
            continue
        for key, item in registry.items():
            if (
                inspect.isfunction(item)
                or inspect.ismethod(item)
                or isinstance(item, functools.partial)
            ):
                offenders.append((registry_name, key))
    assert offenders == [], f"the guard module holds provider callables: {offenders}"


def test_the_provider_object_hands_out_the_guard_and_not_its_entry_point():
    """The ordinary route is closed: the object carries the guard itself."""
    fake = _install_fake_provider("r1_boundary_object")

    assert isinstance(fake.remote, r1.GuardedProviderRemote)
    with pytest.raises(Exception):
        fake.remote({"x": 1})
    assert fake.calls == []


def _reachable_callables(value: Any) -> List[Any]:
    """The callables a value carries: itself and the contents of its closure."""
    found: List[Any] = []
    if callable(value):
        found.append(value)
    for cell in getattr(value, "__closure__", None) or ():
        try:
            content = cell.cell_contents
        except ValueError:  # pragma: no cover - an empty cell
            continue
        if callable(content):
            found.append(content)
    return found


def test_no_callable_of_the_guard_module_reaches_the_provider():
    """The runtime audit: not one callable of the module reaches the provider.

    Every callable the module holds - and every callable in the closure of
    those - is invoked against a fake provider. The fake must record **zero**
    calls: the repository holds no invocable provider entry point.
    """
    fake = _install_fake_provider("r1_boundary_audit")

    for name, value in list(vars(r1).items()):
        for candidate in _reachable_callables(value):
            with contextlib.suppress(Exception):
                candidate({"x": 1})

    assert fake.calls == [], "a callable of the guard module reaches the provider"


def test_no_closure_of_the_guard_module_carries_a_provider_entry_point():
    """The static audit: no closure cell of the module carries an entry point."""
    fake = _install_fake_provider("r1_boundary_closure_audit")
    entry_point = fake.__class__.remote

    offenders = []
    for name, value in list(vars(r1).items()):
        for cell in getattr(value, "__closure__", None) or ():
            try:
                content = cell.cell_contents
            except ValueError:  # pragma: no cover - an empty cell
                continue
            if content is entry_point or content is fake.__dict__.get("remote"):
                offenders.append(name)
    assert offenders == [], f"a closure of the guard module carries the entry point: {offenders}"


# --------------------------------------------------------------------------------------
# P0.2 - the class-method boundary is guarded
# --------------------------------------------------------------------------------------


def _install_fake_class() -> Tuple[Any, FakeClassProviderInstance]:
    """Install the class guard on a fake class and return the raw instance."""
    wrapper = r1.install_class_guard("ProductionAuditAgent", FakeClassProviderInstance)
    guarded_instance = wrapper()
    token = guarded_instance.__dict__["_object_token"]
    return wrapper, r1._GUARDED_OBJECTS[token]


@pytest.mark.parametrize(
    "method_name",
    [
        "generate_solidity_exploit",
        "refine_solidity_exploit",
        "audit_target_contract",
    ],
)
def test_the_method_of_the_raw_class_instance_is_guarded(method_name):
    """P0.2: the raw instance hands out a **guarded** provider method.

    The re-review named this route: the raw class instance is taken from the
    module's registry, the provider method is resolved from it and the method's
    own ``remote`` is called. The fake provider must record **zero** calls.
    """
    _wrapper, raw_instance = _install_fake_class()

    method = getattr(raw_instance, method_name)
    assert isinstance(method, r1.GuardedClassMethod), (
        f"the provider method '{method_name}' of the raw instance is not guarded"
    )
    with pytest.raises(Exception):
        method.remote({"x": 1})
    assert raw_instance.calls == []


@pytest.mark.parametrize(
    "method_name",
    [
        "generate_solidity_exploit",
        "refine_solidity_exploit",
        "audit_target_contract",
    ],
)
def test_the_method_of_the_guarded_instance_is_guarded(method_name):
    """P0.2: the ordinary route of the guarded instance stays guarded."""
    _wrapper, raw_instance = _install_fake_class()
    guarded_instance = _wrapper()

    method = getattr(guarded_instance, method_name)
    assert isinstance(method, r1.GuardedClassMethod)
    with pytest.raises(Exception):
        method.remote({"x": 1})
    assert raw_instance.calls == []


def test_every_access_of_the_raw_instance_yields_a_guarded_method():
    """P0.2: a second access is guarded as well - the SDK produces a new one."""
    _wrapper, raw_instance = _install_fake_class()

    first = getattr(raw_instance, "generate_solidity_exploit")
    second = getattr(raw_instance, "generate_solidity_exploit")
    assert first is not second, "the double must produce a fresh method per access"
    for method in (first, second):
        assert isinstance(method, r1.GuardedClassMethod)
        with pytest.raises(Exception):
            method.remote({"x": 1})
    assert raw_instance.calls == []


# --------------------------------------------------------------------------------------
# P0.3 - the gate is not self-authorising
# --------------------------------------------------------------------------------------


def test_a_policy_constructed_by_the_caller_does_not_authorise_a_dispatch():
    """P0.3: the gate is not an approval boundary on its own.

    The caller constructs a policy with its own ``approved_by``, supplies
    permissive profile and read-back doubles and reaches a provider double.
    That must be refused - and the double must record **zero** calls.
    """
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=_policy(approved_by="maintainer"), autoscaler_reader=_reader(), **world
    )
    fake = FakeProviderCallable()

    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_not_verified"
    assert fake.calls == []


def test_a_policy_without_an_approval_is_refused_for_every_provider_call_site():
    """P0.3: no call site of the authorised trace is dispatchable without one."""
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=_policy(), autoscaler_reader=_reader(), **world
    )

    for function_name in r1.FUNCTION_CLASS:
        fake = FakeProviderCallable()
        with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
            gate.dispatch(
                r1.FUNCTION_CLASS[function_name], function_name, fake, {}
            )
        assert excinfo.value.reason == "approval_not_verified", function_name
        assert fake.calls == [], function_name


def test_the_repository_pins_no_approval_key():
    """P0.3: the repository as it stands cannot authorise a dispatch.

    The pinned public key is absent, so no approval artifact can be verified:
    the live provider dispatch is impossible in R1, and it is impossible
    *structurally* - not only because the bounds are unapproved.
    """
    from core import r1_approval

    assert r1_approval.pinned_public_key() is None
    with pytest.raises(r1_approval.ApprovalNotVerified):
        r1_approval.verify_approval(
            {"step_id": "R3", "approved_by": "maintainer", "approved_at": "2026-11-12"},
            b"not-a-signature",
        )


def test_an_approval_of_another_step_does_not_authorise_this_one():
    """P0.3: an approval covers the step it names and no other."""
    from core import r1_approval

    payload = {
        "step_id": "R2p",
        "approved_by": "maintainer",
        "approved_at": "2026-11-12",
        "call_sites": ["verify_exploit_remote"],
        "policy": {},
    }
    with pytest.raises(r1_approval.ApprovalNotVerified):
        r1_approval.verify_approval(payload, b"not-a-signature")


def test_the_refusal_reasons_name_the_approval_refusals():
    """The reason codes of the approval refusals are stable."""
    assert "approval_not_verified" in r1_dispatch.REFUSAL_REASONS
    assert "approval_policy_mismatch" in r1_dispatch.REFUSAL_REASONS
    assert "call_site_not_approved" in r1_dispatch.REFUSAL_REASONS
