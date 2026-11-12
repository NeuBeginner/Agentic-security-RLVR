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


# --------------------------------------------------------------------------------------
# P0.4 - the approval boundary cannot be minted by an ordinary caller
# --------------------------------------------------------------------------------------


def _forged_approval(policy) -> Any:
    """Forge an approval the way the re-review did: with the module's own token.

    The re-review named the route exactly: read the module attribute that marks
    an approval as *verified*, hand it to the constructor and the constructor
    accepts the instance. The helper does that whenever the attribute exists -
    after the correction it simply builds the same instance without a token,
    because there is no token any more.
    """
    from core import r1_approval

    sentinel = getattr(r1_approval, "_ISSUANCE", None)
    fields: Dict[str, Any] = {
        "step_id": policy.step_id,
        "approved_by": "maintainer",
        "approved_at": policy.approved_at,
        "call_sites": tuple(r1.FUNCTION_CLASS),
        "policy_digest": policy.policy_digest(),
        "artifact_digest": "forged",
    }
    if sentinel is not None:
        fields["_issued_by"] = sentinel
    return r1_approval.VerifiedApproval(**fields)


def test_a_forged_approval_cannot_authorise_a_dispatch():
    """P0.4: a forged approval object authorises nothing.

    Every other gate of the dispatch is **permissive** here: the policy is
    complete, the profiles and the egress declarations are approved and the
    read-back matches the declaration. The approval is the only thing that can
    refuse the dispatch - so the test isolates the approval boundary instead of
    passing because some unrelated bound happens to be unset.

    The fake provider must record **zero** calls.
    """
    policy = _policy()
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_forged_approval(policy),
        autoscaler_reader=_reader(),
        **world,
    )
    fake = FakeProviderCallable()

    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_not_verified"
    assert fake.calls == [], "the forged approval reached the provider"


def test_the_approval_module_holds_no_issuance_token():
    """P0.4: there is no module attribute that marks an approval as verified.

    A sentinel that a caller can read is not an access-control boundary: the
    re-review forged an approval with it. The boundary is the signature, so no
    such token may exist any more.
    """
    from core import r1_approval

    assert not hasattr(r1_approval, "_ISSUANCE"), (
        "the approval module still holds an issuance token: a caller can read it "
        "and mint a verified approval with it"
    )


# --------------------------------------------------------------------------------------
# P0.4 - the negative cases of the approval boundary
#
# Every case below isolates the approval boundary: the policy is complete, the
# profiles and the egress declarations are approved and the read-back matches
# the declaration, so the *approval* is the only thing that can refuse the
# dispatch. Each of them must leave the fake provider with **zero** calls.
# --------------------------------------------------------------------------------------


def _dispatch_with(approval: Any) -> Tuple[Any, List[Tuple[Any, Any]]]:
    """Dispatch one provider call with the given approval - permissive world."""
    policy = _policy()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=approval,
        autoscaler_reader=_reader(),
        **_approved_world(),
    )
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    return excinfo.value, fake.calls


def test_an_approval_without_a_pinned_key_authorises_nothing(signed_approval):
    """P0.4: no key - no approval. The repository pins none, so nothing verifies."""
    artifact = signed_approval(_policy(), pin_key=False)

    refusal, calls = _dispatch_with(artifact)
    assert refusal.reason == "approval_not_verified"
    assert calls == []


def test_an_approval_with_an_invalid_signature_authorises_nothing(signed_approval):
    """P0.4: a signature that does not verify is no signature."""
    artifact = signed_approval(_policy(), corrupt_signature=True)

    refusal, calls = _dispatch_with(artifact)
    assert refusal.reason == "approval_not_verified"
    assert calls == []


def test_an_approval_of_another_step_authorises_nothing(signed_approval):
    """P0.4: an approval covers the step it names and no other."""
    artifact = signed_approval(_policy(), step_id="R2p")

    refusal, calls = _dispatch_with(artifact)
    assert refusal.reason == "approval_not_verified"
    assert calls == []


def test_an_approval_of_another_policy_authorises_nothing(signed_approval):
    """P0.4: the approval binds the exact policy it approves."""
    other = _policy(monetary_ceiling_usd=99.0)
    artifact = signed_approval(_policy(), policy_payload=other.to_payload())

    refusal, calls = _dispatch_with(artifact)
    assert refusal.reason == "approval_policy_mismatch"
    assert calls == []


def test_an_approval_that_covers_no_call_site_authorises_nothing(signed_approval):
    """P0.4: an approval that does not name the call site authorises nothing."""
    artifact = signed_approval(_policy(), call_sites=["some_other_call_site"])

    refusal, calls = _dispatch_with(artifact)
    assert refusal.reason == "call_site_not_approved"
    assert calls == []


def test_a_mutated_artifact_authorises_nothing(signed_approval):
    """P0.4: the signature binds the payload - a payload edited afterwards is dead."""
    artifact = signed_approval(_policy())
    payload = dict(artifact.payload)
    payload["approved_by"] = "somebody-else"
    mutated = type(artifact)(payload=payload, signature=artifact.signature)

    refusal, calls = _dispatch_with(mutated)
    assert refusal.reason == "approval_not_verified"
    assert calls == []


def test_the_gate_verifies_the_artifact_at_dispatch_time(signed_approval):
    """P0.4: the verification happens in the gate, not at the construction.

    The same artifact is verified twice - once per dispatch - and the gate
    never caches a verdict: an artifact that stops verifying stops
    authorising.
    """
    policy = _policy()
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=None,
        autoscaler_reader=_reader(),
        **_approved_world(),
    )
    artifact = signed_approval(policy, dispatch_envelope=gate.dispatch_envelope_payload())
    gate.approval = artifact
    fake = FakeProviderCallable()

    assert gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {}) == {
        "ok": True
    }
    assert len(fake.calls) == 1

    # The signature of the artifact is broken after the first dispatch: the
    # next dispatch must be refused.
    broken = type(artifact)(
        payload=artifact.payload,
        signature=bytes([artifact.signature[0] ^ 0xFF]) + artifact.signature[1:],
    )
    gate.approval = broken
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_not_verified"
    assert len(fake.calls) == 1


# --------------------------------------------------------------------------------------
# P0.4 - the pin of the approval authority
# --------------------------------------------------------------------------------------


def test_the_repository_pins_no_approval_key():
    """P0.4: the repository pins no key, so no approval can be verified.

    The pin is a constant of the source - not a file that is read at runtime -
    and the evidence mirror carries ``null`` as well.
    """
    from core import r1_approval

    assert r1_approval.PINNED_PUBLIC_KEY is None
    assert r1_approval.pinned_public_key() is None


def test_the_evidence_mirror_agrees_with_the_source_pin():
    """P0.4: the mirror of the pin and the pin itself are one fact."""
    import json

    from core import r1_approval

    mirror = json.loads(r1_approval.PINNED_KEY_PATH.read_text(encoding="utf-8"))
    assert mirror.get("public_key") is None, (
        "the evidence mirror carries a key while the source pins none"
    )
    assert r1_approval.PINNED_PUBLIC_KEY is None


def test_a_mirror_that_disagrees_with_the_pin_is_refused(monkeypatch):
    """P0.4: a tampered mirror is a tamper of the pin - and the pin is refused.

    The mirror is a second copy of the pin. When the two disagree, the pin is
    not used: the gate refuses every approval (fail closed).
    """
    from core import r1_approval

    monkeypatch.setattr(r1_approval, "PINNED_PUBLIC_KEY", (int("f" * 256, 16), 65537))
    assert r1_approval.pinned_public_key() is None, (
        "a mirror that does not carry the pinned key must not authorise anything"
    )


def test_a_pinned_key_with_a_matching_mirror_is_used(monkeypatch, tmp_path):
    """P0.4: the pin mechanism itself works - with the *test* key.

    The test pins the test key in the source and writes the matching mirror
    into a temporary directory; the repository's own pin stays ``null``.
    """
    import base64
    import json

    from core import r1_approval

    modulus = int("f" * 256, 16)
    exponent = 65537
    key = (modulus, exponent)
    mirror = tmp_path / "r1_approval_key.json"
    mirror.write_text(
        json.dumps({"public_key": r1_approval.public_key_record(key)}),
        encoding="utf-8",
    )
    monkeypatch.setattr(r1_approval, "PINNED_PUBLIC_KEY", key)
    monkeypatch.setattr(r1_approval, "PINNED_KEY_PATH", mirror)

    assert r1_approval.pinned_public_key() == key
    key_size = (modulus.bit_length() + 7) // 8
    assert base64.b64decode(r1_approval.public_key_record(key)["n"]) == modulus.to_bytes(
        key_size, "big"
    )


# --------------------------------------------------------------------------------------
# P0.5 - the signature binds the complete effective D26-D29 envelope
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", [
    "cpu_request", "cpu_limit", "memory_request", "memory_limit", "timeout",
    "startup_timeout", "scaledown", "autoscaler", "min_containers",
    "buffer_containers", "gpu_type", "provenance", "egress", "ingress",
    "payload_cap", "volume_mount",
])
def test_signed_envelope_rejects_changed_effective_configuration(change, signed_approval, monkeypatch):
    """Any post-signature change to a safety/resource/network bound refuses before provider."""
    policy = _policy()
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(policy=policy, autoscaler_reader=_reader(), **world)
    artifact = signed_approval(policy, dispatch_envelope=gate.dispatch_envelope_payload())
    gate.approval = artifact

    if change == "cpu_request":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], cpu_request_cores=3.0
        )
    elif change == "cpu_limit":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], cpu_limit_cores=8.0
        )
    elif change == "memory_request":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], memory_request_mb=3072
        )
    elif change == "memory_limit":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], memory_limit_mb=8192
        )
    elif change == "timeout":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], timeout_sec=61
        )
    elif change == "startup_timeout":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], startup_timeout_sec=121
        )
    elif change == "scaledown":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], scaledown_window_sec=61
        )
    elif change == "autoscaler":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], max_containers=47
        )
    elif change == "min_containers":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], min_containers=1
        )
    elif change == "buffer_containers":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], buffer_containers=1
        )
    elif change == "gpu_type":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], gpu_type="H100"
        )
    elif change == "provenance":
        gate.profiles[r1.SANDBOX_CPU] = dataclasses.replace(
            gate.profiles[r1.SANDBOX_CPU], provenance={"cpu_limit_cores": "changed"}
        )
    elif change == "egress":
        gate.egress_policies["verify_exploit_remote"] = dataclasses.replace(
            gate.egress_policies["verify_exploit_remote"], protocol_allowance_bytes=2048
        )
    elif change == "ingress":
        from core.r1_bounds import INGRESS_POLICIES
        name = next(iter(INGRESS_POLICIES))
        monkeypatch.setitem(
            INGRESS_POLICIES, name,
            dataclasses.replace(INGRESS_POLICIES[name], ingress_cap_bytes=1),
        )
    elif change == "payload_cap":
        monkeypatch.setattr(r1, "MAX_TRAJECTORY_PAYLOAD_BYTES", 1)
    elif change == "volume_mount":
        gate.profiles[r1.PERSISTENCE] = dataclasses.replace(
            gate.profiles[r1.PERSISTENCE], mounts_volume=False
        )

    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_envelope_mismatch"
    assert fake.calls == []


def test_signed_envelope_is_required_even_for_legacy_signed_policy(signed_approval):
    """A valid legacy signature over StepPolicy alone is no longer sufficient."""
    policy = _policy()
    artifact = signed_approval(policy, include_dispatch_envelope=False)
    gate = r1_dispatch.DispatchGate(
        policy=policy, approval=artifact, autoscaler_reader=_reader(), **_approved_world()
    )
    fake = FakeProviderCallable()
    with pytest.raises(r1_dispatch.DispatchRefusal):
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert fake.calls == []



def test_non_finite_approval_payload_is_refused_before_provider(signed_approval):
    """NaN/Infinity cannot enter a canonical signed approval."""
    policy = _policy()
    world = _approved_world()
    gate = r1_dispatch.DispatchGate(
        policy=policy, autoscaler_reader=_reader(), **world
    )
    valid = signed_approval(policy, dispatch_envelope=gate.dispatch_envelope_payload())
    malformed_payload = dict(valid.payload)
    malformed_payload["unexpected_number"] = float("nan")
    malformed = type(valid)(payload=malformed_payload, signature=valid.signature)
    gate.approval = malformed
    fake = FakeProviderCallable()

    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", fake, {})
    assert excinfo.value.reason == "approval_not_verified"
    assert fake.calls == []
