"""The persistent monetary ledger of the R1 cycle.

The gate of ``benchmarks/r1_dispatch.py`` limits the **number** of dispatches in
the memory of one process. This suite is the proof that the **money** of the
cycle is limited across processes, threads, stages and restarts:

* the cap of 20.00 USD holds across the steps of the cycle;
* parallel threads cannot reserve more than the cap together;
* a step that never started gives its reservation back, a step that started
  keeps its charge - also when it failed;
* a retry cannot buy the same money twice; and
* a gate that is created anew - in this process or in another one - sees the
  money that was already spent.

Everything here is local: no test performs a provider call, a deployment, a
volume operation, a model download or a paid computation. The provider double
of the gate tests is a local object - it starts no container.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict

import pytest

from benchmarks import r1_dispatch
from core import r1_bounds as r1
from core.r1_budget_ledger import (
    DEFAULT_CAP_USD,
    LEDGER_CAP_ENV,
    LEDGER_PATH_ENV,
    MAX_CAP_USD,
    BudgetCapExceeded,
    BudgetLedger,
    ReservationStateError,
    is_billable_provider_object,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _ledger(tmp_path: Path, cap_usd: float = DEFAULT_CAP_USD) -> BudgetLedger:
    """A ledger of the test - its own file, its own cap."""
    return BudgetLedger(path=tmp_path / "r1_budget_ledger.sqlite3", cap_usd=cap_usd)


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


def _approved_world() -> Dict[str, Any]:
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
        "invocation_budgets": {r1.SANDBOX_CPU: 8, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        "concurrency_caps": {r1.SANDBOX_CPU: 1, r1.GPU_CLASS: 1, r1.PERSISTENCE: 1},
        "wall_clock_budget_sec": 1200.0,
        "post_execution_deadline_sec": 3600.0,
        "monetary_ceiling_usd": 5.0,
        "estimate_usd": 0.5,
        "approved_by": "test",
        "approved_at": "2026-11-15",
    }
    values.update(overrides)
    return r1_dispatch.StepPolicy(**values)


def _reader():
    """A read-only autoscaler reader double - no provider call, no mutation."""

    def reader(target, function_name=""):
        return {
            "min_containers": 0,
            "max_containers": 48,
            "buffer_containers": 0,
            "scaledown_window": 60,
        }

    return reader


def _reader_for(world):
    """A reader that reports the autoscaler settings the profiles declare.

    The read-back (D27) compares the effective settings of the provider with
    the declaration of the container class - so a test with more than one
    class needs a reader that answers per call site.
    """

    def reader(target, function_name=""):
        container_class = r1.FUNCTION_CLASS.get(function_name, "")
        profile = world["profiles"].get(container_class) or r1.profile_for(container_class)
        declared = r1.declared_autoscaler_settings(profile)
        return {
            "min_containers": declared["min_containers"],
            "max_containers": declared["max_containers"],
            "buffer_containers": declared["buffer_containers"],
            "scaledown_window": declared["scaledown_window"],
        }

    return reader


def _signed_approval(signed_approval, policy, world=None):
    """Sign the exact effective envelope used by the gate in this test."""
    options = dict(world or {})
    gate = r1_dispatch.DispatchGate(policy=policy, **options)
    return signed_approval(policy, dispatch_envelope=gate.dispatch_envelope_payload())


class ModalProviderDouble:
    """A provider double that the ledger charges.

    The ledger charges the objects that really start a container - the objects
    of the provider SDK. The double declares the provider's own module, so the
    gate treats it as a billable call: it starts no container and spends
    nothing, but the money of the step is reserved and charged.
    """

    __module__ = "modal"

    def __init__(self, error: Any = None) -> None:
        self.calls = []
        self.error = error

    def remote(self, *args, **kwargs):
        if self.error is not None:
            raise self.error
        self.calls.append((args, kwargs))
        return {"ok": True}


class LocalDouble:
    """A local double - it starts no container and costs nothing."""

    def __init__(self) -> None:
        self.calls = []

    def remote(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True}


def _install_double(monkeypatch, name: str, double: Any):
    """Install a double under a call-site name, reversibly."""
    monkeypatch.setitem(r1._INSTALLED_OBJECTS, name, double)
    r1.install_provider_guard(name, double)
    return double


# --------------------------------------------------------------------------------------
# the ledger itself
# --------------------------------------------------------------------------------------


def test_the_default_cap_is_the_twenty_dollar_cycle_cap():
    """The cap of the cycle is 20.00 USD - the cap of the cost scenario."""
    assert DEFAULT_CAP_USD == 20.0
    ledger = BudgetLedger(path=Path("ledger.sqlite3"))
    assert ledger.cap_usd == 20.0


def test_the_path_and_the_cap_are_overridable(tmp_path, monkeypatch):
    """The environment names the ledger file and the cap."""
    path = tmp_path / "from-env.sqlite3"
    monkeypatch.setenv(LEDGER_PATH_ENV, str(path))
    monkeypatch.setenv(LEDGER_CAP_ENV, "12.5")
    ledger = BudgetLedger()
    assert ledger.path == path
    assert ledger.cap_usd == 12.5


def test_a_cap_above_the_twenty_dollar_ceiling_is_refused(tmp_path):
    """The 20.00 USD of the cycle are a ceiling - the cap may not be raised."""
    assert MAX_CAP_USD == 20.0
    with pytest.raises(ValueError) as excinfo:
        BudgetLedger(path=tmp_path / "r1_budget_ledger.sqlite3", cap_usd=20.01)
    assert "20.0" in str(excinfo.value)


def test_a_cap_above_the_ceiling_is_refused_in_the_environment_too(tmp_path, monkeypatch):
    """The environment variable cannot raise the cap either."""
    monkeypatch.setenv(LEDGER_PATH_ENV, str(tmp_path / "from-env.sqlite3"))
    monkeypatch.setenv(LEDGER_CAP_ENV, "100")
    with pytest.raises(ValueError) as excinfo:
        BudgetLedger()
    assert "20.0" in str(excinfo.value)


def test_the_cap_may_be_lowered_but_never_raised(tmp_path, monkeypatch):
    """Lowering the cap is allowed - the ceiling itself is not exceeded."""
    lowered = BudgetLedger(path=tmp_path / "lowered.sqlite3", cap_usd=19.99)
    assert lowered.cap_usd == 19.99

    monkeypatch.setenv(LEDGER_CAP_ENV, "20")
    at_the_ceiling = BudgetLedger(path=tmp_path / "at-the-ceiling.sqlite3")
    assert at_the_ceiling.cap_usd == 20.0


def test_a_reservation_that_would_break_the_cap_is_refused(tmp_path):
    """The whole cap may be reserved - the next cent may not."""
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve("r1-cycle", "R4", 20.0)
    assert reservation.state == "reserved"

    with pytest.raises(BudgetCapExceeded) as excinfo:
        ledger.reserve("r1-cycle", "R4", 0.01)
    assert excinfo.value.reason == "budget_cap_exceeded"
    assert excinfo.value.cap_usd == 20.0
    assert excinfo.value.requested_usd == 0.01

    # The refused reservation reserved nothing.
    state = ledger.state()
    assert state.reserved_usd == 20.0
    assert state.spent_usd == 0.0
    assert state.available_usd == 0.0


def test_the_steps_of_the_cycle_share_one_cap(tmp_path):
    """R2p, R3, R3b and R4 draw from the same 20.00 USD - the ceilings of the scenario."""
    ledger = _ledger(tmp_path)
    ledger.reserve("r1-cycle", "R2p", 5.0)
    ledger.reserve("r1-cycle", "R3", 0.1)
    ledger.reserve("r1-cycle", "R3b", 0.75)
    ledger.reserve("r1-cycle", "R4", 13.5)

    state = ledger.state()
    assert state.reserved_usd == pytest.approx(19.35)
    assert state.available_usd == pytest.approx(0.65)

    with pytest.raises(BudgetCapExceeded):
        ledger.reserve("r1-cycle", "R4", 0.66)


def test_a_second_stage_cannot_bypass_the_cap(tmp_path):
    """A different run and a different step draw from the same ledger."""
    ledger = _ledger(tmp_path)
    ledger.reserve("r1-cycle", "R4", 13.5)

    # The same money under another name is the same money.
    with pytest.raises(BudgetCapExceeded):
        ledger.reserve("r1-cycle-next", "R4", 13.5)
    with pytest.raises(BudgetCapExceeded):
        ledger.reserve("r1-cycle", "R5", 6.6)


def test_parallel_threads_cannot_reserve_more_than_the_cap(tmp_path):
    """Sixteen threads reserve together: the cap holds."""
    ledger = _ledger(tmp_path)

    def attempt(index: int) -> bool:
        try:
            ledger.reserve("r1-cycle", f"R4-{index}", 2.0)
        except BudgetCapExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))

    granted = sum(1 for ok in results if ok)
    state = ledger.state()
    assert granted == 10
    assert state.reserved_usd == pytest.approx(20.0)
    assert state.available_usd == pytest.approx(0.0)


def test_a_release_gives_the_money_back(tmp_path):
    """A step that never started returns its reservation."""
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve("r1-cycle", "R3", 5.0)
    assert ledger.state().reserved_usd == pytest.approx(5.0)

    ledger.release(reservation.reservation_id)

    state = ledger.state()
    assert state.reserved_usd == pytest.approx(0.0)
    assert state.spent_usd == pytest.approx(0.0)
    # The whole cap is available again.
    ledger.reserve("r1-cycle", "R3", 20.0)


def test_a_commit_charges_the_reservation(tmp_path):
    """A step that ran is charged: the reservation becomes the spend."""
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve("r1-cycle", "R3", 5.0)
    ledger.commit(reservation.reservation_id, 4.25)

    state = ledger.state()
    assert state.spent_usd == pytest.approx(4.25)
    assert state.reserved_usd == pytest.approx(0.0)
    assert state.available_usd == pytest.approx(15.75)


def test_a_committed_reservation_is_never_given_back(tmp_path):
    """The money of a step that ran is never returned to the cycle."""
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve("r1-cycle", "R3", 5.0)
    ledger.commit(reservation.reservation_id, 5.0)

    with pytest.raises(ReservationStateError):
        ledger.release(reservation.reservation_id)

    assert ledger.state().spent_usd == pytest.approx(5.0)


def test_a_reservation_is_refused_when_it_costs_more_than_the_whole_cap(tmp_path):
    """A step that is more expensive than the cycle is refused before it is written."""
    ledger = _ledger(tmp_path)
    with pytest.raises(BudgetCapExceeded):
        ledger.reserve("r1-cycle", "R4", 20.01)
    assert ledger.state().reserved_usd == pytest.approx(0.0)


def test_the_money_survives_the_process(tmp_path):
    """Another process reads the same ledger and sees the same money."""
    path = tmp_path / "r1_budget_ledger.sqlite3"
    ledger = BudgetLedger(path=path, cap_usd=20.0)
    reservation = ledger.reserve("r1-cycle", "R3", 0.5)
    ledger.commit(reservation.reservation_id, 0.5)

    script = (
        "import json, sys;"
        "from core.r1_budget_ledger import BudgetLedger;"
        "ledger = BudgetLedger(path=sys.argv[1], cap_usd=20.0);"
        "print(json.dumps(ledger.state().to_record()))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    state = json.loads(completed.stdout.strip().splitlines()[-1])
    assert state["spent_usd"] == pytest.approx(0.5)
    assert state["reserved_usd"] == pytest.approx(0.0)
    assert state["available_usd"] == pytest.approx(19.5)


def test_the_ledger_holds_no_key_and_approves_nothing():
    """The ledger is a money control - it holds no key and authorises nothing."""
    source = (REPO_ROOT / "core" / "r1_budget_ledger.py").read_text(encoding="utf-8")
    for forbidden in ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "PRIVATE_EXPONENT", "modulus"):
        assert forbidden not in source

    # The approval of a step stays in core/r1_approval.py. The repository pins
    # the **public** half of the approval authority's key pair - a public key is
    # not a secret and cannot sign anything - and the private half never enters
    # the repository. No approval artifact exists here, so nothing is approved.
    from core import r1_approval

    assert r1_approval.PINNED_PUBLIC_KEY is not None
    modulus, exponent = r1_approval.PINNED_PUBLIC_KEY
    assert exponent == 65537
    assert r1_approval.pinned_public_key() == (modulus, exponent)

    # The pin is the public half only: the private exponent is nowhere.
    approval_source = (REPO_ROOT / "core" / "r1_approval.py").read_text(encoding="utf-8")
    for forbidden in ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "PRIVATE_EXPONENT"):
        assert forbidden not in approval_source
    key_file = REPO_ROOT / "benchmarks" / "evidence" / "r1_approval_key.json"
    recorded = json.loads(key_file.read_text(encoding="utf-8"))["public_key"]
    assert int(recorded["e"]) == exponent
    assert r1_approval._decode_modulus(str(recorded["n"])) == modulus


# --------------------------------------------------------------------------------------
# the gate and the ledger
# --------------------------------------------------------------------------------------


def test_a_local_double_is_not_charged(tmp_path):
    """A local double starts no container and costs nothing."""
    assert is_billable_provider_object(LocalDouble()) is False
    assert is_billable_provider_object(ModalProviderDouble()) is True


def test_a_provider_dispatch_is_charged_by_the_ledger(monkeypatch, signed_approval, tmp_path):
    """The money of the step is reserved before the provider starts and charged after."""
    world = _approved_world()
    double = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())
    policy = _policy()
    ledger = _ledger(tmp_path)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        result = gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})

    assert result == {"ok": True}
    assert len(double.calls) == 1
    state = ledger.state()
    assert state.spent_usd == pytest.approx(0.5)
    assert state.reserved_usd == pytest.approx(0.0)


def test_a_provider_dispatch_without_a_ledger_is_refused(monkeypatch, signed_approval):
    """The money of a real container is never spent outside the ledger."""
    world = _approved_world()
    double = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())
    policy = _policy()

    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        **world,
    )
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})

    assert excinfo.value.reason == "budget_ledger_missing"
    assert double.calls == []


def test_a_dispatch_is_refused_when_the_cap_is_exhausted(monkeypatch, signed_approval, tmp_path):
    """The next step is refused when the cap of the cycle is used up."""
    world = _approved_world()
    double = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())
    policy = _policy()
    ledger = _ledger(tmp_path, cap_usd=0.5)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})
        with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 2})

    assert excinfo.value.reason == "budget_cap_exceeded"
    assert len(double.calls) == 1
    assert ledger.state().spent_usd == pytest.approx(0.5)


# --------------------------------------------------------------------------------------
# a step with many invocations
# --------------------------------------------------------------------------------------


#: The estimate of R4 - the cost of the **whole** step, as the estimator
#: computes it from the invocation counts of the scenario.
R4_ESTIMATE_USD = 12.9878

#: The money the pilot spent before R4.
PILOT_SPENT_USD = 3.828384


def _r4_policy() -> r1_dispatch.StepPolicy:
    """The policy of R4: 48 sandbox + 32 GPU + 16 persistence invocations."""
    return _policy(
        step_id="R4",
        invocation_budgets={r1.SANDBOX_CPU: 48, r1.GPU_CLASS: 32, r1.PERSISTENCE: 16},
        concurrency_caps={r1.SANDBOX_CPU: 48, r1.GPU_CLASS: 32, r1.PERSISTENCE: 16},
        monetary_ceiling_usd=R4_ESTIMATE_USD,
        estimate_usd=R4_ESTIMATE_USD,
    )


def test_the_estimate_of_a_step_covers_all_its_invocations(monkeypatch, signed_approval, tmp_path):
    """R4 makes ninety-six invocations - and costs its estimate **once**.

    The signed estimate is the cost of the **step**, not of a call: the
    estimator computes it from the invocation counts of the scenario. R4
    (12.9878 USD, 48 sandbox + 32 GPU + 16 persistence invocations) therefore
    fits into the money the cycle has left - even with the 3.83 USD the pilot
    spent before it - and the money of the cycle stays the money of the
    **steps**, not of the ninety-six calls.
    """
    world = _approved_world()
    ledger = _ledger(tmp_path)  # the cap of the cycle: 20.00 USD

    # The pilot spent 3.83 USD before R4.
    spent = ledger.reserve("r1-pilot", "R3b", PILOT_SPENT_USD)
    ledger.commit(spent.reservation_id, PILOT_SPENT_USD)

    policy = _r4_policy()
    sandbox = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())
    gpu = _install_double(
        monkeypatch, "ProductionAuditAgent.generate_solidity_exploit", ModalProviderDouble()
    )
    persistence = _install_double(monkeypatch, "record_trajectory_remote", ModalProviderDouble())

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader_for(world),
        budget_ledger=ledger,
        budget_run_id="r1-pilot",
        **world,
    ) as gate:
        for _ in range(48):
            gate.dispatch(
                r1.SANDBOX_CPU,
                "verify_exploit_remote",
                r1.GuardedRemote(sandbox, "verify_exploit_remote"),
                {"a": 1},
            )
        for _ in range(32):
            gate.dispatch(
                r1.GPU_CLASS,
                "ProductionAuditAgent.generate_solidity_exploit",
                r1.GuardedRemote(gpu, "ProductionAuditAgent.generate_solidity_exploit"),
                {"a": 1},
            )
        for _ in range(16):
            gate.dispatch(
                r1.PERSISTENCE,
                "record_trajectory_remote",
                r1.GuardedRemote(persistence, "record_trajectory_remote"),
                {"trajectory_id": "t", "candidate": {}},
            )

    # Ninety-six invocations, one estimate.
    assert len(sandbox.calls) == 48
    assert len(gpu.calls) == 32
    assert len(persistence.calls) == 16
    state = ledger.state()
    assert state.spent_usd == pytest.approx(PILOT_SPENT_USD + R4_ESTIMATE_USD)
    assert state.reserved_usd == pytest.approx(0.0)
    assert state.spent_usd <= state.cap_usd

    # The estimate of the step was reserved **once**, not ninety-six times.
    rows = [row for row in ledger.reservations() if row.step_id == "R4"]
    assert len(rows) == 1
    assert rows[0].max_cost_usd == pytest.approx(R4_ESTIMATE_USD)
    assert rows[0].state == "committed"


def test_another_run_of_the_step_is_refused_when_the_cap_does_not_fit(monkeypatch, signed_approval, tmp_path):
    """The estimate of a step is reserved once **per run**: a second run pays again.

    A new ``budget_run_id`` is a new attempt of the step, so it reserves the
    estimate again - and the cap of the cycle refuses it when the two do not
    fit. The protection against a repeated run is not weakened by the change.
    """
    world = _approved_world()
    ledger = _ledger(tmp_path)

    spent = ledger.reserve("r1-pilot", "R3b", PILOT_SPENT_USD)
    ledger.commit(spent.reservation_id, PILOT_SPENT_USD)

    policy = _r4_policy()
    sandbox = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader_for(world),
        budget_ledger=ledger,
        budget_run_id="r1-pilot",
        **world,
    ) as gate:
        gate.dispatch(
            r1.SANDBOX_CPU,
            "verify_exploit_remote",
            r1.GuardedRemote(sandbox, "verify_exploit_remote"),
            {"a": 1},
        )

    # The same step, another run: the estimate is reserved again.
    again = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader_for(world),
        budget_ledger=ledger,
        budget_run_id="r1-pilot-next",
        **world,
    )
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        again.dispatch(
            r1.SANDBOX_CPU,
            "verify_exploit_remote",
            r1.GuardedRemote(sandbox, "verify_exploit_remote"),
            {"a": 2},
        )

    assert excinfo.value.reason == "budget_cap_exceeded"
    assert ledger.state().spent_usd == pytest.approx(PILOT_SPENT_USD + R4_ESTIMATE_USD)
    assert len(sandbox.calls) == 1


def test_a_failed_invocation_makes_the_next_one_pay_again(monkeypatch, signed_approval, tmp_path):
    """A failed attempt of a step is charged - and its retry reserves again."""
    world = _approved_world()
    double = _install_double(
        monkeypatch, "verify_exploit_remote", ModalProviderDouble(error=RuntimeError("the container died"))
    )
    policy = _policy()
    ledger = _ledger(tmp_path, cap_usd=0.75)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        with pytest.raises(RuntimeError):
            gate.dispatch(
                r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1}
            )
        # The failed attempt is charged; the retry reserves the estimate again.
        with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
            gate.dispatch(
                r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 2}
            )

    assert excinfo.value.reason == "budget_cap_exceeded"
    assert ledger.state().spent_usd == pytest.approx(0.5)


def test_a_refusal_before_the_provider_starts_releases_the_reservation(
    monkeypatch, signed_approval, tmp_path
):
    """A provider call that never started gives its reservation back."""
    world = _approved_world()
    refusal = r1_dispatch.DispatchRefusal("provider_refused", "the provider refused")
    double = _install_double(
        monkeypatch, "verify_exploit_remote", ModalProviderDouble(error=refusal)
    )
    policy = _policy()
    ledger = _ledger(tmp_path)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        with pytest.raises(r1_dispatch.DispatchRefusal):
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})

    state = ledger.state()
    assert state.reserved_usd == pytest.approx(0.0)
    assert state.spent_usd == pytest.approx(0.0)


def test_a_failed_step_keeps_its_charge(monkeypatch, signed_approval, tmp_path):
    """A container that started and failed keeps the money: it is never reset to zero."""
    world = _approved_world()
    double = _install_double(
        monkeypatch, "verify_exploit_remote", ModalProviderDouble(error=RuntimeError("the container died"))
    )
    policy = _policy()
    ledger = _ledger(tmp_path)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        with pytest.raises(RuntimeError):
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})

    state = ledger.state()
    assert state.spent_usd == pytest.approx(0.5)
    assert state.reserved_usd == pytest.approx(0.0)


def test_a_retry_does_not_bypass_the_cap(monkeypatch, signed_approval, tmp_path):
    """The retry of a failed step pays again - the cap is not a one-off budget."""
    world = _approved_world()
    double = _install_double(
        monkeypatch, "verify_exploit_remote", ModalProviderDouble(error=RuntimeError("the container died"))
    )
    policy = _policy()
    ledger = _ledger(tmp_path, cap_usd=0.75)

    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=ledger,
        **world,
    ) as gate:
        with pytest.raises(RuntimeError):
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})
        # The failed step is charged 0.5: the retry would need another 0.5 and
        # only 0.25 are left.
        with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
            gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 2})

    assert excinfo.value.reason == "budget_cap_exceeded"
    assert ledger.state().spent_usd == pytest.approx(0.5)


def test_a_recreated_gate_sees_the_spent_budget(monkeypatch, signed_approval, tmp_path):
    """A gate that is created anew sees the money that was already spent."""
    world = _approved_world()
    double = _install_double(monkeypatch, "verify_exploit_remote", ModalProviderDouble())
    policy = _policy()
    path = tmp_path / "r1_budget_ledger.sqlite3"

    first = BudgetLedger(path=path, cap_usd=0.5)
    with r1_dispatch.authorised_step(
        policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=first,
        **world,
    ) as gate:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 1})

    # A new gate, a new ledger object, the same file on disk.
    second = BudgetLedger(path=path, cap_usd=0.5)
    gate = r1_dispatch.DispatchGate(
        policy=policy,
        approval=_signed_approval(signed_approval, policy, world),
        autoscaler_reader=_reader(),
        budget_ledger=second,
        **world,
    )
    assert gate.budget_state().spent_usd == pytest.approx(0.5)
    with pytest.raises(r1_dispatch.DispatchRefusal) as excinfo:
        gate.dispatch(r1.SANDBOX_CPU, "verify_exploit_remote", r1.GuardedRemote(double, "verify_exploit_remote"), {"a": 2})

    assert excinfo.value.reason == "budget_cap_exceeded"
    assert len(double.calls) == 1
