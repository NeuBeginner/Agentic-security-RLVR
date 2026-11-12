"""The R1 cost model: one accounting model, one command, one status.

The estimator is the single source of the numbers of the cost proposal. These
tests pin the model itself:

* the storage inside the provider's 1 TiB/month allowance costs **USD 0**, and
  the footprint is computed and reported in every run;
* the storage above the allowance is billed and flagged;
* the per-stage worst case is reconciled with the per-stage ceiling;
* the cycle's worst case, the headroom under the cap and the verdict follow;
* everything stays ``PROVISIONAL_ONLY / NOT_DISPATCHABLE``.

Nothing here performs a provider call.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks import r1_estimator
from core import r1_bounds as r1

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_PATH = REPO_ROOT / "benchmarks" / "evidence" / "r1_cost_scenario.json"
RATE_CARD_PATH = REPO_ROOT / "benchmarks" / "evidence" / "r1_rate_card.json"

#: The one authoritative command of the cost proposal.
AUTHORITATIVE_COMMAND = [
    sys.executable,
    "-m",
    "benchmarks.r1_estimator",
    "--scenario",
    "benchmarks/evidence/r1_cost_scenario.json",
    "--provisional",
]


def _rate_card() -> r1_estimator.RateCard:
    return r1_estimator.RateCard.from_file(str(RATE_CARD_PATH))


def _approved_rate_card() -> r1_estimator.RateCard:
    """The same rates, with an approval - for the arithmetic of the model."""
    card = _rate_card()
    return dataclasses.replace(card, approved_by="test")


def _scenario() -> dict:
    return json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))


def _run() -> dict:
    return r1_estimator.run_scenario(_scenario(), _rate_card(), allow_unapproved_rate_card=True)


# --------------------------------------------------------------------------------------
# the storage (D28)
# --------------------------------------------------------------------------------------


def test_the_storage_inside_the_free_allowance_costs_nothing():
    result = _run()
    storage = result["aggregate"]["storage"]
    assert storage["within_free_allowance"] is True
    assert storage["billable_gib_months"] == 0.0
    assert storage["storage_usd"] == 0.0
    # The footprint is still computed and reported.
    assert storage["peak_footprint_gib"] > 0
    assert storage["time_weighted_footprint_gib"] > 0
    assert storage["footprint_gib_months"] > 0


def test_the_footprint_of_the_cycle_is_the_model_cache_plus_the_trajectories():
    result = _run()
    storage = result["aggregate"]["storage"]
    # The pinned model is 56.888 GiB; the trajectories of the whole cycle add
    # 0.021 GiB. The peak is the footprint at the end of the cycle.
    assert storage["peak_footprint_gib"] == pytest.approx(56.909, abs=0.01)
    assert storage["time_weighted_footprint_gib"] == pytest.approx(56.90, abs=0.05)


def test_the_storage_above_the_allowance_is_billed_and_flagged():
    """A footprint above 1 TiB is not free any more - and it is flagged."""
    world = _approved_world()
    step = r1_estimator.StepInputs(
        step_id="BIG",
        invocations={r1.SANDBOX_CPU: 1},
        concurrency_caps={r1.SANDBOX_CPU: 1},
        baseline_gib=2048.0,
        incremental_gib=0.0,
        t_exec_sec=3600.0,
        t_post_exec_to_publication_sec=3600.0,
    )
    estimate = r1_estimator.estimate_step(
        step,
        _approved_rate_card(),
        world["profiles"],
        world["egress_policies"],
        allow_unapproved_rate_card=True,
    )
    assert estimate.available, estimate.unavailable_reasons
    aggregate = r1_estimator.aggregate_cycle(
        [estimate], _approved_rate_card(), cycle_cap_usd=20.0
    )
    storage = aggregate["storage"]
    assert storage["within_free_allowance"] is False
    assert storage["billable_gib_months"] > 0
    assert storage["storage_usd"] > 0
    assert aggregate["verdict"] == r1_estimator.VERDICT_INFEASIBLE


def test_the_allowance_is_applied_once_and_not_per_stage():
    """The same standing bytes are not priced once per stage."""
    result = _run()
    steps = result["steps"]
    assert len(steps) == 4
    assert all(float(step["terms_usd"]["volume_storage"]) == 0.0 for step in steps)
    # The sum of the per-stage totals is exactly the cycle total.
    assert sum(float(step["total_usd"]) for step in steps) == pytest.approx(
        result["aggregate"]["total_usd"]
    )


def test_the_rate_card_no_longer_deliberately_nets_the_allowance_out():
    card = json.loads(RATE_CARD_PATH.read_text(encoding="utf-8"))
    notes = " ".join(card["notes"])
    assert "NOT netted out" not in notes
    assert card["storage_free_allowance_gib_per_month"] == 1024
    assert card["approved_by"] is None


# --------------------------------------------------------------------------------------
# the per-stage and the aggregate budget
# --------------------------------------------------------------------------------------


def test_every_stage_is_reconciled_with_its_ceiling():
    result = _run()
    for step in result["steps"]:
        assert step["ceiling_usd"] is not None, step["step_id"]
        assert step["within_ceiling"] is True, step["step_id"]
        assert step["headroom_usd"] == pytest.approx(
            float(step["ceiling_usd"]) - float(step["total_usd"])
        )


def test_the_cycle_fits_the_cap_with_a_positive_headroom():
    result = _run()
    aggregate = result["aggregate"]
    assert aggregate["verdict"] == r1_estimator.VERDICT_WITHIN_BUDGET
    assert aggregate["within_cap"] is True
    assert aggregate["total_usd"] == pytest.approx(18.20, abs=0.02)
    assert aggregate["headroom_usd"] == pytest.approx(1.80, abs=0.02)


def test_a_cycle_that_does_not_fit_is_reported_as_exactly_budget_infeasible():
    scenario = _scenario()
    scenario["cycle_cap_usd"] = 1.0
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    assert result["verdict"] == "BUDGET_INFEASIBLE"
    assert result["aggregate"]["within_cap"] is False
    assert result["aggregate"]["headroom_usd"] < 0


def test_every_result_is_provisional_and_not_dispatchable():
    result = _run()
    assert result["status"] == "PROVISIONAL_ONLY / NOT_DISPATCHABLE"
    assert result["aggregate"]["status"] == "PROVISIONAL_ONLY / NOT_DISPATCHABLE"
    # The rate card of the repository is not approved: the estimate is a proposal.
    assert _rate_card().is_approved() is False


def test_the_estimate_is_unavailable_without_an_approved_rate_card():
    result = r1_estimator.run_scenario(_scenario(), _rate_card(), allow_unapproved_rate_card=False)
    assert result["verdict"] == r1_estimator.VERDICT_UNAVAILABLE
    assert result["aggregate"]["unavailable_reasons"]


# --------------------------------------------------------------------------------------
# the one authoritative command
# --------------------------------------------------------------------------------------


def test_the_authoritative_command_reproduces_the_numbers():
    completed = subprocess.run(
        AUTHORITATIVE_COMMAND,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout
    assert "PROVISIONAL_ONLY / NOT_DISPATCHABLE" in output
    assert "WITHIN_BUDGET" in output
    assert "worst_case=$18.2000" in output
    assert "cap=$20.00" in output
    assert "headroom=$1.8000" in output
    # The storage of the cycle is free - inside the 1 TiB/month allowance - and
    # its footprint is reported.
    assert "storage: peak=56.908 GiB" in output
    assert "billable=0.00 GiB-month" in output
    for step_id in ("R2p", "R3", "R3b", "R4"):
        assert step_id in output


def test_the_authoritative_command_is_reproducible():
    first = subprocess.run(
        AUTHORITATIVE_COMMAND,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    second = subprocess.run(
        AUTHORITATIVE_COMMAND,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert first.stdout == second.stdout
    assert first.returncode == second.returncode == 0


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _approved_world() -> dict:
    def approved(base: r1.ResourceProfile, **overrides) -> r1.ResourceProfile:
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

    egress = {
        name: dataclasses.replace(policy, payload_cap_bytes=0, protocol_allowance_bytes=1024 * 1024)
        for name, policy in r1.EGRESS_POLICIES.items()
    }
    return {
        "profiles": {
            r1.SANDBOX_CPU: approved(r1.SANDBOX_CPU_PROFILE),
            r1.GPU_CLASS: approved(r1.GPU_PROFILE),
            r1.PERSISTENCE: approved(r1.PERSISTENCE_PROFILE),
        },
        "egress_policies": egress,
    }
