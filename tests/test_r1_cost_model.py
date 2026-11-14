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


def test_the_storage_baseline_is_the_measured_one_and_is_labelled_as_measured():
    """The baseline is measured: the proof of the capacity is available."""
    result = _run()
    storage = result["aggregate"]["storage"]
    assert storage["baseline_status"] == "MEASURED"
    assert storage["incremental_status"] == "CANDIDATE_ESTIMATE"
    assert storage["capacity_proof"] == "UNAVAILABLE"
    assert storage["capacity_proof_reasons"]
    assert storage["capacity_proof_missing_evidence"] == []
    # The cost of the storage is still USD 0 - the footprint stays inside the
    # allowance - and the proof that the cycle fits the account is now claimed.
    assert storage["storage_usd"] == 0.0
    assert result["aggregate"]["storage_capacity_proof"] == "UNAVAILABLE"
    assert result["aggregate"]["storage_capacity_proof_missing_evidence"] == []
    assert result["aggregate"]["storage_baseline_status"] == "MEASURED"
    assert result["aggregate"]["storage_incremental_status"] == "CANDIDATE_ESTIMATE"


def test_the_open_sub_items_of_the_capacity_proof_are_explicitly_enumerated():
    """Open sub-items keep the capacity proof unavailable and are enumerated."""
    scenario = _scenario()
    residuals = scenario["storage_baseline"]["capacity_proof_residuals"]
    assert isinstance(residuals, list) and len(residuals) == 3
    joined = " ".join(residuals)
    assert "concurrent storage peak" in joined
    assert "model-cache manifest" in joined
    assert "trajectory" in joined
    result = _run()
    assert result["aggregate"]["storage_capacity_proof_residuals"] == residuals
    assert result["aggregate"]["storage"]["capacity_proof"] == "UNAVAILABLE"
    assert result["aggregate"]["storage"]["capacity_proof_missing_evidence"] == []


def test_the_scenario_separates_the_measured_baseline_from_the_candidates():
    scenario = _scenario()
    baseline = scenario["storage_baseline"]
    assert baseline["status"] == "MEASURED"
    assert baseline["capacity_proof"] == "UNAVAILABLE"
    # The volume baseline is the byte-exact measurement of 2026-11-14 ...
    assert baseline["measured_bytes"] == 64349622024
    assert baseline["measured_gib"] == pytest.approx(59.930256)
    # ... the measured local bytes are a separate measurement ...
    assert baseline["measured_local_repository_bytes"] > 0
    # ... and the future run's bytes are a candidate.
    assert baseline["candidate_future_run_gib"] > 0
    # Every step declares the state of its own increment.
    for step in scenario["steps"]:
        assert step.get("incremental_status") in {"CANDIDATE_ESTIMATE", "NO_INCREMENT"}
        assert step.get("incremental_reason", "").strip()


def test_the_footprint_of_the_cycle_starts_at_the_measured_baseline():
    result = _run()
    storage = result["aggregate"]["storage"]
    # The cycle starts from the MEASURED baseline of the Volume (59.930256 GiB),
    # not from an assumed zero; the conservative prefetch worst case (the pinned
    # cache) is added on top of it.
    assert storage["peak_footprint_gib"] == pytest.approx(116.839, abs=0.001)
    assert storage["time_weighted_footprint_gib"] == pytest.approx(116.837, abs=0.01)
    # The footprint still stays inside the free allowance, so the money did not move.
    assert storage["within_free_allowance"] is True
    assert storage["storage_usd"] == 0.0


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
# the measured baseline (the read-only inventory of 2026-11-14)
# --------------------------------------------------------------------------------------


def test_the_baseline_of_the_cycle_is_the_measured_inventory_of_2026_11_14():
    """The baseline is the measurement - not a zero placeholder."""
    evidence = json.loads(
        (
            REPO_ROOT
            / "benchmarks"
            / "evidence"
            / "r1_readonly_evidence_20261114.json"
        ).read_text(encoding="utf-8")
    )
    totals = evidence["deliverable_1_storage_baseline_and_capacity"]["totals"]
    assert totals["total_bytes"] == 64349622024

    scenario = _scenario()
    assert scenario["storage_baseline"]["measured_bytes"] == totals["total_bytes"]
    assert scenario["storage_baseline"]["measured_gib"] == pytest.approx(totals["total_gib"])
    # The cycle starts from that measurement.
    assert scenario["baseline_gib"] == pytest.approx(totals["total_gib"])
    assert scenario["baseline_gib"] > 0

    result = _run()
    first = next(step for step in result["steps"] if step["step_id"] == "R2p")
    volume = first["quantities"]["volume"]
    assert volume["baseline_gib"] == pytest.approx(totals["total_gib"])
    assert volume["baseline_status"] == "MEASURED"


def test_every_step_starts_from_the_footprint_the_previous_step_left_behind():
    """The baseline of a step is the footprint of the step before it."""
    result = _run()
    carried = _scenario()["baseline_gib"]
    for step in result["steps"]:
        volume = step["quantities"]["volume"]
        assert volume["baseline_gib"] == pytest.approx(carried, abs=1e-9)
        carried = volume["volume_gib"]


def test_a_declared_baseline_that_contradicts_the_timeline_fails_closed():
    """A step that declares a baseline which is not the carried-over one is refused."""
    scenario = _scenario()
    scenario["steps"][1]["baseline_gib"] = 1.0
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    r3 = next(step for step in result["steps"] if step["step_id"] == "R3")
    assert r3["available"] is False
    assert any(
        "does not match the footprint carried over" in reason
        for reason in r3["unavailable_reasons"]
    )
    assert result["verdict"] == r1_estimator.VERDICT_UNAVAILABLE


def test_the_measured_baseline_is_verified_against_its_evidence_file():
    """A baseline that is not the measured one never becomes an estimate."""
    # 1. a byte total that the inventory does not carry
    scenario = _scenario()
    scenario["storage_baseline"]["measured_bytes"] = 1
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    first = result["steps"][0]
    assert first["available"] is False
    assert any(
        "does not match its evidence file" in reason
        for reason in first["unavailable_reasons"]
    )

    # 2. an evidence file that does not exist
    scenario = _scenario()
    scenario["storage_baseline"]["evidence_file"] = (
        "benchmarks/evidence/r1_no_such_evidence.json"
    )
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    first = result["steps"][0]
    assert first["available"] is False
    assert any(
        "evidence file of the measured baseline is missing" in reason
        for reason in first["unavailable_reasons"]
    )

    # 3. a zero placeholder instead of the measurement
    scenario = _scenario()
    scenario["storage_baseline"]["measured_bytes"] = 0
    scenario["storage_baseline"]["measured_gib"] = 0.0
    scenario["baseline_gib"] = 0.0
    for step in scenario["steps"]:
        step["baseline_gib"] = 0.0
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    first = result["steps"][0]
    assert first["available"] is False
    assert any(
        "does not match its evidence file" in reason
        for reason in first["unavailable_reasons"]
    )


def test_a_cycle_without_a_starting_footprint_is_not_estimated_from_zero():
    scenario = _scenario()
    scenario.pop("baseline_gib")
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    first = result["steps"][0]
    assert first["available"] is False
    assert any(
        "starting footprint" in reason for reason in first["unavailable_reasons"]
    )


def test_the_measured_baseline_evidence_is_reported_with_its_provenance():
    result = _run()
    evidence = result["aggregate"]["storage"]["baseline_evidence"]
    assert evidence["status"] == "MEASURED"
    assert evidence["measured_bytes"] == 64349622024
    assert evidence["measured_gib"] == pytest.approx(59.930256)
    assert evidence["volume"] == "aegis-model-cache"
    assert "r1_readonly_evidence_20261114.json" in evidence["provenance"]
    assert evidence["measured_at"]


def test_a_scenario_without_a_measured_baseline_keeps_the_capacity_proof_unavailable():
    """The proof follows the state of the baseline - it is not a constant."""
    scenario = _scenario()
    scenario["storage_baseline"]["status"] = "UNKNOWN"
    scenario["storage_baseline"]["capacity_proof_missing_evidence"] = []
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    storage = result["aggregate"]["storage"]
    assert storage["capacity_proof"] == "UNAVAILABLE"
    assert storage["capacity_proof_reasons"]
    # Without a measured baseline the default list of missing evidence is used.
    assert len(storage["capacity_proof_missing_evidence"]) == 4


def test_the_capacity_proof_is_unavailable_when_the_footprint_exceeds_the_allowance():
    """A footprint above the allowance is not a proof that the cycle fits."""
    segment = {
        "step_id": "BIG",
        "kind": "stage",
        "duration_sec": 3600.0,
        "footprint_gib": 2048.0,
        "baseline_status": "MEASURED",
        "baseline_reason": "",
        "incremental_status": "CANDIDATE_ESTIMATE",
        "incremental_reason": "",
    }
    storage = r1_estimator.storage_account([segment], _approved_rate_card())
    assert storage["capacity_proof"] == "UNAVAILABLE"
    assert any(
        "exceeds the free allowance" in reason
        for reason in storage["capacity_proof_reasons"]
    )


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
    assert aggregate["total_usd"] == pytest.approx(13.65, abs=0.02)
    assert aggregate["headroom_usd"] == pytest.approx(6.35, abs=0.02)


# --------------------------------------------------------------------------------------
# the ingress is not the egress (D29)
# --------------------------------------------------------------------------------------


def test_the_model_download_is_ingress_and_is_not_charged_at_the_egress_rate():
    """The 122 GB model download is inbound traffic, not outbound egress."""
    result = _run()
    r2p = next(step for step in result["steps"] if step["step_id"] == "R2p")
    terms = r2p["terms_usd"]
    # The egress term is the protocol allowance of one container - nothing else.
    assert terms["egress_sandbox_cpu"] == pytest.approx(
        (1024 * 1024) / (1024 ** 3) * 0.04
    )
    # The ingress term exists and is zero: ingress is not billed as egress.
    assert terms["ingress_sandbox_cpu"] == 0.0


def test_the_ingress_bytes_are_bounded_and_reported():
    result = _run()
    quantities = result["steps"][0]["quantities"]["sandbox_cpu"]
    # The inbound bytes of the prefetch are bounded and reported ...
    assert quantities["ingress_bytes"] == 122155995204
    assert quantities["ingress_cap_bytes"] == 122155995204
    assert quantities["ingress_complete"] is True
    # ... and they are never billed as egress.
    assert quantities["ingress_is_billed_as_egress"] is False
    # The outbound bytes of the same container are the protocol allowance only.
    assert quantities["egress_bytes"] == 1024 * 1024

    scenario = _scenario()
    ingress = scenario["steps"][0]["candidate_ingress"]["prefetch_model_cache_remote"]
    assert ingress["ingress_cap_bytes"] == 122155995204
    # The declared ingress policy of the prefetch is required-but-unset.
    assert r1.is_unset(
        r1.INGRESS_POLICIES["prefetch_model_cache_remote"].ingress_cap_bytes
    )


def test_only_the_prefetch_step_carries_the_ingress():
    """The model download belongs to R2p - no other stage downloads anything."""
    result = _run()
    for step in result["steps"]:
        quantities = step["quantities"]
        for container_class, values in quantities.items():
            if not isinstance(values, dict):
                continue
            ingress = values.get("ingress_bytes")
            if ingress is None:
                continue
            if step["step_id"] == "R2p":
                assert ingress == 122155995204
            else:
                assert ingress == 0


def test_the_rate_card_states_the_ingress_rate_and_its_source():
    card = json.loads(RATE_CARD_PATH.read_text(encoding="utf-8"))
    assert card["ingress_per_gib"] == 0.0
    assert "network-egress-billing" in card["ingress_source"]
    assert card["approved_by"] is None


def test_a_step_that_dispatches_a_function_with_an_ingress_bound_must_declare_it():
    """A dispatched function with an ingress declaration has to declare it."""
    scenario = _scenario()
    scenario["steps"][0].pop("ingress_functions")
    result = r1_estimator.run_scenario(
        scenario, _rate_card(), allow_unapproved_rate_card=True
    )
    r2p = next(step for step in result["steps"] if step["step_id"] == "R2p")
    assert r2p["available"] is False
    assert any("ingress bound" in reason for reason in r2p["unavailable_reasons"])


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
    assert "worst_case=$13.6493" in output
    assert "cap=$20.00" in output
    assert "headroom=$6.3507" in output
    # The storage of the cycle is free - inside the 1 TiB/month allowance - and
    # its footprint is reported on top of the MEASURED baseline.
    assert "storage: baseline=59.930256 GiB (MEASURED)" in output
    assert "peak=116.839 GiB" in output
    assert "billable=0.00 GiB-month" in output
    # The baseline is measured, the capacity proof remains unavailable, and its
    # open sub-items are printed next to it.
    assert "storage status: baseline=MEASURED" in output
    assert "capacity_proof=UNAVAILABLE" in output
    assert "storage residuals: 3 open item(s)" in output
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
