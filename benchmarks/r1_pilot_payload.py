"""benchmarks/r1_pilot_payload.py
===============================

The **unsigned** approval payload of the R1 pilot (the steps R2p, R3 and R3b
under the ``$3`` budget cap of the pilot).

**This script signs nothing and creates no approval artifact.** It produces the
*canonical payload* - the bytes the owner signs locally with the private key
of the approval authority - and writes it **outside** the repository. The
signed artifact (the payload plus the signature) is assembled by the owner and
handed to the run out of band; it is never committed.

The payload is built with the repository's own machinery:

* the **estimate** of every step comes from ``benchmarks.r1_estimator`` and the
  **approved** rate card - the same accounting model the cost proposal uses;
* the **policy** is a ``benchmarks.r1_dispatch.StepPolicy`` whose bounds are the
  candidate bounds of the cost scenario - the values the owner approves by
  signing them;
* the **dispatch envelope** is the one the gate itself rebuilds at dispatch
  time (``DispatchGate.dispatch_envelope_payload``) for that policy and that
  world - the profiles and egress policies the estimator priced;
* the **canonical bytes** are ``core.r1_approval.canonical_bytes`` - the exact
  bytes the verification recomputes.

Because the envelope binds the SHA-256 of the rate card and of the cost
scenario, the payload has to be generated **on the machine that runs the
pilot**, from the checkout that runs it: a different byte layout (a CRLF
checkout, for example) changes the digest and the signature would no longer
match the envelope the gate rebuilds.

Usage::

    python -m benchmarks.r1_pilot_payload --out-dir ~/r1-approval-key/pilot

The owner then signs each payload with the private key (Git Bash)::

    openssl dgst -sha256 -sign ~/r1-approval-key/r1_approval_private.pem \
        -out ~/r1-approval-key/pilot/pilot_R2p.sig \
        ~/r1-approval-key/pilot/pilot_R2p_payload.json

and hands the payload and its signature to the run out of band. Nothing of
this enters the repository.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks import r1_dispatch, r1_estimator  # noqa: E402
from core import r1_approval  # noqa: E402

#: The scenario and the rate card of the cycle.
SCENARIO_PATH = _ROOT / "benchmarks" / "evidence" / "r1_cost_scenario.json"
RATE_CARD_PATH = _ROOT / "benchmarks" / "evidence" / "r1_rate_card.json"

#: The steps of the pilot. R4 stays out of it: it is the expensive stage.
PILOT_STEPS: Tuple[str, ...] = ("R2p", "R3", "R3b")

#: The budget cap of the pilot - the cap of the ledger, shared by its steps.
PILOT_CAP_USD = 3.0

#: The approver of the pilot.
APPROVED_BY = "owner"


def _world_for(step_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """The effective profiles and egress policies of one step of the scenario.

    These are the values the estimator priced - the candidate bounds of the
    scenario applied to the declared profiles - and they are the values the
    gate has to be constructed with, or the envelope it rebuilds differs from
    the signed one.
    """
    profiles: Dict[str, Any] = {}
    for container_class, overrides in step_data.get("candidate_bounds", {}).items():
        base = r1_estimator.profile_for(container_class)
        profiles[container_class] = r1_estimator.apply_candidate_bounds(base, overrides)
    egress: Dict[str, Any] = {}
    for function_name, overrides in step_data.get("candidate_egress", {}).items():
        policy = r1_estimator.egress_policy(function_name)
        if policy is None:
            continue
        egress[function_name] = dataclasses.replace(policy, **overrides)
    return profiles, egress


def _call_sites_for(step_data: Dict[str, Any]) -> List[str]:
    """The provider call sites the step covers."""
    sites = set()
    for names in step_data.get("egress_functions", {}).values():
        sites.update(names)
    for names in step_data.get("ingress_functions", {}).values():
        sites.update(names)
    return sorted(sites)


def build_payloads(
    *,
    approved_at: str,
    steps: Tuple[str, ...] = PILOT_STEPS,
) -> List[Dict[str, Any]]:
    """Build the canonical payload of every pilot step."""
    scenario = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    rate_card = r1_estimator.RateCard.from_file(str(RATE_CARD_PATH))
    estimate = r1_estimator.run_scenario(scenario, rate_card)
    rows = {row["step_id"]: row for row in estimate["steps"]}
    scenario_steps = {step["step_id"]: step for step in scenario["steps"]}

    payloads: List[Dict[str, Any]] = []
    for step_id in steps:
        step_data = scenario_steps[step_id]
        row = rows[step_id]
        if not row.get("available"):
            raise SystemExit(f"the estimate of {step_id} is unavailable: {row.get('unavailable_reasons')}")
        worst_case = float(row["total_usd"])
        profiles, egress = _world_for(step_data)
        policy = r1_dispatch.StepPolicy(
            step_id=step_id,
            invocation_budgets={
                key: int(value) for key, value in step_data.get("invocations", {}).items()
            },
            concurrency_caps={
                key: int(value) for key, value in step_data.get("concurrency_caps", {}).items()
            },
            wall_clock_budget_sec=float(step_data["t_exec_sec"]),
            post_execution_deadline_sec=float(
                step_data["t_post_exec_to_publication_sec"]
            ),
            # The ceiling of a pilot step is its own worst case: the tightest
            # honest ceiling, and far below the cap of the pilot.
            monetary_ceiling_usd=worst_case,
            estimate_usd=worst_case,
            approved_by=APPROVED_BY,
            approved_at=approved_at,
        )
        gate = r1_dispatch.DispatchGate(
            policy=policy,
            profiles=profiles,
            egress_policies=egress,
        )
        payloads.append(
            {
                "step_id": step_id,
                "approved_by": APPROVED_BY,
                "approved_at": approved_at,
                "call_sites": _call_sites_for(step_data),
                "policy": policy.to_payload(),
                "dispatch_envelope": gate.dispatch_envelope_payload(),
            }
        )
    return payloads


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(Path.home() / "r1-approval-key" / "pilot"),
        help="where the unsigned payloads are written (never inside the repository)",
    )
    parser.add_argument(
        "--approved-at",
        default=None,
        help="the moment of the approval (defaults to now, in UTC)",
    )
    parser.add_argument(
        "--steps",
        default=",".join(PILOT_STEPS),
        help="the steps of the pilot",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).expanduser()
    if _ROOT in out_dir.resolve().parents or out_dir.resolve() == _ROOT:
        print("the payload must not be written inside the repository")
        return 1
    approved_at = args.approved_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    steps = tuple(step.strip() for step in args.steps.split(",") if step.strip())

    out_dir.mkdir(parents=True, exist_ok=True)
    for payload in build_payloads(approved_at=approved_at, steps=steps):
        canonical = r1_approval.canonical_bytes(payload)
        path = out_dir / f"pilot_{payload['step_id']}_payload.json"
        path.write_bytes(canonical)
        print(f"{payload['step_id']}: {path} ({len(canonical)} B)")
        print(f"  policy digest    : {r1_approval.policy_digest(payload['policy'])}")
        print(
            "  envelope digest  : "
            f"{r1_approval.payload_digest(payload['dispatch_envelope'])}"
        )
        print(f"  payload digest   : {r1_approval.payload_digest(payload)}")
        print(f"  call sites       : {payload['call_sites']}")
        print(f"  estimate/ceiling : {payload['policy']['estimate_usd']}")
    print(f"approved_at: {approved_at}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
