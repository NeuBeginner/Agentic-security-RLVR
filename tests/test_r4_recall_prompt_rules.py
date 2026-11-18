"""
tests/test_r4_recall_prompt_rules.py
===================================

The rules that make a candidate reach the vulnerable code at all.

The audit of the R4 run found three defects of the *blindness* of the
generator and of the refine loop:

* the exploit contract had to implement ``receive() external payable`` - the
  harness and the target send ETH to the exploit, and a contract without a
  ``receive()`` rejects that ETH and reverts before the vulnerable code;
* a candidate that hardcoded an amount (``1 ether``, ``100 ether``) in a
  ``{value: ...}`` call reverted with ``OutOfFunds`` and never reached the
  vulnerable code;
* a borrow, a claim or a payout above the balance of the target reverted as
  well.

These tests pin down the rules in the prompts and the coverage of the
invariants of the targets.
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.adapters import TARGET_INVARIANTS
from core.llm_generator import (
    EXPLOIT_ENGINEER_SYSTEM_PROMPT,
    build_analysis_prompt,
    build_exploit_engineer_system_prompt,
    build_refinement_prompt,
    required_entrypoint_for_target,
    validate_exploit_format,
)
from core.schemas import TargetProgram

_ROOT = Path(__file__).resolve().parent.parent

#: Every target of the benchmark, with the invariant it has to breach.
_DATASET = json.loads((_ROOT / "benchmarks" / "benchmark_dataset.json").read_text(encoding="utf-8"))


def _dataset_targets() -> list:
    targets = []
    for klass in _DATASET["classes"]:
        targets.extend(klass["targets"])
    targets.extend(_DATASET.get("synthetic_controls", []))
    return targets


def test_every_target_of_the_benchmark_has_its_invariants():
    """A target without an invariant is attacked against a placeholder."""
    for target in _dataset_targets():
        name = target["target_name"]
        assert name in TARGET_INVARIANTS, f"the invariants of {name} are missing"


def test_the_invariants_name_the_ground_truth_of_the_dataset():
    """The ground truth of the dataset is part of the invariants of the target."""
    for target in _dataset_targets():
        name = target["target_name"]
        ground_truth = target.get("ground_truth_invariant")
        if not ground_truth or ground_truth == "NONE":
            continue
        assert ground_truth in TARGET_INVARIANTS[name], (
            f"the ground truth {ground_truth} of {name} is missing in its invariants"
        )


def test_the_system_prompt_requires_the_receive_function():
    """The exploit contract has to accept the ETH of the harness."""
    assert "receive() external payable" in EXPLOIT_ENGINEER_SYSTEM_PROMPT
    assert "receive() external payable" in build_exploit_engineer_system_prompt("Vault")


def test_the_system_prompt_forbids_hardcoded_amounts():
    """A hardcoded amount reverts with OutOfFunds before the vulnerable code."""
    prompt = build_exploit_engineer_system_prompt("Vault")
    assert "1 ether" in prompt
    assert "OutOfFunds" in prompt
    assert "address(this).balance" in prompt
    assert "address(targetContract).balance" in prompt


def test_the_analysis_prompt_carries_the_rules():
    """The rules of the system prompt are in the user prompt as well."""
    target = TargetProgram(name="Vault", source_code="contract Vault {}")
    prompt = build_analysis_prompt(target)

    assert "receive() external payable" in prompt
    assert "OutOfFunds" in prompt
    assert "address(targetContract).balance" in prompt
    assert "{value: 0}" in prompt


def test_the_refinement_prompt_is_target_aware():
    """The refinement loop speaks about the entrypoint of its target."""
    signature_replay = TargetProgram(
        name="SignatureReplayWallet", source_code="contract SignatureReplayWallet {}"
    )
    prompt = build_refinement_prompt(signature_replay, "contract ExploitModule {}", "reverted")
    assert "runSignatureReplay(bytes32 r, bytes32 s, uint8 v)" in prompt
    assert "OutOfFunds" in prompt

    vault = TargetProgram(name="Vault", source_code="contract Vault {}")
    vault_prompt = build_refinement_prompt(vault, "contract ExploitModule {}", "reverted")
    assert "runExploit()" in vault_prompt


def test_the_system_prompt_names_the_entrypoint_of_the_target():
    """The prompt states the exact signature the harness calls."""
    signature_replay_prompt = build_exploit_engineer_system_prompt("SignatureReplayWallet")
    assert "runSignatureReplay(bytes32 r, bytes32 s, uint8 v)" in signature_replay_prompt

    vault_prompt = build_exploit_engineer_system_prompt("Vault")
    assert "runExploit()" in vault_prompt


def test_the_validator_derives_the_entrypoint_from_the_target():
    """A candidate of the SignatureReplayWallet is judged by its own signature."""
    name, params = required_entrypoint_for_target("SignatureReplayWallet")
    assert name == "runSignatureReplay"
    assert params == ["bytes32", "bytes32", "uint8"]

    candidate = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {SignatureReplayWallet} from "../src/SignatureReplayWallet.sol";
contract ExploitModule {
    SignatureReplayWallet public targetContract;
    constructor(address _target) payable { targetContract = SignatureReplayWallet(payable(_target)); }
    function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external {}
}
"""
    ok, reason = validate_exploit_format(candidate, target_name="SignatureReplayWallet")
    assert ok is True, reason

    # The generic entrypoint is NOT the entrypoint of that target.
    generic = candidate.replace(
        "function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external {}",
        "function runExploit() external payable {}",
    )
    ok, reason = validate_exploit_format(generic, target_name="SignatureReplayWallet")
    assert ok is False
    assert "runSignatureReplay" in reason


def test_the_lending_contract_exposes_the_borrowers():
    """
    The borrower is a fact of the state, not a constant of the exploit.

    The registry of the borrowers is the public fact that lets a liquidator
    find the borrower on chain instead of hardcoding an address.
    """
    source = (_ROOT / "benchmarks" / "targets" / "solidity" / "LendingLiquidation.sol").read_text(
        encoding="utf-8"
    )
    assert "address[] public borrowers" in source
    assert "function getBorrowers()" in source
    assert "borrowers.push(msg.sender)" in source
