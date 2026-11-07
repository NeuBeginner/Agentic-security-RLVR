"""
tests/test_p0_normalization_and_signal.py

Regression suite for the P0 unblocking work:
  1. Mechanical contract-name normalization (llm_generator).
  2. Reward shaping: format failure vs compilation failure must be distinguishable.
  3. GRPO group spread diagnostics + fail-closed on an all-degenerate dataset.
"""

import pytest

from core.config import config
from core.schemas import TargetProgram, ResultCategory
from core.llm_generator import (
    normalize_exploit_contract_name,
    parse_model_response,
    validate_exploit_format,
)
from core.grpo_trainer import diagnose_group_spread, group_rollouts_by_prompt


VAULT_SOL = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdrawAll() external { uint256 b = balances[msg.sender]; (bool s,) = msg.sender.call{value: b}(""); require(s); balances[msg.sender] = 0; }
}
"""


# =============================================================================
# 1. MECHANICAL CONTRACT NAME NORMALIZATION
# =============================================================================

def test_normalization_renames_single_top_level_contract():
    """A single wrongly-named top-level contract is renamed to ExploitModule."""
    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is True
    assert old_name == "VaultAttack"
    assert "contract ExploitModule" in normalized
    assert "VaultAttack" not in normalized


def test_normalization_is_idempotent_on_correct_name():
    """An already-correct contract name is left completely untouched."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is False
    assert old_name == ""
    assert normalized == code


def test_normalization_rewrites_self_references():
    """Self-references such as `new VaultAttack()` must be renamed consistently."""
    code = """pragma solidity ^0.8.20;
contract ReentrancyDrain {
    constructor(address _target) payable {}
    function runExploit() external payable {
        ReentrancyDrain other = new ReentrancyDrain(address(this));
        other.runExploit();
    }
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is True
    assert "new ExploitModule(address(this))" in normalized
    assert "ReentrancyDrain" not in normalized


def test_normalization_never_touches_string_literals_or_comments():
    """String literals and comments mentioning the old name must stay intact."""
    code = """pragma solidity ^0.8.20;
// this comment mentions VaultAttack on purpose
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {
        string memory s = "VaultAttack";
        require(bytes(s).length > 0, "VaultAttack");
    }
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is True
    assert "contract ExploitModule" in normalized
    # The comment and both string literals keep their original content.
    assert "// this comment mentions VaultAttack on purpose" in normalized
    assert 'string memory s = "VaultAttack";' in normalized
    assert '"VaultAttack"' in normalized


def test_normalization_never_renames_imported_symbols():
    """An imported symbol must never be silently aliased into the target contract."""
    code = """pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is True
    assert "import {Vault} from" in normalized
    assert "Vault public target;" in normalized


def test_normalization_declines_when_multiple_contracts_declared():
    """Ambiguity (several contracts) must leave the code untouched."""
    code = """pragma solidity ^0.8.20;
contract Helper {
    constructor() {}
}
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is False
    assert normalized == code


def test_normalization_declines_on_already_correct_and_duplicate_names():
    """Two contracts already named ExploitModule must not be renamed."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is False
    assert normalized == code


def test_parse_model_response_repairs_wrong_contract_name():
    """
    End-to-end: a wrongly-named but otherwise valid exploit must now pass the
    format gate and become eligible for EVM verification.
    """
    raw = """Here is my exploit.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, raw)

    assert payload.format_valid is True
    assert payload.format_error_reason == ""
    assert payload.contract_name_normalized is True
    assert payload.original_contract_name == "VaultAttack"
    assert "contract ExploitModule" in payload.test_code
    assert "contract VaultAttack" not in payload.test_code


def test_parse_model_response_still_rejects_structurally_broken_code():
    """Normalization must not paper over a genuinely missing entrypoint."""
    raw = """```solidity
pragma solidity ^0.8.20;

contract VaultAttack {
    constructor(address _target) payable {}
    // no runExploit here
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, raw)

    assert payload.format_valid is False
    assert payload.format_error_reason != ""


def test_strict_validator_remains_strict():
    """The direct validator API keeps its strict behaviour (no silent repair)."""
    code = """pragma solidity ^0.8.20;
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    is_valid, reason = validate_exploit_format(code)

    assert is_valid is False
    assert "instead of mandatory 'ExploitModule'" in reason


def test_normalization_can_be_disabled_by_configuration(monkeypatch):
    """With the feature flag off, the old strict behaviour is preserved."""
    import dataclasses
    from core import config as config_module
    from core import llm_generator as llm_module

    disabled = dataclasses.replace(
        config_module.config, ENABLE_CONTRACT_NAME_NORMALIZATION=False
    )
    monkeypatch.setattr(llm_module, "config", disabled)

    raw = """```solidity
pragma solidity ^0.8.20;

contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, raw)

    assert payload.format_valid is False
    assert payload.contract_name_normalized is False
    assert "instead of mandatory 'ExploitModule'" in payload.format_error_reason


def test_normalization_audit_fields_reach_the_trajectory():
    """
    The repair must stay auditable: the trajectory records that a rename happened,
    while the training completion keeps the model's ORIGINAL text so token lineage
    and the trained completion stay identical to what the model emitted.
    """
    from core.candidate_lifecycle import create_finalized_trajectory, CandidateRecord
    from core.schemas import AttackHypothesis, VerificationVerdict

    raw = """```solidity
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, raw)

    verdict = VerificationVerdict(
        target_name="Vault",
        is_verified=False,
        reward_score=config.REWARD_SAFE_RUN,
        category=ResultCategory.SAFE_RUN,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="safe",
        state_delta_verified=False,
        reproducible=True,
    )

    record = CandidateRecord(
        candidate_id="c1",
        run_id="r1",
        target_name="Vault",
        generation_iteration=0,
        candidate_index=0,
        payload=payload,
        verdict=verdict,
        model_id="m",
        checkpoint_id="base",
        prompt_text="PROMPT",
        prompt_hash="h" * 64,
        replay_eligible=False,
        reproduced=False,
    )

    traj = create_finalized_trajectory(record, target)

    # Audit trail present.
    assert traj.contract_name_normalized is True
    assert traj.original_contract_name == "VaultAttack"

    # The executable artifact is the renamed one...
    assert "contract ExploitModule" in traj.generated_exploit
    # ...but the training completion is still the model's untouched output.
    assert "contract VaultAttack" in traj.full_completion_text
    assert traj.full_completion_text == raw


# =============================================================================
# 2. REWARD SHAPING
# =============================================================================

def test_format_error_and_compilation_error_are_distinguishable():
    """
    A format failure is mechanically cheap to repair, a compilation failure is not.
    Identical rewards would remove the gradient between those two states.
    """
    assert config.REWARD_FORMAT_ERROR != config.REWARD_COMPILATION_FAIL
    # Format failure must be strictly less punishing than compilation failure.
    assert config.REWARD_FORMAT_ERROR > config.REWARD_COMPILATION_FAIL


def test_reward_ladder_remains_ordered():
    """The full reward ladder must stay monotonically ordered by outcome quality."""
    assert config.REWARD_INVARIANT_BREACH > config.REWARD_BREACH_NO_REPLAY
    assert config.REWARD_BREACH_NO_REPLAY > config.REWARD_INFRA_ERROR
    assert config.REWARD_INFRA_ERROR > config.REWARD_SAFE_RUN
    assert config.REWARD_SAFE_RUN > config.REWARD_RUNTIME_REVERT
    assert config.REWARD_RUNTIME_REVERT > config.REWARD_FORMAT_ERROR
    assert config.REWARD_FORMAT_ERROR > config.REWARD_COMPILATION_FAIL
    assert config.REWARD_COMPILATION_FAIL > config.REWARD_CHEATCODE_PENALTY


# =============================================================================
# 3. GRPO GROUP SPREAD DIAGNOSTICS
# =============================================================================

def _rollout(idx, reward, category="SAFE_RUN"):
    return {
        "candidate_id": f"c{idx}",
        "run_id": "r1",
        "target_name": "Vault",
        "prompt_used": "SAME PROMPT",
        "model_id": "m",
        "checkpoint_id": "base",
        "reward": reward,
        "category": category,
        "full_completion_text": "x",
        "generated_exploit": "y",
    }


def test_diagnose_group_spread_flags_uniform_reward_groups():
    """All-identical rewards produce a degenerate group with zero gradient."""
    groups = group_rollouts_by_prompt([_rollout(i, -0.5) for i in range(4)])
    assert len(groups) == 1

    spread = diagnose_group_spread(groups)

    assert spread["total_groups"] == 1
    assert spread["degenerate_groups"] == 1
    assert spread["informative_groups"] == 0
    assert spread["degenerate_ratio"] == 1.0
    assert spread["mean_abs_advantage"] == 0.0


def test_diagnose_group_spread_detects_informative_group():
    """Reward diversity inside a group produces a usable learning signal."""
    groups = group_rollouts_by_prompt([
        _rollout(0, -0.5),
        _rollout(1, -0.5),
        _rollout(2, -0.5),
        _rollout(3, -0.1, "SAFE_RUN"),
    ])
    spread = diagnose_group_spread(groups)

    assert spread["informative_groups"] == 1
    assert spread["degenerate_groups"] == 0
    assert spread["mean_abs_advantage"] > 0.0


def test_degenerate_group_has_exactly_zero_advantages():
    """A degenerate group must yield all-zero advantages (no gradient)."""
    groups = group_rollouts_by_prompt([_rollout(i, -0.5) for i in range(4)])
    advantages = [r.advantage for r in groups[0].rollouts]

    assert advantages == [0.0, 0.0, 0.0, 0.0]
    assert all(a == 0.0 for a in advantages)
