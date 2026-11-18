from core.llm_generator import (
    SOLIDITY_KEYWORDS,
    analyze_contract_normalization,
    build_analysis_prompt,
    build_refinement_prompt,
    extract_solidity_code,
    tokenize_solidity,
    validate_exploit_format,
)
from core.schemas import TargetProgram


def test_revert_is_tokenized_as_a_solidity_keyword():
    tokens, error = tokenize_solidity("contract A { function f() external { revert A(); } }")
    assert error is None
    revert_tokens = [token for token in tokens if token.value == "revert"]
    assert len(revert_tokens) == 1
    assert revert_tokens[0].type.value == "KEYWORD"
    assert "revert" in SOLIDITY_KEYWORDS


def test_custom_error_reference_after_revert_fails_closed():
    source = "pragma solidity ^0.8.20; contract VaultAttack { function f() external { revert VaultAttack(); } }"
    outcome = analyze_contract_normalization(source)
    assert outcome.renamed is False
    assert outcome.reason == "ambiguous_event_or_error_reference"


def test_signature_replay_prompt_matches_the_target_harness():
    target = TargetProgram(name="SignatureReplayWallet", source_code="contract SignatureReplayWallet {}")
    prompt = build_analysis_prompt(target)
    assert "function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external" in prompt


def test_signature_replay_refinement_prompt_keeps_harness_signature():
    target = TargetProgram(name="SignatureReplayWallet", source_code="contract SignatureReplayWallet {}")
    prompt = build_refinement_prompt(target, "contract ExploitModule {}", "execution reverted")
    assert "Required harness entrypoint" in prompt
    assert "function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external" in prompt


def test_signature_replay_validator_accepts_exact_harness_signature():
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address target) payable {}
    function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external {}
}
"""
    valid, reason = validate_exploit_format(
        code,
        entrypoint_name="runSignatureReplay",
        entrypoint_param_types=["bytes32", "bytes32", "uint8"],
    )
    assert valid, reason


def test_default_validator_still_accepts_canonical_run_exploit():
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address target) payable {}
    function runExploit() external payable {}
}
"""
    valid, reason = validate_exploit_format(code)
    assert valid, reason


def test_extract_solidity_code_recovers_balanced_truncated_exploit_module():
    truncated_but_balanced = """Here is the exploit:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PrecisionStakingPool} from "../src/PrecisionStakingPool.sol";

contract ExploitModule {
    PrecisionStakingPool public targetContract;

    constructor(address _target) payable {
        targetContract = PrecisionStakingPool(payable(_target));
    }

    function runExploit() external payable {
        targetContract.depositWithFee{value: 1}();
    }

    receive() external payable {}
}
"""
    extracted = extract_solidity_code(truncated_but_balanced)
    assert "contract ExploitModule" in extracted
    assert extracted.endswith("}")


def test_extract_solidity_code_rejects_unbalanced_truncated_block():
    truncated_mid_body = """```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PrecisionStakingPool} from "../src/PrecisionStakingPool.sol";

contract ExploitModule {
    PrecisionStakingPool public targetContract;

    constructor(address _target) payable {
        targetContract = PrecisionStakingPool(payable(_target));
    }

    function runExploit() external payable {
        // Deposit 1000000000000000000 wei
        targetContract.depositWithFee{value: 1000000000000000000}();
"""
    assert extract_solidity_code(truncated_mid_body) == ""


def test_extract_solidity_code_rejects_balanced_non_exploit_module_when_unclosed():
    other_contract = """```solidity
pragma solidity ^0.8.20;
contract Helper {
    function ping() external {}
}
"""
    assert extract_solidity_code(other_contract) == ""


def test_refinement_prompt_formats_cleanly_and_enforces_compact_loops():
    target = TargetProgram(name="RewardDistributorLogic", source_code="contract RewardDistributorLogic {}")
    prompt = build_refinement_prompt(target, "contract ExploitModule {}", "Insufficient pool reserves")
    assert "{value: ...}" in prompt
    assert "Step 1 ... Step N" in prompt
    assert "for (uint i = 0; i < N; i++)" in prompt
    assert "OutOfFunds" in prompt
    assert "Insufficient pool reserves" in prompt
