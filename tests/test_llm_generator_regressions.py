from core.llm_generator import (
    SOLIDITY_KEYWORDS,
    analyze_contract_normalization,
    build_analysis_prompt,
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


def test_custom_error_name_collision_after_revert_fails_closed():
    source = "pragma solidity ^0.8.20; contract VaultAttack { error VaultAttack(); function f() external { revert VaultAttack(); } }"
    outcome = analyze_contract_normalization(source)
    assert outcome.renamed is False
    assert outcome.reason == "ambiguous_event_or_error_reference"


def test_signature_replay_prompt_uses_the_harness_entrypoint():
    target = TargetProgram(name="SignatureReplayWallet", source_code="contract SignatureReplayWallet {}")
    prompt = build_analysis_prompt(target)
    assert "function runExploit() external payable" in prompt
    assert "function runSignatureReplay(bytes32 r, bytes32 s, uint8 v) external" not in prompt


def test_validator_accepts_the_entrypoint_required_by_the_prompt():
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address target) payable {}
    function runExploit() external payable {}
}
"""
    valid, reason = validate_exploit_format(code)
    assert valid, reason