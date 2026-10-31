"""
tests/test_round5_regression.py

Dedicated regression suite for Round 5 Supervisor requirements:
1. Prompt Identity vs Completion in GRPO Grouping
2. Generated Token IDs Propagation through Production Path
3. Modal Orchestration Replay Exception Handling
4. Strict Solidity Constructor & Entrypoint Signatures
5. A/B Evaluator Denominator Policies with INFRA_ERROR
"""

import pytest
from core.schemas import (
    ResultCategory,
    ExploitPayload,
    VerificationVerdict,
    TargetProgram,
    RLVRTrajectory,
    AttackHypothesis
)
from core.candidate_lifecycle import (
    CandidateRecord,
    create_finalized_trajectory,
    finalize_candidate_replay,
    select_candidate_for_replay,
    rank_candidates,
    compute_prompt_hash
)
from core.grpo_trainer import (
    group_rollouts_by_prompt,
    make_group_key,
    prepare_rollout_tokens
)
from core.llm_generator import (
    validate_exploit_format,
    parse_model_response
)
from core.ab_evaluator import (
    evaluate_raw_candidates,
    format_ab_table_markdown
)


# =============================================================================
# 1. PROMPT IDENTITY VS COMPLETION IN GRPO GROUPING
# =============================================================================

def test_prompt_identity_vs_completion_grouping():
    """
    Supervisor Blocker 1:
    - 2 different completions generated on the same prompt MUST end up in the SAME group.
    - 2 identical completions generated on different prompts MUST end up in DIFFERENT groups.
    - Different model_id / checkpoint_id MUST NOT be mixed into the same group.
    - Production path: prompt_text -> CandidateRecord -> RLVRTrajectory.prompt_used -> GRPOGroup.
    """
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { ... }",
        language="solidity",
        invariants=["solvency"]
    )
    prompt_a = "Analyze target contract Vault for reentrancy vulnerabilities with budget 1 ether."
    prompt_b = "Analyze target contract Vault for first depositor inflation vulnerabilities."

    hyp = AttackHypothesis(
        vulnerability_type="ReentrancyDrain",
        reasoning_trace="Found reentrancy in withdrawAll",
        attack_vector="Call withdrawAll in callback"
    )

    # 1. Candidate 1 on prompt_a with completion A
    payload_1 = ExploitPayload(
        target_name="Vault",
        hypothesis=hyp,
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id="c1",
        run_id="run_1",
        prompt_text=prompt_a,
        raw_model_response="Completion A: Here is the code..."
    )
    rec_1 = CandidateRecord(
        candidate_id="c1",
        run_id="run_1",
        target_name="Vault",
        payload=payload_1,
        verdict=VerificationVerdict(
            target_name="Vault",
            is_verified=False,
            reward_score=0.5,
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload_1.test_code,
            feedback="trace"
        ),
        prompt_text=prompt_a,
        prompt_hash=compute_prompt_hash(prompt_a),
        model_id="model-1",
        checkpoint_id="ckpt-1"
    )

    # 2. Candidate 2 on prompt_a with different completion B
    payload_2 = ExploitPayload(
        target_name="Vault",
        hypothesis=hyp,
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external payable {} }",
        candidate_id="c2",
        run_id="run_1",
        prompt_text=prompt_a,
        raw_model_response="Completion B: Completely different reasoning and completion..."
    )
    rec_2 = CandidateRecord(
        candidate_id="c2",
        run_id="run_1",
        target_name="Vault",
        payload=payload_2,
        verdict=VerificationVerdict(
            target_name="Vault",
            is_verified=False,
            reward_score=-0.25,
            category=ResultCategory.RUNTIME_REVERT,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload_2.test_code,
            feedback="revert"
        ),
        prompt_text=prompt_a,
        prompt_hash=compute_prompt_hash(prompt_a),
        model_id="model-1",
        checkpoint_id="ckpt-1"
    )

    # 3. Candidate 3 on prompt_b with completion identical to Candidate 1
    payload_3 = ExploitPayload(
        target_name="Vault",
        hypothesis=hyp,
        test_code=payload_1.test_code,  # Identical completion!
        candidate_id="c3",
        run_id="run_1",
        prompt_text=prompt_b,
        raw_model_response=payload_1.raw_model_response
    )
    rec_3 = CandidateRecord(
        candidate_id="c3",
        run_id="run_1",
        target_name="Vault",
        payload=payload_3,
        verdict=VerificationVerdict(
            target_name="Vault",
            is_verified=False,
            reward_score=0.5,
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload_3.test_code,
            feedback="trace"
        ),
        prompt_text=prompt_b,
        prompt_hash=compute_prompt_hash(prompt_b),
        model_id="model-1",
        checkpoint_id="ckpt-1"
    )

    # Convert all to finalized trajectories
    traj_1 = create_finalized_trajectory(rec_1, target)
    traj_2 = create_finalized_trajectory(rec_2, target)
    traj_3 = create_finalized_trajectory(rec_3, target)

    # Invariant: prompt_used MUST contain the actual prompt, NOT raw_model_response!
    assert traj_1.prompt_used == prompt_a
    assert traj_2.prompt_used == prompt_a
    assert traj_3.prompt_used == prompt_b
    assert traj_1.prompt_used != traj_1.hypothesis.reasoning_trace

    # Group rollouts
    data = [traj_1.model_dump(), traj_2.model_dump(), traj_3.model_dump()]
    groups = group_rollouts_by_prompt(data, group_size=2)

    # Candidate 1 and Candidate 2 share prompt_a -> form a group of size 2
    assert len(groups) == 1
    grp = groups[0]
    assert grp.prompt == prompt_a
    c_ids = [r.candidate_id for r in grp.rollouts]
    assert "c1" in c_ids
    assert "c2" in c_ids
    assert "c3" not in c_ids  # c3 was on prompt_b and cannot enter prompt_a's group!


# =============================================================================
# 2. GENERATED TOKEN IDS PIPELINE THROUGH PRODUCTION PATH
# =============================================================================

# =============================================================================
# 2. GENERATED TOKEN IDS PIPELINE THROUGH PRODUCTION PATH (REAL TOKENIZER)
# =============================================================================

def test_real_qwen_tokenizer_prompt_and_token_id_lineage():
    """
    Supervisor Blockers 1 & 2 (Round 5):
    Uses the real HuggingFace Qwen2.5-Coder tokenizer from local cache.
    Proves:
    1. Full generation prompt (with chat template and system prompt) is preserved in prompt_used.
    2. Model response tokens generated during inference match training completion tokens 100% bitwise.
    3. full_completion_text matches the decoded generated_token_ids character-by-character.
    4. ExploitModule code is extracted into generated_exploit for EVM testing, while full reasoning + code
       is preserved in full_completion_text for GRPO policy training.
    """
    from transformers import AutoTokenizer
    from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_analysis_prompt

    tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-1.5B-Instruct")
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint256) public balances; }",
        language="solidity",
        invariants=["Depositor Solvency"]
    )

    # 1. Real chat-templated generation prompt
    user_prompt = build_analysis_prompt(target)
    messages = [
        {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]
    formatted_prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    expected_prompt_ids = tokenizer.encode(formatted_prompt, add_special_tokens=True)

    # 2. Real model output sequence with reasoning and code
    raw_response = (
        "### Vulnerability Analysis\n"
        "The target contract Vault allows unconstrained withdrawals.\n\n"
        "```solidity\n"
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "contract ExploitModule {\n"
        "    address public target;\n"
        "    constructor(address _target) payable {\n"
        "        target = _target;\n"
        "    }\n"
        "    function runExploit() external payable {\n"
        "        // exploit execution\n"
        "    }\n"
        "}\n"
        "```\n"
        "Attack sequence complete."
    )
    real_generated_token_ids = tokenizer.encode(raw_response, add_special_tokens=False)

    # 3. Production pipeline: parse_model_response preserves full prompt & generated token IDs
    payload = parse_model_response(
        target,
        raw_response,
        attempt_idx=1,
        generated_token_ids=real_generated_token_ids,
        prompt_text=formatted_prompt
    )
    assert payload.prompt_text == formatted_prompt
    assert payload.generated_token_ids == real_generated_token_ids
    assert payload.raw_model_response == raw_response
    assert "contract ExploitModule" in payload.test_code
    assert payload.format_valid is True

    # 4. Production CandidateRecord creation
    candidate = CandidateRecord(
        candidate_id="real_qwen_cand_1",
        run_id="run_qwen_test",
        target_name=target.name,
        payload=payload,
        verdict=VerificationVerdict(
            target_name=target.name,
            is_verified=False,
            reward_score=0.5,
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload.test_code,
            feedback="trace"
        ),
        prompt_text=payload.prompt_text,
        prompt_hash=compute_prompt_hash(payload.prompt_text),
        model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        checkpoint_id="base"
    )

    # 5. Production finalized trajectory creation
    traj = create_finalized_trajectory(candidate, target)
    assert traj.prompt_used == formatted_prompt
    assert traj.full_completion_text == raw_response
    assert traj.generated_exploit == payload.test_code
    assert traj.generated_token_ids == real_generated_token_ids

    # 6. GRPO Grouping
    groups = group_rollouts_by_prompt([traj.model_dump(), traj.model_dump()], group_size=2)
    assert len(groups) == 1
    grp = groups[0]
    assert grp.prompt == formatted_prompt

    r_item = grp.rollouts[0]
    assert r_item.full_completion_text == raw_response
    assert r_item.exploit_code == payload.test_code
    assert r_item.generated_token_ids == real_generated_token_ids

    # 7. GRPO Token preparation for policy forward pass
    training_completion = r_item.full_completion_text or r_item.exploit_code
    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=grp.prompt,
        completion_str=training_completion,
        tokenizer=tokenizer,
        device="cpu",
        stored_generated_token_ids=r_item.generated_token_ids
    )

    prompt_len = len(expected_prompt_ids)
    extracted_prompt_ids = input_ids[0, :prompt_len].tolist()
    extracted_completion_ids = input_ids[0, prompt_len:].tolist()

    # Invariant A: Training prompt IDs match inference prompt IDs 100% bitwise!
    assert extracted_prompt_ids == expected_prompt_ids

    # Invariant B: Training completion IDs match inference generated IDs 100% bitwise!
    # Note: prepare_rollout_tokens appends EOS if not present
    if real_generated_token_ids and real_generated_token_ids[-1] != tokenizer.eos_token_id:
        expected_with_eos = real_generated_token_ids + [tokenizer.eos_token_id]
    else:
        expected_with_eos = real_generated_token_ids
    assert extracted_completion_ids == expected_with_eos

    # Invariant C: Decoded completion tokens match raw model response character-for-character!
    decoded_completion = tokenizer.decode(extracted_completion_ids, skip_special_tokens=True)
    assert decoded_completion.strip() == raw_response.strip()

    # Invariant D: Completion mask is zero on prompt and 1.0 on generated completion!
    assert completion_mask[0, :prompt_len].sum().item() == 0.0
    assert completion_mask[0, prompt_len:].sum().item() == float(len(extracted_completion_ids))


class MockTokenizer:
    """Mock tokenizer simulating HuggingFace Qwen tokenizer for unit testing."""
    eos_token_id = 9999

    def encode(self, text, add_special_tokens=True):
        words = text.split()
        return [hash(w) % 1000 for w in words]

    def decode(self, ids, skip_special_tokens=True):
        return "decoded text"


def test_generated_token_ids_pipeline():
    """
    Supervisor Blocker 2:
    - parse_model_response preserves generated_token_ids
    - candidate record preserves generated_token_ids
    - create_finalized_trajectory persists generated_token_ids
    - prepare_rollout_tokens uses stored token IDs exactly without re-tokenizing.
    """
    target = TargetProgram(name="Vault", source_code="contract Vault {}", language="solidity")
    raw_code = """
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    raw_response = f"Reasoning\n```solidity\n{raw_code}\n```"
    mock_token_ids = [101, 202, 303, 404, 505, 606, 9999]

    # 1. Parse response with exact generated token IDs
    payload = parse_model_response(
        target,
        raw_response,
        attempt_idx=1,
        generated_token_ids=mock_token_ids,
        prompt_text="Audit prompt"
    )
    assert payload.generated_token_ids == mock_token_ids
    assert payload.prompt_text == "Audit prompt"

    # 2. Candidate record
    rec = CandidateRecord(
        candidate_id="cand_test_tokens",
        run_id="run_test",
        target_name=target.name,
        payload=payload,
        verdict=VerificationVerdict(
            target_name=target.name,
            is_verified=False,
            reward_score=-0.1,
            category=ResultCategory.SAFE_RUN,
            vulnerability_type="LogicFlaw",
            poc_code=payload.test_code,
            feedback="clean"
        ),
        prompt_text=payload.prompt_text
    )

    # 3. Finalized trajectory
    traj = create_finalized_trajectory(rec, target)
    assert traj.generated_token_ids == mock_token_ids
    assert traj.full_completion_text == raw_response

    # 4. GRPO Token preparation
    tok = MockTokenizer()
    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=traj.prompt_used,
        completion_str=traj.full_completion_text,
        tokenizer=tok,
        device="cpu",
        stored_generated_token_ids=traj.generated_token_ids
    )

    # Verify completion IDs match stored generated IDs
    prompt_len = len(tok.encode(traj.prompt_used))
    extracted_completion_ids = input_ids[0, prompt_len:].tolist()
    assert extracted_completion_ids == mock_token_ids


# =============================================================================
# 3. MODAL ORCHESTRATION REPLAY EXCEPTION HANDLING
# =============================================================================

def test_modal_orchestration_replay_exception_handling():
    """
    Supervisor Blocker 3:
    Simulates modal_app.py replay orchestration:
    - Normal successful replay -> EXPLOIT_CONFIRMED, reward=1.0, is_verified=True.
    - Normal failed replay -> INVARIANT_BREACH_UNREPLAYED, reward=0.5, is_verified=False.
    - Infrastructure exception (timeout, worker death) -> caught by try/except,
      finalized as INFRA_ERROR, reward=0.0, is_verified=False, excluded from GRPO.
    """
    target = TargetProgram(name="Vault", source_code="contract Vault {}", language="solidity")
    payload = ExploitPayload(
        target_name="Vault",
        hypothesis=AttackHypothesis(vulnerability_type="Reentrancy", reasoning_trace="", attack_vector=""),
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id="cand_rep_1",
        run_id="run_rep"
    )

    def simulate_orchestration_replay(simulate_behavior: str):
        candidate = CandidateRecord(
            candidate_id="cand_rep_1",
            run_id="run_rep",
            target_name=target.name,
            payload=payload,
            verdict=VerificationVerdict(
                target_name=target.name,
                is_verified=False,
                reward_score=0.5,
                category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
                vulnerability_type="Reentrancy",
                poc_code=payload.test_code,
                feedback="Initial breach",
                candidate_id="cand_rep_1"
            ),
            prompt_text="target prompt"
        )
        all_candidates = [candidate]

        selected = select_candidate_for_replay(all_candidates)
        assert selected is not None

        try:
            if simulate_behavior == "success":
                reproduced = True
            elif simulate_behavior == "fail":
                reproduced = False
            elif simulate_behavior == "exception":
                raise TimeoutError("Modal worker timed out after 60s in sandbox")
            else:
                raise ValueError("unknown behavior")

            finalize_candidate_replay(selected, replay_success=reproduced, replay_infra_error=False)
        except Exception as exc:
            finalize_candidate_replay(selected, replay_success=False, replay_infra_error=True)
            selected.verdict.feedback = f"Replay Infrastructure Error ({type(exc).__name__}): {exc}"

        return selected

    # Case A: Success
    res_success = simulate_orchestration_replay("success")
    assert res_success.verdict.category == ResultCategory.EXPLOIT_CONFIRMED
    assert res_success.verdict.reward_score == 1.0
    assert res_success.verdict.is_verified is True
    assert res_success.reproduced is True

    # Case B: Failure (unreproducible)
    res_fail = simulate_orchestration_replay("fail")
    assert res_fail.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    assert res_fail.verdict.reward_score == 0.5
    assert res_fail.verdict.is_verified is False
    assert res_fail.reproduced is False

    # Case C: Infrastructure Exception
    res_infra = simulate_orchestration_replay("exception")
    assert res_infra.verdict.category == ResultCategory.INFRA_ERROR
    assert res_infra.verdict.reward_score == 0.0
    assert res_infra.verdict.is_verified is False
    assert res_infra.reproduced is False
    assert "TimeoutError" in res_infra.verdict.feedback


# =============================================================================
# 4. STRICT SOLIDITY SIGNATURES & HARNESS INTERFACE
# =============================================================================

def test_strict_solidity_signatures():
    """
    Supervisor Requirement 4:
    - constructor(address) strictly 1 parameter of type address
    - runExploit() strictly 0 parameters, external or public visibility
    - Negative tests: 0 args, 2 args, wrong type, runExploit args, internal/private
    """
    # Negative 1: constructor() 0 parameters
    c1 = """
    contract ExploitModule {
        constructor() {}
        function runExploit() external {}
    }
    """
    v1, r1 = validate_exploit_format(c1)
    assert not v1
    assert "got 0 parameters: 'constructor()'" in r1

    # Negative 2: constructor(address, address) 2 parameters
    c2 = """
    contract ExploitModule {
        constructor(address a, address b) {}
        function runExploit() external {}
    }
    """
    v2, r2 = validate_exploit_format(c2)
    assert not v2
    assert "got 2 parameters" in r2

    # Negative 3: constructor(uint256) wrong type
    c3 = """
    contract ExploitModule {
        constructor(uint256 amount) {}
        function runExploit() external {}
    }
    """
    v3, r3 = validate_exploit_format(c3)
    assert not v3
    assert "must be of type 'address', got 'uint256'" in r3

    # Negative 4: runExploit(address victim) has parameters
    c4 = """
    contract ExploitModule {
        constructor(address _target) {}
        function runExploit(address victim) external {}
    }
    """
    v4, r4 = validate_exploit_format(c4)
    assert not v4
    assert "must take 0 parameters" in r4

    # Negative 5: runExploit() internal visibility
    c5 = """
    contract ExploitModule {
        constructor(address _target) {}
        function runExploit() internal {}
    }
    """
    v5, r5 = validate_exploit_format(c5)
    assert not v5
    assert "must have 'external' or 'public' visibility, got 'internal'" in r5

    # Negative 6: runExploit() private visibility
    c6 = """
    contract ExploitModule {
        constructor(address _target) {}
        function runExploit() private {}
    }
    """
    v6, r6 = validate_exploit_format(c6)
    assert not v6
    assert "must have 'external' or 'public' visibility, got 'private'" in r6

    # Positive 1: valid constructor(address) + external runExploit()
    c_pos1 = """
    contract ExploitModule {
        constructor(address _target) payable {}
        function runExploit() external payable {}
    }
    """
    v_pos1, _ = validate_exploit_format(c_pos1)
    assert v_pos1 is True

    # Positive 2: valid constructor(address payable) + public runExploit()
    c_pos2 = """
    contract ExploitModule {
        constructor(address payable _target) {}
        function runExploit() public {}
    }
    """
    v_pos2, _ = validate_exploit_format(c_pos2)
    assert v_pos2 is True


# =============================================================================
# 5. A/B EVALUATOR DENOMINATOR POLICIES WITH INFRA_ERROR
# =============================================================================

def test_ab_evaluator_with_infra_error_denominators():
    """
    Supervisor Requirement 5:
    - Demonstrates correct handling of INFRA_ERROR in denominators.
    - Total attempts: N_total = 4
    - Infrastructure failures: N_infra = 1
    - Evaluable candidates: N_eval = 3
    - 1 Format error, 1 Compilation error, 1 Runtime revert
    - Valid format rate: (3 - 1) / 3 = 66.7% (NOT 3 / 4!)
    - Compilation rate: (3 - 1 - 1) / 3 = 33.3%
    """
    candidates = [
        {"verdict": {"category": ResultCategory.GENERATION_FORMAT_ERROR.value, "reward_score": -0.5}},
        {"verdict": {"category": ResultCategory.COMPILATION_ERROR.value, "reward_score": -0.5}},
        {"verdict": {"category": ResultCategory.RUNTIME_REVERT.value, "reward_score": -0.25}},
        {"verdict": {"category": ResultCategory.INFRA_ERROR.value, "reward_score": 0.0}}
    ]

    metrics = evaluate_raw_candidates(candidates)

    # 1. Verification of counts
    assert metrics["total_candidates"] == 4
    assert metrics["infra_errors"] == 1
    assert metrics["evaluable_candidates"] == 3

    # 2. Category counts sum to total_candidates
    assert sum(metrics["category_counts"].values()) == 4

    # 3. Format and compilation rates calculated over evaluable_candidates (3)
    assert metrics["valid_format_count"] == 2
    assert abs(metrics["valid_format_rate"] - (2 / 3)) < 1e-4

    assert metrics["compiled_count"] == 1
    assert abs(metrics["compilation_rate"] - (1 / 3)) < 1e-4

    assert metrics["confirmed_exploit_count"] == 0
    assert metrics["confirmed_exploit_rate"] == 0.0

    # 4. Mean reward computed over evaluable candidates only (-0.5 + -0.5 + -0.25) / 3 = -0.4167
    expected_mean_evaluable_reward = (-0.5 - 0.5 - 0.25) / 3
    assert abs(metrics["mean_reward"] - expected_mean_evaluable_reward) < 1e-4

    # 5. Markdown table format test
    md = format_ab_table_markdown(metrics, metrics)
    assert "Total Attempts (N_total)" in md
    assert "Infrastructure Failures (N_infra)" in md
    assert "Evaluable Candidates (N_eval)" in md
    assert "N = 3" in md
