"""
tests/test_round5_2_token_lineage.py

Regression & Integration tests for AI Supervisor Round 5.2 Blockers 1 & 2:
1. Real token lineage: model.generate() -> persistence -> loader.
2. Complete end-to-end GRPO data path with diagnostic forward/loss (NO OPTIMIZER STEP).

Verifies:
- Direct call to causal LM model.generate().
- Exact slice matching: stored generated_token_ids == output_ids[len(input_ids):].
- Strict non-mixing between initial generation and refinement token lineages.
- Fail-closed exclusion of external_text_only records when require_exact_tokens=True.
- Full round-trip persistence and schema integrity.
- Diagnostic forward/loss pass verifying shapes, boundaries, masks, and finite loss without weight updates.
"""

import json
import pytest
import torch
from transformers import AutoTokenizer, Qwen2Config, Qwen2ForCausalLM

from core.schemas import (
    RLVRTrajectory,
    ResultCategory,
    TargetProgram,
    ExploitPayload,
    VerificationVerdict,
    AttackHypothesis
)
from core.candidate_lifecycle import (
    CandidateRecord,
    create_finalized_trajectory,
    compute_prompt_hash
)
from core.llm_generator import (
    SOLIDITY_SYSTEM_PROMPT,
    build_analysis_prompt,
    build_refinement_prompt,
    parse_model_response
)
from core.grpo_trainer import (
    load_trajectories_from_directory,
    group_rollouts_by_prompt,
    prepare_rollout_tokens,
    get_token_logprobs,
    compute_rollout_baselines
)


@pytest.fixture(scope="module")
def qwen_model_and_tokenizer():
    """Initializes a real Qwen2 causal LM on CPU with matching vocabulary (151665 tokens)."""
    tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-1.5B-Instruct")
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Lightweight causal LM with identical tokenizer vocab, executing real HuggingFace generate()
    config = Qwen2Config(
        vocab_size=151665,
        hidden_size=64,
        intermediate_size=128,
        num_hidden_layers=2,
        num_attention_heads=4,
        num_key_value_heads=2
    )
    model = Qwen2ForCausalLM(config)
    model.eval()
    return model, tokenizer


def test_real_model_generate_token_lineage(qwen_model_and_tokenizer, tmp_path):
    """
    Supervisor Blocker 1:
    Executes actual causal LM model.generate().
    Proves stored generated_token_ids strictly equal output_ids[len(input_ids):].
    Verifies round-trip persistence: generate -> CandidateRecord -> trajectory file -> loader.
    """
    model, tokenizer = qwen_model_and_tokenizer
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint256) public balances; }",
        language="solidity",
        invariants=["Depositor Solvency"]
    )

    # 1. Build chat-templated initial prompt
    user_prompt = build_analysis_prompt(target)
    messages = [
        {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]
    formatted_prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    model_inputs = tokenizer([formatted_prompt], return_tensors="pt")
    prompt_len = model_inputs.input_ids.shape[1]
    prompt_ids_list = model_inputs.input_ids[0].tolist()

    # 2. Call real model.generate()
    torch.manual_seed(42)
    with torch.no_grad():
        outputs = model.generate(
            **model_inputs,
            max_new_tokens=24,
            do_sample=False
        )

    raw_output_ids = outputs[0].tolist()
    # Exact generation slice after separating prompt tokens
    exact_generated_ids = raw_output_ids[prompt_len:]
    assert len(exact_generated_ids) > 0, "model.generate() must produce non-empty completion tokens"

    # 3. Decode completion and parse response
    response_text = tokenizer.decode(exact_generated_ids, skip_special_tokens=False)
    payload = parse_model_response(
        target,
        response_text,
        attempt_idx=1,
        generated_token_ids=exact_generated_ids,
        prompt_text=formatted_prompt
    )

    # Invariant: stored generated_token_ids matches exact slice 100% bitwise!
    assert payload.generated_token_ids == exact_generated_ids
    assert payload.prompt_text == formatted_prompt

    # 4. Create candidate record
    candidate = CandidateRecord(
        candidate_id="cand_init_1",
        run_id="run_lineage_test",
        target_name=target.name,
        generation_iteration=0,
        candidate_index=1,
        payload=payload,
        verdict=VerificationVerdict(
            target_name=target.name,
            is_verified=False,
            reward_score=0.5,
            category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
            vulnerability_type="ReentrancyDrain",
            poc_code=payload.test_code,
            feedback="Initial generation verdict"
        ),
        prompt_text=formatted_prompt,
        prompt_hash=compute_prompt_hash(formatted_prompt),
        model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        checkpoint_id="base",
        dataset_partition="production",
        is_synthetic=False,
        token_provenance="model_generate",
        trainable=True
    )
    assert candidate.payload.generated_token_ids == exact_generated_ids

    # 5. Round-trip: Persist trajectory and load via load_trajectories_from_directory
    traj = create_finalized_trajectory(candidate, target, dataset_partition="production")
    assert traj.prompt_used == formatted_prompt
    assert traj.generated_token_ids == exact_generated_ids
    assert traj.token_provenance == "model_generate"

    fpath = tmp_path / f"traj_{traj.trajectory_id}.json"
    fpath.write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    loaded_records = load_trajectories_from_directory(
        str(tmp_path),
        target_split="train",
        target_partition="production",
        require_exact_tokens=True
    )
    assert len(loaded_records) == 1
    loaded_item = loaded_records[0]
    assert loaded_item["generated_token_ids"] == exact_generated_ids
    assert loaded_item["prompt_used"] == formatted_prompt
    assert loaded_item["token_provenance"] == "model_generate"


def test_initial_vs_refinement_lineage_isolation(qwen_model_and_tokenizer):
    """
    Supervisor Blocker 1 (Part 4):
    Proves initial generation and refinement do NOT mix tokens, prompts, or iterations.
    """
    model, tokenizer = qwen_model_and_tokenizer
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint256) public balances; }",
        language="solidity",
        invariants=["Depositor Solvency"]
    )

    # Initial Prompt & Generation
    init_prompt = tokenizer.apply_chat_template(
        [{"role": "system", "content": SOLIDITY_SYSTEM_PROMPT}, {"role": "user", "content": build_analysis_prompt(target)}],
        tokenize=False,
        add_generation_prompt=True
    )
    init_inputs = tokenizer([init_prompt], return_tensors="pt")
    with torch.no_grad():
        init_out = model.generate(**init_inputs, max_new_tokens=16, do_sample=False)
    init_ids = init_out[0].tolist()[init_inputs.input_ids.shape[1]:]

    # Refinement Prompt & Generation
    ref_prompt = tokenizer.apply_chat_template(
        [{"role": "system", "content": SOLIDITY_SYSTEM_PROMPT}, {"role": "user", "content": build_refinement_prompt(target, "failed code", "Revert in EVM")}],
        tokenize=False,
        add_generation_prompt=True
    )
    ref_inputs = tokenizer([ref_prompt], return_tensors="pt")
    with torch.no_grad():
        ref_out = model.generate(**ref_inputs, max_new_tokens=16, do_sample=False)
    ref_ids = ref_out[0].tolist()[ref_inputs.input_ids.shape[1]:]

    assert init_prompt != ref_prompt, "Initial and refinement prompts must be distinct"
    assert init_ids != ref_ids, "Initial and refinement tokens must be distinct"

    # Verify candidate records keep their separate lineages
    cand_init = CandidateRecord(
        candidate_id="c_init",
        run_id="run_1",
        target_name=target.name,
        generation_iteration=0,
        payload=parse_model_response(target, "code", generated_token_ids=init_ids, prompt_text=init_prompt),
        verdict=VerificationVerdict(target_name=target.name, is_verified=False, reward_score=-0.25, category=ResultCategory.RUNTIME_REVERT, vulnerability_type="ExecutionRevert", poc_code="code", feedback="fb"),
        prompt_text=init_prompt,
        prompt_hash=compute_prompt_hash(init_prompt),
        token_provenance="model_generate"
    )

    cand_ref = CandidateRecord(
        candidate_id="c_ref",
        run_id="run_1",
        target_name=target.name,
        generation_iteration=1,
        payload=parse_model_response(target, "code", generated_token_ids=ref_ids, prompt_text=ref_prompt),
        verdict=VerificationVerdict(target_name=target.name, is_verified=False, reward_score=0.5, category=ResultCategory.INVARIANT_BREACH_UNREPLAYED, vulnerability_type="ReentrancyDrain", poc_code="code", feedback="fb"),
        prompt_text=ref_prompt,
        prompt_hash=compute_prompt_hash(ref_prompt),
        token_provenance="model_generate"
    )

    traj_init = create_finalized_trajectory(cand_init, target)
    traj_ref = create_finalized_trajectory(cand_ref, target)

    assert traj_init.generation_iteration == 0
    assert traj_init.generated_token_ids == init_ids
    assert traj_init.prompt_used == init_prompt

    assert traj_ref.generation_iteration == 1
    assert traj_ref.generated_token_ids == ref_ids
    assert traj_ref.prompt_used == ref_prompt


def test_external_text_only_excluded_from_exact_token_training(tmp_path):
    """
    Supervisor Blocker 1 (Part 5):
    External API completions without token IDs must be marked 'external_text_only'
    and strictly excluded from exact-lineage GRPO training.
    """
    target = TargetProgram(name="Vault", source_code="code", language="solidity", invariants=["inv"])
    payload = ExploitPayload(
        target_name=target.name,
        hypothesis=AttackHypothesis(vulnerability_type="Reentrancy", reasoning_trace="r", attack_vector="a"),
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id="gemini_cand_1",
        run_id="run_ext",
        prompt_text="external prompt",
        raw_model_response="completion without tokens",
        generated_token_ids=None  # No original token IDs from external API
    )
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=True,
        reward_score=1.0,
        category=ResultCategory.EXPLOIT_CONFIRMED,
        vulnerability_type="Reentrancy",
        poc_code=payload.test_code,
        feedback="ok",
        reproducible=True,
        replay_status="CONFIRMED"
    )

    traj = create_finalized_trajectory(
        CandidateRecord(
            candidate_id="gemini_cand_1",
            run_id="run_ext",
            target_name=target.name,
            payload=payload,
            verdict=verdict,
            prompt_text=payload.prompt_text,
            token_provenance="external_text_only"
        ),
        target,
        dataset_partition="production"
    )
    assert traj.token_provenance == "external_text_only"
    assert traj.generated_token_ids is None

    fpath = tmp_path / f"traj_{traj.trajectory_id}.json"
    fpath.write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    # Strict loader: require_exact_tokens=True MUST exclude it!
    loaded_strict = load_trajectories_from_directory(
        str(tmp_path),
        target_partition="production",
        require_exact_tokens=True
    )
    assert len(loaded_strict) == 0, "external_text_only record must NOT be admitted to exact-lineage training!"


def test_end_to_end_diagnostic_grpo_forward(qwen_model_and_tokenizer, tmp_path):
    """
    Supervisor Blocker 2:
    Full end-to-end data path from model.generate() to diagnostic training batch and forward/loss.
    STRICT SAFETY: NO optimizer step, NO weight updates, NO checkpoint modification.
    Verifies:
    - prompt_used contains full chat template with system prompt.
    - input_ids matches prompt_ids + completion_ids exactly without extra special tokens.
    - completion_mask is 0 on prompt and 1 on completion.
    - Diagnostic loss is computed and is a finite non-NaN float.
    """
    model, tokenizer = qwen_model_and_tokenizer
    target = TargetProgram(
        name="Vault",
        source_code="contract Vault { mapping(address => uint256) public balances; }",
        language="solidity",
        invariants=["Depositor Solvency"]
    )

    # 1. Generation
    prompt_str = tokenizer.apply_chat_template(
        [{"role": "system", "content": SOLIDITY_SYSTEM_PROMPT}, {"role": "user", "content": build_analysis_prompt(target)}],
        tokenize=False,
        add_generation_prompt=True
    )
    prompt_inputs = tokenizer([prompt_str], return_tensors="pt")
    prompt_token_count = prompt_inputs.input_ids.shape[1]
    expected_prompt_ids = prompt_inputs.input_ids[0].tolist()

    with torch.no_grad():
        gen_outputs = model.generate(**prompt_inputs, max_new_tokens=20, do_sample=False)
    generated_token_ids = gen_outputs[0].tolist()[prompt_token_count:]
    raw_completion_text = tokenizer.decode(generated_token_ids, skip_special_tokens=False)

    # 2. Candidate & Trajectory Persistence
    payload = parse_model_response(
        target,
        raw_completion_text,
        attempt_idx=1,
        generated_token_ids=generated_token_ids,
        prompt_text=prompt_str
    )
    candidate = CandidateRecord(
        candidate_id="e2e_cand_1",
        run_id="run_e2e",
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
        prompt_text=prompt_str,
        prompt_hash=compute_prompt_hash(prompt_str),
        model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        checkpoint_id="base",
        dataset_partition="production",
        is_synthetic=False,
        token_provenance="model_generate",
        trainable=True
    )
    traj = create_finalized_trajectory(candidate, target, dataset_partition="production")

    (tmp_path / f"traj_{traj.trajectory_id}.json").write_text(json.dumps(traj.model_dump(), indent=2), encoding="utf-8")

    # 3. Dataset Loader
    loaded_data = load_trajectories_from_directory(str(tmp_path), target_split="train", target_partition="production", require_exact_tokens=True)
    assert len(loaded_data) == 1

    # 4. Group Rollouts
    groups = group_rollouts_by_prompt([loaded_data[0], loaded_data[0]], group_size=2)
    assert len(groups) == 1
    group = groups[0]
    assert group.prompt == prompt_str

    # 5. Token preparation & Boundary verification
    r_item = group.rollouts[0]
    input_ids, attention_mask, completion_mask = prepare_rollout_tokens(
        prompt_str=group.prompt,
        completion_str=r_item.full_completion_text or r_item.exploit_code,
        tokenizer=tokenizer,
        device="cpu",
        stored_generated_token_ids=r_item.generated_token_ids
    )

    plen = len(expected_prompt_ids)
    extracted_prompt_ids = input_ids[0, :plen].tolist()
    extracted_completion_ids = input_ids[0, plen:].tolist()

    # Boundary verification: No extra BOS or duplicated system tokens!
    assert extracted_prompt_ids == expected_prompt_ids
    assert completion_mask[0, :plen].sum().item() == 0.0
    assert completion_mask[0, plen:].sum().item() == float(len(extracted_completion_ids))

    # 6. Diagnostic Forward & Loss Computation (NO OPTIMIZER STEP, NO WEIGHT UPDATES)
    model.eval()
    with torch.no_grad():
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        shift_logits = outputs.logits[:, :-1, :].contiguous()
        shift_labels = input_ids[:, 1:].contiguous()
        shift_mask = completion_mask[:, 1:].contiguous()

        log_probs = torch.nn.functional.log_softmax(shift_logits, dim=-1)
        per_token_lp = torch.gather(log_probs, 2, shift_labels.unsqueeze(-1)).squeeze(-1)
        masked_lp = per_token_lp * shift_mask
        diagnostic_loss = -masked_lp.sum() / max(1.0, shift_mask.sum().item())

    loss_val = diagnostic_loss.item()
    print(f"\n[Diagnostic Forward] Loss: {loss_val:.4f} | Completion Tokens: {shift_mask.sum().item()} | Input Shape: {list(input_ids.shape)}")

    assert not torch.isnan(diagnostic_loss), "Loss must not be NaN"
    assert not torch.isinf(diagnostic_loss), "Loss must not be Inf"
    assert loss_val > 0.0, "Cross-entropy loss must be positive"
