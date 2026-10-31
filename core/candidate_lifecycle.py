"""
core/candidate_lifecycle.py

Comprehensive Candidate Lifecycle, Ranking Policy, and Replay Orchestration (Round 4).
Ensures all candidates (initial and refinement) are tracked in an ordered collection,
ranked by an explicit documented policy, and replayed with guaranteed candidate ID consistency.
"""

import time
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

from core.schemas import (
    ResultCategory,
    ExploitPayload,
    VerificationVerdict,
    TargetProgram,
    RLVRTrajectory,
    AttackHypothesis
)
from core.config import config


# Explicit Category Priority (lower number = higher ranking)
CATEGORY_PRIORITY: Dict[ResultCategory, int] = {
    ResultCategory.INVARIANT_BREACH_UNREPLAYED: 1,  # Breached invariant: top priority for replay
    ResultCategory.EXPLOIT_CONFIRMED: 2,            # Confirmed reproducible breach
    ResultCategory.SAFE_RUN: 3,                     # Solved compilation and execution, invariant held
    ResultCategory.RUNTIME_REVERT: 4,               # Valid compilation, reverted in EVM
    ResultCategory.COMPILATION_ERROR: 5,            # Solc compilation error
    ResultCategory.GENERATION_FORMAT_ERROR: 6,      # Format or contract interface error
    ResultCategory.CHEATCODE_DETECTED: 7,           # Prohibited cheatcode attempt
    ResultCategory.INFRA_ERROR: 8,                  # Infrastructure / environment failure
}


class CandidateRecord(BaseModel):
    """
    Immutable audit record for a single generated exploit candidate.
    Preserved across both initial generation and multi-round refinement.
    """
    candidate_id: str
    run_id: str
    target_name: str
    generation_iteration: int = Field(default=0, description="0 for initial batch, 1..N for refinement")
    candidate_index: int = Field(default=0)
    payload: ExploitPayload
    verdict: VerificationVerdict
    model_id: str = Field(default="default")
    checkpoint_id: str = Field(default="base")
    prompt_text: str = Field(default="", description="Original generation prompt passed to LLM")
    prompt_hash: str = Field(default="")
    timestamp: float = Field(default_factory=time.time)
    replay_eligible: bool = False
    reproduced: bool = False
    dataset_partition: str = Field(default="production", description="production, synthetic_control, or test")
    is_synthetic: bool = Field(default=False)
    token_provenance: str = Field(default="model_generate", description="model_generate, external_text_only, or synthetic")
    trainable: bool = Field(default=True)


def compute_prompt_hash(prompt_str: str) -> str:
    """Computes a collision-resistant SHA-256 hash of normalized prompt text."""
    normalized = " ".join(prompt_str.strip().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def candidate_rank_key(cand: CandidateRecord) -> Tuple[int, float, int, int]:
    """
    Explicit multi-factor ranking key for candidate comparison:
    1. Category Priority (1 = INVARIANT_BREACH_UNREPLAYED, ..., 8 = INFRA_ERROR)
    2. Negative Reward Score (-reward_score, so higher reward comes first)
    3. Negative Iteration (-generation_iteration, giving refinement precedence on equal reward)
    4. Candidate Index (lower index comes first for determinism)
    """
    priority = CATEGORY_PRIORITY.get(cand.verdict.category, 99)
    # Return tuple for sorting in ascending order
    return (
        priority,
        -cand.verdict.reward_score,
        -cand.generation_iteration,
        cand.candidate_index
    )


def rank_candidates(candidates: List[CandidateRecord]) -> List[CandidateRecord]:
    """
    Ranks an ordered collection of candidates according to the explicit documented policy.
    Does not drop any candidate from the collection.
    """
    return sorted(candidates, key=candidate_rank_key)


def select_candidate_for_replay(candidates: List[CandidateRecord]) -> Optional[CandidateRecord]:
    """
    Selects the best candidate eligible for independent replay.
    
    CRITICAL POLICY:
    - Only candidates with category INVARIANT_BREACH_UNREPLAYED are eligible for replay.
    - If multiple candidates breached the invariant, the highest-ranked one is selected.
    - If no candidate breached the invariant, returns None (replay is NOT attempted).
    """
    eligible = [
        c for c in candidates
        if c.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED
    ]
    if not eligible:
        return None
    ranked_eligible = rank_candidates(eligible)
    return ranked_eligible[0]


def finalize_candidate_replay(
    candidate: CandidateRecord,
    replay_success: bool,
    replay_infra_error: bool = False
) -> CandidateRecord:
    """
    Applies independent replay outcome to the candidate record.
    Asserts candidate IDs match and enforces strict category/reward invariants.
    """
    # Strict candidate ID identity assertion
    assert candidate.candidate_id == candidate.payload.candidate_id, (
        f"Candidate ID mismatch: record '{candidate.candidate_id}' vs payload '{candidate.payload.candidate_id}'"
    )
    assert candidate.candidate_id == candidate.verdict.candidate_id, (
        f"Candidate ID mismatch: record '{candidate.candidate_id}' vs verdict '{candidate.verdict.candidate_id}'"
    )

    if replay_infra_error:
        # Replay failed due to infrastructure (e.g. sandbox container failure)
        candidate.verdict.category = ResultCategory.INFRA_ERROR
        candidate.verdict.reward_score = config.REWARD_INFRA_ERROR
        candidate.verdict.is_verified = False
        candidate.verdict.reproducible = False
        candidate.verdict.replay_status = "INFRA_ERROR"
        candidate.reproduced = False
        candidate.trainable = False
    elif replay_success:
        # Replay confirmed 100% deterministic reproducibility
        candidate.verdict.category = ResultCategory.EXPLOIT_CONFIRMED
        candidate.verdict.reward_score = config.REWARD_INVARIANT_BREACH  # +1.00
        candidate.verdict.is_verified = True
        candidate.verdict.reproducible = True
        candidate.verdict.replay_status = "CONFIRMED"
        candidate.reproduced = True
    else:
        # Flaky / non-reproducible run
        candidate.verdict.category = ResultCategory.INVARIANT_BREACH_UNREPLAYED
        candidate.verdict.reward_score = config.REWARD_BREACH_NO_REPLAY  # +0.50
        candidate.verdict.is_verified = False
        candidate.verdict.reproducible = False
        candidate.verdict.replay_status = "FAILED"
        candidate.reproduced = False

    return candidate


def create_finalized_trajectory(
    candidate: CandidateRecord,
    target: TargetProgram,
    evaluator_version: str = "v2.0",
    dataset_split: str = "train",
    dataset_partition: Optional[str] = None,
    is_synthetic: Optional[bool] = None,
    token_provenance: Optional[str] = None,
    trainable: Optional[bool] = None
) -> RLVRTrajectory:
    """
    Constructs an immutable, schema-validated RLVRTrajectory from a finalized candidate record.
    Rejects candidates with INFRA_ERROR or unfinalized states from entering training groups.
    Ensures prompt_used strictly contains the original generation prompt, NOT model completion.
    Enforces strict provenance attributes for synthetic control isolation (Round 5.2).
    """
    traj_id = f"traj_{candidate.run_id}_{candidate.candidate_id}"
    actual_prompt = candidate.prompt_text or candidate.payload.prompt_text or target.source_code
    actual_prompt_hash = compute_prompt_hash(actual_prompt)
    full_completion = candidate.payload.raw_model_response or candidate.payload.test_code
    
    # Resolve provenance metadata
    part = dataset_partition if dataset_partition is not None else candidate.dataset_partition
    synth = is_synthetic if is_synthetic is not None else candidate.is_synthetic
    
    # Token provenance resolution
    if token_provenance is not None:
        tok_prov = token_provenance
    elif synth:
        tok_prov = "synthetic"
    elif candidate.payload.generated_token_ids is not None and len(candidate.payload.generated_token_ids) > 0:
        tok_prov = candidate.token_provenance or "model_generate"
    else:
        tok_prov = "external_text_only"
        
    # Trainable eligibility resolution
    if trainable is not None:
        is_trainable = trainable
    elif synth or candidate.verdict.category == ResultCategory.INFRA_ERROR:
        is_trainable = False
    else:
        is_trainable = candidate.trainable

    return RLVRTrajectory(
        trajectory_id=traj_id,
        candidate_id=candidate.candidate_id,
        run_id=candidate.run_id,
        target_name=target.name,
        target_code=target.source_code,
        model_id=candidate.model_id,
        checkpoint_id=candidate.checkpoint_id,
        prompt_hash=actual_prompt_hash,
        generation_iteration=candidate.generation_iteration,
        candidate_index=candidate.candidate_index,
        evaluator_version=evaluator_version,
        is_finalized=True,
        replay_status=candidate.verdict.replay_status,
        timestamp=candidate.timestamp,
        slither_hints=target.slither_findings,
        prompt_used=actual_prompt,
        hypothesis=candidate.payload.hypothesis,
        full_completion_text=full_completion,
        generated_exploit=candidate.payload.test_code,
        reward=candidate.verdict.reward_score,
        category=candidate.verdict.category,
        is_verified=candidate.verdict.is_verified,
        reproduced=candidate.verdict.reproducible,
        feedback_trace=candidate.verdict.feedback,
        dataset_split=dataset_split,
        dataset_partition=part,
        is_synthetic=synth,
        token_provenance=tok_prov,
        trainable=is_trainable,
        generated_token_ids=candidate.payload.generated_token_ids
    )
