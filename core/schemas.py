import time
import uuid
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, model_validator


class ResultCategory(str, Enum):
    """Granular classification of evaluation outcomes for reliable reward assignment."""
    INFRA_ERROR = "INFRA_ERROR"                                   # Harness / environment / toolchain failure
    GENERATION_FORMAT_ERROR = "GENERATION_FORMAT_ERROR"           # Model failed to output expected contract interface
    COMPILATION_ERROR = "COMPILATION_ERROR"                       # Syntax or semantic compilation error in candidate Solidity
    RUNTIME_REVERT = "RUNTIME_REVERT"                             # Compiled successfully, but attack reverted or failed logic check
    SAFE_RUN = "SAFE_RUN"                                         # Executed cleanly, but target security invariant remained unbroken
    CHEATCODE_DETECTED = "CHEATCODE_DETECTED"                     # Exploit attempted forbidden Foundry cheatcode (vm.*)
    INVARIANT_BREACH_UNREPLAYED = "INVARIANT_BREACH_UNREPLAYED"   # Invariant breached in single run, but NOT independently reproduced
    EXPLOIT_CONFIRMED = "EXPLOIT_CONFIRMED"                       # Verified invariant breach WITH independent replay confirmation


class TargetProgram(BaseModel):
    """Represents a code snippet or contract subjected to security auditing."""
    name: str = Field(..., description="Unique identifier or contract name")
    source_code: str = Field(..., description="Raw source code of the target program")
    language: str = Field(default="solidity", description="Language of target (solidity, python, c)")
    invariants: List[str] = Field(default_factory=list, description="Formal security properties/invariants")
    trusted_harness_code: Optional[str] = Field(
        default=None,
        description="Immutable, trusted Foundry test harness for EVM state verification"
    )
    slither_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Static analysis warnings extracted by Slither AST parser"
    )


class AttackHypothesis(BaseModel):
    """Reasoning hypothesis formulated by Auditor or Frontier Agent."""
    vulnerability_type: str = Field(..., description="E.g., Reentrancy, AccessControl, FirstDepositorInflation")
    reasoning_trace: str = Field(..., description="Chain of thought explaining the logical flaw")
    attack_vector: str = Field(..., description="Summary of how to trigger the vulnerability")
    affected_functions: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=1.0)


class ExploitPayload(BaseModel):
    """Executable proof-of-concept payload generated for verification."""
    target_name: str
    hypothesis: AttackHypothesis
    test_code: str = Field(..., description="Executable exploit code (ExploitModule contract)")
    test_filename: str = Field(default="ExploitModule.sol")
    attempt_number: int = Field(default=1)
    generator_engine: str = Field(default="local-gpu")  # e.g., "gemini-flash", "qwen-audit", "qwen-dev"
    raw_model_response: str = Field(default="", description="Preserved unedited text output from LLM for post-mortem")
    format_valid: bool = Field(default=True, description="Whether payload satisfies mandatory contract specifications")
    format_error_reason: str = Field(default="", description="Diagnostic reason if format_valid is False")
    
    # Candidate lifecycle & exact token lineage tracking (Round 4/5)
    candidate_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    run_id: str = Field(default="run-default")
    generation_iteration: int = Field(default=0, description="0 for initial batch, 1..N for refinement")
    candidate_index: int = Field(default=0)
    prompt_text: str = Field(default="", description="Original generation prompt passed to LLM")
    generated_token_ids: Optional[List[int]] = Field(default=None, description="Exact token IDs from LLM generation")


class ExecutionResult(BaseModel):
    """Structured result collected from the isolated Modal sandbox container."""
    return_code: int
    stdout: str
    stderr: str
    execution_time_sec: float
    category: ResultCategory = Field(default=ResultCategory.RUNTIME_REVERT)
    timed_out: bool = False
    invariant_violated: bool = False
    structured_json: Optional[Dict[str, Any]] = None
    test_status: Optional[str] = None       # "Success" or "Failure"
    revert_reason: Optional[str] = None     # Extracted EVM revert / panic reason
    decoded_logs: List[str] = Field(default_factory=list)
    cheatcode_detected: bool = False
    verified_by_harness: bool = False
    reproducibility_confirmed: bool = False
    gas_used: Optional[int] = None
    state_delta: Dict[str, Any] = Field(default_factory=dict)


class VerificationVerdict(BaseModel):
    """Final verified assessment with RLVR computed reward."""
    target_name: str
    is_verified: bool
    reward_score: float = Field(..., description="Calculated RLVR reward (-1.0 to 1.0)")
    category: ResultCategory = Field(default=ResultCategory.RUNTIME_REVERT)
    vulnerability_type: str
    poc_code: str
    feedback: str
    state_delta_verified: bool = False
    reproducible: bool = False
    refinement_iteration: int = 1
    
    # Candidate lifecycle & audit fields (Round 4)
    candidate_id: str = Field(default="")
    run_id: str = Field(default="run-default")
    generation_iteration: int = Field(default=0)
    candidate_index: int = Field(default=0)
    replay_status: str = Field(default="NOT_ELIGIBLE", description="CONFIRMED, FAILED, or NOT_ELIGIBLE")


class RLVRTrajectory(BaseModel):
    """
    Complete ground-truth trajectory pair formatted for GRPO / PPO policy training.
    Accumulated in Modal Volume to fine-tune the reasoning model on verified outputs.
    Strictly validated for schema integrity and category/reward invariants (Round 4).
    """
    trajectory_id: str
    candidate_id: str = Field(default="")
    run_id: str = Field(default="run-default")
    target_name: str
    target_code: str
    model_id: str = Field(default="default")
    checkpoint_id: str = Field(default="base")
    prompt_hash: str = Field(default="")
    generation_iteration: int = Field(default=0)
    candidate_index: int = Field(default=0)
    evaluator_version: str = Field(default="v2.0")
    is_finalized: bool = Field(default=True, description="Must be True before entering GRPO training")
    replay_status: str = Field(default="NOT_ELIGIBLE", description="CONFIRMED, FAILED, or NOT_ELIGIBLE")
    
    timestamp: float = Field(default_factory=time.time)
    slither_hints: List[Dict[str, Any]] = Field(default_factory=list)
    prompt_used: str = Field(default="")
    hypothesis: AttackHypothesis
    full_completion_text: str = Field(default="", description="Full model response text corresponding to generated_token_ids")
    generated_exploit: str
    reward: float
    category: ResultCategory = Field(default=ResultCategory.RUNTIME_REVERT)
    is_verified: bool
    reproduced: bool
    feedback_trace: str
    dataset_split: str = Field(default="train", description="train, val, or holdout")
    generated_token_ids: Optional[List[int]] = Field(default=None)

    @model_validator(mode="after")
    def validate_trajectory_invariants(self) -> "RLVRTrajectory":
        # 1. Missing IDs check
        if not self.trajectory_id or not self.trajectory_id.strip():
            raise ValueError("RLVRTrajectory rejected: trajectory_id must be non-empty")
        if not self.candidate_id or not self.candidate_id.strip():
            raise ValueError("RLVRTrajectory rejected: candidate_id must be non-empty")
        if not self.run_id or not self.run_id.strip():
            raise ValueError("RLVRTrajectory rejected: run_id must be non-empty")
        if not self.prompt_hash or not self.prompt_hash.strip():
            raise ValueError("RLVRTrajectory rejected: prompt_hash must be non-empty")

        # 2. Strict category / reward / replay consistency
        if self.category == ResultCategory.EXPLOIT_CONFIRMED:
            if not self.reproduced or not self.is_verified or self.replay_status != "CONFIRMED":
                raise ValueError(
                    f"Inconsistent trajectory: EXPLOIT_CONFIRMED requires reproduced=True, "
                    f"is_verified=True, and replay_status='CONFIRMED'. Got: "
                    f"reproduced={self.reproduced}, is_verified={self.is_verified}, replay_status='{self.replay_status}'"
                )
            if abs(self.reward - 1.0) > 1e-4:
                raise ValueError(f"Inconsistent trajectory: EXPLOIT_CONFIRMED requires reward=1.0, got {self.reward}")

        elif self.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
            if self.reproduced or self.is_verified:
                raise ValueError(
                    f"Inconsistent trajectory: INVARIANT_BREACH_UNREPLAYED cannot have reproduced=True "
                    f"or is_verified=True. Got reproduced={self.reproduced}, is_verified={self.is_verified}"
                )
            if abs(self.reward - 0.5) > 1e-4:
                raise ValueError(f"Inconsistent trajectory: INVARIANT_BREACH_UNREPLAYED requires reward=0.5, got {self.reward}")

        elif self.category == ResultCategory.INFRA_ERROR:
            if self.is_verified or abs(self.reward - 0.0) > 1e-4:
                raise ValueError(
                    f"Inconsistent trajectory: INFRA_ERROR must have is_verified=False and reward=0.0. "
                    f"Got is_verified={self.is_verified}, reward={self.reward}"
                )

        return self


class GRPORollout(BaseModel):
    """A single candidate rollout in a GRPO group."""
    candidate_id: str
    run_id: str = Field(default="run-default")
    model_id: str = Field(default="default")
    checkpoint_id: str = Field(default="base")
    prompt_hash: str = Field(default="")
    hypothesis: AttackHypothesis
    full_completion_text: str = Field(default="", description="Full model response text corresponding to generated_token_ids")
    exploit_code: str
    reward: float
    category: ResultCategory = Field(default=ResultCategory.RUNTIME_REVERT)
    is_verified: bool
    reproduced: bool
    feedback: str
    advantage: float = 0.0
    generated_token_ids: Optional[List[int]] = None


class GRPOGroup(BaseModel):
    """A group of K candidate rollouts for a single target contract and prompt."""
    group_id: str
    target_name: str
    prompt: str
    prompt_hash: str = Field(default="")
    model_id: str = Field(default="default")
    checkpoint_id: str = Field(default="base")
    system_prompt: str
    rollouts: List[GRPORollout]
    mean_reward: float = 0.0
    std_reward: float = 0.0


class GRPOTrainingStepStats(BaseModel):
    """Statistics logged from a GRPO policy optimization step."""
    step: int
    loss: float
    mean_reward: float
    mean_advantage: float
    kl_divergence: float
    learning_rate: float
