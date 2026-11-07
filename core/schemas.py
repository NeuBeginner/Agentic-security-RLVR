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
    contract_name_normalized: bool = Field(default=False, description="Whether the executable contract name was mechanically repaired")
    original_contract_name: str = Field(default="", description="Contract name before mechanical normalization")
    
    # Candidate lifecycle & exact token lineage tracking (Round 4/5)
    candidate_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    run_id: str = Field(default="run-default")
    generation_iteration: int = Field(default=0, description="0 for initial batch, 1..N for refinement")
    candidate_index: int = Field(default=0)
    prompt_text: str = Field(default="", description="Original generation prompt passed to LLM")
    generated_token_ids: Optional[List[int]] = Field(default=None, description="Exact token IDs from LLM generation")


class ExecutionEvidence(BaseModel):
    """Cryptographic and execution evidence collected from the isolated EVM sandbox."""
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    candidate_id: str = Field(default="")
    target_id: str = Field(default="")
    initial_state_hash: str = Field(default="", description="SHA-256 hash of pre-execution contract state/balances")
    final_state_hash: str = Field(default="", description="SHA-256 hash of post-execution contract state/balances")
    execution_status: str = Field(default="SUCCESS", description="SUCCESS, REVERT, TIMEOUT, COMPILATION_FAIL, INFRA_ERROR")
    execution_success: bool = Field(default=False)
    gas_used: Optional[int] = None
    revert_reason: Optional[str] = None
    logs_reference: List[str] = Field(default_factory=list)
    environment_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    state_delta: Dict[str, Any] = Field(default_factory=dict)


class InvariantResult(BaseModel):
    """Evaluation outcome for an individual formal security invariant."""
    invariant_id: str = Field(..., description="Unique invariant identifier (e.g. INV-VAULT-01-SOLVENCY)")
    invariant_name: str = Field(..., description="Human-readable invariant name")
    passed: bool = Field(..., description="True if invariant remained unbroken; False if breached/violated")
    observed_value: Any = Field(default=None, description="Actual observed metric value (e.g., balance, deficit)")
    expected_condition: str = Field(default="", description="Formal condition expected to hold")
    evidence_reference: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    """Independent verification result separating execution, invariant breach, and replay."""
    execution_success: bool = Field(..., description="Whether the scenario executed to completion without unhandled error")
    invariant_breach: bool = Field(..., description="Whether at least one security invariant was verifiably breached")
    replay_confirmed: bool = Field(default=False, description="Whether the breach was independently reproduced")
    confidence_status: str = Field(default="UNVERIFIED", description="UNVERIFIED, PROVISIONAL_BREACH, REPLAY_CONFIRMED, REJECTED, INFRA_FAILURE")
    evidence: Optional[ExecutionEvidence] = None
    invariant_results: List[InvariantResult] = Field(default_factory=list)
    breached_invariants: List[str] = Field(default_factory=list)
    failure_reason: Optional[str] = None


class VulnerabilityHypothesis(BaseModel):
    """Structured hypothesis generated from auditor findings or static analysis signals."""
    hypothesis_id: str = Field(default_factory=lambda: f"hyp_{uuid.uuid4().hex[:8]}")
    target_id: str = Field(..., description="Target contract identifier")
    source_finding_id: Optional[str] = Field(default=None, description="Originating finding ID from auditor/Slither")
    vulnerability_class: str = Field(..., description="Standardized vulnerability class (Reentrancy, ERC4626Inflation, etc.)")
    affected_contract: str = Field(..., description="Name of affected contract")
    affected_function: Optional[str] = Field(default=None, description="Target function under attack")
    attack_preconditions: List[str] = Field(default_factory=list)
    attack_sequence: List[str] = Field(default_factory=list)
    expected_invariant: str = Field(default="", description="Invariant expected to be violated")
    severity: str = Field(default="Medium", description="Critical, High, Medium, Low")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    validation_status: str = Field(
        default="proposed",
        description="proposed, normalized, prioritized, generated, tested, confirmed, rejected, inconclusive"
    )
    evidence: Optional[Dict[str, Any]] = None
    attempt_count: int = Field(default=0)
    last_error: Optional[str] = None


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
    evidence: Optional[ExecutionEvidence] = None
    invariant_results: List[InvariantResult] = Field(default_factory=list)
    verification_result: Optional[VerificationResult] = None


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
    evidence: Optional[ExecutionEvidence] = None
    verification_result: Optional[VerificationResult] = None
    hypothesis_id: Optional[str] = None


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
    # Provenance and Lifecycle Fields (Round 5.4: No unsafe defaults)
    # Defaulting to None guarantees unpopulated raw fields never masquerade as eligible production data.
    is_finalized: Optional[bool] = Field(default=None, description="Must be True before entering GRPO training")
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
    dataset_split: Optional[str] = Field(default="train", description="train, val, holdout, or test")
    dataset_partition: Optional[str] = Field(default=None, description="production, synthetic_control, or test")
    is_synthetic: Optional[bool] = Field(default=None, description="True if generated by synthetic control harness")
    token_provenance: Optional[str] = Field(default=None, description="model_generate, external_text_only, or synthetic")
    trainable: Optional[bool] = Field(default=None, description="True if eligible for GRPO optimization")
    generated_token_ids: Optional[List[int]] = Field(default=None)
    contract_name_normalized: bool = Field(default=False)
    original_contract_name: str = Field(default="")
    evidence: Optional[ExecutionEvidence] = None
    invariant_results: List[InvariantResult] = Field(default_factory=list)
    hypothesis_id: Optional[str] = None

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

        # 2. Partition and Provenance validation
        valid_partitions = {"production", "synthetic_control", "test"}
        if self.dataset_partition is not None and self.dataset_partition not in valid_partitions:
            raise ValueError(f"RLVRTrajectory rejected: invalid dataset_partition '{self.dataset_partition}', must be one of {valid_partitions}")

        valid_provenances = {"model_generate", "external_text_only", "synthetic"}
        if self.token_provenance is not None and self.token_provenance not in valid_provenances:
            raise ValueError(f"RLVRTrajectory rejected: invalid token_provenance '{self.token_provenance}', must be one of {valid_provenances}")

        if self.is_synthetic is True:
            if self.dataset_partition == "production":
                raise ValueError("RLVRTrajectory rejected: synthetic trajectories cannot have dataset_partition='production'")
            if self.trainable is True:
                raise ValueError("RLVRTrajectory rejected: synthetic trajectories cannot have trainable=True")

        if self.category == ResultCategory.INFRA_ERROR:
            if self.trainable is True:
                raise ValueError("RLVRTrajectory rejected: INFRA_ERROR trajectories cannot have trainable=True")

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
