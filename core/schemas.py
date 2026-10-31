import time
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


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


class ExecutionResult(BaseModel):
    """Structured result collected from the isolated Modal sandbox container."""
    return_code: int
    stdout: str
    stderr: str
    execution_time_sec: float
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
    vulnerability_type: str
    poc_code: str
    feedback: str
    state_delta_verified: bool = False
    reproducible: bool = False
    refinement_iteration: int = 1


class RLVRTrajectory(BaseModel):
    """
    Complete ground-truth trajectory pair formatted for GRPO / PPO policy training.
    Accumulated in Modal Volume to fine-tune the reasoning model on verified outputs.
    """
    trajectory_id: str
    timestamp: float = Field(default_factory=time.time)
    target_name: str
    target_code: str
    slither_hints: List[Dict[str, Any]]
    prompt_used: str
    hypothesis: AttackHypothesis
    generated_exploit: str
    reward: float
    is_verified: bool
    reproduced: bool
    feedback_trace: str
