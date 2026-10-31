from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class TargetProgram(BaseModel):
    """Represents a code snippet or contract subjected to security auditing."""
    name: str = Field(..., description="Unique identifier or contract name (e.g. 'Vault')")
    source_code: str = Field(..., description="Raw source code of the target program")
    language: str = Field(default="solidity", description="Language of target (solidity, python, c)")
    invariants: List[str] = Field(default_factory=list, description="Formal security properties/invariants")


class AttackHypothesis(BaseModel):
    """Reasoning hypothesis formulated by the Generator agent."""
    vulnerability_type: str = Field(..., description="E.g., Reentrancy, AccessControl, IntegerUnderflow")
    reasoning_trace: str = Field(..., description="Chain of thought explaining the logical flaw")
    attack_vector: str = Field(..., description="Summary of how to trigger the vulnerability")


class ExploitPayload(BaseModel):
    """Executable proof-of-concept payload generated for verification."""
    target_name: str
    hypothesis: AttackHypothesis
    test_code: str = Field(..., description="Executable exploit code (ExploitModule contract)")
    test_filename: str = Field(default="ExploitModule.sol")
    attempt_number: int = Field(default=1)


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


class VerificationVerdict(BaseModel):
    """Final verified assessment with RLVR computed reward."""
    target_name: str
    is_verified: bool
    reward_score: float = Field(..., description="Calculated RLVR reward (-1.0 to 1.0)")
    vulnerability_type: str
    poc_code: str
    feedback: str
