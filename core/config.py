import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineConfig:
    # Modal Application Settings
    APP_NAME: str = "aegis-rlvr-security"
    MODEL_VOLUME_NAME: str = "aegis-model-cache"
    MODEL_CACHE_DIR: str = "/vol/models/huggingface"
    TRAJECTORY_DIR: str = "/vol/models/trajectories"
    
    # Primary API Generator (Gemini Flash Frontier Reasoning)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = "gemini-2.5-flash"
    
    # GPU Audit Model (Modal GPU Worker)
    AUDIT_GPU_MODEL: str = "qtum/Qwen3-Coder-30B-A3B-Audit"
    AUDIT_GPU_TYPE: str = "H100"
    
    # Fast reasoning agent fallback (Modal T4 for Dev/CI)
    DEV_GPU_MODEL: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    DEV_GPU_TYPE: str = "T4"
    
    # Static Analysis Layer
    ENABLE_SLITHER: bool = True
    
    # Sandboxed Foundry Execution limits
    SANDBOX_TIMEOUT_SEC: int = 60
    SANDBOX_CPU_CORES: float = 2.0
    SANDBOX_MEMORY_MB: int = 2048
    
    # Scalable Parallelism & Verification Parameters
    DEFAULT_PARALLEL_CANDIDATES: int = 5
    MAX_REFINEMENT_ROUNDS: int = 3
    ENABLE_INDEPENDENT_REPLAY: bool = True
    
    # Solidity / EVM settings
    SOLC_VERSION: str = "0.8.20"
    
    # RLVR Reward Shaping (Multi-Factor & Reproducibility)
    REWARD_INVARIANT_BREACH: float = 1.0       # Verified Exploit + Confirmed Independent Replay
    REWARD_BREACH_NO_REPLAY: float = 0.5      # Invariant breached once, but non-reproducible
    REWARD_RUNTIME_REVERT: float = -0.25      # Compiled cleanly, but reverted during EVM runtime
    REWARD_COMPILATION_FAIL: float = -0.5     # solc / forge compilation error
    REWARD_FORMAT_ERROR: float = -0.5         # Malformed model response / missing contract ExploitModule
    REWARD_SAFE_RUN: float = -0.1             # Clean execution, no invariant breached
    REWARD_TIMEOUT: float = -0.3              # Out of gas / infinite loop
    REWARD_CHEATCODE_PENALTY: float = -1.0    # Attempted to use Foundry cheatcodes / sandbox escape
    REWARD_INFRA_ERROR: float = 0.0           # Infrastructure / harness environment failure (neutral)

    # GRPO Policy Optimization Parameters
    GRPO_GROUP_SIZE: int = 4
    GRPO_LEARNING_RATE: float = 5e-6
    GRPO_BETA_KL: float = 0.04
    GRPO_CLIP_EPS: float = 0.2
    GRPO_LORA_R: int = 16
    GRPO_LORA_ALPHA: int = 32
    GRPO_LORA_DROPOUT: float = 0.05
    GRPO_CHECKPOINT_DIR: str = "/vol/models/checkpoints"
    GRPO_TARGET_MODULES: tuple = (
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    )


config = PipelineConfig()
