from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineConfig:
    # Modal Application Settings
    APP_NAME: str = "aegis-rlvr-security"
    
    # Sandboxed execution limits
    SANDBOX_TIMEOUT_SEC: int = 45
    SANDBOX_CPU_CORES: float = 1.0
    SANDBOX_MEMORY_MB: int = 1024
    
    # Generator model settings
    GENERATOR_GPU: str = "L4"
    DEFAULT_MODEL_NAME: str = "Qwen/Qwen2.5-Coder-7B-Instruct"
    TEMPERATURE: float = 0.2
    MAX_TOKENS: int = 2048

    # RLVR Reward Shaping
    REWARD_INVARIANT_BREACH: float = 1.0      # Verified Exploit found
    REWARD_COMPILATION_FAIL: float = -0.5    # Broken syntax / compilation failure
    REWARD_SAFE_RUN: float = -0.1            # Clean execution, no invariant breached
    REWARD_TIMEOUT: float = -0.3             # Infinite loop or hang


config = PipelineConfig()
