import os
from dataclasses import dataclass
from typing import Optional


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

    # Mechanical repair of the harness-mandated contract name.
    # When enabled, a single top-level contract with a different name is renamed to
    # `ExploitModule` before validation, so otherwise-valid candidates reach the EVM
    # harness and can produce a verifiable reward instead of dying at the format gate.
    # The strict validator itself is unchanged and remains available for direct use.
    ENABLE_CONTRACT_NAME_NORMALIZATION: bool = True

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
    # Format failures are mechanically cheap to fix (interface shape, contract name),
    # while compilation failures require real semantic repair of the exploit logic.
    # Keeping them distinct gives the policy a usable gradient: a candidate that only
    # misses the interface is strictly closer to success than one whose logic does not
    # compile, so the reward must reflect that ordering.
    REWARD_FORMAT_ERROR: float = -0.35        # Malformed model response / missing contract ExploitModule
    REWARD_SAFE_RUN: float = -0.1             # Clean execution, no invariant breached
    REWARD_TIMEOUT: float = -0.3              # Out of gas / infinite loop
    REWARD_CHEATCODE_PENALTY: float = -1.0    # Attempted to use Foundry cheatcodes / sandbox escape
    REWARD_INFRA_ERROR: float = 0.0           # Infrastructure / harness environment failure (neutral)

    # -------------------------------------------------------------------------
    # Reward Specification 2.0.0 (evidence-scoped components)
    # -------------------------------------------------------------------------
    # The total reward is decomposed into five mutually exclusive evidence
    # classes (generation / compilation / verification / invariant / replay)
    # plus a single outcome penalty. The totals are byte-compatible with the
    # legacy ladder above, so stored trajectories and the schema invariants stay
    # valid, while every component can be traced back to exactly one trusted
    # evidence source. See core/reward_shaping.py for the full contract.
    REWARD_SPEC_VERSION: str = "2.0.0"
    REWARD_COMPONENT_GENERATION: float = 0.05    # static format gate accepted the candidate
    REWARD_COMPONENT_COMPILATION: float = 0.10   # trusted compiler accepted the candidate
    REWARD_COMPONENT_VERIFICATION: float = 0.10  # candidate executed in the EVM without reverting
    REWARD_COMPONENT_INVARIANT: float = 0.25     # trusted harness oracle confirmed the breach
    REWARD_COMPONENT_REPLAY: float = 0.50        # independent fresh-EVM run reproduced the breach
    # Outcome penalties (the deficit of the failing stage). Each is calibrated so
    # that sum(components) + penalty reproduces the legacy reward constant above.
    REWARD_PENALTY_FORMAT: float = -0.35
    REWARD_PENALTY_CHEATCODE: float = -1.0
    REWARD_PENALTY_INFRA: float = 0.0
    REWARD_PENALTY_COMPILATION: float = -0.55
    REWARD_PENALTY_REVERT: float = -0.40
    REWARD_PENALTY_TIMEOUT: float = -0.45
    REWARD_PENALTY_SAFE_RUN: float = -0.35
    REWARD_PENALTY_BREACH: float = 0.0

    # GRPO training remains blocked unless explicitly disabled by the operator.
    # The decision is NOT taken here: it is taken by ``is_training_blocked`` at
    # the moment of the call, because the environment of the container is read
    # when the container starts - long after this module was imported.
    #
    # ``TRAINING_BLOCKED`` is kept as a **default**, not as a decision: it says
    # what the gate does when the environment says nothing at all.
    TRAINING_BLOCKED: bool = True

    # The maximum length of one GRPO rollout (prompt + completion) in tokens.
    # A rollout that does not fit is never silently truncated into a lie: it is
    # skipped (fail closed) and counted in the diagnostics of the trainer.
    GRPO_MAX_SEQ_LEN: int = 4096

    # GRPO GPU and Model Settings (PoC default to un-gated Qwen 1.5B on H100)
    GRPO_GPU_TYPE: str = "H100"
    GRPO_BASE_MODEL: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct"

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


# =============================================================================
# The fail-closed training gate
# =============================================================================
# Two environment variables carry the state of the gate, and **both** of them
# must permit the training before a single optimizer step may run:
#
# * ``TRAINING_STATUS`` - the status of the training run. ``BLOCKED`` (the
#   default) forbids the training; ``UNBLOCKED``/``ENABLED``/``RUNNING`` permit it.
# * ``TRAINING_BLOCKED`` - the explicit flag of the gate. ``true``/``1``/``yes``/
#   ``on`` forbid the training; only an explicit false spelling permits it.
#
# The decision is read **at the moment of the call**, never at import time: the
# container reads its environment when it starts, and a configuration object that
# was built at import time carries a value that the operator may have changed
# in the meantime. Every unknown or missing spelling fails closed.

#: The environment variable that carries the status of the training run.
TRAINING_STATUS_ENV = "TRAINING_STATUS"

#: The environment variable that carries the explicit flag of the gate.
TRAINING_BLOCKED_ENV = "TRAINING_BLOCKED"

#: The spellings of ``TRAINING_STATUS`` that forbid the training.
_TRAINING_STATUS_BLOCKED = {"blocked", "disabled", "off", "0", "false", "no"}

#: The spellings of ``TRAINING_STATUS`` that permit the training.
_TRAINING_STATUS_ALLOWED = {"unblocked", "enabled", "on", "1", "true", "yes", "running", "allow", "allowed"}

#: The spellings of ``TRAINING_BLOCKED`` that forbid the training.
_TRAINING_FLAG_BLOCKED = {"1", "true", "yes", "on", "enabled", "blocked"}

#: The spellings of ``TRAINING_BLOCKED`` that permit the training.
_TRAINING_FLAG_ALLOWED = {"0", "false", "no", "off", "disabled", "unblocked"}


def _read_env(name: str) -> str:
    """The current value of an environment variable (never cached)."""
    return os.environ.get(name, "").strip()


def is_training_blocked(cfg: Optional["PipelineConfig"] = None) -> bool:
    """
    Whether GRPO training is blocked - decided **now**, from the live environment.

    The gate is fail-closed: a missing or unreadable variable blocks the
    training, and an unknown spelling blocks it as well. The training may only
    run when **both** variables permit it:

    * ``TRAINING_STATUS`` is not ``BLOCKED`` (default: ``BLOCKED``);
    * ``TRAINING_BLOCKED`` is explicitly false (default: ``true``).

    A state in which one variable permits the training and the other forbids it
    is a contradiction - the operator's intent is ambiguous - and the function
    refuses it with an explicit ``RuntimeError`` that names **both** variables
    and their current values. Nothing is guessed, and nothing is unblocked by
    accident.

    :param cfg: the configuration whose default is used when the environment
        says nothing at all. Defaults to the module-level ``config``.
    :raises RuntimeError: when the two variables contradict each other.
    """
    configuration = cfg if cfg is not None else config

    raw_status = _read_env(TRAINING_STATUS_ENV)
    raw_flag = _read_env(TRAINING_BLOCKED_ENV)

    status = raw_status.lower() if raw_status else "blocked"
    flag = raw_flag.lower() if raw_flag else ""

    if status in _TRAINING_STATUS_ALLOWED:
        status_permits = True
    elif status in _TRAINING_STATUS_BLOCKED:
        status_permits = False
    else:
        # An unknown status fails closed.
        status_permits = False

    if flag in _TRAINING_FLAG_ALLOWED:
        flag_permits = True
    elif flag in _TRAINING_FLAG_BLOCKED:
        flag_permits = False
    elif flag:
        # An unknown spelling of the flag fails closed.
        flag_permits = False
    else:
        # The environment says nothing: the default of the configuration
        # decides, and that default blocks the training.
        flag_permits = not bool(getattr(configuration, "TRAINING_BLOCKED", True))

    if status_permits != flag_permits:
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: the training gate is contradictory. "
            f"{TRAINING_STATUS_ENV}={raw_status or '<unset>'} says "
            f"{'training is permitted' if status_permits else 'training is forbidden'}, "
            f"but {TRAINING_BLOCKED_ENV}={raw_flag or '<unset>'} says "
            f"{'training is permitted' if flag_permits else 'training is forbidden'}. "
            f"Both {TRAINING_STATUS_ENV} and {TRAINING_BLOCKED_ENV} must permit the "
            "training before a single optimizer step may run. Execution aborted fail-closed."
        )

    return not (status_permits and flag_permits)


__all__ = [
    "PipelineConfig",
    "config",
    "is_training_blocked",
    "TRAINING_STATUS_ENV",
    "TRAINING_BLOCKED_ENV",
]
