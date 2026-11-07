import os
import sys
import json
import time
import uuid
import modal
from typing import Optional, List, Dict, Any

# Ensure local core and sandbox packages are in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import config
from core.hypothesis_manager import HypothesisManager
from core.schemas import (
    TargetProgram,
    VulnerabilityHypothesis,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict,
    AttackHypothesis,
    RLVRTrajectory,
    ResultCategory
)
from core.candidate_lifecycle import (
    CandidateRecord,
    rank_candidates,
    select_candidate_for_replay,
    finalize_candidate_replay,
    create_finalized_trajectory,
    compute_prompt_hash
)
from core.evaluator import evaluate_execution_trace, create_trajectory_record
from core.reward_shaping import RewardEvidence, compute_reward_breakdown
from sandbox.runner import (
    sandbox_image,
    run_payload_in_sandbox,
    run_slither_analysis,
    verify_independent_replay
)
from core.llm_generator import (
    build_analysis_prompt,
    build_refinement_prompt,
    parse_model_response,
    synthesize_exploit_gemini,
    SOLIDITY_SYSTEM_PROMPT,
    AUDIT_DETECTOR_SYSTEM_PROMPT
)

# Initialize Modal Application
app = modal.App(name=config.APP_NAME)

# Persistent volume for caching model weights and GRPO training trajectories
model_volume = modal.Volume.from_name(config.MODEL_VOLUME_NAME, create_if_missing=True)

# GPU Image for reasoning and exploit synthesis engine
gpu_image = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install(
        "torch",
        "transformers>=4.40.0",
        "accelerate>=0.28.0",
        "peft>=0.14.0",
        "trl>=0.14.0",
        "pydantic>=2.0.0",
        "google-genai>=2.0.0",
    )
    .add_local_python_source("core", "sandbox")
)


# =============================================================================
# 1. PRODUCTION AUDIT AGENT (H100 - 30B Qtum Web3 Security Model)
# =============================================================================
@app.cls(
    gpu=config.AUDIT_GPU_TYPE,
    image=gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=1200,
)
class ProductionAuditAgent:
    """
    Production Web3 security reasoning agent on Modal H100.
    Operates in dual-mode:
    1. Native security auditor: detects vulnerabilities and outputs JSON finding arrays.
    2. Exploit synthesizer: generates executable unprivileged ExploitModule.
    """
    @modal.enter()
    def load_model(self):
        import os
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        cache_dir = config.MODEL_CACHE_DIR
        os.makedirs(cache_dir, exist_ok=True)
        
        print(f"[*] Initializing Production 30B Model on Modal {config.AUDIT_GPU_TYPE}: {config.AUDIT_GPU_MODEL}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            config.AUDIT_GPU_MODEL,
            cache_dir=cache_dir,
            trust_remote_code=True
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            config.AUDIT_GPU_MODEL,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            cache_dir=cache_dir,
            trust_remote_code=True
        )
        try:
            model_volume.commit()
            print("[✓] Model weights committed to persistent Modal Volume.")
        except Exception as e:
            print(f"[!] Volume commit notice: {e}")

    @modal.method()
    def audit_target_contract(self, target_dict: dict) -> list:
        """Native role: outputs structured JSON findings list."""
        import json
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import AUDIT_DETECTOR_SYSTEM_PROMPT, build_auditor_prompt

        target = TargetProgram(**target_dict)
        prompt = build_auditor_prompt(target)
        messages = [
            {"role": "system", "content": AUDIT_DETECTOR_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=1536,
                temperature=0.2,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        
        try:
            start_idx = response_text.find("[")
            end_idx = response_text.rfind("]")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                return json.loads(response_text[start_idx : end_idx + 1])
        except Exception:
            pass
        return [{"title": "Detected Vulnerability", "category": "LogicFlaw", "description": response_text[:300]}]

    @modal.method()
    def generate_solidity_exploit(self, target_dict: dict, temperature: float = 0.3, hypothesis_dict: Optional[dict] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> dict:
        import torch
        from core.schemas import TargetProgram, VulnerabilityHypothesis
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_analysis_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        hypothesis = VulnerabilityHypothesis(**hypothesis_dict) if hypothesis_dict else None
        user_prompt = build_analysis_prompt(
            target, hypothesis=hypothesis, previous_failures=previous_failures
        )
        messages = [
            {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=temperature,
                do_sample=(temperature > 0.0),
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        token_ids_list = generated_ids[0].tolist()
        return parse_model_response(
            target,
            response_text,
            attempt_idx=1,
            generated_token_ids=token_ids_list,
            prompt_text=text,
            hypothesis=hypothesis
        ).model_dump()

    @modal.method()
    def refine_solidity_exploit(self, target_dict: dict, failed_code: str, error_trace: str, hypothesis_dict: Optional[dict] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> dict:
        import torch
        from core.schemas import TargetProgram, VulnerabilityHypothesis
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_refinement_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        hypothesis = VulnerabilityHypothesis(**hypothesis_dict) if hypothesis_dict else None
        prompt = build_refinement_prompt(
            target, failed_code, error_trace,
            hypothesis=hypothesis, previous_failures=previous_failures
        )
        messages = [
            {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        token_ids_list = generated_ids[0].tolist()
        return parse_model_response(
            target,
            response_text,
            attempt_idx=99,
            generated_token_ids=token_ids_list,
            prompt_text=text,
            hypothesis=hypothesis
        ).model_dump()


# =============================================================================
# 2. DEV SMOKE-TEST AGENT (T4 - Lightweight 1.5B Model for cheap CI/CD)
# =============================================================================
@app.cls(
    gpu=config.DEV_GPU_TYPE,
    image=gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=600,
)
class DevReasoningAgent:
    """Lightweight dev reasoning agent on Modal T4 (Qwen2.5-Coder-1.5B-Instruct)."""
    use_lora: bool = modal.parameter(default=False)
    checkpoint_dir: str = modal.parameter(default="/vol/models/checkpoints/checkpoint-step-1")

    @modal.enter()
    def load_model(self):
        import os
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        cache_dir = config.MODEL_CACHE_DIR
        os.makedirs(cache_dir, exist_ok=True)
        
        print(f"[*] Initializing Dev Agent on Modal {config.DEV_GPU_TYPE}: {config.DEV_GPU_MODEL}")
        self.tokenizer = AutoTokenizer.from_pretrained(config.DEV_GPU_MODEL, cache_dir=cache_dir)
        self.model = AutoModelForCausalLM.from_pretrained(
            config.DEV_GPU_MODEL,
            torch_dtype=torch.float16,
            device_map="auto",
            cache_dir=cache_dir
        )
        if self.use_lora:
            target_ckpt = self.checkpoint_dir
            if os.path.exists("/vol/models/checkpoints"):
                subdirs = [
                    os.path.join("/vol/models/checkpoints", d)
                    for d in os.listdir("/vol/models/checkpoints")
                    if d.startswith("checkpoint-step-")
                ]
                if subdirs:
                    subdirs.sort(key=os.path.getmtime)
                    target_ckpt = subdirs[-1]
            if os.path.exists(target_ckpt):
                try:
                    from peft import PeftModel
                    self.model = PeftModel.from_pretrained(self.model, target_ckpt)
                    print(f"[✓] Successfully attached trained GRPO LoRA adapter from: {target_ckpt}")
                except Exception as e:
                    print(f"[!] Warning attaching LoRA adapter: {e}")
        try:
            model_volume.commit()
        except Exception:
            pass

    @modal.method()
    def generate_solidity_exploit(self, target_dict: dict, temperature: float = 0.3, hypothesis_dict: Optional[dict] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> dict:
        import torch
        from core.schemas import TargetProgram, VulnerabilityHypothesis
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_analysis_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        hypothesis = VulnerabilityHypothesis(**hypothesis_dict) if hypothesis_dict else None
        user_prompt = build_analysis_prompt(
            target, hypothesis=hypothesis, previous_failures=previous_failures
        )
        messages = [
            {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=temperature,
                do_sample=(temperature > 0.0),
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        token_ids_list = generated_ids[0].tolist()
        return parse_model_response(
            target,
            response_text,
            attempt_idx=1,
            generated_token_ids=token_ids_list,
            prompt_text=text,
            hypothesis=hypothesis
        ).model_dump()

    @modal.method()
    def refine_solidity_exploit(self, target_dict: dict, failed_code: str, error_trace: str, hypothesis_dict: Optional[dict] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> dict:
        import torch
        from core.schemas import TargetProgram, VulnerabilityHypothesis
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_refinement_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        hypothesis = VulnerabilityHypothesis(**hypothesis_dict) if hypothesis_dict else None
        prompt = build_refinement_prompt(
            target, failed_code, error_trace,
            hypothesis=hypothesis, previous_failures=previous_failures
        )
        messages = [
            {"role": "system", "content": SOLIDITY_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        token_ids_list = generated_ids[0].tolist()
        return parse_model_response(
            target,
            response_text,
            attempt_idx=99,
            generated_token_ids=token_ids_list,
            prompt_text=text,
            hypothesis=hypothesis
        ).model_dump()


# =============================================================================
# 3. EPHEMERAL CPU WORKERS (Foundry / Slither / Replay Sandbox)
# =============================================================================
@app.function(
    image=sandbox_image,
    timeout=60,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def run_slither_remote(target_dict: dict) -> list:
    """Executes Slither AST static analysis on Modal CPU worker."""
    target = TargetProgram(**target_dict)
    return run_slither_analysis(target)


@app.function(
    image=sandbox_image,
    timeout=config.SANDBOX_TIMEOUT_SEC,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def verify_exploit_remote(target_dict: dict, payload_dict: dict) -> dict:
    """Compiles Solidity exploit and executes forge test --offline --json -vvvv in ephemeral EVM."""
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    
    # 1. Execute in Foundry EVM sandbox
    raw_result = run_payload_in_sandbox(target, payload)
    
    # 2. Evaluate multi-factor verdict
    verdict = evaluate_execution_trace(payload, raw_result)
    return verdict.model_dump()


@app.function(
    image=sandbox_image,
    timeout=config.SANDBOX_TIMEOUT_SEC,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def verify_replay_remote(target_dict: dict, payload_dict: dict) -> bool:
    """Runs the candidate independently in a fresh EVM worker and checks the trusted verdict."""
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    return verify_independent_replay(target, payload)


@app.function(
    image=sandbox_image,
    timeout=60,
)
def verify_replay_fault_injection_remote(target_dict: dict, payload_dict: dict, fault_type: str = "timeout") -> bool:
    """
    Real Modal remote worker for fault injection testing (Round 5.2 Blocker 4).
    Executes in a real isolated Modal EVM container and raises real worker-level infrastructure exceptions.
    """
    if fault_type == "timeout":
        raise TimeoutError("Modal worker execution timed out (60s EVM container limit exceeded)")
    elif fault_type == "connection":
        raise ConnectionResetError("Modal worker sandbox connection dropped by host")
    elif fault_type == "oom":
        raise MemoryError("Modal worker sandbox killed: Out of Memory (1024MB)")
    else:
        raise RuntimeError(f"Modal worker sandbox fatal infrastructure error: {fault_type}")


@app.function(
    image=sandbox_image,
    volumes={"/vol/models": model_volume},
    timeout=60,
)
def record_trajectory_remote(trajectory_dict: dict) -> str:
    """Saves verified execution trajectory pair to persistent volume for GRPO training."""
    traj_dir = config.TRAJECTORY_DIR
    os.makedirs(traj_dir, exist_ok=True)
    traj_id = trajectory_dict.get("trajectory_id", "unknown")
    filepath = os.path.join(traj_dir, f"traj_{traj_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(trajectory_dict, f, indent=2)
    try:
        model_volume.commit()
    except Exception:
        pass
    return filepath


@app.function(
    image=gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=60,
)
def audit_volume_trajectories_remote() -> dict:
    """Read-only audit of stored trajectories in persistent Modal volume (Round 5.2)."""
    from core.grpo_trainer import audit_trajectory_storage
    return audit_trajectory_storage(config.TRAJECTORY_DIR)


@app.function(
    gpu=config.DEV_GPU_TYPE,
    image=gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=600,
)
def diagnostic_grpo_forward_remote(
    model_id: str = config.DEV_GPU_MODEL,
    batch_group_size: int = 4
) -> dict:
    """
    Executes a read-only diagnostic GRPO forward and loss computation on Modal GPU (Round 5.2).
    STRICT SAFETY GUARANTEES:
    - NO optimizer step
    - NO weight updates
    - NO checkpoint modification or creation
    - Strictly verifies tensor shapes, prompt/completion boundaries, completion masks, and loss value.
    """
    import os
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from core.grpo_trainer import (
        load_trajectories_from_directory,
        group_rollouts_by_prompt,
        prepare_rollout_tokens,
        compute_group_advantages,
        get_token_logprobs
    )

    print(f"[Diagnostic Forward] Loading tokenizer and model: {model_id} on Modal GPU...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="cuda"
    )
    model.eval()

    # Load trajectories with strict production allowlist and exact token lineage (Round 5.4)
    from core.grpo_trainer import load_production_trajectories
    traj_records = load_production_trajectories(
        config.TRAJECTORY_DIR,
        target_split="train"
    )
    if not traj_records:
        return {
            "status": "NO_PRODUCTION_TRAJECTORIES",
            "message": "Persistent volume contains 0 eligible production trajectories (all control/synthetic isolated).",
            "eligible_count": 0
        }

    groups = group_rollouts_by_prompt(traj_records, group_size=batch_group_size)
    if not groups:
        return {
            "status": "NO_VALID_GROUPS",
            "message": "No complete groups formed from eligible trajectories.",
            "eligible_count": len(traj_records)
        }

    test_group = groups[0]
    rollout_tensors = []
    for r in test_group.rollouts:
        c_str = r.full_completion_text or r.exploit_code
        inp_ids, att_mask, comp_mask = prepare_rollout_tokens(
            test_group.prompt,
            c_str,
            tokenizer,
            device="cuda",
            stored_generated_token_ids=r.generated_token_ids
        )
        rollout_tensors.append((inp_ids, att_mask, comp_mask))

    with torch.no_grad():
        first_inp, first_att, first_comp = rollout_tensors[0]
        outputs = model(first_inp, attention_mask=first_att)
        logits = outputs.logits[:, :-1, :]
        labels = first_inp[:, 1:]
        mask = first_comp[:, 1:]

        log_probs = torch.log_softmax(logits, dim=-1)
        per_token_lp = torch.gather(log_probs, 2, labels.unsqueeze(2)).squeeze(2)
        masked_lp = per_token_lp * mask
        completion_token_count = mask.sum().item()
        diagnostic_loss = -masked_lp.sum().item() / max(1.0, completion_token_count)

    return {
        "status": "SUCCESS",
        "model_id": model_id,
        "device": str(model.device),
        "input_shape": list(first_inp.shape),
        "mask_shape": list(first_comp.shape),
        "prompt_tokens": int(first_inp.shape[1] - completion_token_count),
        "completion_tokens": int(completion_token_count),
        "diagnostic_loss": float(diagnostic_loss),
        "optimizer_step_executed": False,
        "weights_updated": False,
        "checkpoints_created": False
    }


@app.function(
    gpu=config.DEV_GPU_TYPE,
    image=gpu_image,
    volumes={"/vol/models": model_volume},
    timeout=1800,
)
def train_grpo_remote(
    model_id: str,
    num_steps: int = 5,
    learning_rate: float = 5e-6,
    batch_group_size: int = 4
) -> dict:
    """
    Executes GRPO Policy Gradient training with LoRA on Modal GPU worker.
    Loads verified trajectory groups, computes advantages, updates LoRA parameters,
    and commits the trained adapter checkpoint to Modal Volume.
    """
    import os
    import torch
    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    # FAIL-CLOSED SECURITY GATE (Round 5.4)
    # Strictly prevents direct remote invocation when TRAINING_STATUS = BLOCKED
    training_status = os.environ.get("TRAINING_STATUS", "BLOCKED")
    if training_status == "BLOCKED" or getattr(config, "TRAINING_BLOCKED", True):
        raise RuntimeError(
            "FAIL-CLOSED SECURITY GATE: TRAINING_STATUS = BLOCKED. "
            "Direct remote invocation of train_grpo_remote is strictly prohibited by AI Supervisor. "
            "Optimizer step, weight updates, and checkpoint writes are blocked."
        )

    from transformers import AutoModelForCausalLM, AutoTokenizer
    from core.grpo_trainer import (
        load_production_trajectories,
        group_rollouts_by_prompt,
        setup_lora_model,
        train_grpo_epochs,
        save_lora_checkpoint
    )

    print(f"\n[*] Starting GRPO LoRA Policy Optimization on Modal GPU for: {model_id}")
    trajectories = load_production_trajectories(config.TRAJECTORY_DIR, target_split="train")
    print(f"[*] Loaded {len(trajectories)} verified production trajectory records from {config.TRAJECTORY_DIR}")

    groups = group_rollouts_by_prompt(trajectories, group_size=batch_group_size)
    print(f"[*] Formed {len(groups)} GRPO candidate rollout groups with normalized advantages.")

    if not groups:
        return {
            "status": "skipped",
            "message": "No rollout groups with >=2 candidates found in trajectories. Run audit rollouts first.",
            "steps_completed": 0
        }

    cache_dir = config.MODEL_CACHE_DIR
    print(f"[*] Loading tokenizer for {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir=cache_dir)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[*] Loading base model weights on GPU...")
    dtype = torch.float16 if config.DEV_GPU_TYPE == "T4" else torch.bfloat16
    base_model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=dtype,
        device_map="auto",
        cache_dir=cache_dir
    )

    lora_model = setup_lora_model(
        base_model,
        r=config.GRPO_LORA_R,
        lora_alpha=config.GRPO_LORA_ALPHA,
        lora_dropout=config.GRPO_LORA_DROPOUT
    )

    optimizer = torch.optim.AdamW(
        [p for p in lora_model.parameters() if p.requires_grad],
        lr=learning_rate
    )

    epochs = max(1, num_steps)
    print(f"[*] Executing GRPO training loop for {epochs} epoch(s) across {len(groups)} group(s)...")

    step_stats = train_grpo_epochs(
        model=lora_model,
        optimizer=optimizer,
        groups=groups,
        tokenizer=tokenizer,
        epochs=epochs,
        device="cuda",
        clip_eps=config.GRPO_CLIP_EPS,
        beta_kl=config.GRPO_BETA_KL
    )

    save_path = save_lora_checkpoint(lora_model, tokenizer, config.GRPO_CHECKPOINT_DIR, step=len(step_stats))
    try:
        model_volume.commit()
        print(f"[✓] Checkpoint committed to persistent Modal volume.")
    except Exception as e:
        print(f"[!] Volume commit warning: {e}")

    return {
        "status": "success",
        "checkpoint_path": save_path,
        "steps_completed": len(step_stats),
        "logs": [s.model_dump() for s in step_stats]
    }


def run_control_foundry_tests(target_name: str = "Vault"):
    """
    Executes mandatory control verification tests for the Foundry Harness and Category Reward logic:
    1. Minimal benign ExploitModule (no-op) -> Compiles, links, reverts in harness (reward -0.25, RUNTIME_REVERT)
    2. Working Reentrancy ExploitModule -> Drains vault, breaches invariant, confirmed replay (reward +1.0, EXPLOIT_CONFIRMED)
    3. Structurally broken contract -> Rejected upfront before Foundry (GENERATION_FORMAT_ERROR)
    4. Wrongly-named contract -> Mechanically renamed to ExploitModule, reaches Foundry, real EVM verdict
    """
    print("\n" + "=" * 78)
    print("🧪 EXECUTING MANDATORY FOUNDRY HARNESS CONTROL TEST SUITE (ROUND 5)")
    print("=" * 78)

    benchmarks_dir = os.path.join(os.path.dirname(__file__), "benchmarks", "targets", "solidity")
    target_path = os.path.join(benchmarks_dir, f"{target_name}.sol")
    harness_path = os.path.join(benchmarks_dir, f"{target_name}Harness.t.sol")

    with open(target_path, "r", encoding="utf-8") as f:
        target_source = f.read()
    with open(harness_path, "r", encoding="utf-8") as f:
        harness_source = f.read()

    invariants_map = {
        "Vault": ["address(vault).balance >= balances[victim] (Depositor Solvency)"],
        "ERC4626Vault": [
            "victimShares > 0 (No zero-share deposit robbery)",
            "vault.convertToAssets(victimShares) >= 0.95 * VICTIM_DEPOSIT (Dilution Protection)"
        ]
    }
    target = TargetProgram(
        name=target_name,
        source_code=target_source,
        language="solidity",
        invariants=invariants_map.get(target_name, ["Security invariant intact"]),
        trusted_harness_code=harness_source
    )

    # 1. TEST 1: Minimal Benign ExploitModule (No LLM)
    print("\n[Control Test 1] Testing Minimal Benign ExploitModule (No LLM)...")
    benign_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public targetContract;

    constructor(address _target) payable {
        targetContract = Vault(payable(_target));
    }

    function runExploit() external payable {
        // Benign execution: does not breach solvency invariant
    }

    receive() external payable {}
}
"""
    p1 = parse_model_response(target, f"```solidity\n{benign_code}\n```")
    v1_dict = verify_exploit_remote.remote(target.model_dump(), p1.model_dump())
    v1 = VerificationVerdict(**v1_dict)
    print(f"    Status: {'✅ PASS' if v1.category == ResultCategory.RUNTIME_REVERT else '❌ FAIL'}")
    print(f"    Category: {v1.category.value} | Reward: {v1.reward_score:+.2f}")
    print(f"    Feedback: {v1.feedback[:120]}...")
    assert v1.category == ResultCategory.RUNTIME_REVERT, f"Expected RUNTIME_REVERT, got {v1.category}"
    assert v1.reward_score <= 0.0, f"Expected non-positive reward, got {v1.reward_score}"
    assert not v1.is_verified, "Benign test must not be verified as exploit"
    print("    [✓] Control Test 1 verified: Import and compilation succeeded without Declaration 'ExploitModule' error.")

    # 2. TEST 2: Confirmed Reentrancy ExploitModule
    print("\n[Control Test 2] Testing Confirmed Working Reentrancy ExploitModule...")
    working_exploit = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract ExploitModule {
    Vault public targetContract;
    uint256 public constant ATTACK_AMOUNT = 1 ether;

    constructor(address _target) payable {
        targetContract = Vault(payable(_target));
    }

    function runExploit() external payable {
        targetContract.deposit{value: ATTACK_AMOUNT}();
        targetContract.withdrawAll();
    }

    receive() external payable {
        if (address(targetContract).balance >= ATTACK_AMOUNT) {
            targetContract.withdrawAll();
        }
    }
}
"""
    p2 = parse_model_response(target, f"```solidity\n{working_exploit}\n```")
    v2_dict = verify_exploit_remote.remote(target.model_dump(), p2.model_dump())
    v2 = VerificationVerdict(**v2_dict)

    # Initial run before independent replay: must be INVARIANT_BREACH_UNREPLAYED with reward +0.50
    assert v2.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED, f"Expected INVARIANT_BREACH_UNREPLAYED, got {v2.category}"
    assert not v2.is_verified, "Initial breach must NOT have is_verified=True before independent replay!"
    assert v2.reward_score == config.REWARD_BREACH_NO_REPLAY, f"Expected +0.50, got {v2.reward_score}"
    print(f"    Initial Pre-Replay: ✅ PASS | Category: {v2.category.value} | Reward: {v2.reward_score:+.2f} | is_verified={v2.is_verified}")

    replay_confirmed = verify_replay_remote.remote(target.model_dump(), p2.model_dump())
    v2.reproducible = replay_confirmed
    if replay_confirmed:
        v2.category = ResultCategory.EXPLOIT_CONFIRMED
        v2.is_verified = True
        v2.replay_status = "CONFIRMED"

    # The reward is recomputed with the shared reward specification, so the
    # confirmed replay contributes its own `replay` component.
    _breakdown = compute_reward_breakdown(
        v2.category,
        RewardEvidence(
            format_valid=True,
            compiled=True,
            executed=True,
            invariant_confirmed=True,
            replay_confirmed=bool(replay_confirmed),
        ),
    )
    v2.reward_score = _breakdown.total
    v2.reward_components = dict(_breakdown.components)
    v2.reward_penalty = _breakdown.penalty
    v2.reward_spec_version = _breakdown.spec_version

    print(f"    Status: {'✅ PASS' if v2.is_verified and replay_confirmed else '❌ FAIL'}")
    print(f"    Post-Replay Category: {v2.category.value} | Reward: {v2.reward_score:+.2f} | is_verified={v2.is_verified}")
    print(f"    Reward Attribution: {_breakdown.describe()}")
    print(f"    Feedback: {v2.feedback[:120]}...")
    print(f"    Independent Replay: {'CONFIRMED (independent replay passed)' if replay_confirmed else 'FAILED'}")
    assert v2.is_verified, "Confirmed working exploit must be verified after successful replay"
    assert v2.category == ResultCategory.EXPLOIT_CONFIRMED
    assert v2.reward_score == 1.0
    assert v2.reward_components.get("replay", 0.0) == config.REWARD_COMPONENT_REPLAY
    print("    [✓] Control Test 2 verified: Initial run gave INVARIANT_BREACH_UNREPLAYED (+0.50), post-replay gave EXPLOIT_CONFIRMED (+1.00).")

    # Record this verified trajectory as SYNTHETIC CONTROL TRAJECTORY (Round 5.2)
    # Strictly isolated from production GRPO training dataset!
    prompt_str = build_analysis_prompt(target)
    t_rec = create_trajectory_record(
        target,
        p2,
        v2,
        prompt_used=prompt_str,
        dataset_split="control",
        dataset_partition="synthetic_control",
        is_synthetic=True,
        token_provenance="synthetic",
        trainable=False
    )
    record_trajectory_remote.remote(t_rec.model_dump())
    print("    [✓] Synthetic control trajectory recorded with dataset_partition='synthetic_control', is_synthetic=True (isolated from GRPO dataset)!")

    # 3. TEST 3: Structurally broken contract that mechanical normalization cannot repair
    #    (the wrongly-named-but-otherwise-valid case is now repaired and reaches Foundry;
    #     this control keeps proving that a genuinely malformed exploit is still
    #     rejected upfront, before Foundry is invoked)
    print("\n[Control Test 3] Testing Structurally Broken Contract (missing runExploit entrypoint)...")
    malformed_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultAttack {
    constructor(address _target) payable {}
    // Missing mandatory runExploit() entrypoint
}
"""
    p3 = parse_model_response(target, f"```solidity\n{malformed_code}\n```")
    assert not p3.format_valid, "Structurally broken exploit must be rejected before Foundry"
    v3_dict = verify_exploit_remote.remote(target.model_dump(), p3.model_dump())
    v3 = VerificationVerdict(**v3_dict)
    print(f"    Status: {'✅ PASS' if v3.category == ResultCategory.GENERATION_FORMAT_ERROR else '❌ FAIL'}")
    print(f"    Category: {v3.category.value} | Reward: {v3.reward_score:+.2f}")
    print(f"    Feedback: {v3.feedback[:120]}...")
    assert v3.category == ResultCategory.GENERATION_FORMAT_ERROR
    assert v3.reward_score == config.REWARD_FORMAT_ERROR
    print("    [✓] Control Test 3 verified: Format error caught before invoking Foundry.")

    # 4. TEST 4: Wrongly-named but otherwise valid contract is mechanically repaired
    print("\n[Control Test 4] Testing Mechanical Contract Name Normalization (contract VaultAttack)...")
    renamable_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public targetContract;

    constructor(address _target) payable {
        targetContract = Vault(payable(_target));
    }

    function runExploit() external payable {}

    receive() external payable {}
}
"""
    p4 = parse_model_response(target, f"```solidity\n{renamable_code}\n```")
    assert p4.contract_name_normalized, "Expected mechanical contract-name normalization"
    assert p4.original_contract_name == "VaultAttack"
    assert p4.format_valid, "Renamed exploit must pass the format gate"
    v4_dict = verify_exploit_remote.remote(target.model_dump(), p4.model_dump())
    v4 = VerificationVerdict(**v4_dict)
    print(f"    Renamed: 'VaultAttack' -> 'ExploitModule' | format_valid={p4.format_valid}")
    print(f"    Status: {'✅ PASS' if v4.category != ResultCategory.GENERATION_FORMAT_ERROR else '❌ FAIL'}")
    print(f"    Category: {v4.category.value} | Reward: {v4.reward_score:+.2f}")
    assert v4.category != ResultCategory.GENERATION_FORMAT_ERROR, (
        "Mechanically repaired exploit must reach the EVM harness instead of being rejected"
    )
    print("    [✓] Control Test 4 verified: repaired exploit reaches Foundry and yields a real EVM verdict.")

    # 5. TEST 5: Verification-channel hijack must be rejected before Foundry
    print("\n[Control Test 5] Testing Verification-Channel Hijack Rejection (forged breach marker)...")
    forged_marker_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console} from "forge-std/console.sol";

contract ExploitModule {
    constructor(address _target) payable {}

    function runExploit() external payable {
        // Forges the breach marker in the logs without breaching anything.
        console.log("[INVARIANT_BREACHED:DEPOSITOR_SOLVENCY_COLLAPSE]");
    }

    receive() external payable {}
}
"""
    p5 = parse_model_response(target, f"```solidity\n{forged_marker_code}\n```")
    v5_dict = verify_exploit_remote.remote(target.model_dump(), p5.model_dump())
    v5 = VerificationVerdict(**v5_dict)
    print(f"    Category: {v5.category.value} | Reward: {v5.reward_score:+.2f}")
    print(f"    Feedback: {v5.feedback[:160]}...")
    assert v5.category == ResultCategory.CHEATCODE_DETECTED, (
        f"A candidate that hijacks the verification channel must be rejected, got {v5.category}"
    )
    assert v5.reward_score == config.REWARD_CHEATCODE_PENALTY
    assert not v5.is_verified
    assert v5.reward_components.get("invariant", 0.0) == 0.0
    print("    [✓] Control Test 5 verified: forged marker rejected as security violation, no breach credit.")

    print("\n" + "=" * 78)
    print("🎉 ALL FOUNDRY HARNESS CONTROL TESTS PASSED (0 ERRORS)")
    print("=" * 78 + "\n")


def run_modal_replay_infra_error_integration_test(target_name: str = "Vault"):
    """
    Executes real Modal integration test for replay infrastructure error handling (Round 5.2).
    Verifies that real remote worker exceptions are caught in orchestration,
    classified as INFRA_ERROR with reward 0.0, is_verified=False, and excluded from GRPO persistence.
    """
    print("\n" + "=" * 78)
    print("🧪 EXECUTING REAL MODAL REMOTE REPLAY INFRA ERROR INTEGRATION TEST")
    print("=" * 78)

    benchmarks_dir = os.path.join(os.path.dirname(__file__), "benchmarks", "targets", "solidity")
    target_path = os.path.join(benchmarks_dir, f"{target_name}.sol")
    with open(target_path, "r", encoding="utf-8") as f:
        target_source = f.read()

    target = TargetProgram(name=target_name, source_code=target_source, language="solidity", invariants=["Depositor Solvency"])
    run_id = f"test_infra_run_{int(time.time())}"
    cand_id = f"{run_id}_c1"

    payload = ExploitPayload(
        target_name=target.name,
        hypothesis=AttackHypothesis(vulnerability_type="ReentrancyDrain", reasoning_trace="Trace", attack_vector="Drain"),
        test_code="contract ExploitModule { constructor(address a) {} function runExploit() external {} }",
        candidate_id=cand_id,
        run_id=run_id,
        prompt_text="test prompt",
        raw_model_response="raw",
        generated_token_ids=[100, 101, 102]
    )
    verdict = VerificationVerdict(
        target_name=target.name,
        is_verified=False,
        reward_score=0.5,
        category=ResultCategory.INVARIANT_BREACH_UNREPLAYED,
        vulnerability_type="ReentrancyDrain",
        poc_code=payload.test_code,
        feedback="Pre-replay breach achieved",
        candidate_id=cand_id,
        run_id=run_id
    )
    candidate = CandidateRecord(
        candidate_id=cand_id,
        run_id=run_id,
        target_name=target.name,
        generation_iteration=0,
        candidate_index=1,
        payload=payload,
        verdict=verdict,
        prompt_text="test prompt",
        prompt_hash=compute_prompt_hash("test prompt"),
        replay_eligible=True,
        reproduced=False
    )

    print(f"[*] Candidate prepared: {candidate.candidate_id} (Category: {candidate.verdict.category.value})")
    print(f"[*] Invoking REAL Modal remote worker with injected TimeoutError...")

    # Phase 5: Replay Orchestration with real remote exception
    try:
        reproduced = verify_replay_fault_injection_remote.remote(target.model_dump(), candidate.payload.model_dump(), fault_type="timeout")
        finalize_candidate_replay(candidate, replay_success=reproduced, replay_infra_error=False)
    except Exception as exc:
        print(f"[✓] Successfully caught real Modal remote worker exception: {type(exc).__name__}: {exc}")
        finalize_candidate_replay(candidate, replay_success=False, replay_infra_error=True)
        candidate.verdict.feedback = f"Replay Infrastructure Error ({type(exc).__name__}): {exc}"

    print(f"[*] Post-Exception Category: {candidate.verdict.category.value}")
    print(f"[*] Post-Exception Reward  : {candidate.verdict.reward_score:+.2f}")
    print(f"[*] is_verified            : {candidate.verdict.is_verified}")
    print(f"[*] reproduced             : {candidate.reproduced}")
    print(f"[*] trainable              : {candidate.trainable}")

    assert candidate.verdict.category == ResultCategory.INFRA_ERROR, f"Expected INFRA_ERROR, got {candidate.verdict.category}"
    assert candidate.verdict.reward_score == 0.0, f"Expected 0.0, got {candidate.verdict.reward_score}"
    assert candidate.verdict.is_verified is False, "is_verified must be False"
    assert candidate.reproduced is False, "reproduced must be False"
    assert candidate.trainable is False, "trainable must be False"

    # Phase 6: Persistence Isolation Check
    recorded_count = 0
    if candidate.verdict.category != ResultCategory.INFRA_ERROR:
        traj = create_finalized_trajectory(candidate, target)
        record_trajectory_remote.remote(traj.model_dump())
        recorded_count += 1

    assert recorded_count == 0, "INFRA_ERROR record must strictly NOT be saved to Modal Volume for GRPO!"
    print(f"[✓] Persistence check passed: Candidate excluded from persistent GRPO trajectories (recorded={recorded_count})")
    print("=" * 78)
    print("🎉 REAL MODAL INFRA ERROR INTEGRATION TEST PASSED")
    print("=" * 78 + "\n")


# =============================================================================
# 4. CLI ENTRYPOINT: AEGIS-RLVR 2.0 ORCHESTRATOR
# =============================================================================
@app.local_entrypoint()
def main(
    mode: str = "audit",
    target_name: str = "Vault",
    generator: str = "local",
    num_candidates: int = 3,
    max_rounds: int = 2,
    use_lora: bool = False
):
    """
    Aegis-RLVR 2.0 CLI orchestrator on Modal.
    Usage:
      Production Mode (H100 + Slither + Parallel Map):
        modal run modal_app.py --mode audit --target-name ERC4626Vault --num-candidates 5

      Gemini Flash Mode (Frontier API Reasoning + Modal Foundry Execution):
        modal run modal_app.py --generator gemini --target-name ERC4626Vault --num-candidates 3

      Dev Mode (T4 GPU + Ephemeral Sandboxes):
        modal run modal_app.py --mode dev --target-name Vault

      Inference with trained LoRA adapter:
        modal run modal_app.py --mode dev --target-name Vault --use-lora True
    """
    print("\n" + "=" * 78)
    print("🛡️  AEGIS-RLVR 2.0: Autonomous Multi-Agent Web3 Security Framework")
    print(f"📦 Model Persistent Volume  : '{config.MODEL_VOLUME_NAME}'")
    print(f"⚙️  Execution Profile        : '{mode.upper()}' (Generator: {generator.upper()})")
    print(f"🎯 Target Contract           : '{target_name}'")
    print(f"⚡ Parallel Hypotheses (.map): {num_candidates}")
    print(f"🧬 Use LoRA Adapter Checkpoint: {use_lora}")
    print("=" * 78)

    # Fast-path: Control test suite for Foundry harness verification (Round 5)
    if mode.lower() in ("test-harness", "check-harness", "control"):
        run_control_foundry_tests(target_name)
        return

    # Fast-path: Real Modal remote replay infrastructure error integration test (Round 5.2)
    if mode.lower() in ("test-infra", "test-infra-error", "check-infra"):
        run_modal_replay_infra_error_integration_test(target_name)
        return

    # Fast-path: Read-only audit of persistent volume trajectories (Round 5.2)
    if mode.lower() in ("audit-trajectories", "audit-volume", "audit-data"):
        print("\n" + "=" * 78)
        print("🔍 EXECUTING READ-ONLY AUDIT OF MODAL PERSISTENT VOLUME TRAJECTORIES")
        print("=" * 78)
        audit_res = audit_volume_trajectories_remote.remote()
        print(json.dumps(audit_res, indent=2))
        print("=" * 78 + "\n")
        return

    # Fast-path: Diagnostic forward/loss computation without weight updates (Round 5.2)
    if mode.lower() in ("diagnostic-forward", "diagnostic-loss", "check-loss"):
        print("\n" + "=" * 78)
        print("🧪 EXECUTING DIAGNOSTIC GRPO FORWARD PASS (NO WEIGHT UPDATES / NO OPTIMIZER STEP)")
        print("=" * 78)
        diag_model_id = config.DEV_GPU_MODEL if generator.lower() == "dev" or target_name == "Vault" else config.AUDIT_GPU_MODEL
        diag_res = diagnostic_grpo_forward_remote.remote(model_id=diag_model_id, batch_group_size=num_candidates)
        print(json.dumps(diag_res, indent=2))
        print("=" * 78 + "\n")
        return

    # Fast-path: Offline GRPO Policy Optimization on accumulated trajectories
    if mode.lower() == "train":
        # Supervisor Blocker: TRAINING_STATUS = BLOCKED
        raise RuntimeError(
            "TRAINING_STATUS = BLOCKED: GRPO training is strictly blocked by AI Supervisor until all Round 5.2 criteria are verified! "
            "Optimizer step, checkpoint overwrite, and weight updates are prohibited."
        )

    # 1. Resolve Solidity target contract and trusted verification harness
    benchmarks_dir = os.path.join(os.path.dirname(__file__), "benchmarks", "targets", "solidity")
    target_path = os.path.join(benchmarks_dir, f"{target_name}.sol")
    harness_path = os.path.join(benchmarks_dir, f"{target_name}Harness.t.sol")

    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Target contract file not found: {target_path}")
    if not os.path.exists(harness_path):
        raise FileNotFoundError(f"Verification harness file not found: {harness_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        target_source = f.read()

    with open(harness_path, "r", encoding="utf-8") as f:
        harness_source = f.read()

    invariants_map = {
        "Vault": ["address(vault).balance >= balances[victim] (Depositor Solvency)"],
        "ERC4626Vault": [
            "victimShares > 0 (No zero-share deposit robbery)",
            "vault.convertToAssets(victimShares) >= 0.95 * VICTIM_DEPOSIT (Dilution Protection)"
        ]
    }
    target_invariants = invariants_map.get(target_name, ["Security invariant intact"])

    target = TargetProgram(
        name=target_name,
        source_code=target_source,
        language="solidity",
        invariants=target_invariants,
        trusted_harness_code=harness_source
    )

    print(f"\n[1] Target loaded: '{target.name}.sol'")
    print(f"    Invariants     : {target.invariants}")
    print(f"    Solidity Vers  : {config.SOLC_VERSION}")

    # 2. Phase 1: Static Analysis and model audit findings.
    audit_findings = []
    auditor_agent = None
    if config.ENABLE_SLITHER:
        print("\n[Phase 1] Running Slither Static Analysis on Modal CPU Worker...")
        try:
            slither_findings = run_slither_remote.remote(target.model_dump())
            target.slither_findings = slither_findings
            print(f"[✓] Slither extracted {len(slither_findings)} AST detector signal(s):")
            for sf in slither_findings:
                print(f"    - [{sf.get('impact')}] {sf.get('check')}: {sf.get('description', '')[:70]}...")
        except Exception as e:
            print(f"[!] Slither notice: {e}")

    # In audit mode, collect the actual model findings as a separate source.
    if mode.lower() == "audit":
        print(f"[+] Running audit model ({config.AUDIT_GPU_MODEL}) to produce structured findings...")
        auditor_agent = ProductionAuditAgent()
        try:
            audit_findings = auditor_agent.audit_target_contract.remote(target.model_dump())
            if not isinstance(audit_findings, list):
                audit_findings = []
            print(f"[+] Auditor produced {len(audit_findings)} finding(s).")
        except Exception as e:
            print(f"[!] Audit scan notice: {type(e).__name__}: {e}")
            audit_findings = []

    hypothesis_manager = HypothesisManager(target)
    normalized_findings = list(target.slither_findings or []) + list(audit_findings or [])
    prioritized_hypotheses = hypothesis_manager.ingest_auditor_findings(
        normalized_findings, source_label="modal-audit+slither"
    ) if normalized_findings else []
    top_hypotheses = hypothesis_manager.get_top_hypotheses(limit=max(1, num_candidates))
    if top_hypotheses:
        print("[+] Prioritized vulnerability hypotheses:")
        for item in top_hypotheses[:5]:
            print(f"    - [{item.severity}] {item.vulnerability_class}::{item.affected_function or '*'} ({item.confidence:.2f})")
    else:
        print("[!] No structured findings were normalized; generation proceeds without a selected hypothesis.")

    # 3. Phase 2: Hypothesis Formulation & Multi-Candidate Exploit Synthesis (Round 4 Lifecycle)
    run_id = f"run_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    primary_hypothesis = top_hypotheses[0] if top_hypotheses else None
    primary_attack_hypothesis = hypothesis_manager.to_attack_hypothesis(primary_hypothesis) if primary_hypothesis else None
    target_prompt = build_analysis_prompt(target, hypothesis=primary_attack_hypothesis)
    prompt_hash = compute_prompt_hash(target_prompt)
    candidate_hypothesis_ids: Dict[str, str] = {}
    model_id = config.DEV_GPU_MODEL if generator.lower() == "dev" or target_name == "Vault" else config.AUDIT_GPU_MODEL
    checkpoint_id = "checkpoint-step-2" if use_lora else "base"

    print(f"\n[Phase 2] Synthesizing {num_candidates} parallel exploit hypotheses (Run ID: {run_id})...")
    all_candidate_records: List[CandidateRecord] = []
    initial_payloads: List[ExploitPayload] = []

    if generator.lower() == "gemini":
        print("[+] Generator: Gemini 2.5 Flash (Frontier Reasoning API)")
        for i in range(1, num_candidates + 1):
            selected_hypothesis = top_hypotheses[(i - 1) % len(top_hypotheses)] if top_hypotheses else None
            attack_hypothesis = hypothesis_manager.to_attack_hypothesis(selected_hypothesis) if selected_hypothesis else None
            p = synthesize_exploit_gemini(target, hypothesis=attack_hypothesis)
            p.candidate_id = f"{run_id}_c{i}_r0"
            if selected_hypothesis:
                candidate_hypothesis_ids[p.candidate_id] = selected_hypothesis.hypothesis_id
            p.run_id = run_id
            p.generation_iteration = 0
            p.candidate_index = i
            p.attempt_number = i
            initial_payloads.append(p)
            print(f"    [Candidate #{i} | ID: {p.candidate_id}] Hypothesis: {p.hypothesis.vulnerability_type} (Gemini API)")
    else:
        if mode.lower() == "audit":
            print(f"[+] Generator: Production Tier ({config.AUDIT_GPU_MODEL} on Modal H100)")
            llm_agent = auditor_agent or ProductionAuditAgent()
        else:
            lora_note = " + Trained GRPO LoRA" if use_lora else ""
            print(f"[+] Generator: Dev Tier ({config.DEV_GPU_MODEL}{lora_note} on Modal T4)")
            llm_agent = DevReasoningAgent(use_lora=use_lora)

        temperatures = [0.2 + (i * 0.2) for i in range(num_candidates)]
        for i, temp in enumerate(temperatures, 1):
            selected_hypothesis = top_hypotheses[(i - 1) % len(top_hypotheses)] if top_hypotheses else None
            hypothesis_dict = selected_hypothesis.model_dump() if selected_hypothesis else None
            previous_failures = hypothesis_manager.get_hypothesis_failures(selected_hypothesis.hypothesis_id) if selected_hypothesis else []
            p_dict = llm_agent.generate_solidity_exploit.remote(
                target.model_dump(), temperature=temp,
                hypothesis_dict=hypothesis_dict, previous_failures=previous_failures
            )
            p = ExploitPayload(**p_dict)
            p.candidate_id = f"{run_id}_c{i}_r0"
            if selected_hypothesis:
                candidate_hypothesis_ids[p.candidate_id] = selected_hypothesis.hypothesis_id
            p.run_id = run_id
            p.generation_iteration = 0
            p.candidate_index = i
            p.attempt_number = i
            if not p.prompt_text:
                p.prompt_text = target_prompt
            initial_payloads.append(p)
            print(f"    [Candidate #{i} | ID: {p.candidate_id}] Hypothesis: {p.hypothesis.vulnerability_type} (t={temp:.2f})")

    # 4. Phase 3: Distributed Execution in Parallel Foundry Sandboxes (.map)
    print(f"\n[Phase 3] Dispatching {len(initial_payloads)} concurrent Foundry sandboxes via Modal .map()...")
    target_dicts = [target.model_dump()] * len(initial_payloads)
    payload_dicts = [p.model_dump() for p in initial_payloads]

    verdict_dicts = list(verify_exploit_remote.map(target_dicts, payload_dicts))

    for idx, (p, vd) in enumerate(zip(initial_payloads, verdict_dicts), 1):
        v = VerificationVerdict(**vd)
        v.candidate_id = p.candidate_id
        v.run_id = run_id
        v.generation_iteration = 0
        v.candidate_index = idx
        hypothesis_id = candidate_hypothesis_ids.get(p.candidate_id)
        if hypothesis_id:
            hypothesis_manager.update_hypothesis_outcome(hypothesis_id, v, p.candidate_id)

        status_icon = "✅ BREACHED" if v.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED else "❌ REJECTED"
        print(f"    [Worker #{idx} | {p.candidate_id}] {status_icon} [{v.category.value}] | Reward: {v.reward_score:+.2f} | {v.feedback[:75]}...")

        rec = CandidateRecord(
            candidate_id=p.candidate_id,
            run_id=run_id,
            target_name=target.name,
            generation_iteration=0,
            candidate_index=idx,
            payload=p,
            verdict=v,
            model_id=model_id,
            checkpoint_id=checkpoint_id,
            prompt_text=p.prompt_text or target_prompt,
            prompt_hash=compute_prompt_hash(p.prompt_text or target_prompt),
            replay_eligible=(v.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED),
            reproduced=False
        )
        all_candidate_records.append(rec)

    # 5. Phase 4: Closed-Loop Multi-Round Refinement (if initial batch had no invariant breach)
    current_round = 1
    while current_round <= max_rounds:
        # Check if an invariant breach already exists
        has_breach = any(c.verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED for c in all_candidate_records)
        if has_breach:
            break

        print(f"\n[Phase 4 - Round {current_round}/{max_rounds}] Refining top-ranked candidate from EVM trace...")
        ranked_so_far = rank_candidates(all_candidate_records)
        best_cand = ranked_so_far[0]
        print(f"    Top candidate to refine: {best_cand.candidate_id} | {best_cand.payload.hypothesis.vulnerability_type} (Score: {best_cand.verdict.reward_score:+.2f})")
        print(f"    EVM trace              : {best_cand.verdict.feedback[:180]}...")

        ref_id = f"{run_id}_ref{current_round}"
        parent_hypothesis_id = candidate_hypothesis_ids.get(best_cand.candidate_id)
        parent_hypothesis = hypothesis_manager.hypotheses.get(parent_hypothesis_id) if parent_hypothesis_id else None
        if generator.lower() == "gemini":
            from core.llm_generator import build_refinement_prompt
            from google import genai
            client = genai.Client()
            parent_attack_hypothesis = hypothesis_manager.to_attack_hypothesis(parent_hypothesis) if parent_hypothesis else None
            prior_failures = hypothesis_manager.get_hypothesis_failures(parent_hypothesis_id) if parent_hypothesis_id else []
            ref_prompt = build_refinement_prompt(
                target, best_cand.payload.test_code, best_cand.verdict.feedback,
                hypothesis=parent_attack_hypothesis, previous_failures=prior_failures
            )
            resp = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=ref_prompt,
                config={"system_instruction": SOLIDITY_SYSTEM_PROMPT, "temperature": 0.1}
            )
            refined_payload = parse_model_response(
                target,
                resp.text or "",
                attempt_idx=current_round + 1,
                prompt_text=ref_prompt
            )
        else:
            prior_failures = hypothesis_manager.get_hypothesis_failures(parent_hypothesis_id) if parent_hypothesis_id else []
            ref_dict = llm_agent.refine_solidity_exploit.remote(
                target.model_dump(),
                best_cand.payload.test_code,
                best_cand.verdict.feedback,
                hypothesis_dict=parent_hypothesis.model_dump() if parent_hypothesis else None,
                previous_failures=prior_failures
            )
            refined_payload = ExploitPayload(**ref_dict)
            if not refined_payload.prompt_text:
                from core.llm_generator import build_refinement_prompt
                refined_payload.prompt_text = build_refinement_prompt(target, best_cand.payload.test_code, best_cand.verdict.feedback)

        refined_payload.candidate_id = ref_id
        if parent_hypothesis_id:
            candidate_hypothesis_ids[ref_id] = parent_hypothesis_id
        refined_payload.run_id = run_id
        refined_payload.generation_iteration = current_round
        refined_payload.candidate_index = len(all_candidate_records) + 1
        refined_payload.attempt_number = current_round + 1

        print(f"[+] Re-testing refined candidate {ref_id} in Foundry sandbox...")
        res_dict = verify_exploit_remote.remote(target.model_dump(), refined_payload.model_dump())
        cand_verdict = VerificationVerdict(**res_dict)
        cand_verdict.candidate_id = ref_id
        cand_verdict.run_id = run_id
        cand_verdict.generation_iteration = current_round
        cand_verdict.candidate_index = refined_payload.candidate_index
        if parent_hypothesis_id:
            hypothesis_manager.update_hypothesis_outcome(parent_hypothesis_id, cand_verdict, ref_id)

        status_icon = "✅ BREACHED" if cand_verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED else "❌ REJECTED"
        print(f"    [Refinement #{current_round} | {ref_id}] {status_icon} [{cand_verdict.category.value}] | Reward: {cand_verdict.reward_score:+.2f}")

        # CRITICAL: Preserve refined candidate in the common audit collection
        ref_record = CandidateRecord(
            candidate_id=ref_id,
            run_id=run_id,
            target_name=target.name,
            generation_iteration=current_round,
            candidate_index=refined_payload.candidate_index,
            payload=refined_payload,
            verdict=cand_verdict,
            model_id=model_id,
            checkpoint_id=checkpoint_id,
            prompt_text=refined_payload.prompt_text,
            prompt_hash=compute_prompt_hash(refined_payload.prompt_text),
            replay_eligible=(cand_verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED),
            reproduced=False
        )
        all_candidate_records.append(ref_record)

        if cand_verdict.category == ResultCategory.INVARIANT_BREACH_UNREPLAYED:
            print(f"[✓] Invariant breach successfully achieved during refinement round {current_round}!")
            break

        current_round += 1

    # 6. Phase 5: Explicit Replay Candidate Selection & Verification (Round 4/5)
    print(f"\n[Phase 5] Selecting replay candidate via explicit ranking policy over ALL {len(all_candidate_records)} candidates...")
    replay_candidate = select_candidate_for_replay(all_candidate_records)

    if replay_candidate is not None:
        print(f"[+] Replay candidate selected: {replay_candidate.candidate_id} (Category: {replay_candidate.verdict.category.value})")
        # Strict candidate ID identity assertion
        assert replay_candidate.candidate_id == replay_candidate.payload.candidate_id, "Candidate ID mismatch with payload"
        assert replay_candidate.candidate_id == replay_candidate.verdict.candidate_id, "Candidate ID mismatch with verdict"

        print(f"[*] Executing independent replay in isolated clean EVM sandbox...")
        try:
            reproduced = verify_replay_remote.remote(target.model_dump(), replay_candidate.payload.model_dump())
            finalize_candidate_replay(replay_candidate, replay_success=reproduced, replay_infra_error=False)
            if reproduced:
                print(f"[✓] EXPLOIT CONFIRMED: Candidate {replay_candidate.candidate_id} reproduced in independent replay.")
            else:
                print(f"[!] Replay failed for candidate {replay_candidate.candidate_id}: marked as unconfirmed breach.")
        except Exception as exc:
            print(f"[!] Replay remote invocation raised infrastructure exception: {type(exc).__name__}: {exc}")
            finalize_candidate_replay(replay_candidate, replay_success=False, replay_infra_error=True)
            replay_candidate.verdict.feedback = f"Replay Infrastructure Error ({type(exc).__name__}): {exc}"

        selected_hypothesis_id = candidate_hypothesis_ids.get(replay_candidate.candidate_id)
        if selected_hypothesis_id:
            hypothesis_manager.update_hypothesis_outcome(
                selected_hypothesis_id, replay_candidate.verdict, replay_candidate.candidate_id
            )

        primary_record = replay_candidate
    else:
        print("[-] No candidate breached the security invariant. Replay NOT ELIGIBLE.")
        # Select best non-breach candidate according to ranking policy
        ranked_all = rank_candidates(all_candidate_records)
        primary_record = ranked_all[0]
        print(f"[*] Best non-success candidate: {primary_record.candidate_id} ({primary_record.verdict.category.value})")

    # 7. Phase 6: Trajectory Persistence Post-Replay (Round 4)
    print(f"\n[Phase 6] Persisting verified trajectory records to Modal Volume...")
    recorded_count = 0
    for record in all_candidate_records:
        if record.verdict.category != ResultCategory.INFRA_ERROR:
            try:
                traj = create_finalized_trajectory(record, target)
                record_trajectory_remote.remote(traj.model_dump())
                recorded_count += 1
            except Exception as e:
                print(f"[!] Trajectory persistence notice: {e}")
    print(f"[✓] {recorded_count} finalized candidate trajectory records committed to persistent Modal Volume.")

    # 8. Phase 7: Complete Audit Report & Summary
    print("\n" + "=" * 78)
    status_label = "✅ CONFIRMED EXPLOIT" if primary_record.verdict.is_verified else "❌ NON-SUCCESS"
    print(f"AEGIS-RLVR VERDICT            : [{status_label}]")
    print(f"Selected Candidate ID         : {primary_record.candidate_id} (Iteration: {primary_record.generation_iteration})")
    print(f"Outcome Category              : {primary_record.verdict.category.value}")
    print(f"Vulnerability Type            : {primary_record.verdict.vulnerability_type}")
    print(f"Final RLVR Ground-Truth Reward: {primary_record.verdict.reward_score:+.2f}")
    print(f"Independent EVM Replay        : {'CONFIRMED (independent replay passed)' if primary_record.verdict.reproducible else 'FAILED / NOT_ELIGIBLE'}")
    print(f"Total Candidates Evaluated    : {len(all_candidate_records)}")
    print("Hypothesis Lifecycle:")
    for hyp in hypothesis_manager.get_top_hypotheses(limit=5):
        print(f"  - {hyp.hypothesis_id}: {hyp.vulnerability_class} [{hyp.validation_status}] attempts={hyp.attempt_count}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
