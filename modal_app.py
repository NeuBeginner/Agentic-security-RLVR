import os
import sys
import modal

# Ensure local core and sandbox packages are in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import config
from core.schemas import TargetProgram, ExploitPayload, ExecutionResult, VerificationVerdict
from core.evaluator import evaluate_execution_trace
from sandbox.runner import sandbox_image, run_payload_in_sandbox

# Initialize Modal Application
app = modal.App(name=config.APP_NAME)

# Persistent volume for caching model weights across container restarts
model_volume = modal.Volume.from_name(config.MODEL_VOLUME_NAME, create_if_missing=True)

# GPU Image for reasoning and exploit synthesis engine
gpu_image = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install(
        "torch",
        "transformers>=4.40.0",
        "accelerate>=0.28.0",
        "pydantic>=2.0.0",
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
    Loads specialized Qtum 30B Audit weights (qtum/Qwen3-Coder-30B-A3B-Audit).
    """
    @modal.enter()
    def load_model(self):
        import os
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        cache_dir = config.MODEL_CACHE_DIR
        os.makedirs(cache_dir, exist_ok=True)
        
        print(f"[*] Initializing Production 30B Model on Modal {config.AUDIT_GPU_TYPE}: {config.AUDIT_GPU_MODEL}")
        print(f"[*] Persistent volume cache: {cache_dir}")
        
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
            print("[✓] Production 30B model weights committed to persistent Modal Volume.")
        except Exception as e:
            print(f"[!] Volume commit notice: {e}")
            
        allocated_mb = torch.cuda.memory_allocated() / (1024 ** 2)
        print(f"[+] 30B Audit Model loaded. Active VRAM: {allocated_mb:.1f} MB.")

    @modal.method()
    def generate_solidity_exploit(self, target_dict: dict, temperature: float = 0.3) -> dict:
        """Synthesizes a Foundry test contract using 30B reasoning model."""
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_analysis_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        user_prompt = build_analysis_prompt(target)
        
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
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)
        ]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        return parse_model_response(target, response_text).model_dump()

    @modal.method()
    def refine_solidity_exploit(self, target_dict: dict, failed_code: str, error_trace: str) -> dict:
        """Closed-loop self-correction using 30B model guided by Foundry EVM trace."""
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_refinement_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        prompt = build_refinement_prompt(target, failed_code, error_trace)
        
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
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)
        ]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        return parse_model_response(target, response_text, attempt_idx=99).model_dump()


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
    """
    Lightweight dev reasoning agent on Modal T4 (Qwen2.5-Coder-1.5B-Instruct).
    Used for cost-efficient sanity checks of the Foundry compilation/execution pipeline.
    """
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
        try:
            model_volume.commit()
        except Exception:
            pass
        allocated_mb = torch.cuda.memory_allocated() / (1024 ** 2)
        print(f"[+] Dev Model loaded on T4. VRAM: {allocated_mb:.1f} MB.")

    @modal.method()
    def generate_solidity_exploit(self, target_dict: dict, temperature: float = 0.3) -> dict:
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_analysis_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        user_prompt = build_analysis_prompt(target)
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
        return parse_model_response(target, response_text).model_dump()

    @modal.method()
    def refine_solidity_exploit(self, target_dict: dict, failed_code: str, error_trace: str) -> dict:
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SOLIDITY_SYSTEM_PROMPT, build_refinement_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        prompt = build_refinement_prompt(target, failed_code, error_trace)
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
        return parse_model_response(target, response_text, attempt_idx=99).model_dump()


# =============================================================================
# 3. EPHEMERAL FOUNDRY / EVM SANDBOX WORKER
# =============================================================================
@app.function(
    image=sandbox_image,
    timeout=config.SANDBOX_TIMEOUT_SEC,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def verify_exploit_remote(target_dict: dict, payload_dict: dict) -> dict:
    """
    Modal Remote Function (Foundry / EVM Sandbox Worker):
    Compiles Solidity contract via cached solc and executes forge test --offline --json -vvvv.
    """
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    
    # 1. Execute in Foundry EVM sandbox (offline + JSON)
    raw_result = run_payload_in_sandbox(target, payload)
    
    # 2. Evaluate verifiable reward & invariant status
    verdict = evaluate_execution_trace(payload, raw_result)
    
    return verdict.model_dump()


# =============================================================================
# 4. CLI ENTRYPOINT
# =============================================================================
@app.local_entrypoint()
def main(mode: str = "audit", target_name: str = "Vault"):
    """
    CLI orchestrator on Modal.
    Usage:
      Production Mode (H100 + 30B Qtum Audit Model):
        modal run modal_app.py --mode audit --target-name Vault
        modal run modal_app.py --mode audit --target-name ERC4626Vault

      Dev / Smoke-Test Mode (T4 + 1.5B Model):
        modal run modal_app.py --mode dev --target-name Vault
        modal run modal_app.py --mode dev --target-name ERC4626Vault
    """
    print("\n" + "=" * 75)
    print("🛡️  AEGIS-RLVR: Web3 Smart Contract Foundry EVM Pipeline on Modal")
    print(f"📦 Model Persistent Volume: '{config.MODEL_VOLUME_NAME}'")
    print(f"⚙️  Execution Profile     : '{mode.upper()}'")
    print(f"🎯 Target Contract        : '{target_name}'")
    print("=" * 75)
    
    # Select reasoning engine based on mode
    if mode.lower() == "audit":
        print(f"\n[+] Production Tier: Loading {config.AUDIT_GPU_MODEL} on Modal {config.AUDIT_GPU_TYPE}...")
        generator = ProductionAuditAgent()
    else:
        print(f"\n[+] Dev/CI Tier: Loading {config.DEV_GPU_MODEL} on Modal {config.DEV_GPU_TYPE}...")
        generator = DevReasoningAgent()
    
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
    print(f"    Invariants: {target.invariants}")
    print(f"    Trusted Harness: {target_name}Harness.t.sol")
    print(f"    Solidity Version: {config.SOLC_VERSION}")
    
    # 2. Neural Exploit Synthesis on Modal GPU
    print(f"\n[2] Dispatching to Modal GPU for Solidity Exploit Synthesis...")
    payload_dict = generator.generate_solidity_exploit.remote(target.model_dump(), temperature=0.3)
    payload = ExploitPayload(**payload_dict)
    
    print(f"[+] Model formulated hypothesis: {payload.hypothesis.vulnerability_type}")
    print(f"[+] Reasoning snippet: {payload.hypothesis.reasoning_trace[:150]}...")
    print(f"[+] Synthesized ExploitModule ({len(payload.test_code.splitlines())} lines):")
    print("-" * 50)
    print(payload.test_code)
    print("-" * 50)
    
    # 3. Execution in Foundry Sandbox against Trusted Harness on Modal
    print("\n[3] Spawning ephemeral Foundry/EVM container on Modal Cloud...")
    print(f"    Running: forge test --offline --json -vvvv against {target_name}Harness.t.sol ...")
    
    result_dict = verify_exploit_remote.remote(target.model_dump(), payload.model_dump())
    verdict = VerificationVerdict(**result_dict)
    
    # 4. Closed-loop Refinement if needed
    if not verdict.is_verified:
        print(f"\n[!] Initial exploit rejected: {verdict.feedback[:200]}...")
        print("[*] Feeding structured EVM execution trace back to GPU for refinement...")
        
        refined_dict = generator.refine_solidity_exploit.remote(
            target.model_dump(),
            payload.test_code,
            verdict.feedback
        )
        refined_payload = ExploitPayload(**refined_dict)
        print(f"[+] Refined ExploitModule ({len(refined_payload.test_code.splitlines())} lines):")
        print("-" * 50)
        print(refined_payload.test_code)
        print("-" * 50)
        
        print("[*] Re-testing refined ExploitModule in Foundry sandbox...")
        result_dict = verify_exploit_remote.remote(target.model_dump(), refined_payload.model_dump())
        verdict = VerificationVerdict(**result_dict)
        
    print("\n" + "=" * 75)
    status = f"✅ VERIFIED EXPLOIT ({verdict.vulnerability_type} INVARIANT BREACHED)" if verdict.is_verified else "❌ REJECTED"
    print(f"EVM VERIFICATION VERDICT: [{status}]")
    print(f"Vulnerability Type     : {verdict.vulnerability_type}")
    print(f"RLVR Reward            : {verdict.reward_score:+.2f}")
    print(f"Sandbox Feedback       : {verdict.feedback}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
