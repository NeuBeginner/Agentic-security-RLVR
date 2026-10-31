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

    @modal.method()
    def audit_target_contract(self, target_dict: dict) -> list:
        """
        Native role for Qwen-Audit: analyzes Solidity code and outputs
        structured JSON array of vulnerability findings.
        """
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
def main(mode: str = "audit", target_name: str = "Vault", num_candidates: int = 3):
    """
    CLI orchestrator on Modal.
    Usage:
      Production Mode (H100 + 30B Qtum Audit Model):
        modal run modal_app.py --mode audit --target-name Vault
        modal run modal_app.py --mode audit --target-name ERC4626Vault --num-candidates 3

      Dev / Smoke-Test Mode (T4 + 1.5B Model):
        modal run modal_app.py --mode dev --target-name Vault
        modal run modal_app.py --mode dev --target-name ERC4626Vault --num-candidates 3
    """
    print("\n" + "=" * 75)
    print("🛡️  AEGIS-RLVR: Web3 Smart Contract Foundry EVM Pipeline on Modal")
    print(f"📦 Model Persistent Volume: '{config.MODEL_VOLUME_NAME}'")
    print(f"⚙️  Execution Profile     : '{mode.upper()}'")
    print(f"🎯 Target Contract        : '{target_name}'")
    print(f"⚡ Parallel Candidates    : {num_candidates}")
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
    
    # Optional: If Production mode, run native Qwen-Audit detection first
    if mode.lower() == "audit":
        print("\n[*] Running Native Qwen-Audit Security Scan...")
        try:
            audit_findings = generator.audit_target_contract.remote(target.model_dump())
            print(f"[+] Qwen-Audit identified {len(audit_findings)} finding(s):")
            for idx, finding in enumerate(audit_findings, 1):
                title = finding.get("title", "Unknown")
                cat = finding.get("category", "General")
                sev = finding.get("severity", "Medium")
                print(f"    {idx}. [{sev}] {title} ({cat})")
        except Exception as e:
            print(f"[!] Audit scan notice: {e}")

    # 2. Parallel Exploit Synthesis (Agentic Fuzzing / Multi-Candidate Rollout)
    print(f"\n[2] Dispatching {num_candidates} parallel exploit hypotheses to Modal GPU...")
    temperatures = [0.2 + (i * 0.25) for i in range(num_candidates)]
    candidate_payloads = []
    
    for i, temp in enumerate(temperatures, 1):
        payload_dict = generator.generate_solidity_exploit.remote(target.model_dump(), temperature=temp)
        payload = ExploitPayload(**payload_dict)
        payload.attempt_number = i
        candidate_payloads.append(payload)
        print(f"    [Candidate #{i}] Hypothesis: {payload.hypothesis.vulnerability_type} (temp={temp:.2f})")

    # 3. Parallel Execution in Ephemeral Foundry Sandboxes on Modal Cloud (.map)
    print(f"\n[3] Spawning {len(candidate_payloads)} parallel ephemeral Foundry/EVM containers (.map)...")
    target_dicts = [target.model_dump()] * len(candidate_payloads)
    payload_dicts = [p.model_dump() for p in candidate_payloads]
    
    # Distributed execution across Modal CPU workers
    verdict_dicts = list(verify_exploit_remote.map(target_dicts, payload_dicts))
    verdicts = [VerificationVerdict(**vd) for vd in verdict_dicts]

    for idx, (p, v) in enumerate(zip(candidate_payloads, verdicts), 1):
        status_icon = "✅ BREACHED" if v.is_verified else "❌ REJECTED"
        print(f"    [Worker #{idx}] {status_icon} | Reward: {v.reward_score:+.2f} | {v.feedback[:80]}...")

    # Identify if any candidate succeeded
    verified_verdict = next((v for v in verdicts if v.is_verified), None)
    verified_payload = next((p for p, v in zip(candidate_payloads, verdicts) if v.is_verified), None)

    # 4. Closed-loop Refinement if needed
    if not verified_verdict:
        print("\n[!] None of the initial candidates breached the invariant.")
        print("[*] Selecting candidate with highest reward for closed-loop refinement...")
        best_candidate, best_verdict = max(zip(candidate_payloads, verdicts), key=lambda cv: cv[1].reward_score)
        print(f"    Top candidate: {best_candidate.hypothesis.vulnerability_type} (Score: {best_verdict.reward_score:+.2f})")
        print(f"    EVM feedback: {best_verdict.feedback[:200]}...")
        
        refined_dict = generator.refine_solidity_exploit.remote(
            target.model_dump(),
            best_candidate.test_code,
            best_verdict.feedback
        )
        refined_payload = ExploitPayload(**refined_dict)
        print(f"[+] Refined ExploitModule synthesized ({len(refined_payload.test_code.splitlines())} lines).")
        
        print("[*] Re-testing refined ExploitModule in Foundry sandbox...")
        res_dict = verify_exploit_remote.remote(target.model_dump(), refined_payload.model_dump())
        final_verdict = VerificationVerdict(**res_dict)
        final_payload = refined_payload
    else:
        final_verdict = verified_verdict
        final_payload = verified_payload

    print("\n" + "=" * 75)
    status = f"✅ VERIFIED EXPLOIT ({final_verdict.vulnerability_type} INVARIANT BREACHED)" if final_verdict.is_verified else "❌ REJECTED"
    print(f"EVM VERIFICATION VERDICT: [{status}]")
    print(f"Vulnerability Type     : {final_verdict.vulnerability_type}")
    print(f"RLVR Reward Score      : {final_verdict.reward_score:+.2f}")
    print(f"State Delta Verified   : {final_verdict.state_delta_verified}")
    print(f"Reproducible in EVM    : {final_verdict.reproducible}")
    print(f"Sandbox Feedback       : {final_verdict.feedback}")
    print("=" * 75 + "\n")



if __name__ == "__main__":
    main()
