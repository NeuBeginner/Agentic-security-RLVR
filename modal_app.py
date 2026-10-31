import os
import sys
import modal

# Ensure local core package is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import config
from core.schemas import TargetProgram, ExploitPayload, ExecutionResult, VerificationVerdict
from core.evaluator import evaluate_execution_trace
from sandbox.runner import sandbox_image, run_payload_in_sandbox

# Initialize Modal Application
app = modal.App(name=config.APP_NAME)

# 1. GPU Image for reasoning and refinement engine
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


@app.cls(
    gpu=config.DEV_GPU_TYPE,
    image=gpu_image,
    timeout=600,
)
class SolidityReasoningAgent:
    """
    GPU-accelerated Web3 reasoning agent on Modal.
    Loads neural network weights and synthesizes Foundry (Solidity) exploit test suites.
    """
    @modal.enter()
    def load_model(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        print(f"[*] Initializing model on Modal GPU ({config.DEV_GPU_TYPE}): {config.DEV_GPU_MODEL}")
        self.tokenizer = AutoTokenizer.from_pretrained(config.DEV_GPU_MODEL)
        self.model = AutoModelForCausalLM.from_pretrained(
            config.DEV_GPU_MODEL,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        allocated_mb = torch.cuda.memory_allocated() / (1024 ** 2)
        print(f"[+] Model weights loaded into GPU VRAM: {allocated_mb:.1f} MB allocated.")

    @modal.method()
    def generate_solidity_exploit(self, target_dict: dict, temperature: float = 0.3) -> dict:
        """Synthesizes a Foundry test contract to exploit the target Solidity contract."""
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
        
        payload = parse_model_response(target, response_text)
        return payload.model_dump()

    @modal.method()
    def refine_solidity_exploit(self, target_dict: dict, failed_code: str, error_trace: str) -> dict:
        """Closed-loop self-correction using Foundry (forge test) execution feedback."""
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


@app.function(
    image=sandbox_image,
    timeout=config.SANDBOX_TIMEOUT_SEC,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def verify_exploit_remote(target_dict: dict, payload_dict: dict) -> dict:
    """
    Modal Remote Function (Foundry / EVM Sandbox Worker):
    Compiles Solidity contract via solc 0.8.20 and executes forge test in an isolated EVM.
    """
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    
    # 1. Execute in Foundry EVM sandbox
    raw_result = run_payload_in_sandbox(target, payload)
    
    # 2. Evaluate verifiable reward & invariant status
    verdict = evaluate_execution_trace(payload, raw_result)
    
    return verdict.model_dump()


@app.local_entrypoint()
def main():
    """
    Local CLI entrypoint for orchestrating distributed Foundry verification on Modal.
    Usage: modal run modal_app.py
    """
    print("\n" + "=" * 75)
    print("🛡️  AEGIS-RLVR: Web3 Smart Contract Foundry EVM Pipeline on Modal")
    print("=" * 75)
    
    # 1. Load real Solidity target contract
    target_path = os.path.join(
        os.path.dirname(__file__), "benchmarks", "targets", "solidity", "Vault.sol"
    )
    with open(target_path, "r", encoding="utf-8") as f:
        target_source = f.read()
        
    target = TargetProgram(
        name="Vault",
        source_code=target_source,
        language="solidity",
        invariants=["address(vault).balance >= totalDeposits"]
    )
    
    print(f"\n[1] Target loaded: '{target.name}.sol'")
    print(f"    Invariants: {target.invariants}")
    print(f"    Solidity Version: {config.SOLC_VERSION}")
    
    # 2. Neural Exploit Synthesis on Modal GPU
    print(f"\n[2] Dispatching to Modal GPU ({config.DEV_GPU_TYPE}) for Solidity Exploit Synthesis...")
    generator = SolidityReasoningAgent()
    
    payload_dict = generator.generate_solidity_exploit.remote(target.model_dump(), temperature=0.3)
    payload = ExploitPayload(**payload_dict)
    
    print(f"[+] Model formulated hypothesis: {payload.hypothesis.vulnerability_type}")
    print(f"[+] Reasoning snippet: {payload.hypothesis.reasoning_trace[:150]}...")
    print(f"[+] Synthesized Foundry test: {len(payload.test_code.splitlines())} lines.")
    
    # 3. Execution in Foundry Sandbox on Modal
    print("\n[3] Spawning ephemeral Foundry/EVM container on Modal Cloud...")
    print("    Running: forge test -vvv ...")
    
    result_dict = verify_exploit_remote.remote(target.model_dump(), payload.model_dump())
    verdict = VerificationVerdict(**result_dict)
    
    # 4. Closed-loop Refinement if needed
    if not verdict.is_verified:
        print(f"\n[!] Initial test rejected: {verdict.feedback[:200]}...")
        print("[*] Feeding forge execution trace back to GPU for automated refinement...")
        
        refined_dict = generator.refine_solidity_exploit.remote(
            target.model_dump(),
            payload.test_code,
            verdict.feedback
        )
        refined_payload = ExploitPayload(**refined_dict)
        
        print("[*] Re-testing refined exploit in Foundry sandbox...")
        result_dict = verify_exploit_remote.remote(target.model_dump(), refined_payload.model_dump())
        verdict = VerificationVerdict(**result_dict)
        
    print("\n" + "=" * 75)
    status = "✅ VERIFIED EXPLOIT (EVM INVARIANT BREACHED)" if verdict.is_verified else "❌ REJECTED"
    print(f"EVM VERIFICATION VERDICT: [{status}]")
    print(f"Vulnerability Type     : {verdict.vulnerability_type}")
    print(f"RLVR Reward            : {verdict.reward_score:+.2f}")
    print(f"Sandbox Feedback       : {verdict.feedback}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
