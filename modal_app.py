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

# 1. Image definition for GPU reasoning engine
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
    gpu=config.GENERATOR_GPU,
    image=gpu_image,
    timeout=600,
)
class ReasoningGenerator:
    """
    GPU-accelerated reasoning agent on Modal.
    Loads neural network weights and generates dynamic exploit test suites.
    """
    @modal.enter()
    def load_model(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        print(f"[*] Initializing model on Modal GPU ({config.GENERATOR_GPU}): {config.DEFAULT_MODEL_NAME}")
        self.tokenizer = AutoTokenizer.from_pretrained(config.DEFAULT_MODEL_NAME)
        self.model = AutoModelForCausalLM.from_pretrained(
            config.DEFAULT_MODEL_NAME,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        allocated_mb = torch.cuda.memory_allocated() / (1024 ** 2)
        print(f"[+] Model weights loaded into GPU VRAM: {allocated_mb:.1f} MB allocated.")

    @modal.method()
    def generate_candidate(self, target_dict: dict, temperature: float = 0.2) -> dict:
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SYSTEM_PROMPT, build_analysis_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        user_prompt = build_analysis_prompt(target)
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=config.MAX_TOKENS,
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


@app.function(
    image=sandbox_image,
    timeout=config.SANDBOX_TIMEOUT_SEC,
    cpu=config.SANDBOX_CPU_CORES,
    memory=config.SANDBOX_MEMORY_MB,
)
def verify_exploit_remote(target_dict: dict, payload_dict: dict) -> dict:
    """
    Modal Remote Function:
    Runs an individual exploit candidate inside an isolated, ephemeral sandbox.
    Can be dynamically mapped to hundreds of parallel instances.
    """
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    
    # 1. Execute in isolated sandbox
    raw_result = run_payload_in_sandbox(target, payload)
    
    # 2. Evaluate verifiable reward & invariant status
    verdict = evaluate_execution_trace(payload, raw_result)
    
    return verdict.model_dump()


@app.local_entrypoint()
def main():
    """
    Local CLI entrypoint for orchestrating distributed verification on Modal.
    Usage: modal run modal_app.py
    """
    print("\n" + "=" * 70)
    print("🛡️  AEGIS-RLVR: Scalable Neuro-Symbolic Agentic Fuzzing on Modal")
    print("=" * 70)
    
    # 1. Load benchmark target
    benchmark_file = os.path.join(
        os.path.dirname(__file__), "benchmarks", "targets", "sample_vault.py"
    )
    with open(benchmark_file, "r", encoding="utf-8") as f:
        target_source = f.read()
        
    target = TargetProgram(
        name="vault",
        source_code=target_source,
        language="python",
        invariants=["total_funds >= sum(balances)", "owner == initial_owner"]
    )
    
    print(f"\n[1] Target loaded: '{target.name}'")
    print(f"    Invariants: {target.invariants}")
    
    # 2. Real GPU Inference on Modal
    print(f"\n[2] Dispatching to Modal GPU ({config.GENERATOR_GPU}) for neural exploit synthesis...")
    print(f"    Loading model: {config.DEFAULT_MODEL_NAME}")
    
    generator = ReasoningGenerator()
    
    # Generate 2 distinct rollouts at different sampling temperatures
    print("    Generating Rollout #1 (temp=0.1, greedy/focused)...")
    payload_1 = generator.generate_candidate.remote(target.model_dump(), temperature=0.1)
    
    print("    Generating Rollout #2 (temp=0.6, exploratory)...")
    payload_2 = generator.generate_candidate.remote(target.model_dump(), temperature=0.6)
    
    candidates = [ExploitPayload(**payload_1), ExploitPayload(**payload_2)]
    print(f"[+] Model synthesized {len(candidates)} real exploit payloads via GPU.")
    
    for idx, c in enumerate(candidates, start=1):
        print(f"\n--- Candidate #{idx} (Generated by Model) ---")
        print(f"Vulnerability Type: {c.hypothesis.vulnerability_type}")
        print(f"Reasoning snippet : {c.hypothesis.reasoning_trace[:150]}...")
        print(f"Code lines count  : {len(c.test_code.splitlines())}")

    # 3. Parallel Serverless Execution on Modal CPU Sandboxes
    print(f"\n[3] Dispatching parallel sandboxes to Modal Cloud...")
    print(f"    Spawning {len(candidates)} ephemeral containers for execution...")
    
    targets_data = [target.model_dump() for _ in candidates]
    payloads_data = [c.model_dump() for c in candidates]
    
    results = list(verify_exploit_remote.map(targets_data, payloads_data))
    
    # 4. Results & RLVR Feedback
    print("\n" + "=" * 70)
    print("📊 VERIFICATION RESULTS & REWARD MATRIX")
    print("=" * 70)
    
    verified_count = 0
    for idx, res in enumerate(results, start=1):
        verdict = VerificationVerdict(**res)
        status = "✅ VERIFIED EXPLOIT" if verdict.is_verified else "❌ REJECTED"
        print(f"\nCandidate #{idx}: [{status}]")
        print(f"  Vulnerability : {verdict.vulnerability_type}")
        print(f"  RLVR Reward   : {verdict.reward_score:+.2f}")
        print(f"  Feedback      : {verdict.feedback}")
        if verdict.is_verified:
            verified_count += 1

    print("\n" + "-" * 70)
    print(f"Summary: {verified_count}/{len(candidates)} exploits verified in isolated sandboxes.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
