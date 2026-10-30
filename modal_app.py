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
    gpu=config.GENERATOR_GPU,
    image=gpu_image,
    timeout=900,
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
    def generate_batch(self, target_dict: dict, count: int = 10) -> list:
        """Generates a batch of distinct candidate rollouts using varied sampling temperatures."""
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

        payloads = []
        temperatures = [0.2, 0.3, 0.4, 0.5, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85]
        
        print(f"[*] Generating {count} distinct rollouts on GPU...")
        with torch.no_grad():
            for i in range(count):
                temp = temperatures[i % len(temperatures)]
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=config.MAX_TOKENS,
                    temperature=temp,
                    do_sample=(temp > 0.0),
                    pad_token_id=self.tokenizer.eos_token_id
                )
                generated_ids = [
                    output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)
                ]
                response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
                payload = parse_model_response(target, response_text, attempt_idx=i+1)
                payloads.append(payload.model_dump())
                
        return payloads

    @modal.method()
    def refine_candidate(self, target_dict: dict, failed_code: str, error_feedback: str) -> dict:
        """
        Closed-loop self-correction:
        Feeds the sandbox execution feedback back to the model to synthesize a corrected exploit.
        """
        import torch
        from core.schemas import TargetProgram
        from core.llm_generator import SYSTEM_PROMPT, build_refinement_prompt, parse_model_response

        target = TargetProgram(**target_dict)
        refinement_prompt = build_refinement_prompt(target, failed_code, error_feedback)
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": refinement_prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=config.MAX_TOKENS,
                temperature=0.2,  # Low temperature for careful correction
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(inputs.input_ids, outputs)
        ]
        response_text = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        
        refined_payload = parse_model_response(target, response_text, attempt_idx=99)
        return refined_payload.model_dump()


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
    print("\n" + "=" * 75)
    print("🛡️  AEGIS-RLVR: 10-Rollout Exploration & Closed-Loop Refinement Pipeline")
    print("=" * 75)
    
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
    
    # 2. Batch Generation on Modal GPU (10 attempts)
    print(f"\n[2] Dispatching to Modal GPU ({config.GENERATOR_GPU}) for 10 Neural Rollouts...")
    generator = ReasoningGenerator()
    
    raw_payloads = generator.generate_batch.remote(target.model_dump(), count=10)
    candidates = [ExploitPayload(**p) for p in raw_payloads]
    print(f"[+] Successfully synthesized {len(candidates)} candidates on GPU.")
    
    # 3. Parallel Execution in 10 Modal Sandboxes
    print(f"\n[3] Spawning {len(candidates)} parallel ephemeral sandboxes in Modal Cloud...")
    targets_data = [target.model_dump() for _ in candidates]
    payloads_data = [c.model_dump() for c in candidates]
    
    results = list(verify_exploit_remote.map(targets_data, payloads_data))
    
    print("\n" + "=" * 75)
    print("📊 INITIAL 10-ROLLOUT RESULTS")
    print("=" * 75)
    
    verified_candidates = []
    failed_candidates = []
    
    for idx, res in enumerate(results, start=1):
        verdict = VerificationVerdict(**res)
        status = "✅ VERIFIED EXPLOIT" if verdict.is_verified else "❌ REJECTED"
        print(f"Attempt #{idx:02d}: [{status}] | Type: {verdict.vulnerability_type} | Reward: {verdict.reward_score:+.2f}")
        if verdict.is_verified:
            verified_candidates.append((candidates[idx-1], verdict))
        else:
            failed_candidates.append((candidates[idx-1], verdict))
            
    print(f"\nInitial Pass Rate: {len(verified_candidates)}/{len(candidates)} verified.")

    # 4. Closed-Loop Refinement (Feedback Loop)
    if failed_candidates and len(verified_candidates) < len(candidates):
        print("\n" + "=" * 75)
        print("🔄 ACTIVATING CLOSED-LOOP REFINEMENT (SELF-CORRECTION)")
        print("=" * 75)
        
        # Take the most promising failed attempt that had an execution trace
        candidate_to_refine, failed_verdict = failed_candidates[0]
        print(f"[*] Selected Candidate for refinement: {candidate_to_refine.hypothesis.vulnerability_type}")
        print(f"[*] Sandbox Error Feedback: {failed_verdict.feedback[:200]}...")
        print("[*] Feeding error feedback back to Modal GPU for automated correction...")
        
        refined_dict = generator.refine_candidate.remote(
            target.model_dump(),
            candidate_to_refine.test_code,
            failed_verdict.feedback
        )
        refined_candidate = ExploitPayload(**refined_dict)
        print(f"[+] GPU synthesized refined exploit ({len(refined_candidate.test_code.splitlines())} lines).")
        
        # Re-run refined candidate in sandbox
        print("[*] Dispatching refined candidate to Modal sandbox...")
        refined_result_dict = verify_exploit_remote.remote(target.model_dump(), refined_candidate.model_dump())
        refined_verdict = VerificationVerdict(**refined_result_dict)
        
        ref_status = "✅ VERIFIED EXPLOIT" if refined_verdict.is_verified else "❌ REJECTED"
        print(f"\nRefinement Result: [{ref_status}]")
        print(f"  Vulnerability : {refined_verdict.vulnerability_type}")
        print(f"  RLVR Reward   : {refined_verdict.reward_score:+.2f}")
        print(f"  Feedback      : {refined_verdict.feedback}")
        
        if refined_verdict.is_verified:
            verified_candidates.append((refined_candidate, refined_verdict))

    print("\n" + "=" * 75)
    print(f"🏁 FINAL SUMMARY: {len(verified_candidates)} exploit(s) rigorously proven and verified.")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
