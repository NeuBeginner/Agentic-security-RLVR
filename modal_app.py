import os
import sys
import modal

# Ensure local core package is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import config
from core.schemas import TargetProgram, ExploitPayload, ExecutionResult, VerificationVerdict
from core.evaluator import evaluate_execution_trace
from core.llm_generator import generate_candidate_exploits
from sandbox.runner import sandbox_image, run_payload_in_sandbox

# Initialize Modal Application
app = modal.App(name=config.APP_NAME)


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
    
    # Load sample target benchmark
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
    print(f"    Invariants specified: {target.invariants}")
    
    # Generate hypothesis rollouts
    print("\n[2] Synthesizing candidate exploit hypotheses...")
    candidates = generate_candidate_exploits(target, num_candidates=3)
    print(f"    Generated {len(candidates)} attack candidate payloads for verification.")
    
    # Prepare arguments for distributed execution
    targets_data = [target.model_dump() for _ in candidates]
    payloads_data = [c.model_dump() for c in candidates]
    
    # Parallel Serverless Execution on Modal
    print(f"\n[3] Dispatching parallel sandboxes to Modal Cloud...")
    print(f"    Spawning {len(candidates)} ephemeral containers...")
    
    results = list(verify_exploit_remote.map(targets_data, payloads_data))
    
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
            print(f"  Reproducible PoC File: {candidates[idx-1].test_filename}")

    print("\n" + "-" * 70)
    print(f"Summary: {verified_count}/{len(candidates)} exploits rigorously verified in isolated sandboxes.")
    print("Zero False Positives: Only mathematically proven violations accepted.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
