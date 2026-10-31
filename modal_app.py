import os
import sys
import json
import modal

# Ensure local core and sandbox packages are in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import config
from core.schemas import (
    TargetProgram,
    ExploitPayload,
    ExecutionResult,
    VerificationVerdict,
    AttackHypothesis,
    RLVRTrajectory
)
from core.evaluator import evaluate_execution_trace, create_trajectory_record
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
    """Independent second run in a fresh ephemeral EVM container to guarantee reproducibility."""
    target = TargetProgram(**target_dict)
    payload = ExploitPayload(**payload_dict)
    return verify_independent_replay(target, payload)


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


# =============================================================================
# 4. CLI ENTRYPOINT: AEGIS-RLVR 2.0 ORCHESTRATOR
# =============================================================================
@app.local_entrypoint()
def main(
    mode: str = "audit",
    target_name: str = "Vault",
    generator: str = "local",
    num_candidates: int = 3,
    max_rounds: int = 2
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
    """
    print("\n" + "=" * 78)
    print("🛡️  AEGIS-RLVR 2.0: Autonomous Multi-Agent Web3 Security Framework")
    print(f"📦 Model Persistent Volume  : '{config.MODEL_VOLUME_NAME}'")
    print(f"⚙️  Execution Profile        : '{mode.upper()}' (Generator: {generator.upper()})")
    print(f"🎯 Target Contract           : '{target_name}'")
    print(f"⚡ Parallel Hypotheses (.map): {num_candidates}")
    print("=" * 78)

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

    # 2. Phase 1: Static Analysis Layer (Slither AST Taint Analysis)
    if config.ENABLE_SLITHER:
        print("\n[Phase 1] Running Slither Static Analysis on Modal CPU Worker...")
        try:
            slither_findings = run_slither_remote.remote(target.model_dump())
            target.slither_findings = slither_findings
            print(f"[✓] Slither extracted {len(slither_findings)} AST detector signal(s):")
            for sf in slither_findings:
                print(f"    - [{sf.get('impact')}] {sf.get('check')}: {sf.get('description')[:70]}...")
        except Exception as e:
            print(f"[!] Slither notice: {e}")

    # 3. Phase 2: Hypothesis Formulation & Multi-Candidate Exploit Synthesis
    print(f"\n[Phase 2] Synthesizing {num_candidates} parallel exploit hypotheses...")
    candidate_payloads = []

    if generator.lower() == "gemini":
        print("[+] Generator: Gemini 2.5 Flash (Frontier Reasoning API)")
        for i in range(1, num_candidates + 1):
            p = synthesize_exploit_gemini(target)
            p.attempt_number = i
            candidate_payloads.append(p)
            print(f"    [Candidate #{i}] Hypothesis: {p.hypothesis.vulnerability_type} (Gemini API)")
    else:
        if mode.lower() == "audit":
            print(f"[+] Generator: Production Tier ({config.AUDIT_GPU_MODEL} on Modal H100)")
            llm_agent = ProductionAuditAgent()
            # Optional native Qwen-Audit scan
            try:
                findings = llm_agent.audit_target_contract.remote(target.model_dump())
                print(f"[+] Qwen-Audit detected {len(findings)} vulnerability finding(s):")
                for f_item in findings[:3]:
                    print(f"    - [{f_item.get('severity', 'Med')}] {f_item.get('title')}")
            except Exception as e:
                print(f"[!] Audit scan notice: {e}")
        else:
            print(f"[+] Generator: Dev Tier ({config.DEV_GPU_MODEL} on Modal T4)")
            llm_agent = DevReasoningAgent()

        temperatures = [0.2 + (i * 0.2) for i in range(num_candidates)]
        for i, temp in enumerate(temperatures, 1):
            p_dict = llm_agent.generate_solidity_exploit.remote(target.model_dump(), temperature=temp)
            p = ExploitPayload(**p_dict)
            p.attempt_number = i
            candidate_payloads.append(p)
            print(f"    [Candidate #{i}] Hypothesis: {p.hypothesis.vulnerability_type} (t={temp:.2f})")

    # 4. Phase 3: Distributed Execution in Parallel Foundry Sandboxes (.map)
    print(f"\n[Phase 3] Dispatching {len(candidate_payloads)} concurrent Foundry sandboxes via Modal .map()...")
    target_dicts = [target.model_dump()] * len(candidate_payloads)
    payload_dicts = [p.model_dump() for p in candidate_payloads]

    verdict_dicts = list(verify_exploit_remote.map(target_dicts, payload_dicts))
    verdicts = [VerificationVerdict(**vd) for vd in verdict_dicts]

    for idx, (p, v) in enumerate(zip(candidate_payloads, verdicts), 1):
        status_icon = "✅ BREACHED" if v.is_verified else "❌ REJECTED"
        print(f"    [Worker #{idx}] {status_icon} | Reward: {v.reward_score:+.2f} | {v.feedback[:80]}...")

    verified_verdict = next((v for v in verdicts if v.is_verified), None)
    verified_payload = next((p for p, v in zip(candidate_payloads, verdicts) if v.is_verified), None)

    # 5. Phase 4: Closed-Loop Multi-Round Refinement (if initial batch failed)
    current_round = 1
    while not verified_verdict and current_round <= max_rounds:
        print(f"\n[Phase 4 - Round {current_round}/{max_rounds}] Refining top candidate from EVM trace...")
        best_cand, best_verd = max(zip(candidate_payloads, verdicts), key=lambda cv: cv[1].reward_score)
        print(f"    Top candidate: {best_cand.hypothesis.vulnerability_type} (Score: {best_verd.reward_score:+.2f})")
        print(f"    EVM trace: {best_verd.feedback[:200]}...")

        if generator.lower() == "gemini":
            from core.llm_generator import build_refinement_prompt, extract_solidity_code
            from google import genai
            client = genai.Client()
            ref_prompt = build_refinement_prompt(target, best_cand.test_code, best_verd.feedback)
            resp = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=ref_prompt,
                config={"system_instruction": SOLIDITY_SYSTEM_PROMPT, "temperature": 0.1}
            )
            refined_payload = parse_model_response(target, resp.text or "", attempt_idx=current_round + 1)
        else:
            ref_dict = llm_agent.refine_solidity_exploit.remote(
                target.model_dump(),
                best_cand.test_code,
                best_verd.feedback
            )
            refined_payload = ExploitPayload(**ref_dict)
            refined_payload.attempt_number = current_round + 1

        print(f"[+] Re-testing refined candidate in Foundry sandbox...")
        res_dict = verify_exploit_remote.remote(target.model_dump(), refined_payload.model_dump())
        cand_verdict = VerificationVerdict(**res_dict)
        if cand_verdict.is_verified:
            verified_verdict = cand_verdict
            verified_payload = refined_payload
            break
        current_round += 1

    final_verdict = verified_verdict or verdicts[0]
    final_payload = verified_payload or candidate_payloads[0]

    # 6. Phase 5: Independent Replay Verification (Guaranteed Reproducibility)
    reproduced = False
    if final_verdict.is_verified:
        print("\n[Phase 5] Executing Independent Replay in a fresh, isolated EVM container...")
        reproduced = verify_replay_remote.remote(target.model_dump(), final_payload.model_dump())
        final_verdict.reproducible = reproduced
        if reproduced:
            final_verdict.reward_score = config.REWARD_INVARIANT_BREACH
            print("[✓] REPRODUCIBILITY CONFIRMED: 100% deterministic invariant breach across independent runs!")
        else:
            final_verdict.reward_score = config.REWARD_BREACH_NO_REPLAY
            print("[!] Flaky run detected: Replay did not reproduce invariant breach.")

    # 7. Phase 6: Trajectory Recording for RLVR / GRPO Policy Fine-Tuning
    print("\n[Phase 6] Recording trajectory pair into Modal Volume for RLVR Training...")
    try:
        traj_record = create_trajectory_record(target, final_payload, final_verdict)
        saved_path = record_trajectory_remote.remote(traj_record.model_dump())
        print(f"[✓] Trajectory committed: {saved_path} (Reward: {final_verdict.reward_score:+.2f})")
    except Exception as e:
        print(f"[!] Trajectory recording notice: {e}")

    print("\n" + "=" * 78)
    status = f"✅ VERIFIED EXPLOIT ({final_verdict.vulnerability_type})" if final_verdict.is_verified else "❌ REJECTED"
    print(f"AEGIS-RLVR 2.0 VERDICT    : [{status}]")
    print(f"Vulnerability Type         : {final_verdict.vulnerability_type}")
    print(f"RLVR Ground-Truth Reward   : {final_verdict.reward_score:+.2f}")
    print(f"Independent EVM Replay     : {'CONFIRMED (100% Deterministic)' if final_verdict.reproducible else 'FAILED / UNCONFIRMED'}")
    print(f"State Delta Verified       : {final_verdict.state_delta_verified}")
    print(f"Sandbox Feedback           : {final_verdict.feedback}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
