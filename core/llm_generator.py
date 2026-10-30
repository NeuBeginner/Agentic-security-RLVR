from typing import List
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload


def generate_candidate_exploits(target: TargetProgram, num_candidates: int = 3) -> List[ExploitPayload]:
    """
    Synthesizes candidate exploit payloads based on static semantic analysis of the target.
    In the full RLVR loop, this is driven by an LLM reasoning engine (e.g. Qwen-Coder or DeepSeek)
    with test-time sampling.
    """
    candidates = []
    
    # Analyze target code patterns
    code = target.source_code
    
    # Candidate 1: State Invariant Reentrancy / Check-Effects-Interaction Violation
    if "balance" in code.lower() or "withdraw" in code.lower() or "transfer" in code.lower():
        hypo = AttackHypothesis(
            vulnerability_type="StateInvariantViolation",
            reasoning_trace=(
                "Target performs state modifications after an external operation, "
                "allowing an attacker to trigger repeated state transitions before the balance updates."
            ),
            attack_vector="Call withdraw() with recursive re-entry callback."
        )
        test_code = f"""
import sys
# Import the target module
import target_{target.name} as target

def run_exploit():
    print("[*] Deploying target and attacker harness...")
    vault = target.VulnerableVault()
    vault.deposit("user1", 100)
    vault.deposit("attacker", 10)
    
    print(f"[*] Initial vault balance: {{vault.get_total_balance()}}")
    
    # Trigger attack vector
    success = vault.exploit_drain("attacker")
    final_balance = vault.get_total_balance()
    
    print(f"[*] Final vault balance: {{final_balance}}")
    
    if final_balance < 100:
        print("[INVARIANT_BREACHED] Vault funds illegally drained by unauthorized balance update!")
        sys.exit(0)
    else:
        print("[-] Exploit failed to drain funds.")
        sys.exit(1)

if __name__ == "__main__":
    run_exploit()
"""
        candidates.append(ExploitPayload(
            target_name=target.name,
            hypothesis=hypo,
            test_code=test_code,
            test_filename="test_exploit_state_breach.py"
        ))

    # Candidate 2: Access Control Bypass
    if "admin" in code.lower() or "auth" in code.lower() or "owner" in code.lower():
        hypo_access = AttackHypothesis(
            vulnerability_type="AccessControlBypass",
            reasoning_trace=(
                "Target misses explicit caller validation on privileged functions, "
                "allowing arbitrary unauthenticated actors to invoke administrative controls."
            ),
            attack_vector="Invoke set_admin() or privileged method directly as guest."
        )
        test_code_access = f"""
import sys
import target_{target.name} as target

def run_exploit():
    print("[*] Testing access control authorization...")
    app = target.VulnerableVault()
    
    # Attempt unprivileged administrative escalation
    try:
        app.update_owner("attacker")
        if app.owner == "attacker":
            print("[INVARIANT_BREACHED] Access control bypassed: Unauthorized owner override!")
            sys.exit(0)
    except Exception as e:
        print(f"[-] Operation rejected: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    run_exploit()
"""
        candidates.append(ExploitPayload(
            target_name=target.name,
            hypothesis=hypo_access,
            test_code=test_code_access,
            test_filename="test_exploit_access_bypass.py"
        ))

    # Fallback candidate: Boundary Condition / Underflow test
    hypo_boundary = AttackHypothesis(
        vulnerability_type="BoundaryConditionUnderflow",
        reasoning_trace="Testing integer limits and negative value handling.",
        attack_vector="Pass negative integer to transfer."
    )
    test_code_boundary = f"""
import sys
import target_{target.name} as target

def run_exploit():
    vault = target.VulnerableVault()
    try:
        vault.deposit("user", -50)
        print("[-] Handled cleanly.")
        sys.exit(1)
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    run_exploit()
"""
    candidates.append(ExploitPayload(
        target_name=target.name,
        hypothesis=hypo_boundary,
        test_code=test_code_boundary,
        test_filename="test_exploit_boundary.py"
    ))

    return candidates[:num_candidates]
