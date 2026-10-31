import re
from typing import List
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload


SOLIDITY_SYSTEM_PROMPT = """You are an expert Web3 smart contract security researcher and automated exploit engineer.
Your task is to analyze the provided Solidity target contract and its security invariants, identify logical or economic vulnerabilities, and synthesize a complete, self-contained Foundry test contract (`Exploit.t.sol`).

CRITICAL FOUNDRY INSTRUCTIONS:
1. Provide a reasoning trace explaining the root cause and the exploit vector.
2. Provide the complete Solidity test contract inside a single ```solidity ``` code block.
3. Import the target using relative import: `import "../src/{name}.sol";`
4. The test contract must declare a function: `function testExploit() public` (or `external`).
5. Include any auxiliary helper contracts (like an Attacker contract with receive()/fallback()) directly inside the same file.
6. In `testExploit()`, perform the attack and assert the invariant breach:
   - For example: `assert(address(vault).balance == 0);`
7. Ensure valid Solidity 0.8.20 syntax with matching pragma: `pragma solidity ^0.8.20;`
"""


def build_analysis_prompt(target: TargetProgram) -> str:
    """Constructs the prompt for the generator model."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants)
    prompt = f"""Target Contract Name: {target.name}
Language: Solidity 0.8.20

Security Invariants:
{invariants_text}

Contract Source Code:
```solidity
{target.source_code}
```

Synthesize a complete Foundry test contract with `testExploit()` that reproduces the vulnerability and breaches the invariant.
"""
    return prompt


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str) -> str:
    """Constructs the prompt for self-correction based on Foundry execution traces."""
    return f"""Your previous Foundry exploit test failed to prove the vulnerability.

--- FORGE EXECUTION TRACE ---
{error_feedback}
-----------------------------

Previous Exploit Code:
```solidity
{failed_code}
```

Target Contract:
```solidity
{target.source_code}
```

Carefully inspect the compiler error or revert trace above.
Fix any issues with function signatures, gas, reentrancy guards, or balance setup.
Return the complete, corrected Solidity test contract in a single ```solidity ``` code block with `function testExploit()`.
"""


def extract_solidity_code(model_output: str) -> str:
    """Extracts solidity code block from the model's text response."""
    pattern = r"```(?:solidity)?\s*\n(.*?)```"
    matches = re.findall(pattern, model_output, re.DOTALL)
    if matches:
        return max(matches, key=len).strip()
    return ""


def parse_model_response(target: TargetProgram, raw_text: str, attempt_idx: int = 1) -> ExploitPayload:
    """Parses raw LLM text into a structured ExploitPayload."""
    code = extract_solidity_code(raw_text)
    
    parts = raw_text.split("```")
    reasoning = parts[0].strip() if parts else raw_text[:300]
    
    vuln_type = "Web3Vulnerability"
    lower_r = (reasoning + "\n" + code).lower()
    if "reentrancy" in lower_r or "drain" in lower_r:
        vuln_type = "ReentrancyDrain"
    elif "access" in lower_r or "owner" in lower_r or "auth" in lower_r:
        vuln_type = "AccessControlPrivilegeEscalation"
    elif "flash" in lower_r or "oracle" in lower_r:
        vuln_type = "OraclePriceManipulation"
    elif "overflow" in lower_r or "underflow" in lower_r:
        vuln_type = "ArithmeticError"

    hypothesis = AttackHypothesis(
        vulnerability_type=vuln_type,
        reasoning_trace=reasoning,
        attack_vector="Foundry EVM execution against contract invariants."
    )
    
    return ExploitPayload(
        target_name=target.name,
        hypothesis=hypothesis,
        test_code=code if code else "// Error: No Solidity code generated\n",
        test_filename=f"Exploit_{attempt_idx}.t.sol"
    )
