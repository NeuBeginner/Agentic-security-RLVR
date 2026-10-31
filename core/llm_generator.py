import re
from typing import List
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload


SOLIDITY_SYSTEM_PROMPT = """You are an expert Web3 smart contract security researcher and automated exploit engineer.
Your task is to analyze the provided Solidity target contract and synthesize an executable attacker contract named `ExploitModule` (`contract ExploitModule`).

CRITICAL FOUNDRY EXPLOIT MODULE SPECIFICATIONS:
1. Provide a concise reasoning trace explaining the root cause and exploit vector.
2. Provide the complete, compilable Solidity exploit contract inside a single ```solidity ... ``` code block.
3. The exploit contract MUST be named `ExploitModule`: `contract ExploitModule { ... }`.
4. The constructor MUST accept the target contract address: `constructor(address _target) { ... }`.
5. The attack entrypoint MUST be: `function runExploit() external payable { ... }`.
6. If the exploit receives Ether during execution (e.g. reentrancy or drainage), implement `receive() external payable { ... }`.
7. Import the target contract using: `import "../src/{target_name}.sol";`.
8. Always use valid Solidity 0.8.20 syntax with `pragma solidity ^0.8.20;`.

NOTE: You do NOT write the test assertions. A fixed, trusted verification harness will deploy your `ExploitModule` with an attacker budget and verify whether the victim depositor solvency invariant was breached in the EVM.
"""


def build_analysis_prompt(target: TargetProgram) -> str:
    """Constructs the prompt for the generator model."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants)
    prompt = f"""Target Contract File: src/{target.name}.sol
Target Contract Name: {target.name}
Language: Solidity 0.8.20

Security Invariants Being Tested:
{invariants_text}

Target Contract Source Code:
```solidity
{target.source_code}
```

Instructions:
1. Synthesize the complete `ExploitModule` contract.
2. Import the target: `import "../src/{target.name}.sol";`
3. Implement `constructor(address _target)` and `function runExploit() external payable`.
4. If executing a reentrancy attack, implement `receive() external payable` to re-enter the target before state updates.
"""
    return prompt


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str) -> str:
    """Constructs the prompt for self-correction based on Foundry execution traces."""
    return f"""Your previous ExploitModule failed to breach the security invariant in the EVM.

--- FORGE EXECUTION FEEDBACK ---
{error_feedback}
--------------------------------

Target Contract (src/{target.name}.sol):
```solidity
{target.source_code}
```

Previous ExploitModule Code:
```solidity
{failed_code}
```

Carefully inspect the compiler error, revert trace, or test failure above.
Ensure `contract ExploitModule` implements `constructor(address _target)`, `runExploit() external payable`, and handles reentrant callbacks properly without running out of gas.
Return the complete, corrected Solidity contract in a single ```solidity ``` code block.
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
        attack_vector="Foundry EVM execution against trusted depositor solvency harness."
    )
    
    return ExploitPayload(
        target_name=target.name,
        hypothesis=hypothesis,
        test_code=code if code else "// Error: No Solidity code generated\n",
        test_filename="ExploitModule.sol",
        attempt_number=attempt_idx
    )
