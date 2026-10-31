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
6. Import the target contract using named import: `import { {target_name} } from "../src/{target_name}.sol";`.
7. DO NOT re-declare or redefine `contract {target_name}` or `interface {target_name}`. It is imported from `{target_name}.sol`.
8. Inside `runExploit()`, invoke the actual functions available on the target (e.g. `deposit()`, `withdrawAll()`). Do NOT call `target.runExploit()`.
9. If executing a reentrancy attack, implement `receive() external payable { ... }` to re-enter the target's withdrawal method before state updates.
10. Always use valid Solidity 0.8.20 syntax with `pragma solidity ^0.8.20;`.

NOTE: You do NOT write test assertions. A fixed, trusted verification harness will deploy your `ExploitModule` with an attacker budget (1 ether) and verify whether the depositor solvency invariant was breached in the EVM.
"""


def build_analysis_prompt(target: TargetProgram) -> str:
    """Constructs the prompt for the generator model."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants)
    
    if target.name == "ERC4626Vault":
        target_instructions = """4. Implement `function runExploit() external payable`:
   - Deposit 1 wei into `targetContract.deposit{value: 1}()` to obtain 1 initial share.
   - Transfer all remaining attacker budget (`msg.value - 1`) directly to `payable(address(targetContract))` to inflate totalAssets without minting shares.
   - This causes subsequent victim deposits to round down to 0 shares (first-depositor inflation attack)."""
    elif target.name == "Vault":
        target_instructions = """4. Implement `function runExploit() external payable` that deposits funds and triggers `targetContract.withdrawAll()`.
5. Implement `receive() external payable` to re-enter `targetContract.withdrawAll()` as long as `address(targetContract).balance >= 1 ether`."""
    else:
        target_instructions = """4. Implement `function runExploit() external payable` interacting with targetContract functions to breach the specified invariants."""

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
2. Import the target: `import {{{target.name}}} from "../src/{target.name}.sol";` (do not redefine `{target.name}`).
3. Implement `constructor(address _target)` storing `{target.name} public targetContract = {target.name}(payable(_target));`.
{target_instructions}
"""
    return prompt


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str) -> str:
    """Constructs the prompt for self-correction based on Foundry execution traces."""
    return f"""Your previous ExploitModule failed to compile or breach the security invariant in the EVM.

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

Carefully inspect the compiler error, revert trace, or test failure above:
- If identifier `{target.name}` was already declared: do NOT define `contract {target.name}` inside this file; import it with `import {{{target.name}}} from "../src/{target.name}.sol";`.
- If member "runExploit" was not found on `{target.name}`: remember `runExploit` belongs to `ExploitModule`, whereas `{target.name}` only has `deposit()` and `withdrawAll()`.
- Ensure reentrancy in `receive()` checks `if (address(targetContract).balance >= 1 ether)` to avoid reverting on empty balance.
Return the complete, corrected Solidity contract in a single ```solidity ``` code block.
"""


def extract_solidity_code(model_output: str) -> str:
    """Extracts solidity code block from the model's text response."""
    pattern = r"```(?:solidity|sol)?\s*\n(.*?)```"
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
    elif "inflation" in lower_r or "share" in lower_r or "erc4626" in lower_r:
        vuln_type = "FirstDepositorShareInflation"
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
