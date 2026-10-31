import os
import re
import json
from typing import List, Optional, Dict, Any
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload
from core.config import config


# =============================================================================
# 1. AUDIT DETECTOR PROMPT (Optimized for Qwen-Audit / JSON-formatted audits)
# =============================================================================
AUDIT_DETECTOR_SYSTEM_PROMPT = """You are an elite Web3 security auditor.
Analyze the target Solidity smart contract to identify security flaws, logical errors, and invariant violations.
For each vulnerability, output a structured JSON array of findings with:
- "title": Short title of vulnerability
- "category": e.g. "Reentrancy", "FirstDepositorInflation", "AccessControl", "OracleManipulation", "ArithmeticError", "LogicFlaw"
- "severity": "Critical", "High", "Medium", or "Low"
- "function": Name of vulnerable function
- "description": Explanation of the root cause
- "attack_vector": Step-by-step strategy to trigger the vulnerability
"""


# =============================================================================
# 2. EXPLOIT ENGINEER PROMPT (Optimized for Frontier / Coder Synthesis)
# =============================================================================
EXPLOIT_ENGINEER_SYSTEM_PROMPT = """You are an automated exploit synthesis engineer in an isolated EVM environment.
Your task is to analyze the target contract and the specified security invariants, then synthesize an executable, unprivileged attacker contract named `ExploitModule` (`contract ExploitModule`).

CRITICAL EVM EXPLOIT SPECIFICATIONS:
1. Provide a concise reasoning trace explaining the root cause and exploit strategy.
2. Provide the complete, compilable Solidity exploit contract inside a single ```solidity ... ``` code block.
3. The exploit contract MUST be named `ExploitModule`: `contract ExploitModule { ... }`.
4. The constructor MUST accept the target address: `constructor(address _target) { ... }`.
5. The attack entrypoint MUST be: `function runExploit() external payable { ... }`.
6. Import the target contract using named import: `import { {target_name} } from "../src/{target_name}.sol";`.
7. DO NOT re-declare `contract {target_name}` or its interface.
8. NEVER import `forge-std/Test.sol` or use `vm.*` cheatcodes. `ExploitModule` must be a realistic, unprivileged on-chain contract.
9. Always use valid Solidity 0.8.20 syntax (`pragma solidity ^0.8.20;`).
10. The verification harness will fund your `runExploit()` with an authorized attacker budget and verify whether the specified security invariant is breached.
"""

# Backwards compatibility alias
SOLIDITY_SYSTEM_PROMPT = EXPLOIT_ENGINEER_SYSTEM_PROMPT


def build_auditor_prompt(target: TargetProgram) -> str:
    """Prompt for the auditor model to detect vulnerabilities and output structured JSON."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants) if target.invariants else "- General contract security"
    return f"""Target Contract Name: {target.name}
Language: Solidity 0.8.20

Security Invariants To Verify:
{invariants_text}

Target Contract Source Code:
```solidity
{target.source_code}
```

Identify all vulnerabilities that could breach the stated security invariants.
Output your findings as a valid JSON array of objects.
"""


def build_analysis_prompt(target: TargetProgram, hypothesis: Optional[AttackHypothesis] = None) -> str:
    """
    Target-agnostic prompt for exploit synthesis.
    Integrates Slither static analysis findings and formal invariants without hardcoded contract names.
    """
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants) if target.invariants else "- Depositor equity & solvency"
    
    slither_context = ""
    if target.slither_findings:
        slither_lines = [
            f"- [{f.get('impact', 'Medium')}] {f.get('check')}: {f.get('description')}"
            for f in target.slither_findings
        ]
        slither_context = "\nStatic Analysis (Slither) Detectors:\n" + "\n".join(slither_lines) + "\n"

    hypothesis_context = ""
    if hypothesis:
        hypothesis_context = f"""
Auditor Finding Hypothesis:
- Vulnerability Type: {hypothesis.vulnerability_type}
- Attack Vector     : {hypothesis.attack_vector}
- Analysis Trace    : {hypothesis.reasoning_trace}
"""

    return f"""Target Contract File: src/{target.name}.sol
Target Contract Name: {target.name}
Language: Solidity 0.8.20

Security Invariants Being Tested:
{invariants_text}
{slither_context}{hypothesis_context}
Target Contract Source Code:
```solidity
{target.source_code}
```

Instructions:
1. Carefully inspect all public/external functions, state updates, balance tracking, and transfer logic.
2. Synthesize the complete `ExploitModule` contract.
3. Import the target: `import {{{target.name}}} from "../src/{target.name}.sol";` (do not redefine it).
4. Store the target contract reference: `{target.name} public targetContract = {target.name}(payable(_target));`.
5. Implement `function runExploit() external payable` that executes transactions with the target to breach the invariant.
6. If necessary for callbacks or reentrancy, implement `receive() external payable` or other fallback handlers.
7. Strictly unprivileged: Do NOT use Foundry cheatcodes (vm.*) or test harnesses.
8. Return clean, compilable Solidity code in a single ```solidity ... ``` block.
"""


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str) -> str:
    """
    Constructs a closed-loop refinement prompt guided by structured Foundry EVM trace.
    Target-agnostic and focused on compiler feedback and revert reasons.
    """
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants) if target.invariants else "- Security invariants"
    return f"""Your previous candidate ExploitModule failed to compile or failed to breach the security invariant in the EVM.

--- FOUNDRY EVM EXECUTION FEEDBACK ---
{error_feedback}
--------------------------------------

Target Contract (src/{target.name}.sol):
```solidity
{target.source_code}
```

Security Invariants To Breach:
{invariants_text}

Previous Candidate ExploitModule:
```solidity
{failed_code}
```

Refinement Guidelines:
- If Compilation Error: Check for undefined variables, incorrect function parameters, or redeclaration of imported types.
- If EVM Runtime Revert: Check require statements, msg.value conditions, balance constraints, or call sequencing.
- If Safe Run: The previous exploit did not violate the invariant. Adjust the attack mechanism (e.g. state timing, parameter amounts, reentrancy condition) to ensure the invariant is physically breached in EVM state.
- Strictly unprivileged: Do NOT use `vm.*` cheatcodes.

Return the complete, corrected Solidity contract inside a single ```solidity ... ``` code block.
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
    elif "logic" in lower_r or "invariant" in lower_r:
        vuln_type = "LogicFlawInvariantBreach"

    hypothesis = AttackHypothesis(
        vulnerability_type=vuln_type,
        reasoning_trace=reasoning,
        attack_vector="Synthesized EVM interaction sequence against trusted verification harness."
    )
    
    return ExploitPayload(
        target_name=target.name,
        hypothesis=hypothesis,
        test_code=code if code else "// Error: No Solidity code generated\n",
        test_filename="ExploitModule.sol",
        attempt_number=attempt_idx
    )


def synthesize_exploit_gemini(
    target: TargetProgram,
    hypothesis: Optional[AttackHypothesis] = None,
    api_key: Optional[str] = None
) -> ExploitPayload:
    """
    Synthesizes candidate ExploitModule using Gemini Flash frontier reasoning API.
    Direct integration via google-genai SDK.
    """
    from google import genai
    
    key = api_key or config.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
    client = genai.Client(api_key=key) if key else genai.Client()
    
    prompt = build_analysis_prompt(target, hypothesis)
    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=prompt,
        config={"system_instruction": EXPLOIT_ENGINEER_SYSTEM_PROMPT, "temperature": 0.3}
    )
    payload = parse_model_response(target, response.text or "")
    payload.generator_engine = "gemini-flash"
    return payload
