import re
from typing import List
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload


SYSTEM_PROMPT = """You are an automated software security auditor and exploit synthesis engine.
Your task is to analyze the provided target code and security invariants, identify logical flaws, and synthesize an executable Python test script that demonstrates the flaw by triggering an invariant breach.

CRITICAL INSTRUCTIONS:
1. Provide your reasoning trace explaining the vulnerability.
2. Provide the executable Python test code inside a single ```python ``` code block.
3. The test code must import the target via: `import target_{name} as target`
4. PRECONDITIONS: Carefully inspect all requirement checks! If a method checks `if attacker not in balances` or requires user setup, you MUST perform necessary initial setup (e.g. deposit a small initial amount for the attacker) before invoking the exploit vector.
5. If an invariant is breached (e.g. funds drained, unauthorized ownership change), print: `[INVARIANT_BREACHED]` and exit cleanly with code 0.
6. If the exploit fails, exit cleanly with code 0 without printing the invariant breached tag.
"""


def build_analysis_prompt(target: TargetProgram) -> str:
    """Constructs the prompt for initial exploit synthesis."""
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants)
    prompt = f"""Target Program Name: {target.name}
Language: {target.language}

Security Invariants:
{invariants_text}

Source Code:
```python
{target.source_code}
```

Analyze the program and synthesize an executable test payload to violate one of the security invariants.
Remember to satisfy any prerequisites (like depositing first) so your exploit can execute properly.
"""
    return prompt


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str) -> str:
    """Constructs the prompt for the self-correction refinement loop."""
    return f"""Your previous exploit test script failed when executed in the sandbox.

--- EXECUTION FEEDBACK ---
{error_feedback}
--------------------------

Previous Generated Code:
```python
{failed_code}
```

Target Code:
```python
{target.source_code}
```

Analyze the error. Did an assertion fail? Did you miss a prerequisite (such as calling deposit() before exploit_drain())?
Fix the bug in your test harness and provide the complete corrected Python script inside a single ```python ``` code block.
Ensure that if the vulnerability is triggered, it prints `[INVARIANT_BREACHED]`.
"""


def extract_python_code(model_output: str) -> str:
    """Extracts python code block from the model's text response."""
    pattern = r"```(?:python)?\s*\n(.*?)```"
    matches = re.findall(pattern, model_output, re.DOTALL)
    if matches:
        return max(matches, key=len).strip()
    return ""


def parse_model_response(target: TargetProgram, raw_text: str, attempt_idx: int = 1) -> ExploitPayload:
    """Parses raw LLM text into a structured ExploitPayload."""
    code = extract_python_code(raw_text)
    
    parts = raw_text.split("```")
    reasoning = parts[0].strip() if parts else raw_text[:300]
    
    vuln_type = "LogicVulnerability"
    lower_r = (reasoning + "\n" + code).lower()
    if "reentrancy" in lower_r or "drain" in lower_r or "balance" in lower_r:
        vuln_type = "StateInvariantDrain"
    elif "access" in lower_r or "owner" in lower_r or "auth" in lower_r:
        vuln_type = "AccessControlBypass"
    elif "underflow" in lower_r or "overflow" in lower_r or "boundary" in lower_r:
        vuln_type = "IntegerBoundaryError"

    hypothesis = AttackHypothesis(
        vulnerability_type=vuln_type,
        reasoning_trace=reasoning,
        attack_vector="Model-synthesized test execution against target invariants."
    )
    
    return ExploitPayload(
        target_name=target.name,
        hypothesis=hypothesis,
        test_code=code if code else "# Error: No code generated\nimport sys\nsys.exit(1)\n",
        test_filename=f"test_poc_attempt_{attempt_idx}_{target.name}.py"
    )
