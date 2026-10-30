import re
from typing import List
from core.schemas import TargetProgram, AttackHypothesis, ExploitPayload


SYSTEM_PROMPT = """You are an automated software security auditor and exploit synthesis engine.
Your task is to analyze the provided target code and security invariants, identify logical flaws, and synthesize an executable Python test script that demonstrates the flaw by triggering an invariant breach.

CRITICAL INSTRUCTIONS:
1. First, provide your reasoning trace explaining the vulnerability.
2. Then, provide the executable Python test code inside a single ```python ``` code block.
3. The test code must import the target via: `import target_{name} as target`
4. If an invariant is breached (e.g. funds drained, unauthorized ownership change), your test script MUST print: `[INVARIANT_BREACHED]` and exit cleanly with code 0.
5. If the exploit fails, exit cleanly with code 0 without printing the invariant breached tag.
6. The script must be completely self-contained and run without interactive input.
"""


def build_analysis_prompt(target: TargetProgram) -> str:
    """Constructs the prompt for the generator model."""
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
"""
    return prompt


def extract_python_code(model_output: str) -> str:
    """Extracts python code block from the model's text response."""
    pattern = r"```(?:python)?\s*\n(.*?)```"
    matches = re.findall(pattern, model_output, re.DOTALL)
    if matches:
        return max(matches, key=len).strip()
    return ""


def parse_model_response(target: TargetProgram, raw_text: str) -> ExploitPayload:
    """Parses raw LLM text into a structured ExploitPayload."""
    code = extract_python_code(raw_text)
    
    parts = raw_text.split("```")
    reasoning = parts[0].strip() if parts else raw_text[:300]
    
    vuln_type = "LogicVulnerability"
    lower_r = reasoning.lower()
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
        test_filename=f"test_poc_{target.name}.py"
    )
