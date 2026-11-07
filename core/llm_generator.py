"""
core/llm_generator.py

Multi-engine exploit synthesis and prompt orchestration.
Provides target-agnostic prompts and strict contract validation for ExploitModule.
"""

from __future__ import annotations

import os
import re
import json
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum
from dataclasses import dataclass
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
3. MANDATORY CONTRACT NAME: The exploit contract MUST be named `ExploitModule`: `contract ExploitModule { ... }`.
   DO NOT name it `Attack`, `VaultExploit`, `ReentrancyDrain`, or any other name. The verification harness strictly requires `contract ExploitModule`.
4. The constructor MUST accept the target address: `constructor(address _target) payable { ... }`.
5. The attack entrypoint MUST be: `function runExploit() external payable { ... }`.
6. Import the target contract using named import: `import { {target_name} } from "../src/{target_name}.sol";`.
7. DO NOT re-declare `contract {target_name}` or its interface.
8. NEVER import `forge-std/Test.sol` or use `vm.*` cheatcodes. `ExploitModule` must be a realistic, unprivileged on-chain contract.
9. Always use valid Solidity 0.8.20 syntax (`pragma solidity ^0.8.20;`).
10. If attacking via callbacks or reentrancy, implement `receive() external payable` or `fallback() external payable`.
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


def build_analysis_prompt(target: TargetProgram, hypothesis: Optional[Any] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> str:
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
        vulnerability_type = getattr(hypothesis, "vulnerability_type", None) or getattr(hypothesis, "vulnerability_class", "Unknown")
        severity = getattr(hypothesis, "severity", None) or "Unspecified"
        attack_vector = getattr(hypothesis, "attack_vector", None)
        if not attack_vector:
            attack_vector = " -> ".join(getattr(hypothesis, "attack_sequence", []) or [])
        reasoning_trace = getattr(hypothesis, "reasoning_trace", None)
        if not reasoning_trace:
            reasoning_trace = f"Preconditions: {getattr(hypothesis, 'attack_preconditions', [])}"
        hypothesis_context = f"""
Auditor Finding Hypothesis ({vulnerability_type} - {severity} Severity):
- Vulnerability Type: {vulnerability_type}
- Attack Vector     : {attack_vector}
- Analysis Trace    : {reasoning_trace}
"""

    failure_context = ""
    if previous_failures:
        failure_lines = []
        for failure in previous_failures[:10]:
            if not isinstance(failure, dict):
                continue
            candidate_id = failure.get("candidate_id", "unknown")
            category = failure.get("category", "unknown")
            feedback = failure.get("feedback", failure.get("error", ""))
            failure_lines.append(f"- {candidate_id} [{category}]: {str(feedback)[:500]}")
        if failure_lines:
            failure_context = "\nPREVIOUS FAILED CANDIDATES:\n" + "\n".join(failure_lines) + "\n"

    return f"""Target Contract File: src/{target.name}.sol
Target Contract Name: {target.name}
Language: Solidity 0.8.20

Security Invariants Being Tested:
{invariants_text}
{slither_context}{hypothesis_context}{failure_context}
Target Contract Source Code:
```solidity
{target.source_code}
```

Instructions:
1. Carefully inspect all public/external functions, state updates, balance tracking, and transfer logic.
2. Synthesize the complete `ExploitModule` contract.
3. CRITICAL: The contract declaration MUST be `contract ExploitModule` (do not use any other name).
4. Import the target: `import {{{target.name}}} from "../src/{target.name}.sol";` (do not redefine it).
5. Store the target contract reference: `{target.name} public targetContract = {target.name}(payable(_target));`.
6. Implement `function runExploit() external payable` that executes transactions with the target to breach the invariant.
7. If necessary for callbacks or reentrancy, implement `receive() external payable` or other fallback handlers.
8. Strictly unprivileged: Do NOT use Foundry cheatcodes (vm.*) or test harnesses.
9. Return clean, compilable Solidity code in a single ```solidity ... ``` block.
"""


def build_refinement_prompt(target: TargetProgram, failed_code: str, error_feedback: str, hypothesis: Optional[Any] = None, previous_failures: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Constructs a closed-loop refinement prompt guided by structured Foundry EVM trace.
    Target-agnostic and focused on compiler feedback and revert reasons.
    """
    invariants_text = "\n".join(f"- {inv}" for inv in target.invariants) if target.invariants else "- Security invariants"
    hypothesis_context = ""
    if hypothesis:
        vulnerability_type = getattr(hypothesis, "vulnerability_type", None) or getattr(hypothesis, "vulnerability_class", "Unknown")
        severity = getattr(hypothesis, "severity", None) or "Unspecified"
        attack_vector = getattr(hypothesis, "attack_vector", None) or " -> ".join(getattr(hypothesis, "attack_sequence", []) or [])
        reasoning_trace = getattr(hypothesis, "reasoning_trace", None) or f"Preconditions: {getattr(hypothesis, 'attack_preconditions', [])}"
        hypothesis_context = f"\nPrioritized hypothesis ({vulnerability_type}, {severity}): {attack_vector}\nReasoning: {reasoning_trace}\n"

    failure_context = ""
    if previous_failures:
        failure_lines = [
            f"- {item.get('candidate_id', 'unknown')} [{item.get('category', 'unknown')}]: {str(item.get('feedback', item.get('error', '')))[:500]}"
            for item in previous_failures[:10] if isinstance(item, dict)
        ]
        if failure_lines:
            failure_context = "\nPREVIOUS FAILED CANDIDATES:\n" + "\n".join(failure_lines) + "\n"

    return f"""Your previous candidate ExploitModule failed to compile or failed to breach the security invariant in the EVM.
{hypothesis_context}{failure_context}

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
- The contract MUST be named `contract ExploitModule`.
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


# =============================================================================
# 3. ROBUST SOLIDITY LEXER & CONTRACT SCOPE PARSER (ROUND 4)
# =============================================================================

class SolidityTokenType(str, Enum):
    STRING = "STRING"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    SEMICOLON = "SEMICOLON"
    KEYWORD = "KEYWORD"
    IDENT = "IDENT"
    OTHER = "OTHER"


@dataclass
class SolidityToken:
    type: SolidityTokenType
    value: str
    pos: int


SOLIDITY_KEYWORDS = {
    "contract", "interface", "library", "function", "constructor",
    "modifier", "event", "error", "struct", "enum",
    "public", "external", "internal", "private",
    "pure", "view", "payable", "override", "virtual",
    "returns", "return", "is", "pragma", "import", "using",
    "mapping", "address", "uint", "uint256", "int", "bool", "string", "bytes"
}


def tokenize_solidity(code: str) -> Tuple[List[SolidityToken], Optional[str]]:
    """
    Robust lexical tokenizer for Solidity code.
    Correctly handles:
    - Single-line comments (//) and multi-line comments (/* ... */)
    - Quoted strings ("..." and '...') with escape sequences (\", \', \\)
    - Braces, parentheses, semicolons, keywords, and identifiers
    - Preserves structural tokens outside strings/comments
    
    Returns:
        (tokens, error_message_if_any)
    """
    tokens: List[SolidityToken] = []
    idx = 0
    length = len(code)

    while idx < length:
        ch = code[idx]

        # 1. Skip whitespace
        if ch.isspace():
            idx += 1
            continue

        # 2. Line comment: // ... \n
        if ch == '/' and idx + 1 < length and code[idx + 1] == '/':
            idx += 2
            while idx < length and code[idx] != '\n':
                idx += 1
            continue

        # 3. Block comment: /* ... */
        if ch == '/' and idx + 1 < length and code[idx + 1] == '*':
            start_pos = idx
            idx += 2
            closed = False
            while idx + 1 < length:
                if code[idx] == '*' and code[idx + 1] == '/':
                    idx += 2
                    closed = True
                    break
                idx += 1
            if not closed:
                return [], "Unclosed multi-line block comment (/* without */)"
            continue

        # 4. Quoted string literals: "..." or '...'
        if ch in ('"', "'"):
            quote_char = ch
            start_pos = idx
            str_chars = [ch]
            idx += 1
            closed = False
            while idx < length:
                curr = code[idx]
                if curr == '\\':
                    # Escaped character
                    str_chars.append(curr)
                    if idx + 1 < length:
                        str_chars.append(code[idx + 1])
                        idx += 2
                    else:
                        idx += 1
                    continue
                str_chars.append(curr)
                if curr == quote_char:
                    idx += 1
                    closed = True
                    break
                idx += 1
            if not closed:
                return [], f"Unclosed string literal starting at position {start_pos}"
            tokens.append(SolidityToken(SolidityTokenType.STRING, "".join(str_chars), start_pos))
            continue

        # 5. Structural delimiters
        if ch == '{':
            tokens.append(SolidityToken(SolidityTokenType.LBRACE, "{", idx))
            idx += 1
            continue
        if ch == '}':
            tokens.append(SolidityToken(SolidityTokenType.RBRACE, "}", idx))
            idx += 1
            continue
        if ch == '(':
            tokens.append(SolidityToken(SolidityTokenType.LPAREN, "(", idx))
            idx += 1
            continue
        if ch == ')':
            tokens.append(SolidityToken(SolidityTokenType.RPAREN, ")", idx))
            idx += 1
            continue
        if ch == ';':
            tokens.append(SolidityToken(SolidityTokenType.SEMICOLON, ";", idx))
            idx += 1
            continue

        # 6. Identifiers and keywords (alphanumeric + underscore + dollar)
        if ch.isalpha() or ch == '_' or ch == '$':
            start_pos = idx
            word_chars = []
            while idx < length and (code[idx].isalnum() or code[idx] in ('_', '$')):
                word_chars.append(code[idx])
                idx += 1
            word = "".join(word_chars)
            ttype = SolidityTokenType.KEYWORD if word in SOLIDITY_KEYWORDS else SolidityTokenType.IDENT
            tokens.append(SolidityToken(ttype, word, start_pos))
            continue

        # 7. Other characters (operators, punctuation)
        tokens.append(SolidityToken(SolidityTokenType.OTHER, ch, idx))
        idx += 1

    return tokens, None


def strip_solidity_comments(code: str) -> str:
    """
    Removes comments using the robust lexer.
    Guarantees comment markers inside string literals are NOT stripped!
    """
    tokens, err = tokenize_solidity(code)
    if err:
        return code
    # Reconstruct code from tokens (all comments were already discarded by tokenizer)
    result = []
    last_type = None
    for tok in tokens:
        if last_type in (SolidityTokenType.IDENT, SolidityTokenType.KEYWORD) and tok.type in (SolidityTokenType.IDENT, SolidityTokenType.KEYWORD):
            result.append(" ")
        result.append(tok.value)
        last_type = tok.type
    return "".join(result)


def extract_contract_body(clean_code: str, contract_name: str = "ExploitModule") -> Optional[str]:
    """
    Extracts the body between outer braces of the specified contract using lexer tokens.
    Immune to braces inside string literals or comments.
    """
    tokens, err = tokenize_solidity(clean_code)
    if err or not tokens:
        return None

    # Find the target contract at top level (brace depth 0)
    brace_depth = 0
    target_start_idx = None
    target_end_idx = None

    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok.type == SolidityTokenType.LBRACE:
            brace_depth += 1
        elif tok.type == SolidityTokenType.RBRACE:
            brace_depth -= 1
            if target_start_idx is not None and brace_depth == 0:
                target_end_idx = idx
                break

        # Check for: contract <Name>
        if brace_depth == 0 and tok.value == "contract" and idx + 1 < n:
            name_tok = tokens[idx + 1]
            if name_tok.value == contract_name:
                # Find opening brace of this contract
                brace_search = idx + 2
                while brace_search < n and tokens[brace_search].type != SolidityTokenType.LBRACE:
                    brace_search += 1
                if brace_search < n:
                    target_start_idx = brace_search
                    brace_depth = 1
                    idx = brace_search + 1
                    continue
        idx += 1

    if target_start_idx is not None and target_end_idx is not None:
        body_tokens = tokens[target_start_idx + 1 : target_end_idx]
        return " ".join(t.value for t in body_tokens)
    return None


@dataclass
class ContractNormalizationOutcome:
    """Full, auditable result of the mechanical contract-name repair."""

    code: str
    renamed: bool = False
    original_name: str = ""
    reason: str = ""
    renamed_declarations: int = 0
    renamed_references: int = 0


# Keywords that introduce a NEW declaration. An identifier in such a position is
# a declaration name, NOT a reference to the contract type - rewriting it would
# silently rename an unrelated declaration.
_DECLARATION_KEYWORDS = {
    "contract", "interface", "library", "struct", "enum", "event", "error",
    "modifier", "function", "constructor", "type",
}

# Keywords after which the identifier denotes the contract TYPE.
_TYPE_CONTEXT_KEYWORDS = {"new", "is", "using"}

# Keywords that make the preceding identifier a type followed by a modifier
# (`VaultAttack payable x;` -> the identifier is the type).
_MODIFIER_KEYWORDS = {
    "public", "private", "internal", "memory", "storage", "calldata",
    "immutable", "constant", "payable", "indexed", "override", "virtual",
}

# Keywords after which an identifier denotes an event or a custom error.
_EVENT_ERROR_KEYWORDS = {"emit", "revert"}

# Tokens that can precede a type inside a declaration head.
_TYPE_TOKENS = {
    "address", "uint", "uint256", "int", "bool", "string", "bytes", "mapping",
}

# Tokens that terminate a declared NAME (`uint256 VaultAttack = 1;`).
_NAME_TERMINATORS = {"=", ";", ",", ")", "["}


def _is_type_ish_token(tok: Optional[SolidityToken]) -> bool:
    """True when the token can be the type part of a declaration head."""
    if tok is None:
        return False
    if tok.type == SolidityTokenType.IDENT:
        return True
    if tok.type == SolidityTokenType.KEYWORD and tok.value in _TYPE_TOKENS:
        return True
    if tok.type == SolidityTokenType.RPAREN:
        return True
    if tok.value == "]":
        return True
    return False


def analyze_contract_normalization(
    code: str,
    contract_name: str = "ExploitModule"
) -> ContractNormalizationOutcome:
    """
    Analyzes whether the exploit contract can be renamed mechanically and, if so,
    performs the rename.

    RENAME POLICY (proof based, fail-closed)
    ----------------------------------------
    Only TWO kinds of tokens are rewritten:

    1. the declaration itself (`contract <OldName>` -> `contract ExploitModule`);
    2. PROVEN references to that very contract - an identifier that cannot be
       anything else than a reference to the top-level contract type.

    Everything else is either left untouched or causes the whole repair to be
    declined:

    * identifiers inside `import` statements are NEVER rewritten (an imported
      symbol must not be aliased into the target contract);
    * member names (`x.OldName`) are NEVER rewritten (different namespace);
    * an identifier that DECLARES another symbol with the same name (an
      `interface`, `library`, `struct`, `enum`, `event`, `error`, `modifier`,
      `function`, state variable or parameter of that name) makes the name
      ambiguous - the repair is declined instead of corrupting the file;
    * an identifier that shadows the contract in an inner scope is likewise
      ambiguous and declines the repair.

    Comments and string literals are never touched: the lexer does not emit
    tokens for them at all.
    """
    outcome = ContractNormalizationOutcome(code=code)

    if not code or not code.strip():
        outcome.reason = "empty_code"
        return outcome

    tokens, lex_err = tokenize_solidity(code)
    if lex_err:
        outcome.reason = f"lexer_error: {lex_err}"
        return outcome
    if not tokens:
        outcome.reason = "no_tokens"
        return outcome

    # ------------------------------------------------------------------
    # 1. Import statements: their identifiers are never rewritten.
    # ------------------------------------------------------------------
    import_ranges: List[Tuple[int, int]] = []
    imported_symbols: List[str] = []
    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok.type == SolidityTokenType.KEYWORD and tok.value == "import":
            start = idx
            cursor = idx + 1
            paren_depth = 0
            while cursor < n:
                t = tokens[cursor]
                if t.type == SolidityTokenType.LPAREN:
                    paren_depth += 1
                elif t.type == SolidityTokenType.RPAREN:
                    paren_depth -= 1
                elif t.type == SolidityTokenType.SEMICOLON and paren_depth == 0:
                    break
                cursor += 1
            if cursor < n:
                import_ranges.append((start, cursor + 1))
                for k in range(start, cursor + 1):
                    t = tokens[k]
                    if t.type == SolidityTokenType.IDENT and t.value not in ("from", "as"):
                        imported_symbols.append(t.value)
                idx = cursor + 1
                continue
        idx += 1

    def _in_import(token_index: int) -> bool:
        for start, end in import_ranges:
            if start <= token_index < end:
                return True
        return False

    # ------------------------------------------------------------------
    # 2. Top-level contract declarations.
    # ------------------------------------------------------------------
    top_level_contracts: List[Tuple[str, int]] = []
    brace_depth = 0
    idx = 0
    while idx < n:
        tok = tokens[idx]
        if tok.type == SolidityTokenType.LBRACE:
            brace_depth += 1
        elif tok.type == SolidityTokenType.RBRACE:
            brace_depth -= 1
        elif (
            brace_depth == 0
            and tok.type == SolidityTokenType.KEYWORD
            and tok.value == "contract"
            and idx + 1 < n
            and tokens[idx + 1].type == SolidityTokenType.IDENT
        ):
            top_level_contracts.append((tokens[idx + 1].value, idx + 1))
        idx += 1

    if not top_level_contracts:
        outcome.reason = "no_top_level_contract"
        return outcome
    if len(top_level_contracts) > 1:
        outcome.reason = "ambiguous_multiple_top_level_contracts"
        return outcome

    old_name, declaration_index = top_level_contracts[0]

    if old_name == contract_name:
        outcome.reason = "already_canonical"
        return outcome

    if old_name in imported_symbols:
        # An imported symbol shares the name: the reference cannot be resolved.
        outcome.reason = "ambiguous_import_name_collision"
        outcome.original_name = old_name
        return outcome

    # ------------------------------------------------------------------
    # 3. Classify every occurrence of the old name.
    # ------------------------------------------------------------------
    rename_positions: List[int] = []
    for i, tok in enumerate(tokens):
        if tok.type != SolidityTokenType.IDENT or tok.value != old_name:
            continue

        if i == declaration_index:
            rename_positions.append(i)
            continue

        if _in_import(i):
            # Import statements are never rewritten.
            continue

        prev = tokens[i - 1] if i > 0 else None
        nxt = tokens[i + 1] if i + 1 < n else None

        if prev is None:
            outcome.reason = "ambiguous_bare_identifier"
            outcome.original_name = old_name
            return outcome

        # Member access target: `x.OldName` is a member, not the type.
        if prev.value == ".":
            continue

        if prev.type == SolidityTokenType.KEYWORD:
            if prev.value in _DECLARATION_KEYWORDS:
                # Another declaration with the same name: the identifier is a
                # declaration name, not a reference to the contract type.
                outcome.reason = "ambiguous_declaration_collision"
                outcome.original_name = old_name
                return outcome
            if prev.value in _EVENT_ERROR_KEYWORDS:
                outcome.reason = "ambiguous_event_or_error_reference"
                outcome.original_name = old_name
                return outcome
            if prev.value in _TYPE_CONTEXT_KEYWORDS:
                # `new OldName(...)`, `contract X is OldName`, `using OldName for Y`
                rename_positions.append(i)
                continue

        # `<type> OldName <modifier>` -> the identifier is the TYPE.
        if (
            nxt is not None
            and nxt.type == SolidityTokenType.KEYWORD
            and nxt.value in _MODIFIER_KEYWORDS
        ):
            rename_positions.append(i)
            continue

        # `OldName.member` -> static access on the type.
        if nxt is not None and nxt.value == ".":
            rename_positions.append(i)
            continue

        # `<type> OldName ...` where the identifier DECLARES a name -> the
        # contract type is shadowed in this scope, the rename is ambiguous.
        if _is_type_ish_token(prev) and nxt is not None and nxt.value in _NAME_TERMINATORS:
            outcome.reason = "ambiguous_shadowed_declaration"
            outcome.original_name = old_name
            return outcome

        # Everything else is a proven reference to the contract type.
        rename_positions.append(i)

    if not rename_positions:
        outcome.reason = "no_reference_to_rename"
        outcome.original_name = old_name
        return outcome

    # ------------------------------------------------------------------
    # 4. Apply the rename (identifiers only - comments/strings untouched).
    # ------------------------------------------------------------------
    pieces: List[str] = []
    cursor = 0
    for i in rename_positions:
        tok = tokens[i]
        pieces.append(code[cursor:tok.pos])
        pieces.append(contract_name)
        cursor = tok.pos + len(old_name)

    pieces.append(code[cursor:])
    outcome.code = "".join(pieces)
    outcome.renamed = True
    outcome.original_name = old_name
    outcome.reason = "normalized"
    outcome.renamed_declarations = 1
    outcome.renamed_references = max(0, len(rename_positions) - 1)
    return outcome


def normalize_exploit_contract_name(
    code: str,
    contract_name: str = "ExploitModule"
) -> Tuple[str, bool, str]:
    """
    Renames a single top-level `contract <OtherName>` declaration to the mandatory
    `contract ExploitModule` name required by the verification harness.

    This is a purely mechanical, semantics-preserving repair: it fixes the single
    most common failure mode where the model emits a descriptively named contract
    (`VaultAttack`, `ReentrancyDrain`, ...) instead of the harness-mandated name.
    Without it, such candidates are rejected before Foundry ever runs and can never
    produce a verifiable reward signal.

    Safety rules (fail-closed, never rewrite when uncertain):
    - Only the declaration and PROVEN references to it are rewritten; same-named
      interfaces, libraries, structs, events, functions, state variables and
      parameters are never touched - the repair is declined instead.
    - String literals and comments are untouched (the lexer emits no tokens for
      them).
    - Identifiers inside `import` statements are NEVER rewritten, so an imported
      symbol can never be silently aliased into the target contract.
    - The rename is applied ONLY when exactly ONE top-level contract is declared.
      Multiple contracts mean the intent is ambiguous, so the code is left
      untouched.
    - If `contract ExploitModule` is already present, the code is left untouched.
    - The operation is idempotent: running it on already normalized code is a
      no-op.

    Returns:
        (normalized_code, was_renamed, original_contract_name)
    """
    outcome = analyze_contract_normalization(code, contract_name)
    if outcome.renamed:
        return outcome.code, True, outcome.original_name
    return code, False, ""


def validate_exploit_format(code: str) -> Tuple[bool, str]:
    """
    Validates that synthesized code strictly satisfies ExploitModule requirements
    using the lexical tokenizer and AST contract scope analyzer.
    
    Requirements:
    1. Non-empty code block.
    2. No unclosed markdown blocks or unclosed strings/comments.
    3. Exactly ONE `contract ExploitModule` declared at top level.
    4. Constructor accepts address parameter inside ExploitModule.
    5. Entrypoint `function runExploit() external/public` strictly inside ExploitModule.
    6. Balanced braces throughout file.
    7. No forbidden cheatcodes (vm.*) or test harnesses.
    """
    if not code or not code.strip():
        return False, "No Solidity code block extracted from model response"

    if "```" in code:
        return False, "Malformed Solidity code: contains nested or unclosed markdown fences"

    # Tokenize with full lexer
    tokens, lex_err = tokenize_solidity(code)
    if lex_err:
        return False, f"Solidity Lexer Error: {lex_err}"

    if not tokens:
        return False, "Solidity code contains no active code tokens"

    # Check balanced braces
    depth = 0
    for tok in tokens:
        if tok.type == SolidityTokenType.LBRACE:
            depth += 1
        elif tok.type == SolidityTokenType.RBRACE:
            depth -= 1
            if depth < 0:
                return False, "Solidity syntax error: unexpected closing brace '}' without matching '{'"
    if depth != 0:
        return False, f"Solidity syntax error: unclosed braces (depth = {depth} at end of file)"

    # Check cheatcodes
    for idx, tok in enumerate(tokens):
        if tok.value == "vm" and idx + 1 < len(tokens) and tokens[idx + 1].value == ".":
            return False, "Prohibited cheatcode detected: usage of 'vm.*' is forbidden in unprivileged ExploitModule"
        if tok.type == SolidityTokenType.STRING and "forge-std/Test.sol" in tok.value:
            return False, "Prohibited import detected: 'forge-std/Test.sol' is forbidden in ExploitModule"

    # Scan for top-level contracts and functions
    brace_depth = 0
    declared_contracts: List[str] = []
    contract_token_ranges: Dict[str, List[SolidityToken]] = {}
    current_contract_name = None
    current_contract_tokens: List[SolidityToken] = []

    idx = 0
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]

        if tok.type == SolidityTokenType.LBRACE:
            if brace_depth == 0 and current_contract_name:
                pass  # start of contract body
            brace_depth += 1
            if current_contract_name:
                current_contract_tokens.append(tok)
            idx += 1
            continue

        if tok.type == SolidityTokenType.RBRACE:
            brace_depth -= 1
            if current_contract_name:
                current_contract_tokens.append(tok)
                if brace_depth == 0:
                    # End of contract body
                    contract_token_ranges[current_contract_name] = current_contract_tokens
                    current_contract_name = None
                    current_contract_tokens = []
            idx += 1
            continue

        if brace_depth == 0 and tok.value == "contract" and idx + 1 < n:
            name_tok = tokens[idx + 1]
            if name_tok.type in (SolidityTokenType.IDENT, SolidityTokenType.KEYWORD):
                cname = name_tok.value
                declared_contracts.append(cname)
                current_contract_name = cname
                current_contract_tokens = []
                idx += 2
                continue

        if current_contract_name and brace_depth > 0:
            current_contract_tokens.append(tok)

        idx += 1

    # 1. Validate ExploitModule presence and uniqueness
    exploit_module_count = declared_contracts.count("ExploitModule")
    if exploit_module_count == 0:
        found_name = declared_contracts[0] if declared_contracts else "None"
        return (
            False,
            f"Contract declared as '{found_name}' instead of mandatory 'ExploitModule'. "
            f"Harness requires 'contract ExploitModule'."
        )
    if exploit_module_count > 1:
        return (
            False,
            f"Duplicate contract ExploitModule declaration detected ({exploit_module_count} found). "
            f"Harness strictly requires exactly one 'contract ExploitModule'."
        )

    # 2. Inspect ExploitModule body tokens
    em_tokens = contract_token_ranges.get("ExploitModule", [])

    # Check constructor
    constructor_indices = [i for i, tok in enumerate(em_tokens) if tok.value == "constructor"]
    if not constructor_indices:
        return False, "ExploitModule is missing mandatory constructor(address) within its contract scope"
    if len(constructor_indices) > 1:
        return False, f"Duplicate constructor declarations in ExploitModule ({len(constructor_indices)} found)"

    c_idx = constructor_indices[0]
    # Scan forward to find LPAREN '('
    paren_idx = c_idx + 1
    while paren_idx < len(em_tokens) and em_tokens[paren_idx].type != SolidityTokenType.LPAREN:
        paren_idx += 1
    if paren_idx >= len(em_tokens):
        return False, "ExploitModule constructor missing parameter list '('"

    # Find matching RPAREN ')'
    p_depth = 1
    r_idx = paren_idx + 1
    c_param_tokens = []
    while r_idx < len(em_tokens):
        if em_tokens[r_idx].type == SolidityTokenType.LPAREN:
            p_depth += 1
        elif em_tokens[r_idx].type == SolidityTokenType.RPAREN:
            p_depth -= 1
            if p_depth == 0:
                break
        c_param_tokens.append(em_tokens[r_idx])
        r_idx += 1

    if p_depth != 0:
        return False, "ExploitModule constructor parameter list unclosed (missing ')')'"

    # Analyze parameters
    param_groups = []
    current_group = []
    for p_tok in c_param_tokens:
        if p_tok.value == ",":
            if current_group:
                param_groups.append(current_group)
                current_group = []
        else:
            current_group.append(p_tok)
    if current_group:
        param_groups.append(current_group)

    if len(param_groups) == 0:
        return (
            False,
            "ExploitModule constructor must accept exactly one parameter of type 'address', got 0 parameters: 'constructor()'"
        )
    if len(param_groups) > 1:
        return (
            False,
            f"ExploitModule constructor must accept exactly one parameter of type 'address', got {len(param_groups)} parameters"
        )

    # Check type of single parameter
    first_param_words = [
        t.value for t in param_groups[0]
        if t.type in (SolidityTokenType.IDENT, SolidityTokenType.KEYWORD)
    ]
    if not first_param_words:
        return False, "ExploitModule constructor parameter is invalid or empty"

    param_type = first_param_words[0]
    if param_type != "address":
        return (
            False,
            f"ExploitModule constructor parameter must be of type 'address', got '{param_type}'"
        )

    # Check runExploit inside ExploitModule
    run_exploit_indices = []
    for i, tok in enumerate(em_tokens):
        if tok.value == "function" and i + 1 < len(em_tokens) and em_tokens[i + 1].value == "runExploit":
            run_exploit_indices.append(i)

    if not run_exploit_indices:
        # Check if runExploit was declared in a different contract (common failure mode)
        other_has_run_exploit = False
        for cname, ctoks in contract_token_ranges.items():
            if cname != "ExploitModule":
                for j, tok in enumerate(ctoks):
                    if tok.value == "function" and j + 1 < len(ctoks) and ctoks[j + 1].value == "runExploit":
                        other_has_run_exploit = True
                        break
        if other_has_run_exploit:
            return (
                False,
                "ExploitModule is missing mandatory entrypoint: function runExploit() external within its contract scope "
                "(runExploit was declared in a different contract)."
            )
        return False, "ExploitModule is missing mandatory entrypoint: function runExploit() within its contract scope"

    if len(run_exploit_indices) > 1:
        return False, f"Duplicate runExploit functions detected in ExploitModule ({len(run_exploit_indices)} found)"

    fn_idx = run_exploit_indices[0]
    # Scan forward to find LPAREN '('
    fn_paren_idx = fn_idx + 2
    while fn_paren_idx < len(em_tokens) and em_tokens[fn_paren_idx].type != SolidityTokenType.LPAREN:
        fn_paren_idx += 1
    if fn_paren_idx >= len(em_tokens):
        return False, "ExploitModule function runExploit missing parameter list '('"

    # Find matching RPAREN ')'
    fn_p_depth = 1
    fn_r_idx = fn_paren_idx + 1
    fn_param_tokens = []
    while fn_r_idx < len(em_tokens):
        if em_tokens[fn_r_idx].type == SolidityTokenType.LPAREN:
            fn_p_depth += 1
        elif em_tokens[fn_r_idx].type == SolidityTokenType.RPAREN:
            fn_p_depth -= 1
            if fn_p_depth == 0:
                break
        fn_param_tokens.append(em_tokens[fn_r_idx])
        fn_r_idx += 1

    if fn_p_depth != 0:
        return False, "ExploitModule function runExploit parameter list unclosed (missing ')')'"

    # Parameter count check: runExploit must take NO parameters: function runExploit()
    fn_param_words = [
        t.value for t in fn_param_tokens
        if t.type in (SolidityTokenType.IDENT, SolidityTokenType.KEYWORD)
    ]
    if fn_param_words:
        return (
            False,
            f"ExploitModule function 'runExploit' must take 0 parameters, got parameters in signature: {fn_param_words}"
        )

    # Check visibility after RPAREN up to LBRACE '{' or SEMICOLON ';'
    scan_idx = fn_r_idx + 1
    run_exploit_visibility = None
    while scan_idx < len(em_tokens) and em_tokens[scan_idx].type not in (SolidityTokenType.LBRACE, SolidityTokenType.SEMICOLON):
        tok_val = em_tokens[scan_idx].value
        if tok_val in ("external", "public", "internal", "private"):
            run_exploit_visibility = tok_val
        scan_idx += 1

    if run_exploit_visibility not in ("external", "public"):
        if run_exploit_visibility in ("internal", "private"):
            return (
                False,
                f"ExploitModule method 'runExploit' must have 'external' or 'public' visibility, got '{run_exploit_visibility}'"
            )
        return (
            False,
            "ExploitModule method 'runExploit' must have 'external' or 'public' visibility so harness can invoke it"
        )

    return True, ""


def parse_model_response(
    target: TargetProgram,
    raw_text: str,
    attempt_idx: int = 1,
    generated_token_ids: Optional[List[int]] = None,
    prompt_text: str = "",
    hypothesis: Optional[Any] = None,
    candidate_id: Optional[str] = None,
) -> ExploitPayload:
    """
    Parses raw LLM text into a structured ExploitPayload.
    Applies strict structural validation. If format is invalid, flags format_valid=False
    and preserves raw text for diagnosis without invoking Foundry.
    Preserves exact generated token IDs and prompt text for training lineage.
    """
    code = extract_solidity_code(raw_text)

    # Mechanical repair: rename a single descriptively-named top-level contract to the
    # harness-mandated `ExploitModule`. Without this, candidates that are otherwise
    # valid never reach Foundry and can never yield a verifiable reward.
    normalization_reason = ""
    if config.ENABLE_CONTRACT_NAME_NORMALIZATION:
        outcome = analyze_contract_normalization(code)
        code = outcome.code
        was_renamed = outcome.renamed
        original_name = outcome.original_name if outcome.renamed else ""
        normalization_reason = outcome.reason
    else:
        was_renamed, original_name = False, ""
        normalization_reason = "disabled_by_configuration"

    is_valid, format_reason = validate_exploit_format(code)
    if was_renamed:
        # The rename is a mechanical repair, not a validation failure: after it the
        # candidate satisfies the harness contract. The format error reason stays
        # reserved for genuine validation failures; the repair event is recorded
        # separately on the payload so it remains auditable.
        format_reason = "" if is_valid else format_reason

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

    # Resolve and preserve hypothesis provenance
    from core.schemas import VulnerabilityHypothesis
    hypothesis_id = None
    if hypothesis is not None:
        hypothesis_id = getattr(hypothesis, "hypothesis_id", None)
        if isinstance(hypothesis, dict):
            hypothesis_id = hypothesis.get("hypothesis_id")
        if not hypothesis_id and hasattr(hypothesis, "source_finding_id"):
            hypothesis_id = hypothesis.source_finding_id

    if isinstance(hypothesis, AttackHypothesis):
        attack_hyp = hypothesis
        if hypothesis_id and not attack_hyp.hypothesis_id:
            attack_hyp.hypothesis_id = hypothesis_id
    elif isinstance(hypothesis, VulnerabilityHypothesis):
        attack_hyp = AttackHypothesis(
            vulnerability_type=hypothesis.vulnerability_class,
            reasoning_trace=f"Target: {hypothesis.affected_contract}.{hypothesis.affected_function or 'target'}. Preconditions: {hypothesis.attack_preconditions}",
            attack_vector=" -> ".join(hypothesis.attack_sequence) if hypothesis.attack_sequence else "Synthesized EVM interaction sequence against trusted verification harness.",
            affected_functions=[hypothesis.affected_function] if hypothesis.affected_function else [],
            confidence_score=hypothesis.confidence,
            hypothesis_id=hypothesis.hypothesis_id,
        )
    elif isinstance(hypothesis, dict):
        attack_hyp = AttackHypothesis(
            vulnerability_type=hypothesis.get("vulnerability_class") or hypothesis.get("vulnerability_type") or vuln_type,
            reasoning_trace=str(hypothesis.get("reasoning_trace", reasoning)),
            attack_vector=str(hypothesis.get("attack_vector", "Synthesized EVM interaction sequence against trusted verification harness.")),
            confidence_score=float(hypothesis.get("confidence", 1.0)),
            hypothesis_id=hypothesis.get("hypothesis_id"),
        )
    else:
        attack_hyp = AttackHypothesis(
            vulnerability_type=vuln_type,
            reasoning_trace=reasoning,
            attack_vector="Synthesized EVM interaction sequence against trusted verification harness.",
            hypothesis_id=hypothesis_id
        )

    payload_kwargs = {
        "target_name": target.name,
        "hypothesis": attack_hyp,
        "test_code": code if code else "// Error: No valid Solidity code generated\n",
        "test_filename": "ExploitModule.sol",
        "attempt_number": attempt_idx,
        "raw_model_response": raw_text,
        "format_valid": is_valid,
        "format_error_reason": format_reason,
        "contract_name_normalized": was_renamed,
        "original_contract_name": original_name if was_renamed else "",
        "contract_normalization_reason": normalization_reason,
        "prompt_text": prompt_text,
        "generated_token_ids": generated_token_ids,
        "hypothesis_id": hypothesis_id,
    }
    if candidate_id:
        payload_kwargs["candidate_id"] = candidate_id

    return ExploitPayload(**payload_kwargs)


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
    payload = parse_model_response(target, response.text or "", prompt_text=prompt, hypothesis=hypothesis)
    payload.generator_engine = "gemini-flash"
    return payload
