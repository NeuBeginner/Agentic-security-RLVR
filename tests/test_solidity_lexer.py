"""
tests/test_solidity_lexer.py

Regression test suite for Section 2 (Round 4):
Robust Solidity Lexer, Tokenizer, and ExploitModule Format Validation.
"""

import pytest
from core.llm_generator import (
    tokenize_solidity,
    SolidityTokenType,
    strip_solidity_comments,
    extract_contract_body,
    validate_exploit_format
)


def test_lexer_handles_braces_and_comments_inside_string_literals():
    """Test 1: //, /*, */, {, and } inside string literals must not break tokenization or brace tracking."""
    code = r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    string public constant TRICKY = "String with // comment, /* block */, { open, } close";
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
'''
    tokens, err = tokenize_solidity(code)
    assert err is None
    # Find string token
    str_tokens = [t for t in tokens if t.type == SolidityTokenType.STRING]
    assert len(str_tokens) == 1
    assert "/* block */" in str_tokens[0].value
    assert "{" in str_tokens[0].value

    is_valid, reason = validate_exploit_format(code)
    assert is_valid is True, f"Failed validation: {reason}"


def test_lexer_handles_escaped_quotes_and_backslashes():
    """Test 2: Escaped quotes (\") and backslashes (\\) inside string literals."""
    code = r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    string public constant ESCAPED = "Escaped \" quote and \\ backslash";
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
'''
    tokens, err = tokenize_solidity(code)
    assert err is None
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is True, f"Failed validation: {reason}"


def test_comments_containing_fake_declarations_are_ignored():
    """Test 3: Comments containing fake 'contract ExploitModule' or 'function runExploit'."""
    code = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// contract ExploitModule { constructor(address a) {} function runExploit() external {} }
/* contract ExploitModule {
       function runExploit() external {}
   }
*/

contract MaliciousContract {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
'''
    # Should reject because actual contract is MaliciousContract, while ExploitModule was only in comments!
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is False
    assert "Contract declared as 'MaliciousContract' instead of mandatory 'ExploitModule'" in reason


def test_run_exploit_declared_in_different_contract_rejected():
    """Test 4: runExploit declared in a different contract, but missing in ExploitModule."""
    code = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address _target) payable {}
    // Missing runExploit here!
}

contract Helper {
    constructor() {}
    function runExploit() external payable {}
}
'''
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is False
    assert "runExploit was declared in a different contract" in reason


def test_missing_or_duplicate_exploit_module_rejected():
    """Test 5: Missing or duplicate ExploitModule."""
    # Missing
    no_em = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract VaultAttack {
    constructor(address t) {}
    function runExploit() external {}
}
'''
    valid_missing, reason_m = validate_exploit_format(no_em)
    assert valid_missing is False
    assert "Contract declared as 'VaultAttack'" in reason_m

    # Duplicate
    duplicate_em = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address t) {}
    function runExploit() external {}
}
contract ExploitModule {
    constructor(address t) {}
    function runExploit() external {}
}
'''
    valid_dup, reason_d = validate_exploit_format(duplicate_em)
    assert valid_dup is False
    assert "Duplicate contract ExploitModule declaration detected" in reason_d


def test_valid_minimal_exploit_contract():
    """Test 6: Valid minimal exploit contract passes format check."""
    code = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
'''
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is True, f"Failed on valid minimal contract: {reason}"


def test_malformed_solidity_unclosed_braces():
    """Test 7: Malformed Solidity with unclosed braces."""
    code = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address _target) payable {
    function runExploit() external payable {}
'''
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is False
    assert "unclosed braces" in reason


def test_cheatcode_vm_rejected():
    """Test 8: Prohibited cheatcode vm.* is detected and rejected."""
    code = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {
        vm.prank(address(0x123));
    }
}
'''
    is_valid, reason = validate_exploit_format(code)
    assert is_valid is False
    assert "Prohibited cheatcode detected" in reason
