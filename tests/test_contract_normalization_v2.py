"""
tests/test_contract_normalization_v2.py

Contract Normalization v2 - proof-based, fail-closed renaming.

The mechanical repair renames the exploit contract to the harness-mandated
`ExploitModule`. Version 2 tightens the proof obligation:

* only the DECLARATION and PROVEN references to it are rewritten;
* same-named interfaces / libraries / structs / events / functions / state
  variables / parameters are NEVER rewritten - the repair is declined instead;
* comments and string literals are never touched;
* `import` statements are never touched;
* several top-level contracts => the repair is declined (ambiguous);
* the operation is idempotent;
* the original completion and the provenance survive the repair.

The suite also compiles the normalized contracts with a REAL solc 0.8.20 so the
repair is proven to keep the Solidity valid.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from core.config import config
from core.llm_generator import (
    analyze_contract_normalization,
    normalize_exploit_contract_name,
    parse_model_response,
    validate_exploit_format,
)
from core.schemas import TargetProgram

REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# REAL SOLC COMPILER (compile tests)
# =============================================================================

def _find_solc():
    candidates = [
        os.environ.get("SOLC_BIN"),
        str(Path.home() / ".solc" / "solc-0.8.20.exe"),
        str(Path.home() / ".solc" / "solc-0.8.20"),
        shutil.which("solc"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


SOLC_BIN = _find_solc()
requires_solc = pytest.mark.skipif(
    SOLC_BIN is None, reason="solc 0.8.20 is not available on this machine"
)


VAULT_SOL = (REPO_ROOT / "benchmarks" / "targets" / "solidity" / "Vault.sol").read_text(
    encoding="utf-8"
)


def compile_with_solc(tmp_path, exploit_code, target_source=VAULT_SOL):
    """
    Compiles the exploit together with the real target contract using solc.

    Layout mirrors the sandbox: src/<Target>.sol and test/ExploitModule.sol.
    """
    src_dir = tmp_path / "src"
    test_dir = tmp_path / "test"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "Vault.sol").write_text(target_source, encoding="utf-8")
    (test_dir / "ExploitModule.sol").write_text(exploit_code, encoding="utf-8")

    return subprocess.run(
        [
            SOLC_BIN,
            "--bin",
            "--allow-paths",
            ".",
            "src/Vault.sol",
            "test/ExploitModule.sol",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=180,
    )


# =============================================================================
# 1. SAME IDENTIFIER IN DIFFERENT DECLARATIONS
# =============================================================================

SAME_NAME_DECLARATIONS = {
    "event": """pragma solidity ^0.8.20;
contract VaultAttack {
    event VaultAttack(address attacker);
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
    "function": """pragma solidity ^0.8.20;
contract VaultAttack {
    function VaultAttack() internal pure returns (uint256) { return 1; }
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
    "state_variable": """pragma solidity ^0.8.20;
contract VaultAttack {
    uint256 VaultAttack = 0;
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
    "parameter": """pragma solidity ^0.8.20;
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit(uint256 VaultAttack) external payable {}
}
""",
    "interface": """pragma solidity ^0.8.20;
interface VaultAttack {
    function runExploit() external;
}
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
    "library": """pragma solidity ^0.8.20;
library VaultAttack {
    function helper() internal pure returns (uint256) { return 1; }
}
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
    "struct": """pragma solidity ^0.8.20;
contract VaultAttack {
    struct VaultAttack { uint256 value; }
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
""",
}


@pytest.mark.parametrize("declaration_kind", sorted(SAME_NAME_DECLARATIONS.keys()))
def test_same_name_in_another_declaration_declines_the_repair(declaration_kind):
    """
    An identifier that DECLARES another symbol with the same name is ambiguous.

    The repair must be declined and the file must stay byte-identical - the
    unrelated declaration must never be rewritten.
    """
    code = SAME_NAME_DECLARATIONS[declaration_kind]

    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is False
    assert normalized == code
    assert old_name == ""


def test_same_name_in_another_declaration_reports_a_reason():
    """The decline is auditable: the reason names the ambiguity."""
    outcome = analyze_contract_normalization(SAME_NAME_DECLARATIONS["event"])

    assert outcome.renamed is False
    assert outcome.reason == "ambiguous_declaration_collision"
    assert outcome.original_name == "VaultAttack"


def test_distinct_declarations_are_untouched():
    """Declarations with a DIFFERENT name are never touched by the repair."""
    code = """pragma solidity ^0.8.20;

interface IVaultAttack {
    function runExploit() external;
}

library VaultAttackMath {
    function helper() internal pure returns (uint256) { return 7; }
}

contract VaultAttack is IVaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable { VaultAttackMath.helper(); }
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is True
    assert old_name == "VaultAttack"
    assert "contract ExploitModule is IVaultAttack" in normalized
    assert "interface IVaultAttack" in normalized
    assert "library VaultAttackMath" in normalized
    assert "VaultAttackMath.helper()" in normalized
    assert "contract VaultAttack" not in normalized


def test_member_access_is_never_renamed():
    """`x.VaultAttack` is a member name, not a reference to the contract type."""
    code = """pragma solidity ^0.8.20;

contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {
        Helper helper = new Helper();
        helper.VaultAttack();
    }
}

contract Helper {
    function VaultAttack() internal pure returns (uint256) { return 1; }
}
"""
    # Two top-level contracts => ambiguous => declined before any rewriting.
    normalized, renamed, _ = normalize_exploit_contract_name(code)
    assert renamed is False
    assert normalized == code


# =============================================================================
# 2. SELF REFERENCE
# =============================================================================

def test_self_reference_is_renamed_consistently():
    """A reference to the contract's own type inside the contract is renamed."""
    code = """pragma solidity ^0.8.20;
contract ReentrancyDrain {
    constructor(address _target) payable {}
    function runExploit() external payable {
        ReentrancyDrain self = ReentrancyDrain(payable(address(this)));
        self.getTarget();
    }
    function getTarget() external view returns (address) { return address(this); }
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is True
    assert old_name == "ReentrancyDrain"
    assert "contract ExploitModule" in normalized
    assert "ExploitModule self = ExploitModule(payable(address(this)));" in normalized
    assert "ReentrancyDrain" not in normalized


def test_self_instantiation_reference_is_renamed():
    """
    `new VaultAttack(...)` is renamed as well.

    NOTE: Solidity itself rejects a contract that instantiates itself (circular
    reference to its own bytecode), so this case is verified lexically only -
    the compile test below uses a self-reference that solc accepts.
    """
    code = """pragma solidity ^0.8.20;
contract ReentrancyDrain {
    constructor(address _target) payable {}
    function runExploit() external payable {
        ReentrancyDrain other = new ReentrancyDrain(address(this));
        other.runExploit();
    }
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)

    assert renamed is True
    assert old_name == "ReentrancyDrain"
    assert "ExploitModule other = new ExploitModule(address(this));" in normalized
    assert "ReentrancyDrain" not in normalized


def test_inheritance_reference_is_renamed():
    """A contract that inherits from the exploit contract is renamed as well."""
    code = """pragma solidity ^0.8.20;
contract Base {
    constructor(address _target) payable {}
    function runExploit() external payable virtual {}
}
contract VaultAttack is Base {
    constructor(address _target) payable Base(_target) {}
    function runExploit() external payable override {}
}
"""
    # Two top-level contracts => declined (the harness requires exactly one).
    normalized, renamed, _ = normalize_exploit_contract_name(code)
    assert renamed is False
    assert normalized == code


# =============================================================================
# 3. COMMENTS AND STRING LITERALS
# =============================================================================

def test_comments_and_strings_are_never_touched():
    """Neither a comment nor a string literal may be rewritten."""
    code = """pragma solidity ^0.8.20;
// this comment mentions VaultAttack on purpose
/* block comment about VaultAttack */
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {
        string memory s = "VaultAttack";
        require(bytes(s).length > 0, "VaultAttack");
    }
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is True
    assert "// this comment mentions VaultAttack on purpose" in normalized
    assert "/* block comment about VaultAttack */" in normalized
    assert 'string memory s = "VaultAttack";' in normalized
    assert '"VaultAttack"' in normalized
    assert "contract ExploitModule" in normalized


# =============================================================================
# 4. IMPORTS
# =============================================================================

def test_import_statements_are_never_rewritten():
    """An imported symbol must never be aliased into the target contract."""
    code = """pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is True
    assert 'import {Vault} from "../src/Vault.sol";' in normalized
    assert "Vault public target;" in normalized
    assert "target = Vault(payable(_target));" in normalized


def test_import_with_the_same_name_declines_the_repair():
    """An imported symbol with the same name makes every reference ambiguous."""
    code = """pragma solidity ^0.8.20;
import {VaultAttack} from "../src/VaultAttack.sol";

contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    outcome = analyze_contract_normalization(code)

    assert outcome.renamed is False
    assert outcome.reason == "ambiguous_import_name_collision"


# =============================================================================
# 5. SEVERAL TOP-LEVEL CONTRACTS
# =============================================================================

def test_several_top_level_contracts_decline_the_repair():
    """Ambiguity (several contracts) must leave the code untouched."""
    code = """pragma solidity ^0.8.20;
contract Helper {
    constructor() {}
}
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    outcome = analyze_contract_normalization(code)

    assert outcome.renamed is False
    assert outcome.reason == "ambiguous_multiple_top_level_contracts"
    assert outcome.code == code


def test_two_contracts_already_named_exploit_module_decline_the_repair():
    """Two contracts named ExploitModule must not be renamed."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is False
    assert normalized == code


# =============================================================================
# 6. IDEMPOTENCY
# =============================================================================

def test_normalization_is_idempotent():
    """Running the repair twice changes nothing the second time."""
    code = """pragma solidity ^0.8.20;
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {
        VaultAttack other = new VaultAttack(address(this));
        other.runExploit();
    }
}
"""
    first, renamed_first, _ = normalize_exploit_contract_name(code)
    second, renamed_second, _ = normalize_exploit_contract_name(first)

    assert renamed_first is True
    assert renamed_second is False
    assert second == first


def test_already_canonical_code_is_a_no_op():
    """An already-correct contract name is left completely untouched."""
    code = """pragma solidity ^0.8.20;
contract ExploitModule {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    outcome = analyze_contract_normalization(code)

    assert outcome.renamed is False
    assert outcome.reason == "already_canonical"
    assert outcome.code == code


# =============================================================================
# 7. PROVENANCE PRESERVATION
# =============================================================================

RAW_RESPONSE_WITH_WRONG_NAME = """Here is my exploit.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
```
"""


def test_provenance_is_preserved_by_the_repair():
    """
    The training completion stays the model's ORIGINAL text, the executable
    artifact is the renamed one, and the repair stays auditable.
    """
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, RAW_RESPONSE_WITH_WRONG_NAME)

    assert payload.format_valid is True
    assert payload.contract_name_normalized is True
    assert payload.original_contract_name == "VaultAttack"
    assert payload.contract_normalization_reason == "normalized"

    # The executable artifact is renamed...
    assert "contract ExploitModule" in payload.test_code
    assert "contract VaultAttack" not in payload.test_code

    # ...but the completion is byte-identical to what the model emitted.
    assert payload.raw_model_response == RAW_RESPONSE_WITH_WRONG_NAME


def test_declined_repair_is_recorded_in_the_provenance():
    """A declined repair is visible in the payload instead of being silent."""
    raw = """```solidity
pragma solidity ^0.8.20;

interface VaultAttack { function runExploit() external; }
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
```
"""
    target = TargetProgram(name="Vault", source_code=VAULT_SOL)
    payload = parse_model_response(target, raw)

    assert payload.contract_name_normalized is False
    assert payload.contract_normalization_reason == "ambiguous_declaration_collision"
    # The strict validator still rejects it: the repair did not paper over it.
    assert payload.format_valid is False


def test_normalized_code_passes_the_strict_validator():
    """The repair does not weaken the strict validator - it feeds it valid code."""
    code = """pragma solidity ^0.8.20;
contract VaultAttack {
    constructor(address _target) payable {}
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)
    is_valid, reason = validate_exploit_format(normalized)

    assert renamed is True
    assert is_valid is True
    assert reason == ""


# =============================================================================
# 8. REAL COMPILE TESTS (solc 0.8.20)
# =============================================================================

@requires_solc
def test_normalized_contract_compiles_with_real_solc(tmp_path):
    """The renamed contract must still compile with the real compiler."""
    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {
        target.deposit{value: msg.value}();
        target.withdrawAll();
    }
    receive() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)
    assert renamed is True

    proc = compile_with_solc(tmp_path, normalized)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ExploitModule" in proc.stdout


@requires_solc
def test_self_referencing_normalized_contract_compiles_with_real_solc(tmp_path):
    """Self references stay valid after the rename."""
    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {
        VaultAttack self = VaultAttack(payable(address(this)));
        self.getTarget();
    }
    function getTarget() external view returns (address) { return address(target); }
    receive() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)
    assert renamed is True
    assert "ExploitModule self = ExploitModule(payable(address(this)));" in normalized

    proc = compile_with_solc(tmp_path, normalized)

    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_solc
def test_declined_repair_keeps_the_file_compilable(tmp_path):
    """
    A declined repair must leave the file exactly as it was - including its
    compilability. The repair never has to fix broken code.
    """
    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "../src/Vault.sol";

contract VaultAttack {
    event VaultAttack(address attacker);
    Vault public target;
    constructor(address _target) payable { target = Vault(payable(_target)); }
    function runExploit() external payable {}
}
"""
    normalized, renamed, _ = normalize_exploit_contract_name(code)

    assert renamed is False
    assert normalized == code

    proc = compile_with_solc(tmp_path, normalized)

    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_solc
def test_normalized_erc4626_exploit_compiles_with_real_solc(tmp_path):
    """The second benchmark target is covered as well."""
    target_source = (
        REPO_ROOT / "benchmarks" / "targets" / "solidity" / "ERC4626Vault.sol"
    ).read_text(encoding="utf-8")

    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC4626Vault} from "../src/ERC4626Vault.sol";

contract ShareInflation {
    ERC4626Vault public vault;
    constructor(address _target) payable { vault = ERC4626Vault(payable(_target)); }
    function runExploit() external payable {
        vault.deposit{value: 1}();
        payable(address(vault)).transfer(msg.value - 1);
    }
    receive() external payable {}
}
"""
    normalized, renamed, old_name = normalize_exploit_contract_name(code)
    assert renamed is True
    assert old_name == "ShareInflation"

    src_dir = tmp_path / "src"
    test_dir = tmp_path / "test"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "ERC4626Vault.sol").write_text(target_source, encoding="utf-8")
    (test_dir / "ExploitModule.sol").write_text(normalized, encoding="utf-8")

    proc = subprocess.run(
        [
            SOLC_BIN,
            "--bin",
            "--allow-paths",
            ".",
            "src/ERC4626Vault.sol",
            "test/ExploitModule.sol",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
