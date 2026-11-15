import ast
from pathlib import Path


def _runner_tree():
    source = Path(__file__).resolve().parents[1] / "sandbox" / "runner.py"
    return ast.parse(source.read_text(encoding="utf-8"))


def test_forge_output_uses_a_real_newline_separator():
    tree = _runner_tree()
    assignments = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "output_text" for target in node.targets)
    ]
    assert assignments, "output_text assignment must remain explicit"
    value = assignments[0].value
    assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
    assert isinstance(value.right, ast.BinOp) and isinstance(value.right.op, ast.Add)
    separator = value.right.left
    assert isinstance(separator, ast.Constant)
    assert separator.value == "\n"


def test_subprocess_timeout_is_not_classified_as_an_evm_revert():
    tree = _runner_tree()
    handlers = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Attribute)
        and node.type.attr == "TimeoutExpired"
    ]
    assert handlers, "subprocess.TimeoutExpired handler must remain explicit"
    handler = handlers[0]
    categories = [
        node for node in ast.walk(ast.Module(body=handler.body, type_ignores=[]))
        if isinstance(node, ast.Attribute) and node.attr == "INFRA_ERROR"
    ]
    assert categories, "timeouts must be classified as infrastructure failures"
    timeout_flags = [
        kw.value for node in ast.walk(ast.Module(body=handler.body, type_ignores=[]))
        if isinstance(node, ast.Call) for kw in node.keywords if kw.arg == "timed_out"
    ]
    assert any(isinstance(value, ast.Constant) and value.value is True for value in timeout_flags)