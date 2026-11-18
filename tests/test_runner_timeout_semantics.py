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
    separators = [
        node.value for node in ast.walk(assignments[0].value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert "\n" in separators


def test_subprocess_timeout_is_not_classified_as_an_evm_revert():
    tree = _runner_tree()
    handlers = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Attribute)
        and node.type.attr == "TimeoutExpired"
    ]
    assert handlers, "subprocess.TimeoutExpired handler must remain explicit"
    matching = []
    for handler in handlers:
        subtree = ast.Module(body=handler.body, type_ignores=[])
        has_infra_category = any(
            isinstance(node, ast.Attribute) and node.attr == "INFRA_ERROR"
            for node in ast.walk(subtree)
        )
        has_timeout_flag = any(
            isinstance(kw.value, ast.Constant) and kw.value.value is True
            for node in ast.walk(subtree) if isinstance(node, ast.Call)
            for kw in node.keywords if kw.arg == "timed_out"
        )
        if has_infra_category and has_timeout_flag:
            matching.append(handler)
    assert matching, "subprocess timeouts must be INFRA_ERROR with timed_out=True"