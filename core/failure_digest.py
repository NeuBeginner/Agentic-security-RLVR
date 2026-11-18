"""
core/failure_digest.py
======================

The concrete reason why a candidate failed, read out of the Forge trace.

The verdict of the evaluator says **that** the candidate failed (``RUNTIME_REVERT``
or ``SAFE_RUN``). On its own that statement is useless for the next attempt: the
refinement loop has to repair the candidate, and a verdict without a reason
leaves it guessing. This module reads the reason out of the evidence that the
trusted harness produced - the trace of the failing call.

What is read
------------
* ``EXPLOIT_FAILED: ...`` - the message of the trusted harness: it says which
  invariant was still held;
* the revert reason of the JSON report of the test;
* ``OutOfFunds`` and its relatives - the EVM refused to send more ETH than the
  contract held;
* the call that failed - its address, its selector and the value it carried.

The digest is a **description** of the observed trace, never a guess: it is
built only out of lines that are really in the output of the harness.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: The markers of the EVM error "the contract does not hold enough ETH".
OUT_OF_FUNDS_MARKERS = (
    "OutOfFunds",
    "InsufficientBalance",
    "insufficient balance",
    "insufficient funds",
)

#: The marker of the message of the trusted harness.
EXPLOIT_FAILED_MARKER = "EXPLOIT_FAILED"

#: The glyphs of the tree of the Foundry trace.
_TREE_GLYPHS = "│├└─ "

#: The value of a call in the trace: ``[value: 1000000000000000000]``.
_VALUE_PATTERN = re.compile(r"\[value:\s*([^\]]+)\]")


def _clean_trace_line(line: str) -> str:
    """One line of the trace, without the glyphs of the tree."""
    return line.strip().strip(_TREE_GLYPHS).strip()


_CALL_KINDS = {"CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"}


def _iter_json_objects(text: str) -> List[Dict[str, Any]]:
    """Extract top-level JSON dict objects from text, tolerating surrounding lines."""
    stripped = (text or "").strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    objects: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(stripped):
        start = stripped.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = decoder.raw_decode(stripped, start)
            if isinstance(obj, dict):
                objects.append(obj)
            idx = end
        except Exception:
            idx = start + 1
    return objects


def _deepest_failing_arena_call(arena: List[Dict[str, Any]]) -> Optional[Tuple[int, Dict[str, Any]]]:
    """Recursively find the deepest failing CALL/DELEGATECALL/STATICCALL node in an arena."""
    if not isinstance(arena, list) or not arena:
        return None

    by_idx: Dict[int, Dict[str, Any]] = {}
    for node in arena:
        if isinstance(node, dict) and isinstance(node.get("idx"), int):
            by_idx[node["idx"]] = node

    best: Optional[Tuple[int, Dict[str, Any]]] = None
    visited: set[int] = set()

    def _visit(node: Dict[str, Any]) -> None:
        nonlocal best
        idx = node.get("idx")
        if isinstance(idx, int):
            if idx in visited:
                return
            visited.add(idx)

        trace = node.get("trace")
        if isinstance(trace, dict):
            kind = str(trace.get("kind") or "").upper()
            if trace.get("success") is False and kind in _CALL_KINDS:
                depth = trace.get("depth")
                depth_val = depth if isinstance(depth, int) else 0
                if best is None or depth_val >= best[0]:
                    best = (depth_val, trace)

        children = node.get("children")
        if isinstance(children, list):
            for child_idx in children:
                child = by_idx.get(child_idx)
                if child is not None:
                    _visit(child)

    roots = [n for n in arena if isinstance(n, dict) and n.get("parent") is None]
    for root in roots:
        _visit(root)

    # Fallback for arenas without explicit parent/children links
    for node in arena:
        if isinstance(node, dict):
            _visit(node)

    return best


def _format_arena_call(trace: Dict[str, Any]) -> str:
    """Format a failing Forge arena trace node using only fields present in the trace."""
    kind = str(trace.get("kind") or "CALL").upper()
    decoded = trace.get("decoded") if isinstance(trace.get("decoded"), dict) else {}

    label = decoded.get("label") if isinstance(decoded.get("label"), str) else None
    address = trace.get("address") if isinstance(trace.get("address"), str) else None
    if label and address:
        target = f"{label} ({address})"
    else:
        target = label or address or "unknown"

    fn_part: Optional[str] = None
    call_data = decoded.get("call_data")
    if isinstance(call_data, dict):
        sig = call_data.get("signature") or call_data.get("function")
        if isinstance(sig, str) and sig:
            fn_part = sig
    if fn_part is None:
        data = trace.get("data")
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            fn_part = data[:10]

    header = f"{kind} {target}::{fn_part}" if fn_part else f"{kind} {target}"

    meta: List[str] = []
    val = trace.get("value")
    if val not in (None, "", "0", "0x", "0x0", 0):
        if isinstance(val, str) and val.startswith("0x"):
            try:
                meta.append(f"value: {val} ({int(val, 16)} wei)")
            except ValueError:
                meta.append(f"value: {val}")
        else:
            meta.append(f"value: {val}")

    status = trace.get("status")
    if isinstance(status, str) and status:
        meta.append(f"status: {status}")

    return_data = decoded.get("return_data")
    if return_data:
        meta.append(f"revert: {return_data}")

    if meta:
        return f"{header} [{', '.join(meta)}]"
    return header


def _failing_call_from_forge_json(text: str) -> Optional[str]:
    """Extract the deepest failing call from Forge ``--json`` trace output."""
    best: Optional[Tuple[int, Dict[str, Any]]] = None
    for obj in _iter_json_objects(text):
        for suite_val in obj.values():
            if not isinstance(suite_val, dict):
                continue
            test_results = suite_val.get("test_results")
            if not isinstance(test_results, dict):
                continue
            for test_val in test_results.values():
                if not isinstance(test_val, dict):
                    continue
                traces = test_val.get("traces")
                if not isinstance(traces, list):
                    continue
                # Prefer Execution traces over Setup/Deployment if present
                exec_traces = [
                    item for item in traces
                    if isinstance(item, list) and len(item) == 2 and item[0] == "Execution"
                ]
                ordered = exec_traces or traces
                for item in ordered:
                    if not (isinstance(item, list) and len(item) == 2 and isinstance(item[1], dict)):
                        continue
                    arena = item[1].get("arena")
                    if not isinstance(arena, list):
                        continue
                    candidate = _deepest_failing_arena_call(arena)
                    if candidate is not None and (best is None or candidate[0] >= best[0]):
                        best = candidate

    if best is None:
        return None
    return _format_arena_call(best[1])


def _failing_call(haystack: str) -> Optional[str]:
    """
    The call that failed: its address, its selector and the value it carried.

    Prefers structured Forge ``--json`` arena traces when present, then falls
    back to textual trace lines containing ``"::"``. A call that reverted is
    preferred; a call that carried a value is the next choice, because a call
    that sends ETH is the one that fails with ``OutOfFunds``. The last call of
    the trace is the fallback, so the digest still names the call when the
    trace says nothing more.
    """
    json_call = _failing_call_from_forge_json(haystack)
    if json_call is not None:
        return json_call

    reverted: Optional[str] = None
    valued: Optional[str] = None
    any_call: Optional[str] = None
    for line in haystack.splitlines():
        if "::" not in line:
            continue
        any_call = line
        if "[Revert]" in line or "Revert]" in line:
            reverted = line
            continue
        if _VALUE_PATTERN.search(line):
            valued = line
    chosen = reverted or valued or any_call
    if chosen is None:
        return None
    return _clean_trace_line(chosen)


def _is_json_line(line: str) -> bool:
    """Return True when a line carries a Forge JSON object rather than plain trace text."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return False
    return bool(_iter_json_objects(stripped))


def _extract_exploit_failed_from_json(text: str) -> Optional[str]:
    """Extract the short EXPLOIT_FAILED message from Forge JSON without raw JSON blobs."""
    for obj in _iter_json_objects(text):
        for suite_val in obj.values():
            if not isinstance(suite_val, dict):
                continue
            test_results = suite_val.get("test_results")
            if not isinstance(test_results, dict):
                continue
            for test_val in test_results.values():
                if not isinstance(test_val, dict):
                    continue
                reason = test_val.get("reason")
                if isinstance(reason, str) and EXPLOIT_FAILED_MARKER in reason:
                    return reason.strip()
                for log_key in ("decoded_logs", "logs"):
                    logs = test_val.get(log_key)
                    if isinstance(logs, list):
                        for entry in logs:
                            if isinstance(entry, str) and EXPLOIT_FAILED_MARKER in entry:
                                return entry.strip()
                traces = test_val.get("traces")
                if isinstance(traces, list):
                    for item in traces:
                        if not (isinstance(item, list) and len(item) == 2 and isinstance(item[1], dict)):
                            continue
                        arena = item[1].get("arena")
                        if not isinstance(arena, list):
                            continue
                        for node in arena:
                            if not isinstance(node, dict):
                                continue
                            trace = node.get("trace")
                            if not isinstance(trace, dict):
                                continue
                            decoded = trace.get("decoded")
                            if not isinstance(decoded, dict):
                                continue
                            ret = decoded.get("return_data")
                            if isinstance(ret, str) and EXPLOIT_FAILED_MARKER in ret:
                                return ret.strip()
    match = re.search(r"EXPLOIT_FAILED[^\"\\\n\r}]*", text)
    if match:
        return match.group(0).strip()
    return None


def extract_failure_reason(
    stdout: str = "",
    stderr: str = "",
    revert_reason: Optional[str] = None,
    decoded_logs: Optional[Sequence[str]] = None,
) -> str:
    """
    The concrete reason why the candidate failed, or an empty string.

    The reason is assembled out of the lines that are really in the output of
    the trusted harness; nothing is invented. When the trace says nothing that
    this module understands, the digest is empty - and the caller keeps its own
    wording.
    """
    haystack = "\n".join(
        [stdout or "", stderr or "", "\n".join(str(log) for log in (decoded_logs or []))]
    )

    parts: List[str] = []

    # 1. The message of the trusted harness: it names the invariant that held.
    for line in haystack.splitlines():
        if EXPLOIT_FAILED_MARKER not in line:
            continue
        if _is_json_line(line):
            extracted = _extract_exploit_failed_from_json(line)
            if extracted:
                parts.append(extracted)
                break
        else:
            parts.append(_clean_trace_line(line))
            break

    # 2. The revert reason of the JSON report of the test.
    if revert_reason:
        parts.append(f"revert reason: {str(revert_reason).strip()}")

    # 3. OutOfFunds and its relatives.
    for line in haystack.splitlines():
        matched_marker = next((m for m in OUT_OF_FUNDS_MARKERS if m in line), None)
        if matched_marker is None:
            continue
        if _is_json_line(line):
            parts.append(matched_marker)
        else:
            parts.append(_clean_trace_line(line))
        break

    # 4. The call that failed: its address, its selector and its value.
    failing_call = _failing_call(haystack)
    if failing_call:
        parts.append(f"failing call: {failing_call}")

    # The same reason twice is one reason.
    unique: List[str] = []
    for part in parts:
        if part and part not in unique:
            unique.append(part)

    return "; ".join(unique)


__all__ = [
    "OUT_OF_FUNDS_MARKERS",
    "EXPLOIT_FAILED_MARKER",
    "extract_failure_reason",
]
