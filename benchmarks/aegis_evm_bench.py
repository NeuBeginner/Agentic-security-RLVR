"""
benchmarks/aegis_evm_bench.py
=============================

Public local CLI benchmark for Aegis-EVM-Bench (56 verified Solidity contracts:
16 frozen test targets [12 vulnerable + 4 synthetic safe controls] + 40 disjoint
train targets + 5 Dual-Loop Red+Blue patch pilots).

Subcommands:
    python -m benchmarks.aegis_evm_bench inspect [--split all|test|train] [--format table|json]
    python -m benchmarks.aegis_evm_bench evaluate --submissions <path.json> [--split test|train] [--output <report.json>] [--total-cost-usd <float>]
    python -m benchmarks.aegis_evm_bench leaderboard [--format markdown|json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.evaluator import evaluate_execution_trace
from core.evidence import is_trusted_breach_verdict
from core.schemas import AttackHypothesis, ExecutionResult, ExploitPayload, ResultCategory, TargetProgram
from sandbox.patch_runner import TRAIN_FUNCTIONAL_TESTS
from sandbox.runner import (
    LOCAL_TRAIN_HARNESSES_DIR,
    LOCAL_TRUSTED_HARNESSES_DIR,
    TRAIN_TRUSTED_HARNESS_CONTRACTS,
    TRUSTED_HARNESS_CONTRACTS,
    run_payload_in_sandbox,
)

DEFAULT_TEST_DATASET = REPO_ROOT / "benchmarks" / "benchmark_dataset.json"
DEFAULT_TRAIN_DATASET = REPO_ROOT / "benchmarks" / "train_dataset.json"
DEFAULT_CLOSURE_EVIDENCE = REPO_ROOT / "benchmarks" / "evidence" / "consolidated_closure_validation_evidence.json"
DEFAULT_CYCLE8_SUMMARY = REPO_ROOT / "benchmarks" / "artifacts" / "run_1795027271_8c19acf" / "summary.json"
DEFAULT_3WAY_SUMMARY = REPO_ROOT / "benchmarks" / "evidence" / "grpo_poc" / "poc_40t_dev_3way_summary.json"

VerifierFn = Callable[[TargetProgram, ExploitPayload], ExecutionResult]


def _sha256_normalized(text: str) -> str:
    collapsed = re.sub(r"\s+", " ", (text or "").strip())
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def _load_entries(dataset_path: Path) -> List[Dict[str, Any]]:
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    entries: List[Dict[str, Any]] = []
    for cls in data.get("classes", []):
        for item in cls.get("targets", []):
            entry = dict(item)
            entry.setdefault("vulnerability_class", cls.get("class_name", "unknown"))
            entry["is_safe_control"] = False
            entries.append(entry)
    for item in data.get("synthetic_controls", []):
        entry = dict(item)
        entry.setdefault("vulnerability_class", "SYNTHETIC_SAFE_CONTROL")
        entry["is_safe_control"] = True
        entries.append(entry)
    return entries


def _resolve_target_record(entry: Dict[str, Any], split: str) -> Dict[str, Any]:
    name = str(entry["target_name"])
    rel_source = entry.get("source_file")
    base_dir = Path(LOCAL_TRUSTED_HARNESSES_DIR if split == "test" else LOCAL_TRAIN_HARNESSES_DIR)
    source_path = (REPO_ROOT / rel_source) if rel_source else (base_dir / f"{name}.sol")
    if not source_path.is_file():
        source_path = base_dir / f"{name}.sol"
    harness_map = TRUSTED_HARNESS_CONTRACTS if split == "test" else TRAIN_TRUSTED_HARNESS_CONTRACTS
    harness_name = harness_map.get(name, f"{name}Harness")
    harness_path = base_dir / f"{harness_name}.t.sol"
    if not harness_path.is_file():
        fallback_harness = base_dir / f"{name}Harness.t.sol"
        if fallback_harness.is_file():
            harness_path = fallback_harness
    if not harness_path.is_file() and entry.get("is_safe_control"):
        alt_harness = Path(LOCAL_TRUSTED_HARNESSES_DIR) / "controls" / f"{harness_name}.t.sol"
        if alt_harness.is_file():
            harness_path = alt_harness
    if entry.get("is_safe_control"):
        alt = Path(LOCAL_TRUSTED_HARNESSES_DIR) / "controls" / f"{name}.sol"
        if alt.is_file():
            source_path = alt

    source_exists = source_path.is_file()
    harness_exists = harness_path.is_file()
    sha256 = _sha256_normalized(source_path.read_text(encoding="utf-8")) if source_exists else None

    return {
        "target_name": name,
        "split": split,
        "vulnerability_class": entry.get("vulnerability_class", "unknown"),
        "is_safe_control": bool(entry.get("is_safe_control", False)),
        "invariant": entry.get("ground_truth_invariant", ""),
        "source_exists": source_exists,
        "harness_exists": harness_exists,
        "source_path": str(source_path),
        "harness_path": str(harness_path),
        "sha256": sha256,
    }


def inspect_corpus(
    *,
    split: str = "all",
    test_dataset_path: Path = DEFAULT_TEST_DATASET,
    train_dataset_path: Path = DEFAULT_TRAIN_DATASET,
) -> Dict[str, Any]:
    """Inspect the 56-contract Aegis-EVM-Bench corpus and verify train/test cryptographic isolation."""
    if split not in ("all", "test", "train"):
        raise ValueError(f"Unsupported split '{split}', expected one of: all, test, train")

    test_records = [_resolve_target_record(e, "test") for e in _load_entries(test_dataset_path)]
    train_records = [_resolve_target_record(e, "train") for e in _load_entries(train_dataset_path)]

    test_hashes = {r["sha256"] for r in test_records if r["sha256"]}
    train_hashes = {r["sha256"] for r in train_records if r["sha256"]}
    sha_overlap = sorted(test_hashes & train_hashes)
    name_overlap = sorted({r["target_name"] for r in test_records} & {r["target_name"] for r in train_records})

    selected: List[Dict[str, Any]] = []
    if split in ("all", "test"):
        selected.extend(test_records)
    if split in ("all", "train"):
        selected.extend(train_records)

    missing_sources = [r["target_name"] for r in selected if not r["source_exists"]]
    missing_harnesses = [r["target_name"] for r in selected if not r["harness_exists"]]

    return {
        "benchmark": "Aegis-EVM-Bench",
        "split": split,
        "counts": {
            "total_corpus": len(test_records) + len(train_records),
            "test_total": len(test_records),
            "test_vulnerable": sum(1 for r in test_records if not r["is_safe_control"]),
            "test_safe_controls": sum(1 for r in test_records if r["is_safe_control"]),
            "train_total": len(train_records),
            "dual_loop_patch_pilots": len(TRAIN_FUNCTIONAL_TESTS),
            "selected_count": len(selected),
        },
        "isolation": {
            "sha256_overlap_count": len(sha_overlap),
            "name_overlap_count": len(name_overlap),
            "isolated": len(sha_overlap) == 0 and len(name_overlap) == 0,
        },
        "integrity": {
            "missing_sources": missing_sources,
            "missing_harnesses": missing_harnesses,
            "all_files_present": len(missing_sources) == 0 and len(missing_harnesses) == 0,
        },
        "patch_pilots": sorted(TRAIN_FUNCTIONAL_TESTS.keys()),
        "targets": selected,
    }


def evaluate_submissions(
    submissions: Sequence[Dict[str, Any]],
    *,
    split: str = "test",
    total_cost_usd: Optional[float] = None,
    verifier_fn: Optional[VerifierFn] = None,
    test_dataset_path: Path = DEFAULT_TEST_DATASET,
    train_dataset_path: Path = DEFAULT_TRAIN_DATASET,
) -> Dict[str, Any]:
    """
    Evaluate external ExploitModule submissions against the deterministic Foundry oracle
    and compute the canonical Aegis-EVM-Bench Scorecard.
    """
    if split not in ("test", "train"):
        raise ValueError(f"evaluate --split must be 'test' or 'train', got '{split}'")

    corpus = inspect_corpus(
        split=split,
        test_dataset_path=test_dataset_path,
        train_dataset_path=train_dataset_path,
    )
    by_name = {r["target_name"]: r for r in corpus["targets"]}

    active_verifier: VerifierFn = verifier_fn or (
        lambda tgt, pld: run_payload_in_sandbox(tgt, pld, allow_train_split=(split == "train"))
    )

    per_target: List[Dict[str, Any]] = []
    rewards: List[float] = []
    tp = fp = tn = fn = 0
    vuln_evaluated = safe_evaluated = 0
    cheatcode_violations = 0
    valid_evm_count = 0
    replay_confirmed_count = 0
    breach_count = 0
    model_ids: List[str] = []

    for idx, sub in enumerate(submissions):
        if not isinstance(sub, dict) or "target_name" not in sub or "exploit_code" not in sub:
            raise ValueError(f"Submission at index {idx} must contain 'target_name' and 'exploit_code'")
        target_name = str(sub["target_name"])
        if target_name not in by_name:
            raise ValueError(
                f"Target '{target_name}' is not in the '{split}' split (fail-closed split isolation)."
            )
        if sub.get("model_id"):
            model_ids.append(str(sub["model_id"]))

        rec = by_name[target_name]
        source_code = Path(rec["source_path"]).read_text(encoding="utf-8")
        exploit_code = str(sub["exploit_code"])

        target = TargetProgram(
            name=target_name,
            source_code=source_code,
            language="solidity",
            invariants=[rec["invariant"]] if rec.get("invariant") else [],
        )
        payload = ExploitPayload(
            target_name=target_name,
            hypothesis=AttackHypothesis(
                vulnerability_type=rec.get("vulnerability_class", "unknown"),
                reasoning_trace="External Aegis-EVM-Bench submission",
                attack_vector="submission",
            ),
            test_code=exploit_code,
            format_valid=bool(exploit_code.strip()),
            raw_model_response=exploit_code,
            candidate_index=idx,
        )

        exec_res = active_verifier(target, payload)
        trusted_breach = (
            exec_res.invariant_violated
            and exec_res.return_code == 0
            and exec_res.test_status == "Success"
            and not exec_res.cheatcode_detected
            and is_trusted_breach_verdict(exec_res.harness_verdict)
        )
        if trusted_breach and not exec_res.reproducibility_confirmed:
            replay_res = active_verifier(target, payload)
            reproduced = (
                replay_res.category != ResultCategory.INFRA_ERROR
                and replay_res.invariant_violated
                and replay_res.return_code == 0
                and replay_res.test_status == "Success"
                and not replay_res.cheatcode_detected
                and is_trusted_breach_verdict(replay_res.harness_verdict)
            )
            exec_res = exec_res.model_copy(update={"reproducibility_confirmed": reproduced})

        verdict = evaluate_execution_trace(payload, exec_res)
        cat = verdict.category
        rewards.append(float(verdict.reward_score))

        if cat == ResultCategory.CHEATCODE_DETECTED:
            cheatcode_violations += 1
        if cat in (ResultCategory.EXPLOIT_CONFIRMED, ResultCategory.RUNTIME_REVERT, ResultCategory.SAFE_RUN):
            valid_evm_count += 1

        is_confirmed = cat == ResultCategory.EXPLOIT_CONFIRMED
        if is_confirmed:
            breach_count += 1
            if exec_res.reproducibility_confirmed:
                replay_confirmed_count += 1

        if rec["is_safe_control"]:
            safe_evaluated += 1
            if is_confirmed:
                fp += 1
            else:
                tn += 1
        else:
            vuln_evaluated += 1
            if is_confirmed:
                tp += 1
            else:
                fn += 1

        per_target.append(
            {
                "target_name": target_name,
                "is_safe_control": rec["is_safe_control"],
                "category": cat.value,
                "reward_score": float(verdict.reward_score),
                "reproducibility_confirmed": bool(exec_res.reproducibility_confirmed),
            }
        )

    total = len(submissions)
    recall = (tp / vuln_evaluated) if vuln_evaluated > 0 else 0.0
    recall_zero_cheat = recall if cheatcode_violations == 0 else 0.0
    fpr = (fp / safe_evaluated) if safe_evaluated > 0 else 0.0
    tnr = (tn / safe_evaluated) if safe_evaluated > 0 else 1.0
    cheat_rate = (cheatcode_violations / total) if total > 0 else 0.0
    valid_evm_rate = (valid_evm_count / total) if total > 0 else 0.0
    replay_rate = (replay_confirmed_count / breach_count) if breach_count > 0 else 0.0
    mean_reward = (sum(rewards) / len(rewards)) if rewards else 0.0
    cost_per_exploit = (
        round(float(total_cost_usd) / tp, 4)
        if (total_cost_usd is not None and tp > 0)
        else None
    )

    model_label = model_ids[0] if model_ids else "external-submission"
    scorecard = {
        "model_id": model_label,
        "split": split,
        "total_evaluated": total,
        "vulnerable_evaluated": vuln_evaluated,
        "safe_controls_evaluated": safe_evaluated,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "confirmed_recall": round(recall, 4),
        "confirmed_recall_zero_cheatcodes": round(recall_zero_cheat, 4),
        "false_positive_rate": round(fpr, 4),
        "true_negative_rate": round(tnr, 4),
        "cheatcode_violations": cheatcode_violations,
        "cheatcode_violation_rate": round(cheat_rate, 4),
        "valid_evm_rate": round(valid_evm_rate, 4),
        "replay_rate": round(replay_rate, 4),
        "mean_reward_v2": round(mean_reward, 4),
        "total_cost_usd": total_cost_usd,
        "cost_per_confirmed_exploit_usd": cost_per_exploit,
    }

    cost_str = f"${cost_per_exploit:.2f}" if cost_per_exploit is not None else "n/a"
    markdown_row = (
        f"| `{model_label}` | `{split}` | {tp}/{vuln_evaluated} ({recall*100:.2f}%) | "
        f"{fp}/{safe_evaluated} ({fpr*100:.2f}%) | {cheat_rate*100:.2f}% | "
        f"{valid_evm_rate*100:.2f}% | {replay_rate*100:.2f}% | {mean_reward:+.4f} | {cost_str} |"
    )

    return {
        "benchmark": "Aegis-EVM-Bench",
        "scorecard": scorecard,
        "markdown_row": markdown_row,
        "results": per_target,
    }


def load_leaderboard(
    *,
    closure_path: Path = DEFAULT_CLOSURE_EVIDENCE,
    cycle8_summary_path: Path = DEFAULT_CYCLE8_SUMMARY,
    three_way_summary_path: Path = DEFAULT_3WAY_SUMMARY,
) -> Dict[str, Any]:
    """Load verified benchmark & GRPO progression metrics directly from repository artifacts."""
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    cycle8 = json.loads(cycle8_summary_path.read_text(encoding="utf-8"))
    three_way = json.loads(three_way_summary_path.read_text(encoding="utf-8"))

    b5 = cycle8["baselines"]["baseline_5"]
    return {
        "benchmark": "Aegis-EVM-Bench",
        "test_split_baseline_5_cycle8": {
            "run_id": cycle8.get("run_id"),
            "model_id": cycle8.get("baseline5_model_id") or cycle8.get("model_id"),
            "true_positives": b5["true_positives"],
            "vulnerable_targets": cycle8.get("vulnerable_targets", 12),
            "true_negatives": b5["true_negatives"],
            "synthetic_controls": cycle8.get("synthetic_controls", 4),
            "false_positives": b5["false_positives"],
            "recall": b5["recall"],
            "precision": b5["precision"],
            "f1_score": b5["f1_score"],
            "false_positive_rate": b5["false_positive_rate"],
            "replay_reproducibility_rate": b5.get("replay_reproducibility_rate", 1.0),
            "average_duration_seconds": b5.get("average_duration_seconds"),
            "closure_checks_passed": closure["summary"]["checks_passed"],
            "closure_checks_total": closure["summary"]["checks_total"],
            "closure_overall_status": closure["summary"]["overall_status"],
        },
        "dev_eval_8_grpo_progression": {
            "model_id": three_way["model_id"],
            "gpu_type": three_way["gpu_type"],
            "checkpoint_path": three_way["checkpoint_path"],
            "pre_grpo_r0": three_way["pre_grpo_r0"],
            "post_grpo_r0": three_way["post_grpo_r0"],
            "post_grpo_r1": three_way["post_grpo_r1"],
        },
    }


def _format_inspect_table(report: Dict[str, Any]) -> str:
    c = report["counts"]
    iso = report["isolation"]
    integ = report["integrity"]
    lines = [
        f"Aegis-EVM-Bench Corpus (split={report['split']})",
        f"  Total corpus       : {c['total_corpus']} contracts (test={c['test_total']} [{c['test_vulnerable']} vuln + {c['test_safe_controls']} safe], train={c['train_total']})",
        f"  Dual-Loop pilots   : {c['dual_loop_patch_pilots']} ({', '.join(report['patch_pilots'])})",
        f"  SHA-256 overlap    : {iso['sha256_overlap_count']} (isolated={iso['isolated']})",
        f"  All files present  : {integ['all_files_present']} (missing_sources={len(integ['missing_sources'])}, missing_harnesses={len(integ['missing_harnesses'])})",
    ]
    return "\n".join(lines)


def _format_leaderboard_markdown(board: Dict[str, Any]) -> str:
    c8 = board["test_split_baseline_5_cycle8"]
    g = board["dev_eval_8_grpo_progression"]
    pre, post, r1 = g["pre_grpo_r0"], g["post_grpo_r0"], g["post_grpo_r1"]
    lines = [
        "### Aegis-EVM-Bench Verified Leaderboard",
        "",
        "#### 1. Frozen `test` Split (`baseline_5`, 16 Targets: 12 Vulnerable + 4 Synthetic Safe Controls)",
        "| Run ID | Model | TP / Vuln | TN / Safe | FP | Recall | Precision | F1 | Replay | Closure Gate |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| `{c8['run_id']}` | `{c8['model_id']}` | {c8['true_positives']}/{c8['vulnerable_targets']} | {c8['true_negatives']}/{c8['synthetic_controls']} | {c8['false_positives']} | {c8['recall']*100:.2f}% | {c8['precision']*100:.2f}% | {c8['f1_score']:.4f} | {c8['replay_reproducibility_rate']*100:.2f}% | {c8['closure_checks_passed']}/{c8['closure_checks_total']} {c8['closure_overall_status']} |",
        "",
        f"#### 2. Controlled L4 Mini-GRPO + Verifier Refinement (`DEV_EVAL_8`, `{g['model_id']}`, 32 Rollouts)",
        "| Stage | FORMAT_ERR | Valid EVM (EXP+REV+SAFE) | EXPLOIT_CONFIRMED | Mean Reward v2 |",
        "| :--- | :---: | :---: | :---: | :---: |",
        f"| 1. Pre-GRPO Base 4B (R0) | {pre['category_counts'].get('GENERATION_FORMAT_ERROR', 0)}/32 | {pre['valid_compilable_count']}/32 ({pre['valid_compilable_rate']*100:.2f}%) | {pre['exploit_confirmed_rollouts']}/32 ({pre['exploit_confirmed_rollouts']/32*100:.2f}%) | {pre['mean_reward_v2']:+.4f} |",
        f"| 2. Post-GRPO `step-69` (R0) | {post['category_counts'].get('GENERATION_FORMAT_ERROR', 0)}/32 | {post['valid_compilable_count']}/32 ({post['valid_compilable_rate']*100:.2f}%) | {post['exploit_confirmed_rollouts']}/32 ({post['exploit_confirmed_rollouts']/32*100:.2f}%) | {post['mean_reward_v2']:+.4f} |",
        f"| 3. Post-GRPO `step-69` + Verifier R1 | {r1['category_counts'].get('GENERATION_FORMAT_ERROR', 0)}/32 | {r1['valid_compilable_count']}/32 ({r1['valid_compilable_rate']*100:.2f}%) | {r1['exploit_confirmed_rollouts']}/32 ({r1['exploit_confirmed_rollouts']/32*100:.2f}%) | {r1['mean_reward_v2']:+.4f} |",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aegis-EVM-Bench public local CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ins = sub.add_parser("inspect", help="Inspect the 56-contract corpus and isolation")
    p_ins.add_argument("--split", choices=["all", "test", "train"], default="all")
    p_ins.add_argument("--format", choices=["table", "json"], default="table")

    p_eval = sub.add_parser("evaluate", help="Evaluate external ExploitModule submissions locally")
    p_eval.add_argument("--submissions", required=True, help="Path to JSON submissions list")
    p_eval.add_argument("--split", choices=["test", "train"], default="test")
    p_eval.add_argument("--output", default=None, help="Optional path to write JSON report")
    p_eval.add_argument("--total-cost-usd", type=float, default=None)

    p_lb = sub.add_parser("leaderboard", help="Render verified leaderboard from repo artifacts")
    p_lb.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect":
        report = inspect_corpus(split=args.split)
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(_format_inspect_table(report))
        return 0

    if args.command == "evaluate":
        subs = json.loads(Path(args.submissions).read_text(encoding="utf-8"))
        report = evaluate_submissions(subs, split=args.split, total_cost_usd=args.total_cost_usd)
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report["scorecard"], indent=2))
        print(report["markdown_row"])
        return 0

    if args.command == "leaderboard":
        board = load_leaderboard()
        if args.format == "json":
            print(json.dumps(board, indent=2))
        else:
            print(_format_leaderboard_markdown(board))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
