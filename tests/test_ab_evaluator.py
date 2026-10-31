"""
tests/test_ab_evaluator.py

Regression test suite for Section 6 (Round 4):
A/B Evaluation Recomputation and Metric Correctness.
"""

import pytest
from core.schemas import ResultCategory
from core.ab_evaluator import evaluate_raw_candidates, format_ab_table_markdown


def test_ab_evaluator_sums_categories_to_total_n():
    """Test 1: Category counts sum exactly to total N."""
    candidates = [
        {"verdict": {"category": ResultCategory.GENERATION_FORMAT_ERROR.value, "reward_score": -0.50}},
        {"verdict": {"category": ResultCategory.COMPILATION_ERROR.value, "reward_score": -0.50}},
        {"verdict": {"category": ResultCategory.RUNTIME_REVERT.value, "reward_score": -0.25}},
        {"verdict": {"category": ResultCategory.SAFE_RUN.value, "reward_score": -0.10}},
        {"verdict": {"category": ResultCategory.EXPLOIT_CONFIRMED.value, "reward_score": 1.00}},
    ]
    metrics = evaluate_raw_candidates(candidates)

    assert metrics["total_candidates"] == 5
    assert metrics["valid_format_count"] == 4
    assert metrics["valid_format_rate"] == 4 / 5
    assert metrics["compiled_count"] == 3
    assert metrics["compilation_rate"] == 3 / 5
    assert metrics["confirmed_exploit_count"] == 1
    assert metrics["confirmed_exploit_rate"] == 1 / 5


def test_ab_evaluator_zero_baseline_handling():
    """Test 2: When baseline confirmed exploits is 0, rates are accurately reported without division-by-zero."""
    baseline_raw = [
        {"verdict": {"category": ResultCategory.GENERATION_FORMAT_ERROR.value, "reward_score": -0.50}},
        {"verdict": {"category": ResultCategory.GENERATION_FORMAT_ERROR.value, "reward_score": -0.50}},
    ]
    lora_raw = [
        {"verdict": {"category": ResultCategory.GENERATION_FORMAT_ERROR.value, "reward_score": -0.50}},
        {"verdict": {"category": ResultCategory.COMPILATION_ERROR.value, "reward_score": -0.50}},
    ]

    base_metrics = evaluate_raw_candidates(baseline_raw)
    lora_metrics = evaluate_raw_candidates(lora_raw)

    table_md = format_ab_table_markdown(base_metrics, lora_metrics)

    assert "N = 2" in table_md
    assert "0/2 (0.0%)" in table_md
    # Table must state that Pass@N is 0% for both
    assert "0% confirmed for both" in table_md
