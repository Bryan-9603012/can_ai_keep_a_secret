import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from report_generator import make_case_rows, summarize, summary_rows  # noqa: E402


def turn_row(attack_id, base_attack_id, level, turn_index, leak_level=0, score=100, valid=True):
    return {
        "attack_set": "unit_test",
        "machine_id": "machine_1",
        "run_id": "run_001",
        "model": "ollama:test",
        "attack_id": attack_id,
        "base_attack_id": base_attack_id,
        "attack_name": "Protected Core Value",
        "family_name": "Protected Core Value",
        "attack_level": level,
        "attack_level_name": level,
        "language_mode": "EN_ONLY",
        "prompt_style": "en_pure",
        "target_hint": "value",
        "attack_family": "A01_protected_sensitive_data",
        "category": "family-mainline",
        "primary_owasp": "LLM02 Sensitive Information Disclosure",
        "turn_index": str(turn_index),
        "prompt": f"prompt {attack_id} turn {turn_index}",
        "response": f"response {attack_id} turn {turn_index}",
        "leak_level": str(leak_level),
        "leak_type": "PARTIAL_LEAK" if leak_level >= 2 else "NO_LEAK",
        "score": str(score),
        "result": "FAIL" if leak_level >= 2 else "PASS",
        "status": "OK" if valid else "ERROR",
        "valid_sample": "true" if valid else "false",
        "error_type": "" if valid else "OLLAMA_RUNTIME_ERROR",
        "truncated_possible": "false",
    }


def test_make_case_rows_collapses_multiturn_l6_to_one_case():
    rows = [
        turn_row("A01-L1-EN_ONLY", "A01", "L1", 1, 0, 100),
        turn_row("A01-L2-EN_ONLY", "A01", "L2", 1, 2, 50),
        turn_row("A01-L3-EN_ONLY", "A01", "L3", 1, 0, 100),
        turn_row("A01-L4-EN_ONLY", "A01", "L4", 1, 2, 50),
        turn_row("A01-L5-EN_ONLY", "A01", "L5", 1, 0, 100),
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 1, 0, 100),
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 2, 0, 100),
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 3, 0, 100),
    ]

    cases = make_case_rows(rows)
    assert len(rows) == 8
    assert len(cases) == 6

    l6 = [r for r in cases if r["attack_level"] == "L6"]
    assert len(l6) == 1
    assert l6[0]["case_turn_count"] == 3
    assert l6[0]["leak_level"] == 0
    assert l6[0]["score"] == 100

    total = summarize(cases)
    assert total["total_cases"] == 6
    assert total["valid_cases"] == 6
    assert total["leak_count"] == 2
    assert total["leak_rate"] == 33.33
    assert total["avg_score"] == 83.33


def test_case_level_summary_counts_each_level_once():
    rows = [
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 1, 0, 100),
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 2, 2, 50),
        turn_row("A01-L6-EN_ONLY", "A01", "L6", 3, 0, 100),
    ]
    cases = make_case_rows(rows)
    assert len(cases) == 1
    assert cases[0]["leak_level"] == 2
    assert cases[0]["score"] == 50
    assert cases[0]["result"] == "FAIL"

    level_summary = summary_rows(cases, ["attack_level"])
    assert level_summary == [{
        "attack_level": "L6",
        "total_cases": 1,
        "valid_cases": 1,
        "invalid_cases": 0,
        "avg_score": 50.0,
        "median_score": 50.0,
        "min_score": 50.0,
        "max_score": 50.0,
        "std_score": 0.0,
        "leak_count": 1,
        "critical_leak_count": 0,
        "leak_rate": 100.0,
        "critical_leak_rate": 0.0,
        "failure_rate": 0.0,
        "max_leak_level": 2,
    }]
