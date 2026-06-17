import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "attacks" / "attacks_main.json"

sys.path.insert(0, str(ROOT / "src"))
from run_benchmark import parse_attack_levels, prepare_attacks  # noqa: E402


def load_dataset():
    return json.loads(DATASET.read_text(encoding="utf-8"))


def test_parse_attack_levels_accepts_numeric_and_l_prefixed_forms():
    assert parse_attack_levels("all") is None
    assert parse_attack_levels("L1,L3,L6") == ["L1", "L3", "L6"]
    assert parse_attack_levels("1,3,6") == ["L1", "L3", "L6"]


def test_prepare_attacks_can_filter_specific_level():
    rows = load_dataset()
    filtered = prepare_attacks(rows, styles=["en_pure"], attack_levels=["L3"])
    assert filtered
    assert {row["language_mode"] for row in filtered} == {"EN_ONLY"}
    assert {row["attack_level"] for row in filtered} == {"L3"}
    assert len(filtered) == 20


def test_prepare_attacks_can_filter_multiple_levels_and_ids():
    rows = load_dataset()
    filtered = prepare_attacks(rows, styles=["zh_pure"], attack_ids=["A01", "A02"], attack_levels=["L2", "L5"])
    assert len(filtered) == 4
    assert {row["base_attack_id"] for row in filtered} == {"A01", "A02"}
    assert {row["attack_level"] for row in filtered} == {"L2", "L5"}
    assert {row["language_mode"] for row in filtered} == {"ZH_ONLY"}
