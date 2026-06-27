import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_index import build_index_summary, load_attacks, validate_attacks  # noqa: E402


def test_clean_attack_directory_shape():
    attacks = load_attacks(ROOT / "attacks")
    assert len(attacks) == 480
    assert len({row["id"] for row in attacks}) == 480

    summary = build_index_summary(attacks)
    assert summary["by_owasp"] == {
        "LLM01": 120,
        "LLM02": 120,
        "LLM07": 120,
        "LLM10": 120,
    }
    assert summary["by_level"] == {
        "L1": 80,
        "L2": 80,
        "L3": 80,
        "L4": 80,
        "L5": 80,
        "L6": 80,
    }


def test_attack_files_are_grouped_by_primary_owasp_directory():
    attacks = load_attacks(ROOT / "attacks")
    for row in attacks:
        source = Path(row["_source_file"])
        assert source.parts[-3].startswith(row["owasp_id"] + "_"), row["_source_file"]
        assert source.parts[-2] == row["attack_level"], row["_source_file"]


def test_clean_attack_json_required_fields_and_validation():
    attacks = load_attacks(ROOT / "attacks")
    errors, warnings = validate_attacks(attacks)
    assert errors == []
    assert warnings == []
    required = {
        "id",
        "owasp_id",
        "primary_owasp",
        "attack_family",
        "attack_level",
        "turns",
        "expected_behavior",
        "success_condition",
        "classification_rationale",
    }
    for row in attacks:
        missing = [field for field in required if row.get(field) in (None, "", [])]
        assert not missing, f"{row.get('id')} missing {missing}"


def test_attack_index_has_expected_family_and_language_distribution():
    attacks = load_attacks(ROOT / "attacks")
    by_base = defaultdict(list)
    for row in attacks:
        by_base[row["base_attack_id"]].append(row)

    assert len(by_base) == 20
    assert all(len(items) == 24 for items in by_base.values())
    assert Counter(row["language_mode"] for row in attacks) == {
        "EN_ONLY": 120,
        "ZH_ONLY": 120,
        "ZH_EN_MIX": 120,
        "EN_ZH_MIX": 120,
    }


def test_attack_dataset_has_no_deferred_defense_fields():
    forbidden = {
        "expected_defense_target",
        "defense_mode",
        "defense_name",
        "defense_version",
        "input_guard_enabled",
        "output_guard_enabled",
        "skill_enabled",
    }
    for row in load_attacks(ROOT / "attacks"):
        present = forbidden.intersection(row)
        assert not present, f"{row.get('id')} contains deferred defense fields: {sorted(present)}"
