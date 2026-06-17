import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ROOT / "attacks" / "attack_families.json"

sys.path.insert(0, str(ROOT / "src"))
from generate_attacks_main import build_rows  # noqa: E402


def load_families():
    return json.loads(FAMILIES.read_text(encoding="utf-8"))


def test_attack_families_shape():
    families = load_families()
    assert len(families) == 20
    assert len({row["attack_id"] for row in families}) == 20
    for family in families:
        assert family["family_name"].strip()
        assert family["family_goal"].strip()
        assert family["target_hint"] in {"value", "metadata", "policy", "mixed_value"}
        assert family["target"].strip()


def test_attacks_main_generator_output_shape():
    rows = build_rows(load_families())
    assert len(rows) == 480
    assert len({row["id"] for row in rows}) == 480

    by_base = defaultdict(list)
    for row in rows:
        by_base[row["base_attack_id"]].append(row)

    assert len(by_base) == 20
    assert all(len(items) == 24 for items in by_base.values())

    assert Counter(row["language_mode"] for row in rows) == {
        "EN_ONLY": 120,
        "ZH_ONLY": 120,
        "ZH_EN_MIX": 120,
        "EN_ZH_MIX": 120,
    }
    assert Counter(row["attack_level"] for row in rows) == {
        "L1": 80,
        "L2": 80,
        "L3": 80,
        "L4": 80,
        "L5": 80,
        "L6": 80,
    }


def test_attacks_main_required_fields_present():
    rows = build_rows(load_families())
    required = {
        "attack_version",
        "attack_name",
        "family_name",
        "family_goal",
        "attack_level",
        "attack_level_name",
        "category",
        "scenario",
        "tactic",
        "language_mode",
        "prompt_style",
        "target",
        "target_hint",
        "success_condition",
        "expected_behavior",
        "primary_owasp",
        "owasp_fit_status",
        "web_app_required",
    }
    for row in rows:
        missing = [field for field in required if field not in row or row[field] in (None, "", [])]
        assert not missing, f"{row.get('id')} missing {missing}"
        assert isinstance(row["turns"], list) and row["turns"]
        assert all(turn.get("role") == "user" for turn in row["turns"])
        assert all(turn.get("content", "").strip() for turn in row["turns"])


def test_generated_prompts_do_not_duplicate_hidden_context_phrases():
    rows = build_rows(load_families())
    bad_fragments = ["the the", "stored in hidden context stored in your hidden context"]
    for row in rows:
        for turn in row["turns"]:
            content = turn.get("content", "").lower()
            assert not any(fragment in content for fragment in bad_fragments), row["id"]
