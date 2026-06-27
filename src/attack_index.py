from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ATTACKS_DIR = ROOT / "attacks"
MANIFEST_NAME = "manifest.json"

OWASP_IDS = [f"LLM{i:02d}" for i in range(1, 11)]

REQUIRED_ATTACK_FIELDS = {
    "id",
    "owasp_id",
    "attack_level",
    "attack_family",
    "turns",
    "expected_behavior",
    "success_condition",
}


def normalize_owasp_id(value: object) -> str:
    raw = str(value or "").strip().upper()
    if not raw:
        return ""
    raw = raw.split()[0]
    if re.fullmatch(r"LLM\d{1,2}", raw):
        return f"LLM{int(raw[3:]):02d}"
    return raw


def normalize_level(value: object) -> str:
    raw = str(value or "").strip().upper()
    m = re.search(r"L\d+", raw)
    return m.group(0) if m else raw


def is_attack_file(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    if path.name == MANIFEST_NAME:
        return False
    # Legacy dataset/generator files are not per-case attack JSON objects.
    # Keep them available for legacy generator tests, but never load them as
    # runnable attack cases from the clean OWASP attack index.
    if path.name in {"attack_families.json", "attacks_main.json"}:
        return False
    return True


def iter_attack_files(attacks_path: Path = DEFAULT_ATTACKS_DIR) -> Iterable[Path]:
    attacks_path = Path(attacks_path)
    if attacks_path.is_file():
        if is_attack_file(attacks_path):
            yield attacks_path
        return
    if not attacks_path.exists():
        raise FileNotFoundError(f"找不到 attacks 路徑：{attacks_path}")
    for path in sorted(attacks_path.rglob("*.json")):
        if is_attack_file(path):
            yield path


def load_attack_file(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"attack JSON must be an object: {path}")
    data.setdefault("_source_file", str(path))
    if not data.get("owasp_id") and data.get("primary_owasp"):
        data["owasp_id"] = normalize_owasp_id(data.get("primary_owasp"))
    data["owasp_id"] = normalize_owasp_id(data.get("owasp_id"))
    if not data.get("attack_level") and data.get("level"):
        data["attack_level"] = normalize_level(data.get("level"))
    data["attack_level"] = normalize_level(data.get("attack_level"))
    data.setdefault("level", data.get("attack_level"))
    return data


def load_attacks(attacks_path: Path = DEFAULT_ATTACKS_DIR) -> list[dict]:
    attacks = [load_attack_file(path) for path in iter_attack_files(attacks_path)]
    attacks.sort(key=attack_sort_key)
    return attacks


def attack_sort_key(attack: dict) -> tuple:
    owasp = normalize_owasp_id(attack.get("owasp_id") or attack.get("primary_owasp"))
    level = normalize_level(attack.get("attack_level") or attack.get("level"))
    level_num = int(re.search(r"\d+", level).group(0)) if re.search(r"\d+", level) else 999
    base_id = str(attack.get("base_attack_id") or attack.get("attack_id") or attack.get("family_id") or "")
    lang = str(attack.get("language_mode") or attack.get("prompt_style") or "")
    return (owasp, level_num, base_id, lang, str(attack.get("id", "")))


def available_owasp_ids(attacks: list[dict]) -> list[str]:
    values = {normalize_owasp_id(a.get("owasp_id") or a.get("primary_owasp")) for a in attacks}
    return sorted(v for v in values if v)


def available_levels(attacks: list[dict], owasp_id: str | None = None) -> list[str]:
    selected = normalize_owasp_id(owasp_id) if owasp_id else None
    values = set()
    for attack in attacks:
        if selected and normalize_owasp_id(attack.get("owasp_id")) != selected:
            continue
        level = normalize_level(attack.get("attack_level") or attack.get("level"))
        if level:
            values.add(level)
    return sorted(values, key=lambda v: int(re.search(r"\d+", v).group(0)) if re.search(r"\d+", v) else 999)


def build_index_summary(attacks: list[dict]) -> dict:
    by_owasp = Counter(normalize_owasp_id(a.get("owasp_id") or a.get("primary_owasp")) for a in attacks)
    by_level = Counter(normalize_level(a.get("attack_level") or a.get("level")) for a in attacks)
    by_language = Counter(str(a.get("language_mode") or "") for a in attacks)
    levels_by_owasp: dict[str, list[str]] = {}
    for owasp in sorted(k for k in by_owasp if k):
        levels_by_owasp[owasp] = available_levels(attacks, owasp)
    return {
        "total_attacks": len(attacks),
        "by_owasp": dict(sorted(by_owasp.items())),
        "by_level": dict(sorted(by_level.items(), key=lambda kv: int(re.search(r"\d+", kv[0]).group(0)) if re.search(r"\d+", kv[0]) else 999)),
        "by_language_mode": dict(sorted(by_language.items())),
        "levels_by_owasp": levels_by_owasp,
    }


def validate_attacks(attacks: list[dict]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen: dict[str, str] = {}
    for attack in attacks:
        source = str(attack.get("_source_file", "<unknown>"))
        attack_id = str(attack.get("id") or "").strip()
        if not attack_id:
            errors.append(f"{source}: missing id")
        elif attack_id in seen:
            errors.append(f"duplicate attack id {attack_id}: {seen[attack_id]} and {source}")
        else:
            seen[attack_id] = source

        missing = sorted(field for field in REQUIRED_ATTACK_FIELDS if attack.get(field) in (None, "", []))
        if missing:
            errors.append(f"{attack_id or source}: missing required fields: {', '.join(missing)}")

        owasp = normalize_owasp_id(attack.get("owasp_id") or attack.get("primary_owasp"))
        if owasp and owasp not in OWASP_IDS:
            errors.append(f"{attack_id or source}: invalid owasp_id={owasp}")

        level = normalize_level(attack.get("attack_level") or attack.get("level"))
        if level and not re.fullmatch(r"L\d+", level):
            errors.append(f"{attack_id or source}: invalid attack_level={level}")

        turns = attack.get("turns")
        if turns is not None:
            if not isinstance(turns, list) or not turns:
                errors.append(f"{attack_id or source}: turns must be a non-empty list")
            else:
                for i, turn in enumerate(turns, 1):
                    if not isinstance(turn, dict):
                        errors.append(f"{attack_id or source}: turn {i} must be object")
                        continue
                    if turn.get("role") not in {"user", "assistant", "system"}:
                        errors.append(f"{attack_id or source}: turn {i} has invalid role={turn.get('role')}")
                    if not str(turn.get("content") or "").strip():
                        errors.append(f"{attack_id or source}: turn {i} missing content")

        if not attack.get("classification_rationale"):
            warnings.append(f"{attack_id or source}: missing classification_rationale")
    return errors, warnings


def load_and_validate(attacks_path: Path = DEFAULT_ATTACKS_DIR) -> tuple[list[dict], list[str], list[str]]:
    attacks = load_attacks(attacks_path)
    errors, warnings = validate_attacks(attacks)
    return attacks, errors, warnings
