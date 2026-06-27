"""Data-driven attack level selection helpers.

The UI and presets should not hard-code L1/L2/L3.  These helpers derive the
available levels from attack.json metadata and apply human-friendly policies.
"""
from __future__ import annotations

import math
import re
from typing import Iterable


def normalize_level(value: object) -> str:
    raw = str(value or "").strip().upper()
    m = re.search(r"L\d+", raw)
    return m.group(0) if m else raw


def level_sort_key(level: str) -> tuple[int, str]:
    m = re.search(r"\d+", str(level or ""))
    return (int(m.group(0)) if m else 9999, str(level))


def available_levels_from_attacks(attacks: Iterable[dict]) -> list[str]:
    levels = {
        normalize_level(a.get("attack_level") or a.get("level"))
        for a in attacks
        if normalize_level(a.get("attack_level") or a.get("level"))
    }
    return sorted(levels, key=level_sort_key)


def resolve_level_policy(policy: str | None, attacks: Iterable[dict]) -> list[str] | None:
    """Resolve a level policy to concrete levels.

    Returns None for all available levels so existing filtering code can keep the
    same semantics.
    """
    policy = (policy or "explicit").strip().lower()
    levels = available_levels_from_attacks(attacks)
    if not levels:
        return None
    if policy in {"", "explicit", "none"}:
        return None
    if policy in {"all", "all_available", "full"}:
        return None
    if policy in {"basic", "quick", "lowest"}:
        return [levels[0]]
    if policy in {"standard", "middle", "half"}:
        n = max(1, math.ceil(len(levels) / 2))
        return levels[:n]
    raise ValueError(f"Unsupported level_policy={policy!r}. Use basic, standard, all_available, or explicit.")


def describe_level_policy(policy: str | None, attacks: Iterable[dict]) -> str:
    resolved = resolve_level_policy(policy, attacks)
    if resolved is None:
        return "all_available"
    return ",".join(resolved)
