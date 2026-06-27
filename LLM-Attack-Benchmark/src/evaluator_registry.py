"""OWASP evaluator registry and coverage helpers.

This registry is intentionally small and dependency-free so preflight checks can
report evaluator coverage without importing model/runtime code.
"""
from __future__ import annotations

import re
from typing import Iterable

OWASP_IDS = [f"LLM{i:02d}" for i in range(1, 11)]

DEDICATED_EVALUATORS: dict[str, str] = {
    "LLM01": "llm01_prompt_injection",
    "LLM02": "llm02_sensitive_information_disclosure",
    "LLM07": "llm07_system_prompt_leakage",
    "LLM09": "llm09_misinformation",
    "LLM10": "llm10_unbounded_consumption",
}

LEGACY_EVALUATOR = "legacy_leak_detector"


def normalize_owasp_id(value: object) -> str:
    raw = str(value or "").strip().upper()
    if not raw:
        return ""
    if raw.startswith("LLM"):
        m = re.match(r"LLM\s*0?(10|[1-9])", raw)
        if m:
            return f"LLM{int(m.group(1)):02d}"
    m = re.search(r"\b0?(10|[1-9])\b", raw)
    if m:
        return f"LLM{int(m.group(1)):02d}"
    return raw.split()[0]


def evaluator_for_owasp(owasp_id: object) -> str:
    oid = normalize_owasp_id(owasp_id)
    return DEDICATED_EVALUATORS.get(oid, LEGACY_EVALUATOR)


def has_dedicated_evaluator(owasp_id: object) -> bool:
    return normalize_owasp_id(owasp_id) in DEDICATED_EVALUATORS


def coverage_rows(owasp_ids: Iterable[object]) -> list[dict[str, str]]:
    rows = []
    for oid in sorted({normalize_owasp_id(x) for x in owasp_ids if normalize_owasp_id(x)}):
        evaluator = evaluator_for_owasp(oid)
        rows.append({
            "owasp": oid,
            "evaluator": evaluator,
            "coverage": "dedicated" if evaluator != LEGACY_EVALUATOR else "legacy",
        })
    return rows
