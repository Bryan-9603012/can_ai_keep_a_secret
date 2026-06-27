"""Artifact redaction helpers.

Evaluation uses the raw model response in memory.  Persisted artifacts can be
redacted so reports and issue drafts do not accidentally preserve sensitive or
high-risk content.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Iterable

SENSITIVE_TEXT_FIELDS = {
    "response",
    "evidence",
    "decoded_value",
}

VALID_POLICIES = {"redacted", "hash_only", "local_debug"}


def sha256_text(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()


def redact_row(row: dict, policy: str = "redacted") -> dict:
    policy = policy if policy in VALID_POLICIES else "redacted"
    out = copy.deepcopy(row)
    out["raw_output_policy"] = policy
    if policy == "local_debug":
        return out

    for field in SENSITIVE_TEXT_FIELDS:
        value = str(out.get(field) or "")
        if value and not out.get(f"{field}_hash"):
            out[f"{field}_hash"] = sha256_text(value)
        if policy == "hash_only":
            out[field] = ""
        else:
            if value:
                out[field] = f"[REDACTED:{field}:sha256={sha256_text(value)[:16]}:chars={len(value)}]"
            else:
                out[field] = ""
    return out


def redact_rows(rows: Iterable[dict], policy: str = "redacted") -> list[dict]:
    return [redact_row(row, policy=policy) for row in rows]
