"""Incremental run checkpoint helpers."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable


def append_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except json.JSONDecodeError:
                out.append({"status": "ERROR", "error_type": "CORRUPT_JSONL_LINE", "raw_line": line})
    return out


def attack_key(run_no: int, attack: dict) -> str:
    return f"run_{run_no:03d}::{attack.get('id', '')}"


def completed_attack_keys(rows: Iterable[dict]) -> set[str]:
    keys: set[str] = set()
    for row in rows:
        run_id = str(row.get("run_id", ""))
        attack_id = str(row.get("attack_id", ""))
        if run_id and attack_id and attack_id != "__INTERRUPTED__":
            keys.add(f"{run_id}::{attack_id}")
    return keys


def write_state(run_dir: Path, *, status: str, total_attacks: int, completed_attacks: int, extra: dict | None = None) -> None:
    payload = {
        "status": status,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "total_attacks": total_attacks,
        "completed_attacks": completed_attacks,
        "progress_percent": round(completed_attacks / total_attacks * 100, 2) if total_attacks else 0.0,
    }
    if extra:
        payload.update(extra)
    (run_dir / "run_state.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
