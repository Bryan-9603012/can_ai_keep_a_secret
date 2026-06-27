from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from google_sheets_sync import (  # noqa: E402
    discover_export_files,
    read_csv_values,
    read_json_values,
    safe_worksheet_title,
    sync_report_to_google_sheets,
)


def test_safe_worksheet_title_removes_google_sheet_forbidden_chars() -> None:
    assert safe_worksheet_title("raw/results:[all]*?") == "raw_results_all"


def test_read_csv_values_handles_utf8_sig(tmp_path: Path) -> None:
    p = tmp_path / "summary_by_model.csv"
    p.write_text("\ufeffmodel,avg_score\nmock,100\n", encoding="utf-8")
    assert read_csv_values(p) == [["model", "avg_score"], ["mock", "100"]]


def test_read_json_values_flattens_dict(tmp_path: Path) -> None:
    p = tmp_path / "experiment_config.json"
    p.write_text(json.dumps({"runs": 1, "models": ["mock"]}, ensure_ascii=False), encoding="utf-8")
    values = read_json_values(p)
    assert values[0] == ["key", "value"]
    assert ["runs", "1"] in values
    assert ["models", '["mock"]'] in values


def test_discover_export_files_uses_stable_order_and_can_skip_raw(tmp_path: Path) -> None:
    for name in ["raw_results_all.csv", "summary_by_attack.csv", "summary_by_model.csv"]:
        (tmp_path / name).write_text("a\n1\n", encoding="utf-8")
    files = [p.name for p in discover_export_files(tmp_path, include_raw=False)]
    assert files == ["summary_by_model.csv", "summary_by_attack.csv"]


def test_sync_dry_run_builds_manifest_without_google_dependency(tmp_path: Path) -> None:
    p = tmp_path / "summary_by_model.csv"
    p.write_text("model,avg_score\nmock,100\n", encoding="utf-8")
    manifest = sync_report_to_google_sheets(
        spreadsheet_id="",
        files=[p],
        dry_run=True,
    )
    assert manifest == [{"file": str(p), "worksheet": "summary_by_model", "rows": 2, "cols": 2}]
