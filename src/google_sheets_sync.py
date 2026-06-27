from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

# Load local .env automatically so Google Sheet settings work after install.bat.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass
REPORTS_DIR = ROOT / "reports"

# Stable top-level report files. Model-specific subfolders are intentionally not
# uploaded by default because they can create dozens of tabs and make the Google
# Sheet hard to review.
DEFAULT_EXPORT_ORDER = [
    # Case-level summaries. These are the formal research tables.
    "summary_by_model.csv",
    "summary_by_prompt_style.csv",
    "summary_by_model_prompt_style.csv",
    "summary_by_attack_level.csv",
    "summary_by_target_hint.csv",
    "summary_by_family_level.csv",
    "summary_by_attack_case.csv",
    "summary_by_attack.csv",
    "rerun_list.csv",
    "experiment_metadata.csv",
    # Case-level and turn-level detail tables.
    "case_results_all.csv",
    "raw_results_all.csv",
    # Quantization outputs, when present.
    "quant_model_summary.csv",
    "quant_pairwise_comparison.csv",
    "human_review_template.csv",
    "experiment_config.json",
    "model_metadata_manifest.json",
]

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]


def safe_worksheet_title(name: str) -> str:
    """Return a Google Sheets worksheet title that is readable and valid."""
    title = re.sub(r"[\\/*?:\[\]]+", "_", name.strip())
    title = re.sub(r"\s+", "_", title)
    title = title.strip("_'") or "sheet"
    return title[:95]


def read_csv_values(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    return [[str(cell) for cell in row] for row in rows] or [[""]]


def _stringify_json_value(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None:
        return ""
    return str(value)


def read_json_values(path: Path) -> list[list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        if not data:
            return [["value"]]
        if all(isinstance(item, dict) for item in data):
            headers: list[str] = []
            for item in data:
                for key in item.keys():
                    if key not in headers:
                        headers.append(key)
            return [headers] + [[_stringify_json_value(item.get(h, "")) for h in headers] for item in data]
        return [["index", "value"]] + [[str(i), _stringify_json_value(v)] for i, v in enumerate(data, start=1)]
    if isinstance(data, dict):
        return [["key", "value"]] + [[str(k), _stringify_json_value(v)] for k, v in data.items()]
    return [["value"], [_stringify_json_value(data)]]


def read_table_values(path: Path) -> list[list[str]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return read_csv_values(path)
    if suffix == ".json":
        return read_json_values(path)
    raise ValueError(f"Unsupported export file type: {path}")


def latest_report_dir(reports_dir: Path = REPORTS_DIR) -> Path:
    if not reports_dir.exists():
        raise FileNotFoundError(f"Reports folder not found: {reports_dir}")
    candidates = []
    for child in reports_dir.iterdir():
        if not child.is_dir():
            continue
        if any((child / name).exists() for name in DEFAULT_EXPORT_ORDER):
            candidates.append(child)
    if not candidates:
        raise FileNotFoundError(f"No report folders with exportable CSV/JSON files found under: {reports_dir}")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def discover_export_files(report_dir: Path, include_raw: bool = True) -> list[Path]:
    report_dir = Path(report_dir)
    if not report_dir.exists():
        raise FileNotFoundError(f"Report folder not found: {report_dir}")
    files: list[Path] = []
    for name in DEFAULT_EXPORT_ORDER:
        if not include_raw and name == "raw_results_all.csv":
            continue
        p = report_dir / name
        if p.exists() and p.is_file():
            files.append(p)
    return files


def _normalize_files(files: Sequence[str | Path] | None, report_dir: Path | None, include_raw: bool) -> list[Path]:
    if files:
        return [Path(p) for p in files]
    selected_dir = Path(report_dir) if report_dir else latest_report_dir()
    return discover_export_files(selected_dir, include_raw=include_raw)


def _worksheet_by_title(spreadsheet, title: str):
    try:
        return spreadsheet.worksheet(title)
    except Exception:
        return None


def _resize_worksheet(worksheet, rows: int, cols: int) -> None:
    worksheet.resize(rows=max(1, rows), cols=max(1, cols))


def _replace_worksheet(spreadsheet, title: str, values: list[list[str]]) -> None:
    rows = max(1, len(values))
    cols = max(1, max((len(row) for row in values), default=1))
    worksheet = _worksheet_by_title(spreadsheet, title)
    if worksheet is None:
        worksheet = spreadsheet.add_worksheet(title=title, rows=rows, cols=cols)
    else:
        worksheet.clear()
        _resize_worksheet(worksheet, rows, cols)
    worksheet.update("A1", values, value_input_option="RAW")
    try:
        worksheet.freeze(rows=1)
    except Exception:
        pass


def _append_worksheet(spreadsheet, title: str, values: list[list[str]]) -> None:
    worksheet = _worksheet_by_title(spreadsheet, title)
    if worksheet is None:
        rows = max(100, len(values) + 10)
        cols = max(1, max((len(row) for row in values), default=1))
        worksheet = spreadsheet.add_worksheet(title=title, rows=rows, cols=cols)
        worksheet.update("A1", values, value_input_option="RAW")
        try:
            worksheet.freeze(rows=1)
        except Exception:
            pass
        return

    existing = worksheet.get_all_values()
    rows_to_append = values
    if existing and values and existing[0] == values[0]:
        rows_to_append = values[1:]
    if rows_to_append:
        worksheet.append_rows(rows_to_append, value_input_option="RAW")


def authorize_gspread(credentials_path: str | Path | None = None):
    """Authorize Google Sheets lazily so normal benchmark runs need no extra dependency."""
    try:
        import gspread  # type: ignore
        from google.oauth2.service_account import Credentials  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on optional packages
        raise RuntimeError(
            "Google Sheets sync requires optional packages. Install them with: "
            "pip install -r requirements-google-sheets.txt"
        ) from exc

    credentials_path = credentials_path or os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GOOGLE_SHEETS_CREDENTIALS")
    if not credentials_path:
        raise ValueError(
            "Missing Google service account credential JSON. Set GOOGLE_APPLICATION_CREDENTIALS "
            "or pass --credentials path\\to\\service-account.json"
        )
    credentials = Credentials.from_service_account_file(str(credentials_path), scopes=GOOGLE_SCOPES)
    return gspread.authorize(credentials)


def sync_report_to_google_sheets(
    spreadsheet_id: str,
    credentials_path: str | Path | None = None,
    report_dir: str | Path | None = None,
    files: Sequence[str | Path] | None = None,
    mode: str = "replace",
    include_raw: bool = True,
    dry_run: bool = False,
) -> list[dict]:
    """Upload top-level report CSV/JSON files to a Google Spreadsheet.

    Returns a small manifest of uploaded files/tabs. In dry-run mode, no network
    call is made and the same manifest is returned for inspection.
    """
    if not spreadsheet_id and not dry_run:
        raise ValueError("Missing spreadsheet_id")
    if mode not in {"replace", "append"}:
        raise ValueError("mode must be 'replace' or 'append'")

    export_files = _normalize_files(files, Path(report_dir) if report_dir else None, include_raw=include_raw)
    manifest: list[dict] = []
    for p in export_files:
        p = Path(p)
        title = safe_worksheet_title(p.stem)
        values = read_table_values(p)
        manifest.append({
            "file": str(p),
            "worksheet": title,
            "rows": len(values),
            "cols": max((len(row) for row in values), default=0),
        })

    if dry_run:
        return manifest

    gc = authorize_gspread(credentials_path)
    spreadsheet = gc.open_by_key(spreadsheet_id)
    for item in manifest:
        values = read_table_values(Path(item["file"]))
        if mode == "replace":
            _replace_worksheet(spreadsheet, item["worksheet"], values)
        else:
            _append_worksheet(spreadsheet, item["worksheet"], values)
    return manifest


def print_manifest(manifest: Iterable[dict]) -> None:
    print("Google Sheets sync manifest:")
    for item in manifest:
        print(f"- {item['worksheet']}: {item['rows']} rows x {item['cols']} cols <- {item['file']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync LLM-Attack-Benchmark report CSV/JSON files to Google Sheets.")
    parser.add_argument("--spreadsheet-id", default=os.getenv("GOOGLE_SHEETS_SPREADSHEET_ID", ""), help="Google Spreadsheet ID. The sheet must be shared with the service account email.")
    parser.add_argument("--credentials", default=os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GOOGLE_SHEETS_CREDENTIALS") or "", help="Path to Google service account JSON credentials.")
    parser.add_argument("--report-dir", default=os.getenv("GOOGLE_SHEETS_REPORT_DIR", ""), help="Report folder to sync. Default: newest reports/* folder with CSV/JSON outputs.")
    parser.add_argument("--files", nargs="*", help="Specific CSV/JSON files to sync. Overrides --report-dir discovery.")
    parser.add_argument("--mode", choices=["replace", "append"], default="replace", help="replace tabs or append rows. Default: replace.")
    parser.add_argument("--no-raw", action="store_true", help="Skip raw_results_all.csv to keep the Google Sheet lightweight.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded without connecting to Google.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        manifest = sync_report_to_google_sheets(
            spreadsheet_id=args.spreadsheet_id,
            credentials_path=args.credentials or None,
            report_dir=args.report_dir or None,
            files=args.files,
            mode=args.mode,
            include_raw=not args.no_raw,
            dry_run=args.dry_run,
        )
        print_manifest(manifest)
        if not args.dry_run:
            print("[OK] Google Sheets sync completed.")
        return 0
    except Exception as exc:
        print(f"[ERROR] GOOGLE_SHEETS_SYNC_FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
