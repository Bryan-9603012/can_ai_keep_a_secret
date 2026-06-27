from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return path.as_posix()


def resolve_run_input(value: str) -> tuple[Path, dict, dict]:
    """Accept a run directory, summary.json, or report mirror summary file."""
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if path.is_dir():
        summary_path = path / "summary.json"
        manifest_path = path / "run_manifest.json"
    else:
        summary_path = path
        # Mirror summary filenames are <run_id>_summary.json; manifest may not be present.
        manifest_path = path.parent / path.name.replace("_summary.json", "_run_manifest.json")
    summary = load_json(summary_path, {}) or {}
    manifest = load_json(manifest_path, {}) or {}
    if not summary:
        raise FileNotFoundError(f"Missing or empty summary.json: {summary_path}")
    return summary_path, summary, manifest


def model_name(manifest: dict, summary_path: Path) -> str:
    model = (manifest.get("model") or {}).get("model_name") if manifest else ""
    if model:
        return str(model)
    # Fallback to run id slug in mirror filename.
    return ""


def overall_row(summary_path: Path, summary: dict, manifest: dict) -> dict:
    return {
        "run_id": manifest.get("run_id") or summary_path.stem.replace("_summary", ""),
        "source": rel(summary_path),
        "config_hash": manifest.get("config_hash", ""),
        "run_hash": manifest.get("run_hash", ""),
        "model": model_name(manifest, summary_path),
        "scope": ",".join((manifest.get("selected_scope") or {}).get("owasp_types") or []),
        "level": "ALL",
        "owasp": "OVERALL",
        "total": summary.get("total_cases", 0),
        "valid": summary.get("valid_cases", 0),
        "invalid": summary.get("invalid_cases", 0),
        "unsafe": summary.get("attack_success_count", 0),
        "asr": summary.get("attack_success_rate", 0),
        "safety": summary.get("safety_score", 0),
        "reliability": summary.get("reliability_score", 0),
    }


def by_owasp_rows(summary_path: Path, summary: dict, manifest: dict) -> list[dict]:
    base = overall_row(summary_path, summary, manifest)
    rows = []
    for item in summary.get("by_owasp") or summary.get("owasp_breakdown") or []:
        rows.append({
            **base,
            "owasp": item.get("owasp", ""),
            "level": "ALL",
            "total": item.get("total", 0),
            "valid": item.get("valid", 0),
            "invalid": item.get("invalid", 0),
            "unsafe": item.get("unsafe", 0),
            "asr": item.get("attack_success_rate", 0),
            "safety": item.get("safety_score", 0),
            "reliability": item.get("reliability_score", 0),
        })
    return rows


def by_owasp_level_rows(summary_path: Path, summary: dict, manifest: dict) -> list[dict]:
    base = overall_row(summary_path, summary, manifest)
    rows = []
    for item in summary.get("by_owasp_level") or []:
        rows.append({
            **base,
            "owasp": item.get("owasp", ""),
            "level": item.get("level", ""),
            "total": item.get("total", 0),
            "valid": item.get("valid", 0),
            "invalid": item.get("invalid", 0),
            "unsafe": item.get("unsafe", 0),
            "asr": item.get("attack_success_rate", 0),
            "safety": item.get("safety_score", 0),
            "reliability": item.get("reliability_score", 0),
        })
    return rows



def by_asset_type_rows(summary_path: Path, summary: dict, manifest: dict) -> list[dict]:
    base = overall_row(summary_path, summary, manifest)
    rows = []
    for item in summary.get("by_asset_type") or []:
        rows.append({
            **base,
            "owasp": "ALL",
            "level": "ALL",
            "asset_type": item.get("asset_type", ""),
            "total": item.get("total", 0),
            "valid": item.get("valid", 0),
            "invalid": item.get("invalid", 0),
            "unsafe": item.get("unsafe", 0),
            "asr": item.get("attack_success_rate", 0),
            "safety": item.get("safety_score", 0),
            "reliability": item.get("reliability_score", 0),
        })
    return rows


def by_owasp_asset_type_rows(summary_path: Path, summary: dict, manifest: dict) -> list[dict]:
    base = overall_row(summary_path, summary, manifest)
    rows = []
    for item in summary.get("by_owasp_asset_type") or []:
        rows.append({
            **base,
            "owasp": item.get("owasp", ""),
            "level": "ALL",
            "asset_type": item.get("asset_type", ""),
            "total": item.get("total", 0),
            "valid": item.get("valid", 0),
            "invalid": item.get("invalid", 0),
            "unsafe": item.get("unsafe", 0),
            "asr": item.get("attack_success_rate", 0),
            "safety": item.get("safety_score", 0),
            "reliability": item.get("reliability_score", 0),
        })
    return rows

def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def md_table(rows: list[dict], columns: list[tuple[str, str]]) -> list[str]:
    lines = ["| " + " | ".join(h for h, _ in columns) + " |", "|" + "|".join("---" if i == 0 else "---:" for i, _ in enumerate(columns)) + "|"]
    if not rows:
        lines.append("| none |" + " - |" * (len(columns) - 1))
        return lines
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(k, "")).replace("|", "\\|") for _, k in columns) + " |")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare benchmark run summaries.")
    parser.add_argument("inputs", nargs="+", help="Run directories or summary.json files.")
    parser.add_argument("--output-dir", default="", help="Output directory. Defaults to reports/comparisons/<timestamp>.")
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir) if args.output_dir else ROOT / "reports" / "comparisons" / f"comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    loaded = [resolve_run_input(x) for x in args.inputs]
    overall = [overall_row(*item) for item in loaded]
    by_owasp = []
    by_owasp_level = []
    by_asset_type = []
    by_owasp_asset_type = []
    for item in loaded:
        by_owasp.extend(by_owasp_rows(*item))
        by_owasp_level.extend(by_owasp_level_rows(*item))
        by_asset_type.extend(by_asset_type_rows(*item))
        by_owasp_asset_type.extend(by_owasp_asset_type_rows(*item))

    write_csv(out_dir / "comparison_overall.csv", overall)
    write_csv(out_dir / "comparison_by_owasp.csv", by_owasp)
    write_csv(out_dir / "comparison_by_owasp_level.csv", by_owasp_level)
    write_csv(out_dir / "comparison_by_asset_type.csv", by_asset_type)
    write_csv(out_dir / "comparison_by_owasp_asset_type.csv", by_owasp_asset_type)

    lines = [
        "# Benchmark Run Comparison",
        "",
        f"Generated at: `{datetime.now().isoformat(timespec='seconds')}`",
        "",
        "## Overall",
        "",
        *md_table(overall, [
            ("Run ID", "run_id"),
            ("Model", "model"),
            ("Config Hash", "config_hash"),
            ("Cases", "total"),
            ("Valid", "valid"),
            ("Invalid", "invalid"),
            ("Unsafe", "unsafe"),
            ("ASR", "asr"),
            ("Safety", "safety"),
            ("Reliability", "reliability"),
        ]),
        "",
        "## By OWASP",
        "",
        *md_table(by_owasp, [
            ("Run ID", "run_id"),
            ("OWASP", "owasp"),
            ("Cases", "total"),
            ("Valid", "valid"),
            ("Invalid", "invalid"),
            ("Unsafe", "unsafe"),
            ("ASR", "asr"),
            ("Safety", "safety"),
            ("Reliability", "reliability"),
        ]),
        "",
        "## By Sensitive Asset Type",
        "",
        *md_table(by_asset_type, [
            ("Run ID", "run_id"),
            ("Asset Type", "asset_type"),
            ("Cases", "total"),
            ("Valid", "valid"),
            ("Invalid", "invalid"),
            ("Unsafe", "unsafe"),
            ("ASR", "asr"),
            ("Safety", "safety"),
            ("Reliability", "reliability"),
        ]),
        "",
        "## Notes",
        "",
        "- Same experimental settings should share the same `config_hash`; different executions should have different `run_hash` values.",
        "- Use `comparison_by_owasp_level.csv` and `comparison_by_asset_type.csv` for heatmaps or deeper analysis.",
    ]
    (out_dir / "comparison_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[OK] Comparison written to: {rel(out_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
