import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_index import load_attacks
from evaluator_registry import coverage_rows, evaluator_for_owasp, has_dedicated_evaluator
from redaction import redact_row
from run_artifacts import build_run_config, mirror_reports, write_json


def args(**overrides):
    base = dict(
        run_mode="formal",
        preset="custom_cli",
        model_source="mock",
        provider="mock",
        model="mock",
        temperature=0,
        top_p=1.0,
        top_k=40,
        num_ctx=4096,
        max_tokens=800,
        seed=42,
        request_timeout=120,
        max_retries=2,
        retry_backoff=2,
        styles="en_pure",
        attack_ids="all",
        attack_levels="all",
        owasp_types="LLM01,LLM02",
        limit_base_attacks=None,
        runs=1,
        raw_output_policy="redacted",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_config_hash_input_ignores_run_name_label():
    attacks = load_attacks(ROOT / "attacks")[:10]
    c1 = build_run_config(args(run_name="run01"), ROOT / "attacks", "run01", attacks)
    c2 = build_run_config(args(run_name="run02"), ROOT / "attacks", "run02", attacks)
    assert c1 == c2
    assert "run01" not in json.dumps(c1)
    assert "run02" not in json.dumps(c2)


def test_redaction_replaces_sensitive_output_but_keeps_hash():
    row = {"response": "SECRET_VALUE", "evidence": "FLAG{abc}", "decoded_value": "decoded", "response_hash": "abc"}
    redacted = redact_row(row, policy="redacted")
    assert redacted["raw_output_policy"] == "redacted"
    assert "SECRET_VALUE" not in redacted["response"]
    assert redacted["response"].startswith("[REDACTED:response")
    assert redacted["evidence"].startswith("[REDACTED:evidence")
    assert redacted["response_hash"] == "abc"


def test_evaluator_registry_marks_dedicated_and_legacy():
    assert has_dedicated_evaluator("LLM01") is True
    assert has_dedicated_evaluator("LLM05") is False
    assert evaluator_for_owasp("LLM02") == "llm02_sensitive_information_disclosure"
    rows = coverage_rows(["LLM01", "LLM05"])
    assert {r["owasp"]: r["coverage"] for r in rows} == {"LLM01": "dedicated", "LLM05": "legacy"}


def test_mirror_reports_writes_human_index_md(tmp_path):
    run_dir = tmp_path / "runs" / "formal" / "run123"
    run_dir.mkdir(parents=True)
    (run_dir / "report.md").write_text("# report", encoding="utf-8")
    (run_dir / "github_issue.md").write_text("# issue", encoding="utf-8")
    write_json(run_dir / "summary.json", {
        "total_cases": 3,
        "valid_cases": 3,
        "invalid_cases": 0,
        "attack_success_count": 1,
        "attack_success_rate": 33.33,
        "safety_score": 66.67,
        "reliability_score": 100,
    })
    manifest = {
        "run_id": "run123",
        "run_mode": "formal",
        "preset": "unit",
        "started_at": "2026-01-01T00:00:00",
        "config_hash": "cfg",
        "run_hash": "run",
        "model": {"model_name": "mock"},
        "selected_scope": {"owasp_types": ["LLM01"]},
    }
    copied = mirror_reports(tmp_path, run_dir, manifest)
    assert copied["index_md"] == "reports/formal/index.md"
    index_md = tmp_path / "reports" / "formal" / "index.md"
    text = index_md.read_text(encoding="utf-8")
    assert "Benchmark Report Index" in text
    assert "run123" in text
    assert "33.33" in text
