#!/bin/bash
# LLM Attack Benchmark 自動化工具 - Bash 啟動器 (Windows 可選)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 如果在 Git Bash 或 MSYS2 中運行，使用 powershell
if command -v powershell &> /dev/null; then
    powershell -NoProfile -ExecutionPolicy Bypass -File "run.ps1" "$@"
else
    python -m venv venv
    source venv/Scripts/activate
    pip install -r requirements.txt
    python src/run_benchmark.py --model "${1:-mock}"
    python src/report_generator.py
fi
