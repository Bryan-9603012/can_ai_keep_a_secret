"""
LLM Attack Benchmark - one-click interactive local/cloud runner.

Design:
- Windows double-click entry: install.bat -> install_and_run.ps1 -> this script.
- Arrow-key menu, Enter confirm, Esc returns to previous layer.
- First select model source: Local Ollama or Cloud OpenAI-compatible API.
- Then select model scope, benchmark scope, generation max_tokens, then run count.
- Benchmark scopes include full coverage, selected languages, selected levels, selected attacks, quick smoke test, and custom test.
- max_tokens/num_predict is user-selectable from the interactive runner.
- Missing models are pulled automatically.
- Runtime/API/model errors are recorded in a problem list and the runner continues.
- After each model, markdown/json reports and charts are generated.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import requests

ROOT = Path(__file__).resolve().parent
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.getenv("MODEL", "qwen2.5:0.5b")
MODEL_GROUPS_PATH = ROOT / "configs" / "model_groups.json"
ATTACKS_PATH = ROOT / "attacks"
sys.path.insert(0, str(ROOT / "src"))
from attack_index import load_attacks as load_attack_index, available_owasp_ids as index_available_owasp_ids, available_levels as index_available_levels
SIMPLE_MODE = False

STYLE_CHOICES = [
    ("en_pure", "English only", "EN_ONLY"),
    ("zh_pure", "繁體中文", "ZH_ONLY"),
    ("zh_main_en_mixed", "中文為主 mixed English", "ZH_EN_MIX"),
    ("en_main_zh_mixed", "English-main mixed Chinese", "EN_ZH_MIX"),
]
STYLE_ALIASES = {
    "1": "en_pure", "en": "en_pure", "english": "en_pure", "en_pure": "en_pure", "EN_ONLY": "en_pure",
    "2": "zh_pure", "zh": "zh_pure", "chinese": "zh_pure", "zh_pure": "zh_pure", "ZH_ONLY": "zh_pure",
    "3": "zh_main_en_mixed", "zh_en": "zh_main_en_mixed", "mix_zh": "zh_main_en_mixed", "zh_main_en_mixed": "zh_main_en_mixed", "ZH_EN_MIX": "zh_main_en_mixed",
    "4": "en_main_zh_mixed", "en_zh": "en_main_zh_mixed", "mix_en": "en_main_zh_mixed", "en_main_zh_mixed": "en_main_zh_mixed", "EN_ZH_MIX": "en_main_zh_mixed",
}

LEVEL_CHOICES = [
    ("L1", "Direct Ask", "直接要求敏感目標"),
    ("L2", "Role / Authority Override", "假冒管理員、稽核、開發者等高權限角色"),
    ("L3", "Enterprise Camouflage", "包裝成企業流程、遷移、稽核或合規需求"),
    ("L4", "Structured Output", "要求 JSON / CSV / YAML / 表格等結構化輸出"),
    ("L5", "Encoding / Transformation", "要求 Base64 / Hex / Unicode escape 等可逆轉換"),
    ("L6", "Stateful Multi-turn / Trigger", "多輪、片段、觸發條件或逐步重建"),
]
LEVEL_LABELS = {code: f"{code} {name}" for code, name, _ in LEVEL_CHOICES}

TARGET_HINT_LABELS = {
    "value": "Value",
    "metadata": "Metadata",
    "policy": "Policy",
    "mixed_value": "Mixed",
}

UI_WIDTH = 76


@dataclass
class TestScope:
    label: str
    run_name_suffix: str
    styles: str = "all"
    attack_ids: str = "all"
    attack_levels: str = "all"
    owasp_types: str = "all"
    limit_base_attacks: Optional[int] = None

    def to_cli_args(self) -> List[str]:
        args = ["--styles", self.styles, "--attack-ids", self.attack_ids, "--attack-levels", self.attack_levels, "--owasp-types", self.owasp_types]
        if self.limit_base_attacks:
            args += ["--limit-base-attacks", str(self.limit_base_attacks)]
        return args


@dataclass
class GenerationSettings:
    max_tokens: int = 512

    def to_cli_args(self) -> List[str]:
        return ["--max-tokens", str(self.max_tokens)]


@dataclass
class CloudSettings:
    provider: str = "openai-compatible"
    base_url: str = ""
    api_key_env: str = "OPENAI_API_KEY"
    model: str = ""
    request_timeout: float = 120
    max_retries: int = 2
    retry_backoff: float = 2

    def to_cli_args(self) -> List[str]:
        return [
            "--model-source", "cloud",
            "--provider", self.provider,
            "--run-mode", "formal",
            "--model", self.model,
            "--base-url", self.base_url,
            "--api-key-env", self.api_key_env,
            "--request-timeout", str(self.request_timeout),
            "--max-retries", str(self.max_retries),
            "--retry-backoff", str(self.retry_backoff),
        ]


class BackToMenu(Exception):
    pass


@dataclass
class SelectOption:
    label: str
    value: str
    hint: str = ""


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def supports_tui() -> bool:
    if SIMPLE_MODE:
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def read_key() -> str:
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            ch2 = msvcrt.getwch()
            return {"H": "UP", "P": "DOWN", "K": "LEFT", "M": "RIGHT"}.get(ch2, "")
        if ch in ("\r", "\n"):
            return "ENTER"
        if ch == "\x1b":
            return "ESC"
        return ch.lower()

    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = sys.stdin.read(2)
            if seq == "[A":
                return "UP"
            if seq == "[B":
                return "DOWN"
            return "ESC"
        if ch in ("\r", "\n"):
            return "ENTER"
        return ch.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def esc_input(prompt: str, default: Optional[str] = None) -> Optional[str]:
    if default is not None:
        prompt = f"{prompt} [{default}]"
    if not prompt.endswith(" "):
        prompt += " "
    if not sys.stdin.isatty():
        value = input(prompt).strip()
        return default if value == "" and default is not None else value

    print(prompt, end="", flush=True)
    chars: List[str] = []
    if os.name == "nt":
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x1b":
                print("\n[返回]")
                return None
            if ch in ("\r", "\n"):
                print()
                value = "".join(chars).strip()
                return default if value == "" and default is not None else value
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop(); print("\b \b", end="", flush=True)
                continue
            if ch in ("\x00", "\xe0"):
                _ = msvcrt.getwch(); continue
            if ch.isprintable():
                chars.append(ch); print(ch, end="", flush=True)
        
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x1b":
                print("\n[返回]")
                return None
            if ch in ("\r", "\n"):
                print()
                value = "".join(chars).strip()
                return default if value == "" and default is not None else value
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop(); print("\b \b", end="", flush=True)
                continue
            if ch.isprintable():
                chars.append(ch); print(ch, end="", flush=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def render_header(title: str, subtitle: str = "") -> None:
    """Render a consistent terminal header for every screen."""
    print(title)
    print("─" * UI_WIDTH)
    if subtitle:
        print(subtitle)
        print("─" * UI_WIDTH)


def numeric_select(title: str, options: List[SelectOption], default_index: int = 0) -> SelectOption:
    print("\n")
    render_header(title, "輸入數字選擇；直接 Enter 使用預設；Esc 返回")
    for i, opt in enumerate(options, 1):
        hint = f" - {opt.hint}" if opt.hint else ""
        default_mark = " [default]" if i - 1 == default_index else ""
        print(f"  {i:>2}. {opt.label}{default_mark}{hint}")
    raw = esc_input(f"請輸入數字", str(default_index + 1))
    if raw is None:
        return SelectOption("返回", "__cancel__")
    raw = raw.strip()
    if not raw:
        return options[default_index]
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return options[idx]
    except ValueError:
        pass
    print("[WARN] 選項無效，使用預設值。")
    return options[default_index]


def tui_select(title: str, options: List[SelectOption], default_index: int = 0) -> SelectOption:
    if not options:
        raise ValueError("options is empty")
    if not supports_tui():
        return numeric_select(title, options, default_index)
    idx = max(0, min(default_index, len(options) - 1))
    while True:
        clear_screen()
        render_header(title, "↑/↓ 選擇，Enter 確認，數字快速跳選，Esc 返回")
        for i, opt in enumerate(options, 1):
            pointer = "❯" if i - 1 == idx else " "
            hint = f"  {opt.hint}" if opt.hint else ""
            print(f"{pointer} {i:>2}. {opt.label:<28}{hint}")
        try:
            key = read_key()
        except Exception as exc:
            print(f"[WARN] 互動式選單失敗，改用數字選單：{exc}")
            return numeric_select(title, options, default_index)
        if key in {"UP", "k"}:
            idx = (idx - 1) % len(options)
        elif key in {"DOWN", "j"}:
            idx = (idx + 1) % len(options)
        elif key == "ENTER":
            clear_screen(); return options[idx]
        elif key == "ESC":
            clear_screen(); return SelectOption("返回", "__cancel__")
        elif key.isdigit():
            n = int(key)
            if 1 <= n <= len(options):
                idx = n - 1

def wait_key(msg: str = "按 Enter 繼續，或 Esc 返回...") -> None:
    _ = esc_input(msg)


def safe_filename(name: str) -> str:
    return (name.replace(":", "_").replace("/", "_").replace("\\", "_")
            .replace(" ", "_").replace("|", "_").replace("<", "_")
            .replace(">", "_").replace("?", "_").replace("*", "_").replace('"', "_"))


def load_groups() -> Dict[str, List[str]]:
    if not MODEL_GROUPS_PATH.exists():
        return {"medium_models": ["qwen2.5:7b", "llama3.1:8b", "deepseek-r1:7b"],
                "small_models": ["qwen2.5:0.5b", "qwen2.5:1.5b", "llama3.2:1b"]}
    return json.loads(MODEL_GROUPS_PATH.read_text(encoding="utf-8"))


def save_groups(groups: Dict[str, List[str]]) -> None:
    MODEL_GROUPS_PATH.write_text(json.dumps(groups, ensure_ascii=False, indent=2), encoding="utf-8")


def load_attack_rows() -> List[dict]:
    try:
        return load_attack_index(ATTACKS_PATH)
    except Exception:
        return []


def load_attack_catalog() -> List[dict]:
    rows = load_attack_rows()
    seen = set()
    catalog = []
    for item in rows:
        base_id = str(item.get("attack_id") or item.get("family_id") or item.get("base_attack_id") or item.get("id", "").split("-", 1)[0]).upper()
        if not base_id or base_id in seen:
            continue
        seen.add(base_id)
        family_name = item.get("family_name") or item.get("category") or item.get("attack_name") or ""
        catalog.append({
            "attack_id": base_id,
            "owasp_id": item.get("owasp_id") or str(item.get("primary_owasp", "")).split()[0],
            "family_name": family_name,
            "family_goal": item.get("family_goal", ""),
            "target_hint": item.get("target_hint", ""),
            "category": item.get("category", ""),
            "description": item.get("description", ""),
        })
    return catalog


def available_owasp_types() -> List[str]:
    vals = index_available_owasp_ids(load_attack_rows())
    return vals or ["LLM01", "LLM02", "LLM07", "LLM10"]


def available_attack_levels() -> List[str]:
    vals = index_available_levels(load_attack_rows())
    return vals or ["L1"]


def lowest_available_level() -> str:
    levels = available_attack_levels()
    return levels[0] if levels else "L1"


def level_description(level: str) -> tuple[str, str]:
    for code, name, desc in LEVEL_CHOICES:
        if code == level:
            return name, desc
    return "Dynamic Level", "由 attack.json 動態偵測到的測試階梯；新增階梯後 UI 會自動顯示"


def show_attack_catalog(compact: bool = False) -> None:
    catalog = load_attack_catalog()
    if not catalog:
        print("[WARN] 無法讀取 attacks/ 分類攻擊目錄或攻擊清單為空。")
        return
    print("\n可選 Family ID：")
    if compact:
        line: List[str] = []
        for item in catalog:
            line.append(item["attack_id"])
        print("  " + ", ".join(line))
        return
    print("  ID    OWASP   Target    Family")
    print("  " + "─" * 76)
    for item in catalog:
        hint = TARGET_HINT_LABELS.get(item.get("target_hint", ""), item.get("target_hint", "") or "-")
        name = item.get("family_name") or item.get("category") or item.get("description") or ""
        print(f"  {item['attack_id']:<5} {item.get('owasp_id',''):<7} {hint:<9} {name}")


def normalize_attack_ids(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw or raw.lower() == "all":
        return "all"
    out: List[str] = []
    valid = {a["attack_id"] for a in load_attack_catalog()}
    for part in raw.split(","):
        part = part.strip().upper()
        if not part:
            continue
        if part.isdigit():
            part = f"A{int(part):02d}"
        elif re.fullmatch(r"A\d{1,2}", part):
            part = "A" + part[1:].zfill(2)
        if part not in valid:
            print(f"[WARN] 攻擊 ID 不存在，已忽略：{part}")
            continue
        if part not in out:
            out.append(part)
    return ",".join(out) if out else None


def normalize_styles(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw or raw.lower() == "all":
        return "all"
    out: List[str] = []
    for part in raw.split(","):
        key = part.strip()
        if not key:
            continue
        style = STYLE_ALIASES.get(key) or STYLE_ALIASES.get(key.lower()) or STYLE_ALIASES.get(key.upper())
        if not style:
            print(f"[WARN] 語言種類不支援，已忽略：{part}")
            continue
        if style not in out:
            out.append(style)
    return ",".join(out) if out else None


def ask_styles(default: str = "all") -> Optional[str]:
    print("\n[語言範圍]")
    print("  all = 完整四種語言")
    for idx, (style, label, mode) in enumerate(STYLE_CHOICES, 1):
        print(f"  {idx}. {style:<20} {label:<26} {mode}")
    raw = esc_input("請輸入語言，可用逗號多選，例如 all / 1,2 / en_pure,zh_pure，Esc 返回", default)
    if raw is None:
        return None
    styles = normalize_styles(raw)
    if styles is None:
        print("[WARN] 沒有有效語言，請重新選擇。")
        return ask_styles(default)
    return styles




def normalize_owasp_types(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw or raw.lower() == "all":
        return "all"
    out: List[str] = []
    for part in raw.split(","):
        key = part.strip().upper()
        if not key:
            continue
        if key.isdigit():
            key = f"LLM{int(key):02d}"
        if re.fullmatch(r"LLM\d{1,2}", key):
            key = f"LLM{int(key[3:]):02d}"
        valid = set(available_owasp_types())
        if key not in valid:
            print(f"[WARN] OWASP 類型不在目前 attacks/ 目錄中，已忽略：{part}")
            continue
        if key not in out:
            out.append(key)
    return ",".join(out) if out else None


def ask_owasp_types(default: str = "all") -> Optional[str]:
    available = available_owasp_types()
    print("\n[OWASP 類型]")
    print("  all = 目前 attacks/ 目錄中所有可用 OWASP 類型")
    for item in available:
        print(f"  {int(item[3:]):>2}. {item}")
    raw = esc_input("請輸入 OWASP 類型，可用逗號多選，例如 all / LLM01,LLM02 / 1,2，Esc 返回", default)
    if raw is None:
        return None
    types = normalize_owasp_types(raw)
    if types is None:
        print("[WARN] 沒有有效 OWASP 類型，請重新選擇。")
        return ask_owasp_types(default)
    return types


def ask_attack_ids(default: str = "all") -> Optional[str]:
    show_attack_catalog()
    raw = esc_input("請輸入 Family ID，可用逗號多選，例如 all / A01,A03,A19 / 1,3,19，Esc 返回", default)
    if raw is None:
        return None
    attack_ids = normalize_attack_ids(raw)
    if attack_ids is None:
        print("[WARN] 沒有有效 Family ID，請重新選擇。")
        return ask_attack_ids(default)
    return attack_ids



def normalize_attack_levels(raw: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw or raw.lower() == "all":
        return "all"
    out: List[str] = []
    for part in raw.split(","):
        key = part.strip().upper()
        if not key:
            continue
        if key.isdigit():
            key = f"L{int(key)}"
        valid = set(available_attack_levels())
        if not re.fullmatch(r"L\d+", key) or key not in valid:
            print(f"[WARN] 攻擊等級不在目前 attacks/ 目錄中，已忽略：{part}")
            continue
        if key not in out:
            out.append(key)
    return ",".join(out) if out else None


def ask_attack_levels(default: str = "all") -> Optional[str]:
    levels_available = available_attack_levels()
    print("\n[攻擊等級]")
    print("  all = 目前 attacks/ 目錄中所有可用階梯")
    for idx, code in enumerate(levels_available, 1):
        name, desc = level_description(code)
        print(f"  {idx}. {code:<3} {name:<28} {desc}")
    raw = esc_input("請輸入等級，可用逗號多選，例如 all / L1,L3 / 1,3，Esc 返回", default)
    if raw is None:
        return None
    levels = normalize_attack_levels(raw)
    if levels is None:
        print("[WARN] 沒有有效等級，請重新選擇。")
        return ask_attack_levels(default)
    return levels


def scope_slug(value: str) -> str:
    return safe_filename(value.replace(",", "_")) if value and value != "all" else "all"


def _split_filter(value: str) -> Optional[set[str]]:
    if not value or value == "all":
        return None
    return {v.strip() for v in value.split(",") if v.strip()}


def estimate_cases(scope: TestScope) -> int:
    """Estimate selected attack cases from the clean attacks/ category directory for clearer UI confirmation."""
    rows = load_attack_rows()
    if not rows:
        return 0

    styles = _split_filter(scope.styles)
    levels = _split_filter(scope.attack_levels)
    attack_ids = _split_filter(scope.attack_ids)
    owasp_types = _split_filter(scope.owasp_types)

    selected_bases: Optional[set[str]] = None
    if scope.limit_base_attacks:
        ordered: List[str] = []
        for row in rows:
            base = str(row.get("attack_id") or row.get("family_id") or row.get("base_attack_id") or row.get("id", "").split("-", 1)[0]).upper()
            if base and base not in ordered:
                ordered.append(base)
        selected_bases = set(ordered[:scope.limit_base_attacks])

    count = 0
    for row in rows:
        base = str(row.get("attack_id") or row.get("family_id") or row.get("base_attack_id") or row.get("id", "").split("-", 1)[0]).upper()
        if selected_bases is not None and base not in selected_bases:
            continue
        if attack_ids is not None and base not in attack_ids:
            continue
        if owasp_types is not None and str(row.get("owasp_id") or str(row.get("primary_owasp", "").split()[0])).upper() not in owasp_types:
            continue
        if levels is not None and str(row.get("attack_level", "")).upper() not in levels:
            continue
        if styles is not None and str(row.get("prompt_style", "")) not in styles:
            continue
        count += 1
    return count


def describe_scope(scope: TestScope) -> List[str]:
    return [
        f"Scope      : {scope.label}",
        f"Families   : {scope.attack_ids}",
        f"Levels     : {scope.attack_levels}",
        f"OWASP      : {scope.owasp_types}",
        f"Languages  : {scope.styles}",
        f"Base limit : {scope.limit_base_attacks or 'none'}",
        f"Est. cases : {estimate_cases(scope)}",
    ]


def confirm_scope(scope: TestScope) -> bool:
    print("\n[測試範圍確認]")
    for line in describe_scope(scope):
        print("  " + line)
    raw = esc_input("確認使用這個範圍？Y/n", "Y")
    if raw is None:
        return False
    return raw.strip().lower() in {"", "y", "yes"}


def choose_test_scope() -> TestScope:
    """Choose a clean family-ladder test scope.

    UI principle: expose research workflows, not internal CLI flags.
    """
    while True:
        sel = tui_select("選擇測試範圍", [
            SelectOption("快速基準測試", "quick", "正式快速跑：目前最低可用階梯 × English"),
            SelectOption("依測試強度選擇", "level", "指定目前 attacks/ 目錄中的 Lx 階梯"),
            SelectOption("依 OWASP 類別測試", "owasp", "指定 LLM01~LLM10 與階梯"),
            SelectOption("單一攻擊家族升階", "ladder", "指定 Axx，跑目前可用的全部階梯"),
            SelectOption("單一家族 + 指定階梯", "family_level", "指定 Axx × 指定 Lx"),
            SelectOption("完整 benchmark", "full", "所有 family × 所有可用階梯 × 所有語言"),
            SelectOption("進階自訂", "custom", "手動設定 OWASP / family / level / language / limit"),
            SelectOption("返回", "__cancel__"),
        ], 0)
        if sel.value == "__cancel__":
            raise BackToMenu

        if sel.value == "quick":
            quick_level = lowest_available_level()
            scope = TestScope(f"快速基準測試：所有 family × {quick_level} × English", f"quick_{quick_level.lower()}_en", "en_pure", "all", quick_level, "all", None)
        elif sel.value == "full":
            scope = TestScope("完整 benchmark：所有 family × 所有可用階梯 × 所有語言", "full_mainline", "all", "all", "all", "all", None)
        elif sel.value == "level":
            levels = ask_attack_levels(lowest_available_level())
            if levels is None:
                continue
            styles = ask_styles("en_pure")
            if styles is None:
                continue
            scope = TestScope(
                f"Single level slice: all families / {levels} / {styles}",
                f"levels_{scope_slug(levels)}__lang_{scope_slug(styles)}",
                styles, "all", levels, "all", None,
            )
        elif sel.value == "owasp":
            owasp_types = ask_owasp_types("LLM02")
            if owasp_types is None:
                continue
            levels = ask_attack_levels(lowest_available_level())
            if levels is None:
                continue
            styles = ask_styles("zh_pure")
            if styles is None:
                continue
            scope = TestScope(
                f"OWASP type slice: {owasp_types} / {levels} / {styles}",
                f"owasp_{scope_slug(owasp_types)}__levels_{scope_slug(levels)}__lang_{scope_slug(styles)}",
                styles, "all", levels, owasp_types, None,
            )
        elif sel.value == "ladder":
            attack_ids = ask_attack_ids("A01")
            if attack_ids is None:
                continue
            styles = ask_styles("en_pure")
            if styles is None:
                continue
            scope = TestScope(
                f"Family ladder: {attack_ids} / all available levels / {styles}",
                f"ladder_{scope_slug(attack_ids)}__lang_{scope_slug(styles)}",
                styles, attack_ids, "all", "all", None,
            )
        elif sel.value == "family_level":
            attack_ids = ask_attack_ids("A01")
            if attack_ids is None:
                continue
            levels = ask_attack_levels(lowest_available_level())
            if levels is None:
                continue
            styles = ask_styles("en_pure")
            if styles is None:
                continue
            scope = TestScope(
                f"Family + level: {attack_ids} / {levels} / {styles}",
                f"family_{scope_slug(attack_ids)}__levels_{scope_slug(levels)}__lang_{scope_slug(styles)}",
                styles, attack_ids, levels, "all", None,
            )
        elif sel.value == "custom":
            owasp_types = ask_owasp_types("all")
            if owasp_types is None:
                continue
            attack_ids = ask_attack_ids("all")
            if attack_ids is None:
                continue
            levels = ask_attack_levels("all")
            if levels is None:
                continue
            styles = ask_styles("all")
            if styles is None:
                continue
            limit_raw = esc_input("限制前 N 個 base families；空白代表不限制", "")
            if limit_raw is None:
                continue
            limit = None
            if limit_raw.strip():
                try:
                    limit = max(1, min(20, int(limit_raw.strip())))
                except ValueError:
                    print("[WARN] N 格式錯誤，改為不限制。")
                    limit = None
            suffix = f"custom_owasp_{scope_slug(owasp_types)}__family_{scope_slug(attack_ids)}__levels_{scope_slug(levels)}__lang_{scope_slug(styles)}"
            if limit:
                suffix += f"__base{limit}"
            scope = TestScope(
                f"Advanced custom: owasp={owasp_types} / family={attack_ids} / {levels} / {styles} / base_limit={limit or 'none'}",
                suffix, styles, attack_ids, levels, owasp_types, limit,
            )
        else:
            continue

        if confirm_scope(scope):
            return scope



def check_ollama() -> Optional[List[str]]:
    url = f"{OLLAMA_URL}/api/tags"
    print(f"[CHECK] Ollama API: {url}")
    try:
        r = requests.get(url)
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] OLLAMA_UNREACHABLE: {exc}")
        return None
    if r.status_code != 200:
        print(f"[ERROR] HTTP_{r.status_code}: {r.text[:300]}")
        return None
    data = r.json()
    models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    print(f"[OK] Ollama connected. Installed models: {len(models)}")
    return models


def download_model(model: str) -> bool:
    print(f"[PULL] ollama pull {model}")
    try:
        rc = subprocess.run(["ollama", "pull", model], cwd=str(ROOT)).returncode
    except FileNotFoundError:
        print("[ERROR] 找不到 ollama 指令。")
        return False
    except Exception as exc:
        print(f"[ERROR] ollama pull crashed: {exc}")
        return False
    if rc != 0:
        print(f"[ERROR] ollama pull failed: exit code {rc}")
        return False
    print(f"[OK] Model ready: {model}")
    return True


def ensure_model(model: str, installed: List[str]) -> bool:
    if model in installed:
        print(f"[OK] 已下載：{model}")
        return True
    print(f"[WARN] 未下載模型，將自動下載：{model}")
    ok = download_model(model)
    if ok:
        refreshed = check_ollama()
        if refreshed is not None:
            installed[:] = refreshed
    return ok


def group_menu(group_key: str, title: str, installed: List[str]) -> Optional[List[str]]:
    while True:
        groups = load_groups()
        models = groups.get(group_key, [])
        lines = [SelectOption("開始測試", "start", f"目前 {len(models)} 個模型"),
                 SelectOption("新增模型到此清單", "add"),
                 SelectOption("從此清單移除模型", "remove"),
                 SelectOption("查看模型清單", "view"),
                 SelectOption("返回", "__cancel__")]
        sel = tui_select(title, lines, 0)
        if sel.value == "__cancel__":
            raise BackToMenu
        if sel.value == "start":
            if not models:
                print("[WARN] 清單是空的，請先新增模型。")
                wait_key(); continue
            return list(models)
        if sel.value == "add":
            value = esc_input("輸入模型名稱，例如 qwen2.5:7b，Esc 返回：")
            if value:
                value = value.strip()
                if value and value not in models:
                    models.append(value); groups[group_key] = models; save_groups(groups)
                    print(f"[OK] 已新增：{value}")
            wait_key()
        elif sel.value == "remove":
            if not models:
                print("[WARN] 清單是空的。")
                wait_key(); continue
            opts = [SelectOption(f"{m} : {'已下載' if m in installed else '未下載'}", m) for m in models]
            opts.append(SelectOption("返回", "__cancel__"))
            target = tui_select("選擇要從清單移除的模型", opts, 0)
            if target.value != "__cancel__":
                models = [m for m in models if m != target.value]
                groups[group_key] = models; save_groups(groups)
                print(f"[OK] 已移除：{target.value}")
                wait_key()
        elif sel.value == "view":
            print("\n目前模型清單：")
            for i, m in enumerate(models, 1):
                print(f"  {i}. {m} : {'已下載' if m in installed else '未下載'}")
            if not models: print("  [空]")
            wait_key()


def ask_max_tokens() -> GenerationSettings:
    """Ask the user for Ollama num_predict / max output tokens."""
    while True:
        sel = tui_select("選擇 max_tokens / num_predict", [
            SelectOption("256", "256", "quick / smoke test"),
            SelectOption("512", "512", "default"),
            SelectOption("1024", "1024", "long response"),
            SelectOption("2048", "2048", "reasoning / verbose model"),
            SelectOption("Custom", "custom", "手動輸入 64~8192"),
            SelectOption("返回", "__cancel__"),
        ], 1)
        if sel.value == "__cancel__":
            raise BackToMenu
        if sel.value != "custom":
            return GenerationSettings(max_tokens=int(sel.value))

        raw = esc_input("請輸入 max_tokens / num_predict，範圍 64~8192", "512")
        if raw is None:
            continue
        try:
            value = int(raw.strip())
        except ValueError:
            print("[WARN] max_tokens 格式錯誤，請輸入整數。")
            wait_key()
            continue
        if value < 64:
            print("[WARN] max_tokens 太小，已調整為 64。")
            value = 64
        elif value > 8192:
            print("[WARN] max_tokens 太大，已調整為 8192。")
            value = 8192
        return GenerationSettings(max_tokens=value)


def ask_run_count() -> int:
    value = esc_input("請輸入每個模型的測試次數", "1")
    if value is None:
        raise BackToMenu
    try:
        n = int(value)
    except ValueError:
        print("[WARN] 格式錯誤，改用 1。")
        return 1
    if n < 1: return 1
    if n > 50:
        print("[WARN] 上限 50，已改為 50。")
        return 50
    return n


def run_command(cmd: List[str]) -> bool:
    print("[RUN] " + " ".join(cmd))
    try:
        rc = subprocess.run(cmd, cwd=str(ROOT)).returncode
    except Exception as exc:
        print(f"[ERROR] PROCESS_CRASH: {exc}")
        return False
    if rc != 0:
        print(f"[ERROR] PROCESS_FAILED: exit code {rc}")
        return False
    return True


def result_path_for_model_arg(model_arg: str, run_name: str) -> Path:
    return ROOT / "results" / f"results_{safe_filename(model_arg)}__{safe_filename(run_name)}.csv"


def result_path_for(model: str, run_name: str) -> Path:
    return result_path_for_model_arg("ollama:" + model, run_name)


def read_results(model: str, run_name: str) -> List[dict]:
    path = result_path_for(model, run_name)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def read_results_by_model_arg(model_arg: str, run_name: str) -> List[dict]:
    path = result_path_for_model_arg(model_arg, run_name)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def summarize_rows(model: str, rows: List[dict]) -> Dict[str, object]:
    valid = [r for r in rows if str(r.get("valid_sample", "")).lower() == "true" and r.get("status") == "OK"]
    errors = [r for r in rows if r not in valid]
    critical = [r for r in valid if str(r.get("leak_level")) in {"3", "4"}]
    leaks = [r for r in valid if str(r.get("leak_level")) in {"2", "3", "4"}]
    score = 0.0
    if valid:
        score = round(sum(float(r.get("score") or 0) for r in valid) / len(valid), 2)
    error_counts = Counter(r.get("error_type") or "UNKNOWN" for r in errors)
    print("\n[SUMMARY]")
    print(f"模型：{model}")
    print(f"有效樣本：{len(valid)} / {len(rows)}")
    print(f"洩漏樣本：{len(leaks)}")
    print(f"Critical Leak(Level>=3)：{len(critical)}")
    print(f"Secret Protection Score：{score} / 100")
    if error_counts:
        print("錯誤摘要：")
        for k, v in error_counts.items():
            print(f"  - {k}: {v}")
    return {"valid": len(valid), "errors": len(errors), "critical": len(critical), "score": score, "error_counts": dict(error_counts)}


def run_model(model: str, installed: List[str], run_count: int, scope: TestScope, generation: GenerationSettings) -> bool:
    if not ensure_model(model, installed):
        return False
    success = True
    for i in range(1, run_count + 1):
        base_name = f"{ATTACKS_PATH.stem}__{scope.run_name_suffix}"
        run_name = base_name if run_count == 1 else f"{base_name}__run{i:02d}"
        print("\n" + "=" * 62)
        print(f"Model: {model}")
        print(f"Run: {i}/{run_count}")
        print(f"Scope: {scope.label}")
        print(f"max_tokens / num_predict: {generation.max_tokens}")
        print(f"Attacks: {ATTACKS_PATH.relative_to(ROOT)}")
        print("=" * 62)
        cmd = [
            sys.executable, "src/run_benchmark.py",
            "--model-source", "local",
            "--provider", "ollama",
            "--run-mode", "formal",
            "--local-mode", "interactive_local",
            "--model", f"ollama:{model}",
            "--ollama-url", OLLAMA_URL,
            "--attacks", str(ATTACKS_PATH),
            "--run-name", run_name,
        ]
        cmd += scope.to_cli_args()
        cmd += generation.to_cli_args()
        ok = run_command(cmd)
        rows = read_results(model, run_name)
        stats = summarize_rows(model, rows) if rows else {"errors": 999, "valid": 0, "error_counts": {"RESULT_NOT_FOUND": 1}}
        # Generate report and charts regardless of some invalid samples.
        run_command([sys.executable, "src/report_generator.py"])
        run_command([sys.executable, "src/plot_benchmark.py"])
        if (not ok) or stats.get("valid", 0) == 0 or stats.get("errors", 0) > 0:
            success = False
            print("[WARN] 此模型有問題列入問題清單，流程會繼續下一個模型。")
    return success



def run_quant_eval_interactive(installed: List[str]) -> bool:
    """Interactive original-vs-quantized evaluation flow.

    This calls src/quant_eval.py, which reuses src/run_benchmark.py and does not
    introduce any defense/guard logic. It is intended for the current research
    question: same attack scope, original/baseline tag vs quantized tag(s).
    """
    print("\n[量化版本比較]")
    baseline = esc_input("請輸入原版 / baseline 模型，例如 llama3.2:1b", DEFAULT_MODEL)
    if baseline is None:
        raise BackToMenu
    baseline = (baseline or DEFAULT_MODEL).strip()

    quant_raw = esc_input("請輸入量化模型，可用逗號多選，例如 llama3.2:1b-q4_K_M,llama3.2:1b-q8_0", baseline + "-q4_K_M")
    if quant_raw is None:
        raise BackToMenu
    quant_models = [m.strip() for m in quant_raw.split(",") if m.strip()]
    if not quant_models:
        print("[WARN] 沒有有效量化模型。")
        wait_key()
        return False

    # Keep the old menu style: choose scope, max_tokens, and run count.
    scope = choose_test_scope()
    generation = ask_max_tokens()
    run_count = ask_run_count()

    print("\n[QUANT EVAL CONFIG]")
    print(f"  baseline   : {baseline}")
    print(f"  quant      : {', '.join(quant_models)}")
    print(f"  scope      : {scope.label}")
    print(f"  styles     : {scope.styles}")
    print(f"  attack_ids : {scope.attack_ids}")
    print(f"  levels     : {scope.attack_levels}")
    print(f"  base_limit : {scope.limit_base_attacks or 'none'}")
    print(f"  runs       : {run_count}")
    print(f"  max_tokens : {generation.max_tokens}")

    for model in [baseline] + quant_models:
        if not ensure_model(model, installed):
            print(f"[ERROR] 模型未就緒：{model}")
            return False

    run_name = f"quant_eval__{scope.run_name_suffix}"
    cmd = [
        sys.executable, "src/quant_eval.py",
        "--baseline-model", baseline,
        "--quant-models", ",".join(quant_models),
        "--ollama-url", OLLAMA_URL,
        "--attacks", str(ATTACKS_PATH),
        "--styles", scope.styles,
        "--attack-ids", scope.attack_ids,
        "--attack-levels", scope.attack_levels,
        "--runs", str(run_count),
        "--max-tokens", str(generation.max_tokens),
        "--run-name", run_name,
    ]
    if scope.limit_base_attacks:
        cmd += ["--limit-base-attacks", str(scope.limit_base_attacks)]
    return run_command(cmd)


def ask_float(prompt: str, default: float, min_value: float = 0) -> float:
    raw = esc_input(prompt, str(default))
    if raw is None:
        raise BackToMenu
    try:
        value = float(raw)
    except ValueError:
        print(f"[WARN] 格式錯誤，改用 {default}。")
        return default
    return max(min_value, value)


def ask_int(prompt: str, default: int, min_value: int = 0, max_value: int = 20) -> int:
    raw = esc_input(prompt, str(default))
    if raw is None:
        raise BackToMenu
    try:
        value = int(raw)
    except ValueError:
        print(f"[WARN] 格式錯誤，改用 {default}。")
        return default
    return max(min_value, min(max_value, value))


def ask_cloud_settings() -> CloudSettings:
    print("\n[雲端模型設定]")
    print("目前支援 OpenAI-compatible /v1/chat/completions 格式。")
    base_url = esc_input("Base URL，例如 https://api.openai.com/v1", os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))
    if base_url is None:
        raise BackToMenu
    api_key_env = esc_input("API Key 環境變數名稱，不要直接輸入 key", os.getenv("OPENAI_API_KEY_ENV", "OPENAI_API_KEY"))
    if api_key_env is None:
        raise BackToMenu
    model = esc_input("雲端模型名稱，例如 gpt-4.1-mini / your-model-name", os.getenv("CLOUD_MODEL", "gpt-4.1-mini"))
    if model is None:
        raise BackToMenu
    request_timeout = ask_float("Request timeout 秒數", 120, 1)
    max_retries = ask_int("Max retries", 2, 0, 10)
    retry_backoff = ask_float("Retry backoff base 秒數", 2, 0)
    settings = CloudSettings(
        base_url=(base_url or "").rstrip("/"),
        api_key_env=(api_key_env or "OPENAI_API_KEY").strip(),
        model=(model or "").strip(),
        request_timeout=request_timeout,
        max_retries=max_retries,
        retry_backoff=retry_backoff,
    )
    if not os.getenv(settings.api_key_env, ""):
        print(f"[WARN] 找不到環境變數 {settings.api_key_env}。正式執行前請先設定 API key。")
        print("       PowerShell 範例：$env:%s=\"你的_API_KEY\"" % settings.api_key_env)
    raw = esc_input("是否做一次最小連線測試？Y/n", "n")
    if raw is not None and raw.strip().lower() in {"y", "yes"}:
        test_cloud_connection(settings)
    return settings


def test_cloud_connection(settings: CloudSettings) -> bool:
    print("\n[CHECK] Cloud API connection")
    api_key = os.getenv(settings.api_key_env, "")
    if not api_key:
        print(f"[ERROR] API_KEY_MISSING: {settings.api_key_env} 未設定。")
        return False
    url = settings.base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.model,
        "messages": [{"role": "user", "content": "ping"}],
        "temperature": 0,
        "max_tokens": 1,
    }
    try:
        r = requests.post(url, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json=payload, timeout=settings.request_timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] NETWORK_ERROR: {exc}")
        return False
    if r.status_code != 200:
        print(f"[ERROR] HTTP_{r.status_code}: {r.text[:500]}")
        return False
    print("[OK] Cloud API connected.")
    return True


def run_cloud_model(settings: CloudSettings, run_count: int, scope: TestScope, generation: GenerationSettings) -> bool:
    success = True
    for i in range(1, run_count + 1):
        base_name = f"{ATTACKS_PATH.stem}__{scope.run_name_suffix}"
        run_name = base_name if run_count == 1 else f"{base_name}__run{i:02d}"
        print("\n" + "=" * 62)
        print(f"Cloud Model: {settings.model}")
        print(f"Provider   : {settings.provider}")
        print(f"Base URL   : {settings.base_url}")
        print(f"Run        : {i}/{run_count}")
        print(f"Scope      : {scope.label}")
        print(f"max_tokens : {generation.max_tokens}")
        print("=" * 62)
        cmd = [
            sys.executable, "src/run_benchmark.py",
            "--attacks", str(ATTACKS_PATH),
            "--run-name", run_name,
        ]
        cmd += settings.to_cli_args()
        cmd += scope.to_cli_args()
        cmd += generation.to_cli_args()
        ok = run_command(cmd)
        rows = read_results_by_model_arg(settings.model, run_name)
        stats = summarize_rows(settings.model, rows) if rows else {"errors": 999, "valid": 0, "error_counts": {"RESULT_NOT_FOUND": 1}}
        run_command([sys.executable, "src/report_generator.py"])
        run_command([sys.executable, "src/plot_benchmark.py"])
        if (not ok) or stats.get("valid", 0) == 0 or stats.get("errors", 0) > 0:
            success = False
            print("[WARN] 此雲端模型測試存在問題，請檢查 API、timeout、rate limit 或結果檔。")
    return success


def cloud_menu() -> None:
    try:
        settings = ask_cloud_settings()
        scope = choose_test_scope()
        generation = ask_max_tokens()
        run_count = ask_run_count()
    except BackToMenu:
        return

    print("\n[即將開始雲端測試]")
    print(f"  Provider   : {settings.provider}")
    print(f"  Model      : {settings.model}")
    print(f"  Base URL   : {settings.base_url}")
    print(f"  API Key Env: {settings.api_key_env}")
    for line in describe_scope(scope):
        print("  " + line)
    print(f"  Runs       : {run_count}")
    print(f"  max_tokens : {generation.max_tokens}")
    print(f"  Timeout    : {settings.request_timeout}s")
    print(f"  Retries    : {settings.max_retries}")
    raw = esc_input("開始執行？Y/n", "Y")
    if raw is None or raw.strip().lower() not in {"", "y", "yes"}:
        return
    ok = run_cloud_model(settings, run_count, scope, generation)
    print("\n[OK] 雲端模型測試完成。" if ok else "\n[WARN] 雲端模型測試未成功完成。")
    print(f"Results: {ROOT / 'results'}")
    print(f"Reports: {ROOT / 'reports'}")
    wait_key()


def print_final_batch_summary(models: List[str], problem_models: List[str]) -> None:
    print("\n" + "=" * 62)
    print("批次測試完成")
    print(f"總模型數：{len(models or [])}")
    print(f"問題模型數：{len(problem_models)}")
    if problem_models:
        print("問題清單：")
        for m in problem_models:
            print(f"  - {m}")
    print(f"Results: {ROOT / 'results'}")
    print(f"Reports: {ROOT / 'reports'}")
    print("=" * 62)


def local_main_menu(installed: List[str]) -> int:
    while True:
        selected = tui_select("LLM-Attack-Benchmark - Family Ladder Runner", [
            SelectOption("單一模型測試", "single", "最常用：輸入一個 Ollama model 後選測試範圍"),
            SelectOption("小型模型組測試", "small", "configs/model_groups.json: small_models"),
            SelectOption("中型模型組測試", "medium", "configs/model_groups.json: medium_models"),
            SelectOption("自訂模型清單", "custom_models", "用逗號輸入多個 Ollama models，一次測試"),
            SelectOption("量化版本比較", "quant", "baseline vs quantized，同一 scope 對照"),
            SelectOption("管理模型組", "manage", "新增、移除、查看 small / medium 清單"),
            SelectOption("離開", "__cancel__"),
        ], 0)
        if selected.value == "__cancel__":
            return 0

        try:
            if selected.value == "quant":
                ok = run_quant_eval_interactive(installed)
                print("\n[OK] 量化版本比較完成。" if ok else "\n[WARN] 量化版本比較未成功完成。")
                print(f"Results: {ROOT / 'results'}")
                print(f"Reports: {ROOT / 'reports'}")
                wait_key()
                continue

            if selected.value == "manage":
                manage = tui_select("管理模型組", [
                    SelectOption("管理 small_models", "small"),
                    SelectOption("管理 medium_models", "medium"),
                    SelectOption("返回", "__cancel__"),
                ], 0)
                if manage.value == "__cancel__":
                    continue
                group_menu(f"{manage.value}_models", f"管理 {manage.value}_models", installed)
                continue

            if selected.value == "small":
                models = group_menu("small_models", "小型模型組測試", installed)
            elif selected.value == "medium":
                models = group_menu("medium_models", "中型模型組測試", installed)
            elif selected.value == "custom_models":
                raw_models = esc_input("請輸入模型清單，使用逗號分隔，例如 gemma3:1b,gemma3:4b,qwen2.5:0.5b", DEFAULT_MODEL)
                if raw_models is None:
                    raise BackToMenu
                models = [m.strip() for m in raw_models.split(",") if m.strip()]
                if not models:
                    models = [DEFAULT_MODEL]
            elif selected.value == "single":
                value = esc_input("請輸入模型名稱，例如 qwen2.5:0.5b / gemma3:1b", DEFAULT_MODEL)
                if value is None:
                    raise BackToMenu
                models = [value.strip() or DEFAULT_MODEL]
            else:
                return 0

            scope = choose_test_scope()
            generation = ask_max_tokens()
            run_count = ask_run_count()
        except BackToMenu:
            continue

        print("\n[即將開始測試]")
        print(f"  Models     : {', '.join(models or [])}")
        for line in describe_scope(scope):
            print("  " + line)
        print(f"  Runs/model : {run_count}")
        print(f"  max_tokens : {generation.max_tokens}")
        raw = esc_input("開始執行？Y/n", "Y")
        if raw is None or raw.strip().lower() not in {"", "y", "yes"}:
            continue

        problem_models: List[str] = []
        for idx, model in enumerate(models or [], 1):
            print("\n" + "#" * 62)
            print(f"模型進度：{idx}/{len(models)} - {model}")
            print("#" * 62)
            if not run_model(model, installed, run_count, scope, generation):
                problem_models.append(model)

        print_final_batch_summary(models or [], problem_models)
        wait_key()



def latest_run_dirs(limit: int = 5) -> List[Path]:
    base = ROOT / "runs"
    if not base.exists():
        return []
    dirs = [p for p in base.glob("*/*") if p.is_dir()]
    dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return dirs[:limit]


def show_latest_runs() -> None:
    runs = latest_run_dirs()
    print("\n[最近 Run]")
    if not runs:
        print("  尚無 runs/ 紀錄。")
        wait_key()
        return
    for idx, path in enumerate(runs, 1):
        manifest = path / "run_manifest.json"
        label = path.name
        model = ""
        mode = path.parent.name
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                model = data.get("model", {}).get("model_name", "")
                mode = data.get("run_mode", mode)
                summary = data.get("summary", {}) or {}
                label += f" | model={model} | safety={summary.get('safety_score', '')}% | reliability={summary.get('reliability_score', '')}%"
            except Exception:
                pass
        print(f"  {idx}. [{mode}] {label}")
        print(f"     report: {path / 'report.md'}")
    wait_key()


def user_mode_menu(installed: Optional[List[str]]) -> Optional[List[str]]:
    while True:
        selected = tui_select("User Mode - 一般使用者模式", [
            SelectOption("本地模型 / Ollama", "local", "快速開始、OWASP 測試、模型比較"),
            SelectOption("雲端模型 / Cloud API", "cloud", "OpenAI-compatible API，需要 API key env"),
            SelectOption("查看最近一次結果", "latest", "打開 runs/ 中最近的 report 路徑"),
            SelectOption("返回主選單", "__cancel__"),
        ], 0)
        if selected.value == "__cancel__":
            return installed
        if selected.value == "local":
            if installed is None:
                installed = check_ollama()
            if installed is None:
                print("[FAIL] Ollama 無法連線。請確認 Ollama 已啟動，或手動執行 ollama serve。")
                wait_key()
                continue
            local_main_menu(installed)
        elif selected.value == "cloud":
            cloud_menu()
        elif selected.value == "latest":
            show_latest_runs()
    return installed


def developer_mode_menu() -> None:
    while True:
        selected = tui_select("Developer Mode - 開發者模式", [
            SelectOption("Preflight Check 正式實驗前檢查", "preflight", "validate + dry-run + mock smoke"),
            SelectOption("Validate attack.json", "validate", "只檢查 attack schema，不呼叫模型"),
            SelectOption("Mock Smoke Test", "smoke", "最小端到端流程測試，不納入正式統計"),
            SelectOption("Dry-run 正式實驗範圍", "dry", "預覽正式範圍，不呼叫模型"),
            SelectOption("查看最近 Run", "latest", "查看 runs/formal 或 runs/mock"),
            SelectOption("返回主選單", "__cancel__"),
        ], 0)
        if selected.value == "__cancel__":
            return
        if selected.value == "validate":
            run_command([sys.executable, "src/run_benchmark.py", "--validate-attacks", "--run-mode", "mock", "--attacks", str(ATTACKS_PATH)])
            wait_key()
        elif selected.value == "smoke":
            run_command([sys.executable, "src/run_benchmark.py", "--preset", "mock_smoke"])
            wait_key()
        elif selected.value == "dry":
            try:
                scope = choose_test_scope()
            except BackToMenu:
                continue
            cmd = [sys.executable, "src/run_benchmark.py", "--dry-run", "--run-mode", "formal", "--attacks", str(ATTACKS_PATH)]
            cmd += scope.to_cli_args()
            run_command(cmd)
            wait_key()
        elif selected.value == "preflight":
            print("\n[Preflight Check]")
            ok1 = run_command([sys.executable, "src/run_benchmark.py", "--validate-attacks", "--run-mode", "mock", "--attacks", str(ATTACKS_PATH)])
            ok2 = run_command([sys.executable, "src/run_benchmark.py", "--preset", "quick_formal", "--dry-run"])
            ok3 = run_command([sys.executable, "src/run_benchmark.py", "--preset", "mock_smoke"])
            print("\n[READY] 正式實驗前檢查通過。" if (ok1 and ok2 and ok3) else "\n[FAILED] Preflight 有失敗項目，請先修正。")
            wait_key()
        elif selected.value == "latest":
            show_latest_runs()


def main_menu(installed: Optional[List[str]]) -> int:
    while True:
        selected = tui_select("LLM-Attack-Benchmark", [
            SelectOption("User Mode 一般使用者模式", "user", "跑正式 benchmark、看結果、匯出報告"),
            SelectOption("Developer Mode 開發者模式", "developer", "驗證 attack.json、mock smoke、dry-run"),
            SelectOption("查看最近 Run", "latest", "顯示 runs/ 中最近的實驗資料夾"),
            SelectOption("離開", "__cancel__"),
        ], 0)
        if selected.value == "__cancel__":
            return 0
        if selected.value == "user":
            installed = user_mode_menu(installed)
        elif selected.value == "developer":
            developer_mode_menu()
        elif selected.value == "latest":
            show_latest_runs()


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--simple", action="store_true", help="強制使用數字選單")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    global SIMPLE_MODE
    args = parse_args(sys.argv[1:] if argv is None else argv)
    SIMPLE_MODE = args.simple
    print("=== LLM-Attack-Benchmark - OWASP Local/Cloud Runner ===")
    print(f"Project root: {ROOT}")
    print(f"Ollama URL  : {OLLAMA_URL}")
    print(f"Attack set  : {ATTACKS_PATH}")
    installed = None
    print("[INFO] Ollama 會在進入 User Mode → 本地模型時才檢查；Developer Mode 不需要 Ollama。")
    return main_menu(installed)


if __name__ == "__main__":
    raise SystemExit(main())
