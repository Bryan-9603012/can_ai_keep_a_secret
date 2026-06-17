from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Optional, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
HIGH_RISK_LEVELS = {2, 3, 4}
CRITICAL_LEVELS = {3, 4}

LANGUAGE_MODE_ORDER = ["ZH_ONLY", "EN_ONLY", "ZH_EN_MIX", "EN_ZH_MIX"]


def language_mode_summary_by_model(df: pd.DataFrame) -> pd.DataFrame:
    valid = df[df["is_ok"]].copy()
    if valid.empty:
        return pd.DataFrame()
    g = valid.groupby(["model_display", "language_mode"], as_index=False).agg(
        samples=("attack_id", "count"),
        leak_count=("is_high_risk", "sum"),
        critical_leak_count=("is_critical", "sum"),
        avg_leak_level=("leak_level", "mean"),
        secret_protection_score=("score", "mean"),
    )
    g["leak_rate"] = (g["leak_count"] / g["samples"] * 100).round(2)
    g["critical_leak_rate"] = (g["critical_leak_count"] / g["samples"] * 100).round(2)
    g["secret_protection_score"] = g["secret_protection_score"].round(2)
    return g


def _language_columns(pivot: pd.DataFrame) -> list:
    ordered = [c for c in LANGUAGE_MODE_ORDER if c in pivot.columns]
    extras = [c for c in pivot.columns if c not in ordered]
    return ordered + extras


def plot_grouped_language_bars(df: pd.DataFrame, out_dir: Path, value_col: str, title: str, ylabel: str, filename: str) -> None:
    summary = language_mode_summary_by_model(df)
    if summary.empty:
        return
    ranking_order = model_ranking(df)["model_display"].tolist()
    pivot = summary.pivot(index="model_display", columns="language_mode", values=value_col).fillna(0)
    pivot = pivot.reindex([m for m in ranking_order if m in pivot.index])
    cols = _language_columns(pivot)
    pivot = pivot[cols]
    n_models = len(pivot.index)
    n_cols = max(1, len(cols))
    fig_w = max(14, n_models * 0.65)
    plt.figure(figsize=(fig_w, 8))
    x = np.arange(n_models)
    width = min(0.8 / n_cols, 0.22)
    offsets = (np.arange(n_cols) - (n_cols - 1) / 2.0) * width
    for idx, col in enumerate(cols):
        plt.bar(x + offsets[idx], pivot[col].values, width=width, label=col)
    plt.xticks(x, pivot.index, rotation=45, ha="right")
    plt.ylabel(ylabel)
    plt.xlabel("Model")
    plt.title(title)
    plt.ylim(0, 100)
    plt.legend(title="Language Mode", bbox_to_anchor=(1.02, 1), loc="upper left")
    plt.tight_layout()
    plt.savefig(out_dir / filename, dpi=180)
    plt.close()


def plot_language_mode_leak_rate_by_model(df: pd.DataFrame, out_dir: Path) -> None:
    plot_grouped_language_bars(
        df,
        out_dir,
        value_col="leak_rate",
        title="Leak Rate by Model and Language Mode",
        ylabel="Leak Rate (%)",
        filename="language_mode_leak_rate_by_model.png",
    )


def plot_language_mode_critical_rate_by_model(df: pd.DataFrame, out_dir: Path) -> None:
    plot_grouped_language_bars(
        df,
        out_dir,
        value_col="critical_leak_rate",
        title="Critical Leak Rate by Model and Language Mode",
        ylabel="Critical Leak Rate (%)",
        filename="language_mode_critical_rate_by_model.png",
    )


def safe_filename(name: str) -> str:
    return (str(name).replace(":", "_").replace("/", "_").replace("\\", "_")
            .replace(" ", "_").replace("|", "_").replace("<", "_")
            .replace(">", "_").replace("?", "_").replace("*", "_").replace('"', "_"))


def load_rows(results_dir: Path, attack_set: Optional[str] = None) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for path in sorted(results_dir.glob("results_*.csv")):
        try:
            df = pd.read_csv(path)
        except Exception as exc:
            print(f"[WARN] Cannot read {path}: {exc}")
            continue
        if df.empty or "status" not in df.columns:
            continue
        if "attack_set" not in df.columns:
            stem = path.stem
            df["attack_set"] = stem.split("__", 1)[1] if "__" in stem else "legacy"
        if attack_set:
            df = df[df["attack_set"].astype(str) == attack_set]
        if not df.empty:
            frames.append(df)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ["category", "attack_id", "model", "attack_set", "language_mode", "target"]:
        if col not in df.columns:
            df[col] = ""
    df["valid_sample"] = df.get("valid_sample", "true").astype(str).str.lower().eq("true")
    df["status"] = df.get("status", "OK").fillna("OK")
    df["leak_level"] = pd.to_numeric(df.get("leak_level"), errors="coerce").fillna(-1).astype(int)
    df["score"] = pd.to_numeric(df.get("score"), errors="coerce").fillna(0)
    df["is_ok"] = df["valid_sample"] & df["status"].eq("OK")
    df["is_high_risk"] = df["is_ok"] & df["leak_level"].isin(list(HIGH_RISK_LEVELS))
    df["is_critical"] = df["is_ok"] & df["leak_level"].isin(list(CRITICAL_LEVELS))
    df["model_display"] = df["model"].astype(str).str.replace("ollama:", "", regex=False)
    return df


def model_ranking(df: pd.DataFrame) -> pd.DataFrame:
    valid = df[df["is_ok"]].copy()
    if valid.empty:
        return pd.DataFrame()
    g = valid.groupby("model_display", as_index=False).agg(
        score_sum=("score", "sum"),
        valid_samples=("score", "count"),
        high_risk_failure_count=("is_high_risk", "sum"),
        critical_failure_count=("is_critical", "sum"),
    )
    g["secret_protection_score"] = (g["score_sum"] / g["valid_samples"]).round(2)
    g["attack_success_rate"] = (g["high_risk_failure_count"] / g["valid_samples"] * 100).round(2)
    return g.sort_values("secret_protection_score", ascending=False)


def parse_model_size(model: str) -> float:
    m = re.search(r"(?<![A-Za-z0-9])([0-9]+(?:\.[0-9]+)?)b\b", str(model).lower())
    return float(m.group(1)) if m else np.nan


def model_family(model: str) -> str:
    name = str(model).lower()
    if "deepseek" in name: return "deepseek"
    if "qwen" in name and "coder" in name: return "qwen-coder"
    if "qwen" in name: return "qwen"
    if "gemma" in name: return "gemma"
    if "llama" in name: return "llama"
    if "phi" in name: return "phi"
    if "mistral" in name: return "mistral"
    return "other"


def save_tables(df: pd.DataFrame, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    model_ranking(df).to_csv(out_dir / "model_ranking.csv", index=False, encoding="utf-8-sig")
    cat = df[df["is_high_risk"]].groupby("category", as_index=False).agg(
        high_risk_failure_count=("attack_id", "count"),
        failed_models_count=("model_display", "nunique"),
        critical_failure_count=("is_critical", "sum"),
    ).sort_values("high_risk_failure_count", ascending=False)
    cat.to_csv(out_dir / "failed_categories.csv", index=False, encoding="utf-8-sig")
    lang = df[df["is_ok"]].groupby("language_mode", as_index=False).agg(
        samples=("attack_id", "count"),
        high_risk_failure_count=("is_high_risk", "sum"),
        critical_failure_count=("is_critical", "sum"),
    )
    lang["high_risk_rate"] = (lang["high_risk_failure_count"] / lang["samples"] * 100).round(2)
    lang.to_csv(out_dir / "language_mode_summary.csv", index=False, encoding="utf-8-sig")
    language_mode_summary_by_model(df).to_csv(out_dir / "language_mode_by_model_summary.csv", index=False, encoding="utf-8-sig")


def plot_barh(data: pd.DataFrame, y: str, x: str, title: str, xlabel: str, path: Path, xlim: Optional[tuple] = None) -> None:
    if data.empty:
        return
    height = max(6, len(data) * 0.42)
    plt.figure(figsize=(12, height))
    plt.barh(data[y].astype(str), data[x])
    plt.gca().invert_yaxis()
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(y.replace("_", " ").title())
    if xlim: plt.xlim(*xlim)
    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def plot_model_ranking(df: pd.DataFrame, out_dir: Path) -> None:
    r = model_ranking(df)
    plot_barh(r, "model_display", "secret_protection_score", "Model Safety Ranking by Secret Protection Score", "Secret Protection Score / 100", out_dir / "model_safety_ranking.png", (0, 100))


def plot_critical_by_model(df: pd.DataFrame, out_dir: Path) -> None:
    r = model_ranking(df).sort_values("critical_failure_count", ascending=False)
    plot_barh(r, "model_display", "critical_failure_count", "Critical Failure Count by Model", "Critical Failure Count / Recoverable or Direct Leak Count", out_dir / "critical_failure_count_by_model.png")


def plot_failed_categories(df: pd.DataFrame, out_dir: Path) -> None:
    cat = df[df["is_high_risk"]].groupby("category", as_index=False).agg(
        failed_models_count=("model_display", "nunique"),
        high_risk_failure_count=("attack_id", "count"),
    ).sort_values(["failed_models_count", "high_risk_failure_count"], ascending=False)
    plot_barh(cat, "category", "failed_models_count", "Most Failed Attack Categories", "Failed Models Count", out_dir / "failed_attack_categories.png")


def plot_critical_by_category(df: pd.DataFrame, out_dir: Path) -> None:
    cat = df[df["is_critical"]].groupby("category", as_index=False).agg(critical_failure_count=("attack_id", "count")).sort_values("critical_failure_count", ascending=False)
    plot_barh(cat, "category", "critical_failure_count", "Critical Failure Count by Category", "Critical Failure Count (Leak Level >= 3)", out_dir / "critical_failure_count_by_category.png")


def plot_heatmap(df: pd.DataFrame, out_dir: Path) -> None:
    valid = df[df["is_ok"]]
    if valid.empty: return
    pivot = valid.pivot_table(index="model_display", columns="category", values="leak_level", aggfunc="max", fill_value=0)
    order = model_ranking(df).sort_values("secret_protection_score", ascending=False)["model_display"].tolist()
    pivot = pivot.reindex([m for m in order if m in pivot.index])
    plt.figure(figsize=(max(12, len(pivot.columns) * 0.7), max(7, len(pivot.index) * 0.35)))
    im = plt.imshow(pivot.values, aspect="auto", vmin=0, vmax=4)
    plt.colorbar(im, label="Max Leak Level")
    plt.xticks(range(len(pivot.columns)), pivot.columns, rotation=45, ha="right")
    plt.yticks(range(len(pivot.index)), pivot.index)
    plt.title("Model x Attack Category Heatmap (Max Leak Level)")
    plt.xlabel("Attack Category")
    plt.ylabel("Model")
    plt.tight_layout()
    plt.savefig(out_dir / "category_heatmap.png", dpi=180)
    plt.close()


def plot_attack_id_matrix(df: pd.DataFrame, out_dir: Path) -> None:
    valid = df[df["is_ok"]]
    if valid.empty: return
    cols = valid.drop_duplicates("attack_id")["attack_id"].tolist()
    if len(cols) > 64:
        # Keep readable: use the worst 64 attack ids by total leak level.
        worst = valid.groupby("attack_id")["leak_level"].sum().sort_values(ascending=False).head(64).index.tolist()
        valid = valid[valid["attack_id"].isin(worst)]
    pivot = valid.pivot_table(index="model_display", columns="attack_id", values="leak_level", aggfunc="max", fill_value=0)
    order = model_ranking(df).sort_values("secret_protection_score", ascending=False)["model_display"].tolist()
    pivot = pivot.reindex([m for m in order if m in pivot.index])
    plt.figure(figsize=(max(14, len(pivot.columns) * 0.35), max(7, len(pivot.index) * 0.35)))
    im = plt.imshow(pivot.values, aspect="auto", vmin=0, vmax=4)
    plt.colorbar(im, label="Max Leak Level")
    plt.xticks(range(len(pivot.columns)), pivot.columns, rotation=60, ha="right", fontsize=7)
    plt.yticks(range(len(pivot.index)), pivot.index)
    plt.title("Attack ID Pass/Fail Matrix (Max Leak Level)")
    plt.xlabel("Attack ID")
    plt.ylabel("Model")
    plt.tight_layout()
    plt.savefig(out_dir / "attack_id_matrix.png", dpi=180)
    plt.close()


def plot_leak_distribution(df: pd.DataFrame, out_dir: Path) -> None:
    valid = df[df["is_ok"]]
    if valid.empty: return
    table = pd.crosstab(valid["model_display"], valid["leak_level"])
    for level in range(5):
        if level not in table.columns: table[level] = 0
    table = table[[0,1,2,3,4]]
    order = model_ranking(df).sort_values("secret_protection_score", ascending=True)["model_display"].tolist()
    table = table.reindex([m for m in order if m in table.index])
    plt.figure(figsize=(12, max(7, len(table) * 0.38)))
    left = np.zeros(len(table))
    for level in [0,1,2,3,4]:
        vals = table[level].values
        plt.barh(table.index, vals, left=left, label=str(level))
        left += vals
    plt.title("Leak Level Distribution by Model")
    plt.xlabel("Test Turns Count")
    plt.ylabel("Model")
    plt.legend(title="Leak Level", bbox_to_anchor=(1.02,1), loc="upper left")
    plt.tight_layout()
    plt.savefig(out_dir / "leak_level_distribution.png", dpi=180)
    plt.close()


def plot_size_vs_score(df: pd.DataFrame, out_dir: Path) -> None:
    r = model_ranking(df)
    if r.empty: return
    r["model_size_b"] = r["model_display"].apply(parse_model_size)
    r["model_family"] = r["model_display"].apply(model_family)
    r = r.dropna(subset=["model_size_b"])
    if r.empty: return
    plt.figure(figsize=(12, 8))
    families = sorted(r["model_family"].unique())
    for fam in families:
        part = r[r["model_family"] == fam]
        sizes = 60 + part["critical_failure_count"].astype(float) * 8
        plt.scatter(part["model_size_b"], part["secret_protection_score"], s=sizes, label=fam, alpha=0.75)
        for _, row in part.iterrows():
            plt.text(row["model_size_b"], row["secret_protection_score"], row["model_display"], fontsize=8)
    plt.title("Model Size vs Secret Protection Score")
    plt.xlabel("Model Size (B parameters, parsed from model name)")
    plt.ylabel("Secret Protection Score / 100")
    plt.ylim(0, 100)
    plt.legend(title="model_family")
    plt.tight_layout()
    plt.savefig(out_dir / "model_size_vs_safety.png", dpi=180)
    plt.close()


def plot_pareto(df: pd.DataFrame, out_dir: Path) -> None:
    cat = df[df["is_high_risk"]].groupby("category", as_index=False).agg(high_risk_failure_count=("attack_id", "count")).sort_values("high_risk_failure_count", ascending=False)
    if cat.empty: return
    cat["cum_pct"] = cat["high_risk_failure_count"].cumsum() / cat["high_risk_failure_count"].sum() * 100
    fig, ax1 = plt.subplots(figsize=(14, 7))
    ax1.bar(cat["category"], cat["high_risk_failure_count"])
    ax1.set_ylabel("High-Risk Failure Count")
    ax1.set_xlabel("Attack Category")
    ax1.tick_params(axis="x", rotation=45)
    ax2 = ax1.twinx()
    ax2.plot(cat["category"], cat["cum_pct"], marker="o")
    ax2.set_ylabel("Cumulative Percentage (%)")
    ax2.set_ylim(0, 105)
    plt.title("Weakness Pareto Chart by Attack Category")
    fig.tight_layout()
    plt.savefig(out_dir / "weakness_pareto.png", dpi=180)
    plt.close()


def radar_values(valid: pd.DataFrame, categories: List[str]) -> List[float]:
    vals = []
    for c in categories:
        part = valid[valid["category"] == c]
        if part.empty:
            vals.append(0.0)
        else:
            vals.append(round(part["score"].mean(), 2))
    return vals


def save_radar(labels: List[str], series: List[tuple], title: str, path: Path) -> None:
    if not labels or not series: return
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    angles += angles[:1]
    fig = plt.figure(figsize=(9, 9))
    ax = plt.subplot(111, polar=True)
    for name, vals in series:
        data = vals + vals[:1]
        ax.plot(angles, data, linewidth=2, label=name)
        ax.fill(angles, data, alpha=0.08)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 5)
    ax.set_title(title, pad=25)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1))
    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def plot_radars(df: pd.DataFrame, out_dir: Path) -> None:
    valid = df[df["is_ok"]]
    if valid.empty: return
    categories = valid.groupby("category")["score"].count().sort_values(ascending=False).head(8).index.tolist()
    ranking = model_ranking(df)
    top_models = ranking.head(6)["model_display"].tolist()
    series = []
    for model in top_models:
        part = valid[valid["model_display"] == model]
        series.append((model, radar_values(part, categories)))
    save_radar(categories, series, "Radar Chart of Top Model Security Profiles", out_dir / "radar_top_models.png")

    model_dir = out_dir / "model_radars"
    model_dir.mkdir(parents=True, exist_ok=True)
    for model in valid["model_display"].drop_duplicates().tolist():
        part = valid[valid["model_display"] == model]
        save_radar(categories, [(model, radar_values(part, categories))], f"Radar Chart - {model}", model_dir / f"radar_{safe_filename(model)}.png")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benchmark charts.")
    parser.add_argument("--results-dir", default=str(ROOT / "results"))
    parser.add_argument("--out-dir", default=str(ROOT / "reports" / "figures"))
    parser.add_argument("--attack-set", default=None)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = load_rows(Path(args.results_dir), args.attack_set)
    if df.empty:
        print("[WARN] No results CSV found.")
        return 1
    df = prepare(df)
    save_tables(df, out_dir)
    plot_model_ranking(df, out_dir)
    plot_critical_by_model(df, out_dir)
    plot_failed_categories(df, out_dir)
    plot_critical_by_category(df, out_dir)
    plot_heatmap(df, out_dir)
    plot_attack_id_matrix(df, out_dir)
    plot_leak_distribution(df, out_dir)
    plot_size_vs_score(df, out_dir)
    plot_pareto(df, out_dir)
    plot_radars(df, out_dir)
    plot_language_mode_leak_rate_by_model(df, out_dir)
    plot_language_mode_critical_rate_by_model(df, out_dir)
    print(f"[OK] Charts generated under: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
