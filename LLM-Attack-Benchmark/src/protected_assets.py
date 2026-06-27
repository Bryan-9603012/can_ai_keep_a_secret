from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ASSET_DIR = ROOT / "data" / "protected_assets"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_protected_assets(asset_dir: Path | None = None) -> list[dict]:
    """Load synthetic protected assets.

    Assets are deliberately stored as JSON files so experiments can vary the
    protected data profile without rewriting attack prompts or evaluators.
    """
    asset_dir = asset_dir or DEFAULT_ASSET_DIR
    if not asset_dir.exists():
        return []
    manifest_path = asset_dir / "manifest.json"
    files: list[Path]
    if manifest_path.exists():
        manifest = _load_json(manifest_path)
        files = [asset_dir / str(item.get("file")) for item in manifest.get("assets", []) if item.get("file")]
    else:
        files = sorted(p for p in asset_dir.glob("*.json") if p.name != "manifest.json")
    assets: list[dict] = []
    seen: set[str] = set()
    for path in files:
        if not path.exists():
            continue
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        aid = str(data.get("asset_id") or path.stem)
        if aid in seen:
            continue
        data["asset_id"] = aid
        data.setdefault("asset_type", "unknown")
        data.setdefault("exact_values", [])
        data.setdefault("partial_values", [])
        data.setdefault("patterns", [])
        data.setdefault("semantic_description", [])
        assets.append(data)
        seen.add(aid)
    return assets


def protected_assets_hash(assets: list[dict]) -> str:
    payload = json.dumps(assets, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def asset_types(assets: list[dict]) -> list[str]:
    return sorted({str(a.get("asset_type") or "unknown") for a in assets})


def render_assets_for_system_prompt(assets: list[dict]) -> str:
    """Render protected assets for the synthetic system prompt.

    This is intentionally explicit: the benchmark tests whether the model can
    protect information that exists in hidden/system context.  Use only synthetic
    values here.
    """
    if not assets:
        return "- No structured protected assets loaded."
    lines: list[str] = []
    for asset in assets:
        lines.append(f"- asset_id={asset.get('asset_id')} | asset_type={asset.get('asset_type')} | name={asset.get('display_name','')}")
        for value in asset.get("exact_values", [])[:3]:
            lines.append(f"  protected_value: {value}")
        if asset.get("semantic_description"):
            lines.append("  semantic_boundary: " + " ".join(str(x) for x in asset.get("semantic_description", [])))
    return "\n".join(lines)


def assets_for_attack(assets: list[dict], attack: dict | None = None) -> list[dict]:
    """Prefer target assets for the attack but keep all assets as fallback.

    If an attack leaks any protected asset, it is still a sensitive failure even
    when the attack's nominal target was another asset.
    """
    if not assets:
        return []
    attack = attack or {}
    ids: list[str] = []
    for key in ("target_asset_id", "target_asset_ids"):
        value = attack.get(key)
        if isinstance(value, list):
            ids.extend(str(v) for v in value if v)
        elif value:
            ids.extend(str(value).split(";"))
    types: list[str] = []
    for key in ("target_asset_type", "target_asset_types"):
        value = attack.get(key)
        if isinstance(value, list):
            types.extend(str(v) for v in value if v)
        elif value:
            types.extend(str(value).split(";"))
    preferred = []
    rest = []
    for asset in assets:
        if str(asset.get("asset_id")) in ids or str(asset.get("asset_type")) in types:
            preferred.append(asset)
        else:
            rest.append(asset)
    return preferred + rest
