"""Central benchmark preset registry.

Presets are intentionally policy-oriented.  The UI can present friendly names
while the runner receives stable CLI fields.  Mock presets are never formal
experiments and should not be included in formal statistics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Preset:
    preset_id: str
    run_mode: str
    label: str
    description: str
    values: dict[str, Any]


_PRESETS: dict[str, Preset] = {
    "quick_formal": Preset(
        preset_id="quick_formal",
        run_mode="formal",
        label="Quick formal baseline",
        description="Formal quick baseline: all available OWASP families, lowest available level, English only.",
        values={
            "styles": "en_pure",
            "attack_ids": "all",
            "attack_levels": "all",
            "level_policy": "basic",
            "owasp_types": "all",
            "limit_base_attacks": None,
        },
    ),
    "pilot_local": Preset(
        preset_id="pilot_local",
        run_mode="formal",
        label="Formal local pilot",
        description="Small formal pilot for local models before larger runs.",
        values={
            "styles": "en_pure",
            "attack_ids": "all",
            "attack_levels": "all",
            "level_policy": "basic",
            "owasp_types": "all",
            "limit_base_attacks": 5,
        },
    ),
    "full_formal": Preset(
        preset_id="full_formal",
        run_mode="formal",
        label="Full formal benchmark",
        description="Formal full benchmark over all available attacks, levels, and languages.",
        values={
            "styles": "all",
            "attack_ids": "all",
            "attack_levels": "all",
            "level_policy": "all_available",
            "owasp_types": "all",
            "limit_base_attacks": None,
        },
    ),
    "mock_smoke": Preset(
        preset_id="mock_smoke",
        run_mode="mock",
        label="Mock smoke test",
        description="Minimal end-to-end pipeline test. Not included in formal statistics.",
        values={
            "model_source": "mock",
            "provider": "mock",
            "model": "mock",
            "styles": "en_pure",
            "attack_ids": "all",
            "attack_levels": "all",
            "level_policy": "basic",
            "owasp_types": "all",
            "limit_base_attacks": 2,
        },
    ),
}

_ALIASES = {
    "smoke": "mock_smoke",
    "quick": "quick_formal",
    "formal_quick": "quick_formal",
    "full": "full_formal",
}


def list_presets(run_mode: str | None = None) -> list[Preset]:
    out = list(_PRESETS.values())
    if run_mode:
        out = [p for p in out if p.run_mode == run_mode]
    return sorted(out, key=lambda p: (p.run_mode, p.preset_id))


def get_preset(preset_id: str | None) -> Preset | None:
    if not preset_id:
        return None
    key = _ALIASES.get(preset_id, preset_id)
    if key not in _PRESETS:
        raise KeyError(f"Unknown preset: {preset_id}")
    return _PRESETS[key]


def apply_preset_to_args(args) -> None:
    preset = get_preset(getattr(args, "preset", None))
    if not preset:
        return
    args.run_mode = preset.run_mode
    for key, value in preset.values.items():
        setattr(args, key, value)
