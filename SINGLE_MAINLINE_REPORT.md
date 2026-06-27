# Single Mainline Refactor Report

This package keeps one production attack mainline only.

## Mainline

- `attacks/attack_families.json`
- `attacks/attacks_main.json`
- `src/generate_attacks_main.py`

The dataset shape is:

```text
20 attack families × 6 escalation levels × 4 language variants = 480 cases
```

## Preserved UI / interactive entry points

- `semi_auto_ollama.py`
- `install_and_run.bat`
- `install_and_run.ps1`
- `run_attacks_main.bat`
- `run_attacks_main.ps1`
- `run_multi_models.ps1`

## Removed from the package

- old `attacks_v2_enterprise.json` production dataset
- family-ladder prototype/example files
- attack archive
- docs archive
- old v2 dataset test file
- obvious cache / git folders

## Current runner default

`src/run_benchmark.py` now defaults to:

```text
attacks/attacks_main.json
```
