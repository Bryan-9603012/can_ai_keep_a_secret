# UI Optimization Report

## Goal

Reduce confusion in the interactive terminal UI while keeping the current research mainline:

```text
A01~A20 family × L1~L6 escalation level × 4 language variants
```

## Main changes

### 1. Main menu simplified

Before, model group testing, single model testing, and quant evaluation were listed without a clear priority.  
Now the menu starts with the most common workflow:

1. Single model benchmark
2. Small model group benchmark
3. Medium model group benchmark
4. Quantized comparison
5. Model group management
6. Exit

### 2. Test scope menu rewritten around research workflows

The old menu exposed overlapping concepts such as language test, level test, attack test, and custom test.  
The new menu is organized by the actual experimental question:

- Quick L1 baseline: `A01~A20 × L1 × English`
- Single level slice: `A01~A20 × selected Lx × selected languages`
- Family ladder: `selected Axx × L1~L6 × selected languages`
- Family + level: `selected Axx × selected Lx × selected languages`
- Full official: `20 × 6 × 4 = 480 cases`
- Advanced custom

### 3. Attack level descriptions added

The level selector now displays clear labels:

- L1 Direct Ask
- L2 Role / Authority Override
- L3 Enterprise Camouflage
- L4 Structured Output
- L5 Encoding / Transformation
- L6 Stateful Multi-turn / Trigger

### 4. Family list made readable

The family selector now shows:

```text
ID    Target     Family
A01   Value      Protected Core Value
A08   Metadata   Field Inventory
A14   Policy     System Prompt Text
```

This makes it easier to choose attacks by research target.

### 5. Scope confirmation added

Before running, the UI now shows:

- selected families
- selected levels
- selected languages
- base limit
- estimated case count

This reduces accidental full 480-case runs.

### 6. Final execution confirmation added

After model, scope, max_tokens, and runs are selected, the UI asks for final confirmation before execution.

## Files changed

- `semi_auto_ollama.py`

## Validation

Executed:

```bash
python -m py_compile semi_auto_ollama.py src/run_benchmark.py src/quant_eval.py
python -m pytest -q tests/test_attack_level_filters.py tests/test_attacks_main.py tests/test_leak_detector.py
```

Result:

```text
11 passed
```
