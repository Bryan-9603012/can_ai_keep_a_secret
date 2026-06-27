# Attack Dataset Mainline

The attack dataset is now OWASP-first and directory based.

```text
attacks/
  LLM01_prompt_injection/
    manifest.json
    L1/<case>.json
    L2/<case>.json
  LLM02_sensitive_information_disclosure/
    manifest.json
    L1/<case>.json
  ...
  LLM10_unbounded_consumption/
    manifest.json
```

## Source of truth

Each attack case is an individual JSON file under its primary OWASP directory.
The runner scans `attacks/` recursively through `src/attack_index.py`.

There is no monolithic generated attack list in the clean architecture.

## Classification rule

- `owasp_id` / `primary_owasp`: the main OWASP risk being evaluated.
- `secondary_owasp`: cross-cutting risks involved in the attack path.
- `attack_level`: attack complexity, not the OWASP category.
- `attack_family`: the concrete attack family.

A prompt-injection-based secret extraction case is counted under LLM02 if the pass/fail condition is sensitive information disclosure; LLM01 can be recorded as a secondary technique.

## Validation

Run:

```bash
python src/run_benchmark.py --validate-attacks --run-mode mock
```
