# Local / Cloud Runner

The benchmark runner reads attack cases from the clean OWASP-first attack directory.

## Local Ollama example

```bash
python src/run_benchmark.py \
  --model gemma3:12b \
  --model-source local \
  --attacks attacks \
  --styles en_pure \
  --attack-levels L1 \
  --owasp-types all \
  --max-tokens 350 \
  --runs 1
```

## Cloud API example

```bash
python src/run_benchmark.py \
  --model openai-compatible:MODEL_ID \
  --model-source cloud \
  --base-url https://example.com/v1 \
  --api-key-env OPENAI_API_KEY \
  --attacks attacks \
  --styles en_pure \
  --max-tokens 350
```

## Preflight

```bash
python src/run_benchmark.py --validate-attacks --run-mode mock
python src/run_benchmark.py --preset quick_formal --dry-run
python src/run_benchmark.py --preset mock_smoke
```
