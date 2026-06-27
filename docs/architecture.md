# Architecture

目前主線為 Direct LLM Attack Benchmark。

```text
configs + attacks + prompts + protected data
        ↓
src/run_benchmark.py
        ↓
results/*.csv
        ↓
src/report_generator.py
        ↓
reports/<run_id>/
```

## Default files

- Attack set: `attacks/attacks_v2_enterprise.json`
- Protected data: `data/protected_data.txt`
- System prompt: `prompts/system_prompt.txt`
- Model groups: `configs/model_groups.json`
- Model list: `configs/model_list.txt`
