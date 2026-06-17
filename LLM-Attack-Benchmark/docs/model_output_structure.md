# Model Output Folder Structure

每次 benchmark 產生報告後，`reports/<run_id>/models/<model_name>/` 會保存該模型的完整輸出。

## 目錄內容

```text
reports/<run_id>/models/<model_name>/
├── raw_rounds/
│   ├── run_001.csv
│   ├── run_002.csv
│   └── ...
├── total_table.csv
├── raw_results.csv
├── summary_total.csv
├── summary_by_attack.csv
├── summary_by_prompt_style.csv
├── summary_by_leak_level.csv
├── charts/
│   ├── score_by_attack.png
│   ├── leak_rate_by_attack.png
│   ├── critical_leak_rate_by_attack.png
│   ├── score_by_prompt_style.png
│   ├── leak_rate_by_prompt_style.png
│   ├── critical_leak_rate_by_prompt_style.png
│   ├── leak_level_distribution.png
│   └── radar_prompt_style.png
└── model_report.md
```

## 檔案意義

| 檔案 | 說明 |
|---|---|
| `raw_rounds/run_XXX.csv` | 每一輪的原始模型回應與評分結果 |
| `total_table.csv` | 該模型所有輪次合併後的總表 |
| `raw_results.csv` | 舊版相容用，內容同 `total_table.csv` |
| `summary_total.csv` | 該模型整體統計 |
| `summary_by_attack.csv` | 依攻擊手法彙總，可用來看 Top attack |
| `summary_by_prompt_style.csv` | 依語言/提示風格彙總 |
| `charts/*.png` | 由該模型總表與 summary 表生成的圖 |
| `model_report.md` | 該模型的 Markdown 報告 |

## 設計目的

這個結構讓每個模型都能獨立檢查：

1. 每一輪原始資料。
2. 合併後總表。
3. 以總表與彙總表產生的圖。
4. 單模型報告。

這樣比較原版模型與量化模型時，可以直接打開各自的模型資料夾檢查。
