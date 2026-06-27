# Google Sheets Sync

本功能用來把實驗產生的 `reports/*` 結果同步到 Google 試算表，方便老師、組員或不同 Host 共同檢視結果。

## 設計原則

這個功能是**報表同步層**，不會改變：

- attack prompt
- defense/scoring 邏輯
- leak detector
- 模型推論參數
- 原本輸出的 CSV / MD / PNG 報表

建議流程是：

```text
run_benchmark.py / quant_eval.py → 產生 reports 資料夾 → 同步 CSV/JSON 到 Google Sheets
```

## 需要準備

### 1. 安裝選用套件

```bash
pip install -r requirements-google-sheets.txt
```

### 2. 建立 Google Cloud Service Account

1. 到 Google Cloud Console 建立專案。
2. 啟用 Google Sheets API。
3. 建立 Service Account。
4. 建立 JSON key，下載成例如：

```text
credentials/service-account.json
```

### 3. 分享 Google 試算表

打開你的 Google 試算表，將編輯權限分享給 service account email。

service account email 會長得像：

```text
xxxxx@xxxxx.iam.gserviceaccount.com
```

## 使用方式一：實驗跑完後手動同步

同步最新的 `reports/*` 資料夾：

```bash
python src/google_sheets_sync.py ^
  --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM ^
  --credentials credentials/service-account.json
```

指定某個 report 資料夾：

```bash
python src/google_sheets_sync.py ^
  --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM ^
  --credentials credentials/service-account.json ^
  --report-dir reports/run_20260611_120000
```

先檢查會上傳哪些分頁，不真的連線：

```bash
python src/google_sheets_sync.py --report-dir reports/run_20260611_120000 --dry-run
```

## 使用方式二：跑 benchmark 後自動同步

```bash
python src/run_benchmark.py ^
  --model ollama:gemma3:12b ^
  --attacks attacks/attacks_v2_enterprise.json ^
  --styles all ^
  --runs 1 ^
  --max-tokens 800 ^
  --sync-google-sheets ^
  --google-sheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM ^
  --google-credentials credentials/service-account.json
```

## 使用方式三：量化比較後自動同步

```bash
python src/quant_eval.py ^
  --baseline-model gemma3:12b ^
  --quant-models gemma3:12b-q4_K_M,gemma3:12b-q8_0 ^
  --attacks attacks/attacks_v2_enterprise.json ^
  --styles en_pure ^
  --attack-ids all ^
  --runs 1 ^
  --sync-google-sheets ^
  --google-sheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM ^
  --google-credentials credentials/service-account.json
```

## 會同步哪些分頁

若 report 資料夾內存在以下檔案，會自動同步成同名 worksheet：

| 檔案 | Google Sheets 分頁 | 用途 |
|---|---|---|
| `summary_by_model.csv` | `summary_by_model` | 各模型總體表現 |
| `summary_by_prompt_style.csv` | `summary_by_prompt_style` | 不同語言/風格比較 |
| `summary_by_model_prompt_style.csv` | `summary_by_model_prompt_style` | 模型 × prompt style |
| `summary_by_attack.csv` | `summary_by_attack` | 各 family 的成功/失敗分布 |
| `summary_by_attack_level.csv` | `summary_by_attack_level` | L1~L6 case-level 比較 |
| `summary_by_target_hint.csv` | `summary_by_target_hint` | value / metadata / policy 比較 |
| `summary_by_family_level.csv` | `summary_by_family_level` | family × level 比較 |
| `summary_by_attack_case.csv` | `summary_by_attack_case` | 每個 attack_id 的 case-level 統計 |
| `case_results_all.csv` | `case_results_all` | 正式 case-level 結果 |
| `rerun_list.csv` | `rerun_list` | 需要重跑或人工檢查的案例 |
| `experiment_metadata.csv` | `experiment_metadata` | 模型、環境與參數 metadata |
| `raw_results_all.csv` | `raw_results_all` | 完整 turn-level 原始結果，主要用於 evidence/debug |
| `quant_model_summary.csv` | `quant_model_summary` | 量化模型總表 |
| `quant_pairwise_comparison.csv` | `quant_pairwise_comparison` | 原版 vs 量化逐案比較 |
| `human_review_template.csv` | `human_review_template` | 建議人工檢查案例 |
| `experiment_config.json` | `experiment_config` | 量化實驗設定 |
| `model_metadata_manifest.json` | `model_metadata_manifest` | 模型 metadata manifest |

## 模式

### replace，預設

每次同步都清空並重寫分頁。

適合：正式報表、彙整報表、給老師看的版本。

```bash
python src/google_sheets_sync.py --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM --credentials credentials/service-account.json --mode replace
```

### append

將資料追加到既有 worksheet 後面。

適合：多台 Host 分批回收 raw CSV，但要小心重複資料。

```bash
python src/google_sheets_sync.py --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM --credentials credentials/service-account.json --mode append --files results/results_xxx.csv
```

## raw_results_all 太大怎麼辦

可以加上 `--no-raw`，只同步 summary 表。

```bash
python src/google_sheets_sync.py ^
  --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM ^
  --credentials credentials/service-account.json ^
  --no-raw
```

## 常見錯誤

### Missing Google service account credential JSON

代表沒有提供 service account JSON。

修正：

```bash
python src/google_sheets_sync.py --credentials credentials/service-account.json --spreadsheet-id 1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM
```

### Google Sheets sync requires optional packages

代表尚未安裝 Google Sheets 選用套件。

修正：

```bash
pip install -r requirements-google-sheets.txt
```

### The caller does not have permission

代表你沒有把 Google 試算表分享給 service account email。

修正：

1. 打開 Google 試算表。
2. 按分享。
3. 輸入 service account email。
4. 權限設為 Editor。

## 建議用法

正式實驗建議用：

```text
replace mode + --no-raw 關閉 raw 大表
```

也就是先把 summary 同步給老師看，raw CSV 保留在本地或 GitHub/USB 中。等需要人工查證時，再同步 `raw_results_all.csv` 或 `human_review_template.csv`。
