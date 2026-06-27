# 🚀 快速啟動指南

## Windows 環境自動化 (完整版本 - 含 WSL/Ollama 檢查)

本專案已配置完整的自動化工具，包括依賴檢查與自動安裝。

---

## ⚡ 推薦快速開始流程 (5-10 分鐘)

### 第一步：檢查依賴
```cmd
run.bat -CheckDeps
```

檢查結果範例：
```
依賴檢查結果:
────────────────────────
  [✓] Python        ← 必需
  [!] WSL 2         ← 可選
  [!] Ollama        ← 可選
────────────────────────
```

### 第二步：自動安裝缺失的依賴
```cmd
run.bat -AutoInstall
```

此命令會詢問：
- 是否安裝 WSL 2? (用於 Ollama)
- 是否安裝 Ollama? (用於本地模型測試)

### 第三步：完整自動化測試
```cmd
run.bat -Full
```

完成後查看報告：
```cmd
start reports\report_mock.md
```

---

## ⚡ 最少要求版本 (3 秒 - 僅 Mock)

如果您只想快速測試 Mock 模型，無需安裝 WSL/Ollama：

```cmd
run.bat -Full
```

完成！會自動：
1. ✓ 檢查 Python
2. ✓ 建立虛擬環境
3. ✓ 安裝依賴
4. ✓ 運行 mock 測試
5. ✓ 生成報告

---

## 📚 詳細文檔

### 主要自動化指南
📖 查看 [AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md) 了解所有選項

### 快速參考

| 任務 | 命令 |
|------|------|
| **檢查依賴** | `run.bat -CheckDeps` |
| **自動安裝依賴** | `run.bat -AutoInstall` |
| **完整流程 (推薦)** | `run.bat -Full` |
| 僅安裝環境 | `run.bat -Setup` |
| 運行測試 | `run.bat -Test` |
| 生成報告 | `run.bat -Report` |
| 清理輸出 | `run.bat -Clean` |
| 列出 Ollama 模型 | `run.bat -ListModels` |
| 顯示幫助 | `run.bat -Help` |

---

## 🎯 常見場景

### 📊 首次使用 (推薦 - 完整流程)
```cmd
# 1. 檢查依賴
run.bat -CheckDeps

# 2. 自動安裝缺失的依賴
run.bat -AutoInstall

# 3. 完整測試 (約 2-5 秒)
run.bat -Full

# 4. 查看報告
start reports\report_mock.md
```

### ⚡ 只要快速測試？
```cmd
run.bat -Full
```

### 🔄 定期更新測試
```cmd
# 清理舊結果
run.bat -Clean

# 重新測試
run.bat -Test

# 生成新報告
run.bat -Report
```

### 🧪 測試 Ollama 本地模型 (需要 10GB+ 磁盤)
```powershell
# 1. 確保已安裝 Ollama
run.bat -CheckDeps

# 2. 如果未安裝，自動安裝
run.bat -AutoInstall

# 3. 列出已安裝的模型
.\run.ps1 -ListModels

# 4. 測試特定模型
.\run.ps1 -Full -Model ollama:llama2

# 5. 或批量測試所有模型
.\run_multi_models.ps1 -All -CombinedReport
```

### 💬 互動式手動測試
```cmd
python src/main.py --model mock
```

---

## 📦 依賴說明

| 依賴 | 必需? | 用途 | 狀態 |
|------|------|------|------|
| **Python 3.8+** | ✅ 是 | 運行主程序 | 必須安裝 |
| **WSL 2** | ❌ 否 | 運行 Ollama | 可選 |
| **Ollama** | ❌ 否 | 本地模型 | 可選 |

### 快速檢查
```cmd
python --version      # ✓ 應該顯示 Python 3.8+
wsl --version         # 檢查 WSL (可選)
ollama --version      # 檢查 Ollama (可選)
```

---

## ✅ 系統要求

- ✅ Windows 10 或更新版本
- ✅ Python 3.8+ (已安裝)
- ✅ 互聯網連接 (下載依賴)
- ✅ 500 MB+ 磁盤空間 (Mock 模型)
- ⚠️ 5-40 GB 磁盤空間 (Ollama 模型 - 可選)

---

## 🆘 遇到問題?

### ❌ Python 找不到
```cmd
python --version
```

如果返回 "python 不是內部命令"：
1. 下載 Python: https://www.python.org/downloads/
2. **重要**: 安裝時勾選 "Add Python to PATH"
3. 重啟命令提示字元
4. 再試一遍

### ❌ 執行策略錯誤 (PowerShell)
```
PowerShell 指令碼在此系統上執行被停用
```

解決方案：
```powershell
# 以管理員身份打開 PowerShell，執行：
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### ❌ WSL 安裝失敗
需要管理員權限：
```powershell
# 右鍵點擊 PowerShell → "以管理員身份執行"
run.bat -InstallWsl
```

### ❌ Ollama 連接失敗
確保 Ollama 正在運行：
1. 打開 Ollama 應用
2. 或在終端機運行: `ollama serve`

### ✅ 更多幫助
```cmd
run.bat -Help
```

查看 [AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md) 的 "故障排除" 章節

---

## 📁 生成的文件位置

```
項目根目錄/
├── venv/              # Python 虛擬環境
├── results/           # 測試結果 (CSV)
│   └── results_mock.csv
├── reports/           # 測試報告 (Markdown)
│   └── report_mock.md
└── logs/              # 詳細日誌 (可選)
```

### 快速查看報告
```cmd
start reports\report_mock.md
```

---

## 🔧 高級選項

### 手動安裝特定依賴
```cmd
run.bat -InstallWsl      # 安裝 WSL
run.bat -InstallOllama   # 安裝 Ollama
run.bat -ListModels      # 列出 Ollama 模型
```

### 使用 PowerShell 獲得更多控制
```powershell
.\run.ps1 -CheckDeps                    # 詳細依賴檢查
.\run.ps1 -Full -Model ollama:llama2    # 指定模型
.\run_multi_models.ps1 -All             # 批量測試
```

### 進階配置
查看 [AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md) 的 "進階配置" 章節

---

## 💡 使用技巧

1. **首次運行**: 使用 `-CheckDeps` 檢查環境，然後 `-AutoInstall`
2. **日常測試**: 直接 `run.bat -Full` (約 5-10 秒)
3. **多模型測試**: 使用 `.\run_multi_models.ps1 -All`
4. **遇到問題**: 查看 [AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md)

---

## 📞 需要幫助?

| 問題 | 查看 |
|------|------|
| 依賴安裝 | [AUTOMATION_GUIDE.md - 依賴檢查和安裝](AUTOMATION_GUIDE.md#-依賴檢查和安裝) |
| 故障排除 | [AUTOMATION_GUIDE.md - 故障排除](AUTOMATION_GUIDE.md#-故障排除) |
| 常見問題 | [AUTOMATION_GUIDE.md - 常見問題](AUTOMATION_GUIDE.md#-常見問題) |
| 所有命令 | [AUTOMATION_GUIDE.md - 所有可用命令](AUTOMATION_GUIDE.md#-所有可用命令) |

---

**🎯 立即開始**:
```cmd
run.bat -CheckDeps
run.bat -AutoInstall  
run.bat -Full
```

完成後檢查報告 → `start reports\report_mock.md`


## Attack level filter

You can restrict one benchmark round to specific escalation levels. Examples:

```bash
python src/run_benchmark.py --attack-levels L3
python src/run_benchmark.py --attack-levels L1,L2,L3
python src/run_benchmark.py --attack-levels all
```
