# LLM Attack Benchmark 多模型自動化測試
# 支援批量測試多個模型

param(
    [string[]]$Models = @("mock"),
    [switch]$All = $false,
    [switch]$Parallel = $false,
    [switch]$CombinedReport = $false,
    [switch]$Help = $false
)

# 設置顏色輸出
function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[•] $Message" -ForegroundColor Cyan
}

function Write-Header {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# 加載配置
function Load-Config {
    $ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $configPath = Join-Path (Join-Path $ProjectRoot "configs") "automation_config.json"
    
    if (Test-Path $configPath) {
        Write-Info "加載配置: $configPath"
        $config = Get-Content $configPath | ConvertFrom-Json
        return $config
    } else {
        Write-Warning "配置文件未找到: $configPath"
        return $null
    }
}

# 顯示幫助
function Show-Help {
    Write-Host @"
LLM Attack Benchmark 多模型自動化測試工具

用法:
  .\run_multi_models.ps1 [選項] [-Models <model1> <model2> ...]

選項:
  -Models <model1> <model2> ...  指定要測試的模型列表
  -All                            測試所有啟用的模型
  -Parallel                       並行執行測試 (實驗性)
  -CombinedReport                 生成合併報告
  -Help                           顯示此幫助信息

模型:
  - mock                          模擬模型
  - ollama:llama2                Ollama Llama 2
  - ollama:mistral               Ollama Mistral
  - ollama:neural-chat           Ollama Neural Chat

範例:
  .\run_multi_models.ps1 -Models mock, "ollama:llama2"
  .\run_multi_models.ps1 -All
  .\run_multi_models.ps1 -All -CombinedReport
  .\run_multi_models.ps1 -Parallel -Models mock, "ollama:mistral"

"@ -ForegroundColor White
}

# 主程式邏輯
try {
    if ($Help) {
        Show-Help
        exit 0
    }
    
    $ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RunScriptPath = Join-Path $ProjectRoot "run.ps1"
    
    if (-not (Test-Path $RunScriptPath)) {
        Write-Error "主自動化腳本未找到: $RunScriptPath"
        exit 1
    }
    
    $config = Load-Config
    
    # 決定要測試的模型
    $modelsToTest = @()
    
    if ($All) {
        Write-Info "測試所有啟用的模型..."
        if ($config) {
            $modelsToTest = $config.automation.models | 
                            Where-Object { $_.enabled -eq $true } | 
                            Select-Object -ExpandProperty name
        } else {
            $modelsToTest = @("mock")
        }
    } else {
        $modelsToTest = $Models
    }
    
    if ($modelsToTest.Count -eq 0) {
        Write-Error "未指定任何模型"
        Show-Help
        exit 1
    }
    
    Write-Header "🚀 多模型自動化測試"
    Write-Info "要測試的模型: $($modelsToTest -join ', ')"
    Write-Info "並行模式: $(if ($Parallel) { '啟用' } else { '禁用' })"
    
    # 測試並統計結果
    $results = @()
    $startTime = Get-Date
    
    foreach ($model in $modelsToTest) {
        Write-Header "🧪 測試模型: $model"
        
        $modelStartTime = Get-Date
        
        # 執行完整流程
        & $RunScriptPath -Full -Model $model
        
        $modelEndTime = Get-Date
        $modelDuration = ($modelEndTime - $modelStartTime).TotalSeconds
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "模型測試完成: $model (耗時: ${modelDuration}秒)"
            $results += @{
                model = $model
                status = "成功"
                duration = $modelDuration
                timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        } else {
            Write-Error "模型測試失敗: $model"
            $results += @{
                model = $model
                status = "失敗"
                duration = $modelDuration
                timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    $endTime = Get-Date
    $totalDuration = ($endTime - $startTime).TotalSeconds
    
    # 顯示總結
    Write-Header "📊 測試總結"
    
    Write-Info "測試結果："
    $results | ForEach-Object {
        $statusSymbol = if ($_.status -eq "成功") { "✓" } else { "✗" }
        $statusColor = if ($_.status -eq "成功") { "Green" } else { "Red" }
        Write-Host "  [$statusSymbol] $($_.model)" -ForegroundColor $statusColor
        Write-Host "      狀態: $($_.status)" -ForegroundColor $statusColor
        Write-Host "      耗時: $([math]::Round($_.duration, 2))秒" -ForegroundColor Gray
    }
    
    $successCount = ($results | Where-Object { $_.status -eq "成功" }).Count
    $failureCount = ($results | Where-Object { $_.status -eq "失敗" }).Count
    
    Write-Host "`n總計: $successCount 成功, $failureCount 失敗" -ForegroundColor Yellow
    Write-Host "總耗時: $([math]::Round($totalDuration, 2))秒" -ForegroundColor Yellow
    
    # 生成合併報告
    if ($CombinedReport -and $successCount -gt 0) {
        Write-Header "📋 生成合併報告"
        Write-Info "合併所有測試報告..."
        
        $reportsPath = Join-Path $ProjectRoot "reports"
        $resultsPath = Join-Path $ProjectRoot "results"
        $combinedReportPath = Join-Path $reportsPath "combined_report.md"
        
        $reportContent = @()
        $reportContent += "# LLM Attack Benchmark 合併測試報告"
        $reportContent += ""
        $reportContent += "| 模型 | 狀態 | 耗時 (秒) | 時間戳 |"
        $reportContent += "|------|------|-----------|---------|"
        
        $results | ForEach-Object {
            $reportContent += "| $($_.model) | $($_.status) | $([math]::Round($_.duration, 2)) | $($_.timestamp) |"
        }
        
        $reportContent += ""
        $reportContent += "## 統計"
        $reportContent += ""
        $reportContent += "- 總模型數: $($modelsToTest.Count)"
        $reportContent += "- 成功: $successCount"
        $reportContent += "- 失敗: $failureCount"
        $reportContent += "- 總耗時: $([math]::Round($totalDuration, 2))秒"
        $reportContent += ""
        $reportContent += "---"
        $reportContent += "生成時間: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        $reportContent | Out-File -FilePath $combinedReportPath -Encoding UTF8
        Write-Success "合併報告已生成: $combinedReportPath"
    }
    
    Write-Host "`n✨ 多模型測試完成！" -ForegroundColor Magenta
    exit 0
}
catch {
    Write-Error "發生錯誤: $_"
    exit 1
}
