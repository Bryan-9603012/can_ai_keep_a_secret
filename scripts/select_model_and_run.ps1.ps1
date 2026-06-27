param(
    [string]$DistroName = "Ubuntu",
    [switch]$SkipBenchmark,
    [switch]$SkipReport
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

$BaseUrl = "http://localhost:11434"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message ==" -ForegroundColor Cyan
}

function Invoke-WslBash {
    param(
        [string]$Command
    )

    & wsl.exe -d $DistroName -e bash -lc $Command
}

function Get-LocalOllamaModels {
    try {
        $response = Invoke-RestMethod -Uri "$BaseUrl/api/tags" -TimeoutSec 5

        if ($null -eq $response.models) {
            return @()
        }

        return @($response.models | ForEach-Object { $_.name })
    }
    catch {
        return @()
    }
}

function Pull-OllamaModel {
    param([string]$ModelName)

    Write-Host ""
    Write-Host "Downloading model: $ModelName" -ForegroundColor Yellow

    Invoke-WslBash "ollama pull '$ModelName'"

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to download model: $ModelName"
    }

    Write-Host "Model downloaded: $ModelName" -ForegroundColor Green
}

function Select-ExistingModel {
    param([array]$Models)

    if ($Models.Count -eq 0) {
        Write-Host "No local Ollama models found." -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    Write-Host "Local Ollama models:" -ForegroundColor Green

    for ($i = 0; $i -lt $Models.Count; $i++) {
        $index = $i + 1
        Write-Host "[$index] $($Models[$i])"
    }

    Write-Host ""
    $choice = Read-Host "請輸入要測試的模型編號"

    if (-not ($choice -as [int])) {
        Write-Host "Invalid input." -ForegroundColor Red
        return $null
    }

    $choiceNumber = [int]$choice

    if ($choiceNumber -lt 1 -or $choiceNumber -gt $Models.Count) {
        Write-Host "Invalid model number." -ForegroundColor Red
        return $null
    }

    return $Models[$choiceNumber - 1]
}

Write-Step "Step 1: Check WSL / Ubuntu / Ollama"

$checkScript = Join-Path $PSScriptRoot "check_wsl_ubuntu_ollama.ps1"

if (-not (Test-Path $checkScript)) {
    throw "Missing script: $checkScript. Please create check_wsl_ubuntu_ollama.ps1 first."
}

& $checkScript -DistroName $DistroName -InstallOllama -StartOllama

Write-Step "Step 2: Choose model"

$localModels = Get-LocalOllamaModels

Write-Host ""
Write-Host "請選擇操作：" -ForegroundColor Cyan
Write-Host "[1] 使用本地已下載模型"
Write-Host "[2] 輸入新的模型名稱並下載"
Write-Host "[3] 只輸入模型名稱，不下載，直接測試"

$mode = Read-Host "請輸入選項 1 / 2 / 3"

$selectedModel = $null

switch ($mode) {
    "1" {
        $selectedModel = Select-ExistingModel -Models $localModels

        if (-not $selectedModel) {
            Write-Host "No model selected." -ForegroundColor Red
            exit 1
        }
    }

    "2" {
        $newModel = Read-Host "請輸入要下載的 Ollama 模型名稱，例如 llama3.2:1b 或 qwen2.5:3b"

        if ([string]::IsNullOrWhiteSpace($newModel)) {
            Write-Host "Model name cannot be empty." -ForegroundColor Red
            exit 1
        }

        Pull-OllamaModel -ModelName $newModel
        $selectedModel = $newModel
    }

    "3" {
        $manualModel = Read-Host "請輸入要測試的 Ollama 模型名稱，例如 llama3.2:1b"

        if ([string]::IsNullOrWhiteSpace($manualModel)) {
            Write-Host "Model name cannot be empty." -ForegroundColor Red
            exit 1
        }

        $selectedModel = $manualModel
    }

    default {
        Write-Host "Invalid option." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Selected model: $selectedModel" -ForegroundColor Green

if (-not $SkipBenchmark) {
    Write-Step "Step 3: Run benchmark"

    python src/run_benchmark.py --model "ollama:$selectedModel"

    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark failed."
    }
}

if (-not $SkipReport) {
    Write-Step "Step 4: Generate report"

    python src/report_generator.py

    if ($LASTEXITCODE -ne 0) {
        throw "Report generation failed."
    }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Results folder: results/"
Write-Host "Reports folder: reports/"