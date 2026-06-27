param(
    [string]$Model = "mock",
    [switch]$Setup,
    [switch]$Test,
    [switch]$Report,
    [switch]$Full,
    [switch]$Clean,
    [switch]$CheckDeps,
    [switch]$InstallWsl,
    [switch]$InstallOllama,
    [switch]$AutoInstall,
    [switch]$ListModels,
    [switch]$Interactive,
    [switch]$BatchTest,
    [switch]$SingleTest,
    [switch]$Help
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $ProjectRoot "venv"
$PythonVenv = Join-Path $VenvPath "Scripts\python.exe"
$PipVenv = Join-Path $VenvPath "Scripts\pip.exe"

function Write-OK { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-FAIL { Write-Host "[FAIL]  $args" -ForegroundColor Red }
function Write-INFO { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-WARN { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Header { Write-Host "`n========================================`n$args`n========================================`n" -ForegroundColor Yellow }

function Test-Python {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pythonCmd) { return $false }
    return $true
}

function Test-WSL {
    $wslCmd = Get-Command wsl -ErrorAction SilentlyContinue
    if ($null -ne $wslCmd) { return $true }
    return $false
}

function Test-Ollama {
    $ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($null -ne $ollamaCmd) { return $true }
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) { return $true }
    }
    catch { }
    return $false
}

function Check-Dependencies {
    Write-Header "Dependency Check"
    $pythonOk = Test-Python
    $wslOk = Test-WSL
    $ollamaOk = Test-Ollama
    Write-Host "Status:" -ForegroundColor Cyan
    Write-Host "────────────────────"
    if ($pythonOk) { Write-OK "Python" } else { Write-FAIL "Python" }
    if ($wslOk) { Write-OK "WSL 2" } else { Write-WARN "WSL 2 (Optional)" }
    if ($ollamaOk) { Write-OK "Ollama" } else { Write-WARN "Ollama (Optional)" }
    Write-Host "────────────────────`n"
}

function Install-WSL {
    Write-Header "Installing WSL2"
    Write-INFO "Enabling WSL features..."
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) { Write-FAIL "Requires Administrator"; exit 1 }
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        Write-OK "WSL features enabled"
        Write-WARN "Please restart and run again"
    }
    catch { Write-FAIL "Installation failed: $_" }
}

function Install-Ollama {
    Write-Header "Installing Ollama"
    if (Test-Ollama) { Write-INFO "Ollama already installed"; return }
    Write-INFO "Downloading installer..."
    try {
        $tempPath = Join-Path $env:TEMP "OllamaSetup.exe"
        Invoke-WebRequest -Uri "https://ollama.ai/download/OllamaSetup.exe" -OutFile $tempPath -TimeoutSec 30
        if (Test-Path $tempPath) {
            Write-OK "Download complete"
            & $tempPath
            Write-OK "Installer started"
        }
    }
    catch { Write-FAIL "Download failed: $_" }
}

function List-OllamaModels {
    Write-Header "Installed Ollama Models"
    if (-not (Test-Ollama)) { Write-FAIL "Ollama not available"; return @() }
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 5 -UseBasicParsing | ConvertFrom-Json
        if ($response.models.Count -eq 0) {
            Write-WARN "No models installed"
            return @()
        } else {
            Write-OK "Installed:"
            $response.models | ForEach-Object {
                $size = if ($_.size) { ([math]::Round($_.size / 1GB, 2)).ToString() + " GB" } else { "Unknown" }
                Write-Host "  * $($_.name) ($size)" -ForegroundColor Green
            }
            return $response.models
        }
    }
    catch { Write-FAIL "Cannot connect to Ollama"; return @() }
}

function Get-InstalledOllamaModels {
    if (-not (Test-Ollama)) { return @() }
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 5 -UseBasicParsing | ConvertFrom-Json
        return $response.models | Select-Object -ExpandProperty name
    }
    catch { return @() }
}

function Download-OllamaModel {
    param([string]$ModelName)
    Write-Header "Downloading Model"
    if (-not (Test-Ollama)) { Write-FAIL "Ollama not available"; return $false }
    Write-INFO "Downloading: $ModelName"
    Write-INFO "This may take several minutes..."
    try {
        & ollama pull $ModelName
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Model downloaded successfully"
            return $true
        } else {
            Write-FAIL "Download failed"
            return $false
        }
    }
    catch { Write-FAIL "Error: $_"; return $false }
}

function Show-ModelSelectionMenu {
    Write-Header "Model Selection"
    Write-Host "Available models:" -ForegroundColor Cyan
    Write-Host "  1) mock (Built-in, fast)" -ForegroundColor Green
    
    $installedModels = Get-InstalledOllamaModels
    if ($installedModels.Count -gt 0) {
        Write-Host "`n  Installed Ollama Models:" -ForegroundColor Cyan
        $i = 2
        foreach ($model in $installedModels) {
            Write-Host "  $i) $model" -ForegroundColor Green
            $i++
        }
        $modelMap = @("mock") + $installedModels
    } else {
        $modelMap = @("mock")
    }
    
    Write-Host "`n  99) Download new model" -ForegroundColor Yellow
    Write-Host "  0)  Exit" -ForegroundColor Yellow
    
    $choice = Read-Host "`nSelect model (number)"
    
    if ($choice -eq "99") {
        $newModel = Read-Host "Enter model name (e.g., llama2, mistral, neural-chat)"
        if ($newModel) {
            $success = Download-OllamaModel -ModelName $newModel
            if ($success) {
                return "ollama:$newModel"
            } else {
                Write-FAIL "Failed to download model"
                return ""
            }
        }
        return ""
    } elseif ($choice -eq "0") {
        return ""
    } elseif ([int]$choice -ge 1 -and [int]$choice -lt $modelMap.Count + 1) {
        $selectedModel = $modelMap[[int]$choice - 1]
        if ($selectedModel -eq "mock") {
            return "mock"
        } else {
            return "ollama:$selectedModel"
        }
    } else {
        Write-FAIL "Invalid selection"
        return ""
    }
}

function Interactive-SingleTest {
    Write-Header "Single Model Test"
    $model = Show-ModelSelectionMenu
    if ([string]::IsNullOrEmpty($model)) {
        Write-WARN "No model selected"
        return
    }
    
    Write-INFO "Setup environment..."
    New-VirtualEnvironment
    Install-Dependencies
    
    Write-INFO "Starting benchmark..."
    Run-Benchmark -ModelName $model
    
    Write-INFO "Generating report..."
    Generate-Report
    
    Write-Header "Complete!"
    Write-OK "Test finished for model: $model"
}

function Interactive-BatchTest {
    Write-Header "Batch Model Test"
    
    $models = @("mock")
    $installedModels = Get-InstalledOllamaModels
    if ($installedModels.Count -gt 0) {
        $models += $installedModels | ForEach-Object { "ollama:$_" }
    }
    
    Write-Host "Available models to test:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $models.Count; $i++) {
        $checked = "[  ]"
        Write-Host "  $checked $($i+1). $($models[$i])" -ForegroundColor Green
    }
    
    Write-Host "`nEnter model numbers to test (comma-separated, e.g., 1,2,3 or 'all'):" -ForegroundColor Yellow
    $selection = Read-Host "Selection"
    
    $selectedModels = @()
    if ($selection.ToLower() -eq "all") {
        $selectedModels = $models
    } else {
        $numbers = $selection -split "," | ForEach-Object { $_.Trim() }
        foreach ($num in $numbers) {
            if ([int]$num -ge 1 -and [int]$num -le $models.Count) {
                $selectedModels += $models[[int]$num - 1]
            }
        }
    }
    
    if ($selectedModels.Count -eq 0) {
        Write-FAIL "No models selected"
        return
    }
    
    Write-INFO "Setup environment..."
    New-VirtualEnvironment
    Install-Dependencies
    
    Write-Header "Starting batch tests"
    $results = @()
    foreach ($model in $selectedModels) {
        Write-INFO "Testing: $model"
        Run-Benchmark -ModelName $model
        $results += $model
    }
    
    Write-INFO "Generating combined report..."
    Generate-Report
    
    Write-Header "Batch Complete!"
    Write-OK "Tested $($results.Count) models"
    $results | ForEach-Object { Write-Host "  * $_" -ForegroundColor Green }
}

function New-VirtualEnvironment {
    Write-Header "Setting up Virtual Environment"
    if (Test-Path $VenvPath) { Write-INFO "Venv already exists"; return }
    Write-INFO "Creating venv..."
    python -m venv $VenvPath
    if ($LASTEXITCODE -eq 0) { Write-OK "Venv created" } else { Write-FAIL "Venv creation failed"; exit 1 }
}

function Install-Dependencies {
    Write-Header "Installing Dependencies"
    $reqFile = Join-Path $ProjectRoot "requirements.txt"
    if (-not (Test-Path $reqFile)) { Write-FAIL "requirements.txt not found"; exit 1 }
    Write-INFO "Installing packages..."
    & $PipVenv install -r $reqFile
    if ($LASTEXITCODE -eq 0) { Write-OK "Dependencies installed" } else { Write-FAIL "Installation failed"; exit 1 }
}

function Run-Benchmark {
    param([string]$ModelName = "mock")
    Write-Header "Running Benchmark"
    Write-INFO "Model: $ModelName"
    $srcPath = Join-Path $ProjectRoot "src"
    $benchPath = Join-Path $srcPath "run_benchmark.py"
    if (-not (Test-Path $benchPath)) { Write-FAIL "Script not found"; exit 1 }
    Push-Location $ProjectRoot
    & $PythonVenv $benchPath --model $ModelName
    if ($LASTEXITCODE -eq 0) { Write-OK "Benchmark complete" } else { Write-FAIL "Benchmark failed"; Pop-Location; exit 1 }
    Pop-Location
}

function Generate-Report {
    Write-Header "Generating Report"
    $srcPath = Join-Path $ProjectRoot "src"
    $repPath = Join-Path $srcPath "report_generator.py"
    if (-not (Test-Path $repPath)) { Write-FAIL "Script not found"; exit 1 }
    Push-Location $ProjectRoot
    & $PythonVenv $repPath
    if ($LASTEXITCODE -eq 0) { Write-OK "Report generated" } else { Write-FAIL "Report failed"; Pop-Location; exit 1 }
    Pop-Location
}

function Clean-Output {
    Write-Header "Cleaning Output"
    $resPath = Join-Path $ProjectRoot "results"
    $repPath = Join-Path $ProjectRoot "reports"
    if (Test-Path $resPath) { Remove-Item (Join-Path $resPath "*") -Force; Write-OK "Results cleaned" }
    if (Test-Path $repPath) { Remove-Item (Join-Path $repPath "*") -Force; Write-OK "Reports cleaned" }
}

function Show-Help {
    @"
LLM Attack Benchmark - Automation Tool

Options:
  -CheckDeps      Check all dependencies
  -AutoInstall    Auto-install missing dependencies
  -InstallWsl     Install WSL
  -InstallOllama  Install Ollama
  -ListModels     List Ollama models
  -Setup          Create venv + install deps
  -Test           Run benchmark
  -Report         Generate report
  -Full           Full workflow (Setup+Test+Report)
  -Clean          Clean output files
  -Model <name>   Specify model (default: mock)
  -Interactive    Launch interactive test menu
  -SingleTest     Single model test (interactive selection)
  -BatchTest      Batch test multiple models
  -Help           Show this help message

Examples:
  .\run.ps1 -CheckDeps
  .\run.ps1 -AutoInstall
  .\run.ps1 -Interactive
  .\run.ps1 -SingleTest
  .\run.ps1 -BatchTest
  .\run.ps1 -Full
  .\run.ps1 -Full -Model ollama:llama2

"@ | Write-Host -ForegroundColor White
}

# Main logic
Write-Host "LLM Attack Benchmark - Automation Tool" -ForegroundColor Magenta
Write-INFO "Project: $ProjectRoot`n"

if ($Help) { Show-Help; exit 0 }
if ($CheckDeps) { Check-Dependencies; exit 0 }
if ($InstallWsl) { Install-WSL; exit 0 }
if ($InstallOllama) { Install-Ollama; exit 0 }
if ($ListModels) { List-OllamaModels; exit 0 }

if ($AutoInstall) {
    Write-Header "Auto-installing"
    if (-not (Test-Python)) { Write-FAIL "Python required"; exit 1 }
    if (-not (Test-WSL)) {
        $choice = Read-Host "Install WSL? (y/n)"
        if ($choice -eq 'y') { Install-WSL }
    }
    if (-not (Test-Ollama)) {
        $choice = Read-Host "Install Ollama? (y/n)"
        if ($choice -eq 'y') { Install-Ollama }
    }
    exit 0
}

# Require Python
if (-not (Test-Python)) { Write-FAIL "Python not found"; exit 1 }

if ($SingleTest) {
    Interactive-SingleTest
    exit 0
}

if ($BatchTest) {
    Interactive-BatchTest
    exit 0
}

if ($Interactive) {
    Write-Header "Test Mode Selection"
    Write-Host "1) Single Model Test (choose one model)" -ForegroundColor Green
    Write-Host "2) Batch Test (test multiple models)" -ForegroundColor Green
    Write-Host "0) Exit" -ForegroundColor Yellow
    
    $mode = Read-Host "`nSelect mode (number)"
    
    if ($mode -eq "1") {
        Interactive-SingleTest
    } elseif ($mode -eq "2") {
        Interactive-BatchTest
    }
    exit 0
}

if ($Full) {
    Write-INFO "Running full workflow...`n"
    if ($Model.StartsWith("ollama:")) {
        if (-not (Test-Ollama)) { Write-FAIL "Ollama not available"; exit 1 }
        List-OllamaModels
    }
    New-VirtualEnvironment
    Install-Dependencies
    Run-Benchmark -ModelName $Model
    Generate-Report
    Write-Header "Complete!"
    Write-OK "Workflow finished"
} else {
    if ($Setup) { New-VirtualEnvironment; Install-Dependencies }
    if ($Test) {
        if ($Model.StartsWith("ollama:")) {
            if (-not (Test-Ollama)) { Write-FAIL "Ollama not available"; exit 1 }
        }
        Run-Benchmark -ModelName $Model
    }
    if ($Report) { Generate-Report }
    if ($Clean) { Clean-Output }
    if (-not ($Setup -or $Test -or $Report -or $Clean -or $CheckDeps -or $AutoInstall -or $SingleTest -or $BatchTest -or $Interactive)) { Show-Help }
}
