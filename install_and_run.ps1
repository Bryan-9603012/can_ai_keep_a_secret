param(
    [switch]$NoRun,
    [switch]$CheckOnly,
    [switch]$SimpleMenu,
    [string]$VenvName = ".venv",
    [string]$OllamaUrl = "http://127.0.0.1:11434"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $ProjectRoot $VenvName
$PythonVenv = Join-Path $VenvPath "Scripts\python.exe"
$RequiredPython = "3.9.6"
$PythonInstallerUrl = "https://www.python.org/ftp/python/$RequiredPython/python-$RequiredPython-amd64.exe"
$PythonInstallDir = Join-Path $env:LOCALAPPDATA "Programs\Python\Python39"

function Write-OK   { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-INFO { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-WARN { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-FAIL { Write-Host "[FAIL]  $args" -ForegroundColor Red }
function Header($t) { Write-Host "`n========================================`n$t`n========================================" -ForegroundColor Yellow }

function Test-Command($name) { return $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }
function Add-PathForCurrentSession($p) { if ((Test-Path $p) -and ($env:Path -notlike "*$p*")) { $env:Path = "$p;$env:Path" } }

function Get-Python396 {
    $candidates = @(
        (Join-Path $PythonInstallDir "python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python396\python.exe"),
        "C:\Python39\python.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            try {
                $v = & $c -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
                if ($v -eq $RequiredPython) { return $c }
            } catch {}
        }
    }
    if (Test-Command "py") {
        try {
            $v = & py -3.9 -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
            if ($v -eq $RequiredPython) { return "py -3.9" }
        } catch {}
    }
    if (Test-Command "python") {
        try {
            $v = & python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
            if ($v -eq $RequiredPython) { return "python" }
        } catch {}
    }
    return $null
}

function Install-Python396 {
    Header "Python $RequiredPython Check"
    $py = Get-Python396
    if ($py) { Write-OK "Python $RequiredPython found: $py"; return $py }

    Write-WARN "Python $RequiredPython not found. It will be installed for current user."
    $installer = Join-Path $env:TEMP "python-$RequiredPython-amd64.exe"
    Write-INFO "Downloading Python installer: $PythonInstallerUrl"
    Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $installer -UseBasicParsing
    if (-not (Test-Path $installer)) { throw "Python installer download failed." }

    Write-INFO "Running Python installer silently..."
    $args = @("/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_test=0", "Include_pip=1", "TargetDir=$PythonInstallDir")
    $p = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Python installer failed. Exit code: $($p.ExitCode)" }
    Add-PathForCurrentSession $PythonInstallDir
    Add-PathForCurrentSession (Join-Path $PythonInstallDir "Scripts")

    $py = Get-Python396
    if (-not $py) { throw "Python $RequiredPython installation finished, but python.exe was not found." }
    Write-OK "Python $RequiredPython installed: $py"
    return $py
}

function Invoke-Python($pythonCmd, $argList) {
    if ($pythonCmd -eq "py -3.9") {
        & py -3.9 @argList
    } elseif ($pythonCmd -eq "python") {
        & python @argList
    } else {
        & $pythonCmd @argList
    }
    return $LASTEXITCODE
}

function Ensure-Venv($pythonCmd) {
    Header "Virtual Environment"
    if ((Test-Path $VenvPath) -and (-not (Test-Path $PythonVenv))) {
        Write-WARN "Broken venv detected. Removing: $VenvPath"
        Remove-Item -Recurse -Force $VenvPath
    }
    if (-not (Test-Path $PythonVenv)) {
        Write-INFO "Creating venv with Python ${RequiredPython}: $VenvName"
        Invoke-Python $pythonCmd @("-m", "venv", $VenvPath) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed." }
    }
    Write-OK "venv ready: $PythonVenv"
    & $PythonVenv --version
}

function Install-Dependencies {
    Header "Python Dependencies"
    & $PythonVenv -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }

    $baseRequirements = Join-Path $ProjectRoot "requirements.txt"
    & $PythonVenv -m pip install -r $baseRequirements
    if ($LASTEXITCODE -ne 0) { throw "requirements installation failed." }

    $googleSheetsRequirements = Join-Path $ProjectRoot "requirements-google-sheets.txt"
    if (Test-Path $googleSheetsRequirements) {
        Write-INFO "Installing optional Google Sheets sync dependencies..."
        & $PythonVenv -m pip install -r $googleSheetsRequirements
        if ($LASTEXITCODE -ne 0) { throw "Google Sheets requirements installation failed." }
        Write-OK "Google Sheets sync dependencies installed."
    } else {
        Write-WARN "requirements-google-sheets.txt not found. Skipping Google Sheets sync dependencies."
    }

    Write-OK "Dependencies installed."
}

function Add-OllamaPaths {
    $paths = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Ollama"),
        (Join-Path $env:LOCALAPPDATA "Ollama"),
        "C:\Program Files\Ollama"
    )
    foreach ($p in $paths) { Add-PathForCurrentSession $p }
}

function Ensure-Ollama {
    Header "Ollama"
    Add-OllamaPaths
    if (-not (Test-Command "ollama")) {
        Write-WARN "Ollama not found. Trying winget install first."
        if (Test-Command "winget") {
            winget install -e --id Ollama.Ollama --accept-package-agreements --accept-source-agreements
            Add-OllamaPaths
        }
    }
    if (-not (Test-Command "ollama")) {
        Write-WARN "winget not available or install failed. Downloading official Ollama installer."
        $installer = Join-Path $env:TEMP "OllamaSetup.exe"
        Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installer -UseBasicParsing
        Start-Process -FilePath $installer -Wait
        Add-OllamaPaths
    }
    if (-not (Test-Command "ollama")) { throw "Ollama installation failed or command is not in PATH." }
    Write-OK "Ollama found."
    ollama --version
}

function Test-OllamaApi {
    try {
        Invoke-WebRequest -Uri ($OllamaUrl.TrimEnd('/') + "/api/tags") -TimeoutSec 5 -UseBasicParsing | Out-Null
        return $true
    } catch { return $false }
}

function Start-OllamaIfNeeded {
    Header "Ollama Server"
    if (Test-OllamaApi) { Write-OK "Ollama API is reachable: $OllamaUrl"; return }
    Write-INFO "Starting ollama serve in a minimized PowerShell window..."
    Start-Process powershell -WindowStyle Minimized -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command ollama serve"
    Start-Sleep -Seconds 5
    if (-not (Test-OllamaApi)) {
        Write-WARN "Ollama API still not reachable. If this persists, open another terminal and run: ollama serve"
    } else {
        Write-OK "Ollama API is reachable."
    }
}

Header "LLM Attack Benchmark One-click Setup"
Write-INFO "Project root: $ProjectRoot"
Set-Location $ProjectRoot
foreach ($folder in @("logs", "reports", "results", "reports\figures")) {
    $p = Join-Path $ProjectRoot $folder
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

$py = Install-Python396
Ensure-Venv $py
Install-Dependencies
Ensure-Ollama
Start-OllamaIfNeeded

if ($CheckOnly) { Write-OK "Check-only finished."; exit 0 }
if ($NoRun) { Write-OK "Install-only finished."; exit 0 }

Header "Launch Tool UI"
$args = @((Join-Path $ProjectRoot "semi_auto_ollama.py"))
if ($SimpleMenu) { $args += "--simple" }
& $PythonVenv @args
exit $LASTEXITCODE
