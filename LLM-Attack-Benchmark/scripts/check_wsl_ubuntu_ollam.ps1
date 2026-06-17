param(
    [string]$DistroName = "Ubuntu",
    [switch]$InstallMissing,
    [switch]$InstallOllama,
    [switch]$StartOllama,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = "Stop"
$BaseUrl = "http://localhost:11434"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message ==" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WslDistros {
    $raw = & wsl.exe -l -q 2>$null

    return $raw |
        ForEach-Object { ($_ -replace "`0", "").Trim() } |
        Where-Object { $_ -ne "" }
}

function Invoke-WslBash {
    param(
        [string]$Distro,
        [string]$Command
    )

    & wsl.exe -d $Distro -e bash -lc $Command
}

function Test-OllamaApiFromWindows {
    try {
        Invoke-RestMethod -Uri "$BaseUrl/api/tags" -TimeoutSec 3 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-OllamaApiFromWsl {
    param([string]$Distro)

    Invoke-WslBash $Distro "curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1"
    return ($LASTEXITCODE -eq 0)
}

Write-Step "Step 1: Check WSL"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Fail "WSL is not installed or wsl.exe is not available."

    if ($InstallMissing) {
        if (-not (Test-Admin)) {
            Write-Fail "Installing WSL requires Administrator PowerShell."
            Write-Host "Please reopen PowerShell as Administrator and run:"
            Write-Host ".\scripts\check_wsl_ubuntu_ollama.ps1 -InstallMissing"
            exit 1
        }

        Write-Warn "Installing WSL and Ubuntu..."
        wsl --install -d $DistroName
        Write-Warn "WSL installation may require reboot. After reboot, run this script again."
        exit 0
    }

    Write-Host "You can install WSL manually with:"
    Write-Host "wsl --install -d Ubuntu"
    exit 1
}

Write-Ok "wsl.exe found."

Write-Step "Step 2: Check Ubuntu distro"

$distros = Get-WslDistros

if (-not $distros -or $distros.Count -eq 0) {
    Write-Warn "No WSL distro found."

    if ($InstallMissing) {
        Write-Warn "Installing Ubuntu..."
        wsl --install -d $DistroName
        Write-Warn "After installation, open Ubuntu once to finish username/password setup, then run this script again."
        exit 0
    }

    Write-Host "Install Ubuntu with:"
    Write-Host "wsl --install -d Ubuntu"
    exit 1
}

$selectedDistro = $null

if ($distros -contains $DistroName) {
    $selectedDistro = $DistroName
}
else {
    $selectedDistro = $distros | Where-Object { $_ -like "Ubuntu*" } | Select-Object -First 1
}

if (-not $selectedDistro) {
    Write-Fail "Ubuntu distro not found."
    Write-Host "Installed distros:"
    $distros | ForEach-Object { Write-Host " - $_" }

    if ($InstallMissing) {
        Write-Warn "Installing Ubuntu..."
        wsl --install -d $DistroName
        Write-Warn "After installation, open Ubuntu once to finish username/password setup, then run this script again."
        exit 0
    }

    exit 1
}

Write-Ok "Using WSL distro: $selectedDistro"

Write-Step "Step 3: Test Ubuntu startup"

Invoke-WslBash $selectedDistro "echo WSL_OK && grep '^PRETTY_NAME=' /etc/os-release"

if ($LASTEXITCODE -ne 0) {
    Write-Fail "Ubuntu failed to start."
    exit 1
}

Write-Ok "Ubuntu is working."

Write-Step "Step 4: Check basic Linux tools"

Invoke-WslBash $selectedDistro "command -v curl >/dev/null 2>&1 && echo curl OK || echo curl MISSING"
Invoke-WslBash $selectedDistro "command -v zstd >/dev/null 2>&1 && echo zstd OK || echo zstd MISSING"

Write-Step "Step 5: Check Ollama command in Ubuntu"

Invoke-WslBash $selectedDistro "command -v ollama >/dev/null 2>&1"

if ($LASTEXITCODE -ne 0) {
    Write-Warn "Ollama is not installed in Ubuntu."

    if ($InstallOllama) {
        Write-Warn "Installing Ollama in Ubuntu..."
        Invoke-WslBash $selectedDistro "sudo apt-get update && sudo apt-get install -y curl zstd && curl -fsSL https://ollama.com/install.sh | sh"

        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Ollama installation failed."
            exit 1
        }

        Write-Ok "Ollama installed."
    }
    else {
        Write-Host "Install Ollama automatically with:"
        Write-Host ".\scripts\check_wsl_ubuntu_ollama.ps1 -InstallOllama"
        exit 1
    }
}
else {
    Write-Ok "Ollama command found in Ubuntu."
}

Write-Step "Step 6: Check Ollama API"

$apiOkWindows = Test-OllamaApiFromWindows
$apiOkWsl = Test-OllamaApiFromWsl $selectedDistro

if ($apiOkWindows) {
    Write-Ok "Ollama API is reachable from Windows: $BaseUrl"
}
else {
    Write-Warn "Ollama API is not reachable from Windows."
}

if ($apiOkWsl) {
    Write-Ok "Ollama API is reachable inside Ubuntu."
}
else {
    Write-Warn "Ollama API is not running inside Ubuntu."
}

if (-not $apiOkWindows -and -not $apiOkWsl) {
    if ($StartOllama) {
        Write-Warn "Starting Ollama in Ubuntu..."

        Invoke-WslBash $selectedDistro "mkdir -p ~/ollama-logs; nohup ollama serve > ~/ollama-logs/ollama.log 2>&1 < /dev/null &"

        $start = Get-Date
        $ready = $false

        while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSec) {
            Start-Sleep -Seconds 2

            $apiOkWindows = Test-OllamaApiFromWindows
            $apiOkWsl = Test-OllamaApiFromWsl $selectedDistro

            if ($apiOkWindows -or $apiOkWsl) {
                $ready = $true
                break
            }

            Write-Host "Waiting for Ollama..."
        }

        if (-not $ready) {
            Write-Fail "Ollama did not start within $TimeoutSec seconds."
            Write-Host "Check WSL log with:"
            Write-Host "wsl -d $selectedDistro -e bash -lc `"cat ~/ollama-logs/ollama.log`""
            exit 1
        }

        Write-Ok "Ollama started successfully."
    }
    else {
        Write-Host "Start Ollama automatically with:"
        Write-Host ".\scripts\check_wsl_ubuntu_ollama.ps1 -StartOllama"
        exit 1
    }
}

Write-Step "Step 7: Show Ollama model list"

Invoke-WslBash $selectedDistro "ollama ls"

Write-Host ""
Write-Ok "WSL + Ubuntu + Ollama check completed."