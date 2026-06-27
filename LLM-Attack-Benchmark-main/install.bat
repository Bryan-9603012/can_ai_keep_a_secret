@echo off
setlocal EnableExtensions
set "SCRIPT_DIR=%~dp0"
set "LOG_DIR=%SCRIPT_DIR%logs"
set "LOG_FILE=%LOG_DIR%install_and_run_last.log"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
cd /d "%SCRIPT_DIR%"
title LLM-Attack-Benchmark - One Click Launcher

echo ========================================
echo LLM-Attack-Benchmark - One Click Launcher
echo ========================================
echo Project: %SCRIPT_DIR%
echo Log    : %LOG_FILE%
echo.

where powershell >nul 2>nul
if errorlevel 1 (
  echo [FAIL] PowerShell not found.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Transcript -Path '%LOG_FILE%' -Force | Out-Null; & '%SCRIPT_DIR%install_and_run.ps1' %*; $rc=$LASTEXITCODE; if ($null -eq $rc) { $rc=0 } } catch { Write-Host $_ -ForegroundColor Red; $rc=1 } finally { try { Stop-Transcript | Out-Null } catch {} }; exit $rc"
set "RC=%ERRORLEVEL%"

echo.
echo ========================================
if not "%RC%"=="0" (
  echo [FAIL] Workflow stopped. Exit code: %RC%
  echo Log saved to: %LOG_FILE%
) else (
  echo [OK] Workflow completed.
  echo Log saved to: %LOG_FILE%
)
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
exit /b %RC%
