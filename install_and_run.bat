@echo off
setlocal EnableExtensions EnableDelayedExpansion
title LLM Attack Benchmark - Install and Run

REM ============================================================
REM LLM Attack Benchmark - Safe Windows Launcher for AIA Demo
REM Pure CMD version: no PowerShell, no .ps1 dependency.
REM It always pauses before closing so errors remain visible.
REM ============================================================

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "LOG_DIR=%SCRIPT_DIR%logs"
set "RESULTS_DIR=%SCRIPT_DIR%results"
set "LOG_FILE=%LOG_DIR%\install_and_run_last.log"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

REM Reset last-run log
> "%LOG_FILE%" echo %date% %time% [INFO] New install_and_run.bat session started.

call :log "========================================"
call :log " LLM Attack Benchmark - Install and Run"
call :log " AIA Demo Workflow"
call :log "========================================"
call :log " Project : %SCRIPT_DIR%"
call :log " Log     : %LOG_FILE%"
call :log "========================================"
call :log ""

REM --- Basic file checks ---
if not exist "%SCRIPT_DIR%src\run_benchmark.py" (
    call :fail "Missing file: src\run_benchmark.py"
    goto :end_fail
)

REM --- Python check ---
set "PYTHON_CMD="
where python >nul 2>nul
if not errorlevel 1 set "PYTHON_CMD=python"

if not defined PYTHON_CMD (
    where py >nul 2>nul
    if not errorlevel 1 set "PYTHON_CMD=py"
)

if not defined PYTHON_CMD (
    call :fail "Python command not found. Install Python 3.9+ and add it to PATH."
    goto :end_fail
)

call :log "[OK] Python command: %PYTHON_CMD%"

REM --- Ollama command check ---
where ollama >nul 2>nul
if errorlevel 1 (
    call :fail "Ollama command not found. Please install Ollama first."
    call :log "      Download: https://ollama.com/download"
    goto :end_fail
)
call :log "[OK] Ollama command found."

REM --- Ollama API check ---
call :log "[INFO] Checking Ollama server at http://127.0.0.1:11434/api/tags ..."

where curl >nul 2>nul
if not errorlevel 1 (
    curl -fsS "http://127.0.0.1:11434/api/tags" >nul 2>nul
    set "OLLAMA_CHECK_RC=!ERRORLEVEL!"
) else (
    %PYTHON_CMD% -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=3).read()" >nul 2>nul
    set "OLLAMA_CHECK_RC=!ERRORLEVEL!"
)

if not "%OLLAMA_CHECK_RC%"=="0" (
    call :fail "OLLAMA_UNREACHABLE: Ollama is installed but the local server is not responding."
    call :log "      Fix: open another CMD or PowerShell window and run: ollama serve"
    call :log "      Keep that Ollama window open, then run install_and_run.bat again."
    goto :end_fail
)
call :log "[OK] Ollama server is reachable."

REM --- Install environment safely ---
if exist "%SCRIPT_DIR%install.bat" (
    call :log ""
    call :log "[INFO] Running install.bat in a child CMD process ..."
    cmd /d /c "cd /d "%SCRIPT_DIR%" && call "%SCRIPT_DIR%install.bat""
    set "INSTALL_RC=!ERRORLEVEL!"
    call :log "[INFO] install.bat exit code: !INSTALL_RC!"
    if not "!INSTALL_RC!"=="0" (
        call :fail "install.bat failed. See the messages above or logs."
        goto :end_fail
    )
) else (
    call :log "[WARN] install.bat not found. Skipping install step."
)

REM --- Activate virtual environment if available ---
if exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    call :log "[INFO] Activating .venv ..."
    call "%SCRIPT_DIR%.venv\Scripts\activate.bat"
) else (
    call :log "[WARN] .venv\Scripts\activate.bat not found. Running with system Python."
)

REM --- Show installed Ollama models for visibility ---
call :log ""
call :log "[INFO] Installed Ollama models:"
ollama list
call :log ""

REM --- Run benchmark ---
call :log "[INFO] Starting benchmark workflow ..."
call :log "[INFO] If the benchmark asks for a model, choose an installed model."
call :log ""

%PYTHON_CMD% "%SCRIPT_DIR%src\run_benchmark.py"
set "RUN_RC=!ERRORLEVEL!"

call :log ""
call :log "[INFO] run_benchmark.py exit code: !RUN_RC!"

if not "!RUN_RC!"=="0" (
    call :fail "Benchmark failed or was interrupted."
    goto :end_fail
)

REM --- Generate report if available ---
if exist "%SCRIPT_DIR%src\report_generator.py" (
    call :log ""
    call :log "[INFO] Generating report with src\report_generator.py ..."
    %PYTHON_CMD% "%SCRIPT_DIR%src\report_generator.py"
    set "REPORT_RC=!ERRORLEVEL!"
    call :log "[INFO] report_generator.py exit code: !REPORT_RC!"

    if not "!REPORT_RC!"=="0" (
        call :log "[WARN] Report generator failed, but benchmark may have completed."
        call :log "[WARN] Please check results\ and reports\ manually."
    ) else (
        call :log "[OK] Report generator completed."
    )
) else (
    call :log "[WARN] src\report_generator.py not found. Skipping report generation."
)

call :log ""
call :log "[OK] Workflow completed."
call :log "[OK] Check results\, reports\, or logs\ for outputs."
goto :end_ok

:log
echo %~1
>> "%LOG_FILE%" echo %date% %time% %~1
exit /b 0

:fail
echo [FAIL] %~1
>> "%LOG_FILE%" echo %date% %time% [FAIL] %~1
exit /b 0

:end_fail
echo.
echo ========================================
echo [FAIL] Workflow stopped.
echo Log file: %LOG_FILE%
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
exit /b 1

:end_ok
echo.
echo ========================================
echo [OK] Done.
echo Log file: %LOG_FILE%
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
exit /b 0
