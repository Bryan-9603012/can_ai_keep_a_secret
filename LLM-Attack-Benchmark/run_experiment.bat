@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
set "PYTHON_EXE=python"
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"
set "DEFAULT_ATTACKS=attacks\attacks_main.json"
set "DEFAULT_STYLES=all"
set "DEFAULT_RUNS=3"
set "DEFAULT_TEMP=0"
set "DEFAULT_TOP_P=1"
set "DEFAULT_TOP_K=40"
set "DEFAULT_NUM_CTX=4096"
set "DEFAULT_MAX_TOKENS=300"
set "DEFAULT_SEED=42"

:MENU
cls
echo ================================================
echo  LLM Attack Benchmark Experiment Runner
echo ================================================
echo.
echo  1. Smoke Test - mock, small check
echo  2. Full Test - 1 model x 20 attacks x 4 styles x 3 runs
echo  3. PC01 Formal Test - input model, runs=3
echo  4. PC02 Formal Test - input model, runs=3
echo  5. PC03 Formal Test - input model, runs=3
echo  6. Merge CSV reports
echo  7. Exit
echo.
set /p CHOICE=Select option: 
if "%CHOICE%"=="1" goto SMOKE
if "%CHOICE%"=="2" goto FULL
if "%CHOICE%"=="3" set "MACHINE_ID=PC01" & goto FORMAL
if "%CHOICE%"=="4" set "MACHINE_ID=PC02" & goto FORMAL
if "%CHOICE%"=="5" set "MACHINE_ID=PC03" & goto FORMAL
if "%CHOICE%"=="6" goto MERGE
if "%CHOICE%"=="7" goto END
goto MENU

:ASK_MODEL
set "MODEL_NAME="
echo.
set /p MODEL_NAME=Enter model name ^(example: qwen2.5:7b, qwen2.5-coder:14b, mock^): 
if "%MODEL_NAME%"=="" set "MODEL_NAME=mock"
if /i "%MODEL_NAME%"=="mock" (
    set "MODEL_ARG=mock"
) else (
    echo %MODEL_NAME% | findstr /B /I "ollama:" >nul
    if errorlevel 1 (
        set "MODEL_ARG=ollama:%MODEL_NAME%"
    ) else (
        set "MODEL_ARG=%MODEL_NAME%"
    )
)
exit /b 0

:SMOKE
set "MACHINE_ID=SMOKE"
set "MODEL_ARG=mock"
echo.
echo [RUN] Smoke Test with mock model
"%PYTHON_EXE%" "%SCRIPT_DIR%src\run_benchmark.py" --model mock --attacks "%DEFAULT_ATTACKS%" --styles en_pure --machine-id SMOKE --runs 1 --limit-base-attacks 1 --temperature %DEFAULT_TEMP% --top-p %DEFAULT_TOP_P% --top-k %DEFAULT_TOP_K% --num-ctx %DEFAULT_NUM_CTX% --max-tokens %DEFAULT_MAX_TOKENS% --seed %DEFAULT_SEED%
goto PAUSE_MENU

:FULL
call :ASK_MODEL
set "MACHINE_ID="
set /p MACHINE_ID=Enter machine id ^(default PC01^): 
if "%MACHINE_ID%"=="" set "MACHINE_ID=PC01"
echo.
echo [RUN] Full Test: 1 model x 20 attacks x 4 styles x 3 runs
echo Model: %MODEL_ARG%
echo Machine: %MACHINE_ID%
"%PYTHON_EXE%" "%SCRIPT_DIR%src\run_benchmark.py" --model "%MODEL_ARG%" --attacks "%DEFAULT_ATTACKS%" --styles all --machine-id "%MACHINE_ID%" --runs 3 --limit-base-attacks 20 --temperature %DEFAULT_TEMP% --top-p %DEFAULT_TOP_P% --top-k %DEFAULT_TOP_K% --num-ctx %DEFAULT_NUM_CTX% --max-tokens %DEFAULT_MAX_TOKENS% --seed %DEFAULT_SEED%
goto PAUSE_MENU

:FORMAL
call :ASK_MODEL
echo.
echo [RUN] Formal Test: %MACHINE_ID%, 1 model x 20 attacks x 4 styles x 3 runs
echo Model: %MODEL_ARG%
"%PYTHON_EXE%" "%SCRIPT_DIR%src\run_benchmark.py" --model "%MODEL_ARG%" --attacks "%DEFAULT_ATTACKS%" --styles all --machine-id "%MACHINE_ID%" --runs 3 --limit-base-attacks 20 --temperature %DEFAULT_TEMP% --top-p %DEFAULT_TOP_P% --top-k %DEFAULT_TOP_K% --num-ctx %DEFAULT_NUM_CTX% --max-tokens %DEFAULT_MAX_TOKENS% --seed %DEFAULT_SEED%
goto PAUSE_MENU

:MERGE
echo.
echo Put the CSV paths below. You can drag-and-drop CSV files into this window.
echo Example: results\PC01.csv results\PC02.csv results\PC03.csv
echo.
set /p CSV_LIST=CSV files: 
if "%CSV_LIST%"=="" goto PAUSE_MENU
set /p OUT_DIR=Output report dir ^(default reports\merged_manual^): 
if "%OUT_DIR%"=="" set "OUT_DIR=reports\merged_manual"
"%PYTHON_EXE%" "%SCRIPT_DIR%src\run_benchmark.py" --merge %CSV_LIST% --report-dir "%OUT_DIR%"
goto PAUSE_MENU

:PAUSE_MENU
echo.
echo Press any key to return to menu...
pause >nul
goto MENU

:END
exit /b 0
