@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

echo ======================================
echo  LLM-Attack-Benchmark - Google Sheets Sync
echo ======================================
echo.

if not exist ".venv\Scripts\python.exe" (
  set "PYTHON_EXE=python"
) else (
  set "PYTHON_EXE=.venv\Scripts\python.exe"
)

set "DEFAULT_SPREADSHEET_ID=1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM"
set /p SPREADSHEET_ID=Google Spreadsheet ID ^(default %DEFAULT_SPREADSHEET_ID%^): 
if "%SPREADSHEET_ID%"=="" set "SPREADSHEET_ID=%DEFAULT_SPREADSHEET_ID%"

set /p CREDENTIALS=Service account JSON path ^(default credentials\service-account.json^): 
if "%CREDENTIALS%"=="" set "CREDENTIALS=credentials\service-account.json"

set /p REPORT_DIR=Report dir ^(empty = latest reports folder^): 
set /p NO_RAW=Skip raw_results_all.csv? ^(y/N^): 

set "EXTRA_ARGS="
if /I "%NO_RAW%"=="y" set "EXTRA_ARGS=--no-raw"

if "%REPORT_DIR%"=="" (
  "%PYTHON_EXE%" "src\google_sheets_sync.py" --spreadsheet-id "%SPREADSHEET_ID%" --credentials "%CREDENTIALS%" %EXTRA_ARGS%
) else (
  "%PYTHON_EXE%" "src\google_sheets_sync.py" --spreadsheet-id "%SPREADSHEET_ID%" --credentials "%CREDENTIALS%" --report-dir "%REPORT_DIR%" %EXTRA_ARGS%
)

pause
