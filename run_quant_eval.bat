@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"

echo ================================================
echo  Quantization Evaluation - Baseline Tag vs Quantized
echo ================================================
echo Note: Ollama default tags are treated as baseline tags.
echo       Do not call them full precision unless metadata confirms FP16/BF16.
echo.

set "BASELINE="
set /p BASELINE=Baseline tag [qwen2.5:0.5b]: 
if "%BASELINE%"=="" set "BASELINE=qwen2.5:0.5b"

set "QUANTS="
set /p QUANTS=Quantized model(s), comma separated [qwen2.5:0.5b-q4_K_M]: 
if "%QUANTS%"=="" set "QUANTS=qwen2.5:0.5b-q4_K_M"

set "ATTACK_IDS="
set /p ATTACK_IDS=Attack IDs [A01]: 
if "%ATTACK_IDS%"=="" set "ATTACK_IDS=A01"

set "STYLES="
set /p STYLES=Styles [en_pure]: 
if "%STYLES%"=="" set "STYLES=en_pure"

set "RUNS="
set /p RUNS=Runs [5]: 
if "%RUNS%"=="" set "RUNS=5"

set "MAXTOK="
set /p MAXTOK=max_tokens / num_predict [800]: 
if "%MAXTOK%"=="" set "MAXTOK=800"

set "PLOTS="
set /p PLOTS=Generate PNG figures? Y/N [Y]: 
if "%PLOTS%"=="" set "PLOTS=Y"

set "PLOT_FLAG="
if /I "%PLOTS%"=="N" set "PLOT_FLAG=--no-plots"

set "RUNNAME=quant_eval_manual_%DATE:/=-%_%TIME::=-%"
set "RUNNAME=%RUNNAME: =_%"
set "RUNNAME=%RUNNAME:.=_%"

echo.
echo [RUN] %PY% src\quant_eval.py --baseline-model "%BASELINE%" --quant-models "%QUANTS%" --attack-ids "%ATTACK_IDS%" --styles "%STYLES%" --runs %RUNS% --max-tokens %MAXTOK% --run-name "%RUNNAME%" %PLOT_FLAG%
%PY% src\quant_eval.py --baseline-model "%BASELINE%" --quant-models "%QUANTS%" --attack-ids "%ATTACK_IDS%" --styles "%STYLES%" --runs %RUNS% --max-tokens %MAXTOK% --run-name "%RUNNAME%" %PLOT_FLAG%

echo.
echo Done. Check reports\%RUNNAME%\quant_compare_report.md
echo Also check reports\%RUNNAME%\quant_model_summary.csv and human_review_template.csv
pause
