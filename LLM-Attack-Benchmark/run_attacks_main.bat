@echo off
setlocal
set MODEL=%1
if "%MODEL%"=="" set MODEL=mock
python src\run_benchmark.py --model %MODEL% --attacks attacks\attacks_main.json --styles all --runs 1 --max-tokens 800 --num-ctx 4096
endlocal
