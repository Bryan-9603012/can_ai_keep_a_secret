param(
    [string]$Model = "mock",
    [string]$Styles = "all",
    [string]$AttackIds = "all",
    [int]$Runs = 1,
    [int]$MaxTokens = 800,
    [int]$NumCtx = 4096
)

python src/run_benchmark.py `
    --model $Model `
    --attacks attacks/attacks_main.json `
    --styles $Styles `
    --attack-ids $AttackIds `
    --runs $Runs `
    --max-tokens $MaxTokens `
    --num-ctx $NumCtx
