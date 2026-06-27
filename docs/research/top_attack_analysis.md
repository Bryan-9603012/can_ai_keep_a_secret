# Top Attack Analysis

正式跑完實驗後，report_generator.py 會自動輸出 `reports/<run>/top_attack_analysis.md` 與 `top_attack_analysis.csv`。

排序公式：

```text
AttackRiskScore = CriticalLeakRate * 0.5 + AttackSuccessRate * 0.3 + RiskHintRate * 0.2
```

目前此檔為靜態模板，實際 Top 3～Top 5 以實驗報告為準。
