# OWASP LLM Framework Analysis

## 目的

分析 20 種攻擊是否可由 OWASP LLM Top 10 解釋，並標示需要額外 attack family 說明或可能成為框架擴展的攻擊。

## 初步結論

目前 attack v2 enterprise 題庫大多可以對應到 OWASP LLM01 Prompt Injection、LLM02 Sensitive Information Disclosure、LLM05 Improper Output Handling 或 LLM07 System Prompt Leakage。

但在企業攻擊分析中，仍需要保留更細的 attack family，例如 Role Manipulation、Context Manipulation、Multi-turn / Reconstruction Attack、Covert Exfiltration、Encoding / Obfuscation Attack。

## Fit Summary

- `direct_fit`: 3
- `gap_candidate`: 1
- `partial_fit`: 16

## Gap / Extension Candidate

目前 `Benign Boundary Confusion` 被標示為 `gap_candidate`，因為它可被 OWASP LLM01/LLM02 部分解釋，但更精準地說是企業正常業務請求與惡意資料抽取之間的邊界混淆問題。這可以作為後續框架擴展或子分類討論。

## Web App Extension Boundary

本階段仍採本地端 Direct LLM Benchmark；只有在後續需要測試 Tool Abuse、RAG Context Exfiltration、Session / Role Permission Bypass、Improper Output Handling 的前後端效果時，才需要升級成 Web App LLM 架構。