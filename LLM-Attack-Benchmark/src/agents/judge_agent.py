"""
第二版預留：Judge LLM

目標：
- 搭配 rule-based leak_detector 做人工語意輔助判斷。
- 第一版優先使用規則偵測，確保結果可重複。
"""


class JudgeAgent:
    def judge(self, prompt: str, response: str) -> dict:
        raise NotImplementedError("第二版 AI vs AI 時再實作。")
