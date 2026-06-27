"""
第二版預留：Attacker LLM

目標：
- 根據 Target LLM 的上一輪回覆，自動產生下一個攻擊 prompt。
- 第一版不使用，避免 benchmark 不公平。
"""


class AttackerAgent:
    def generate_attack(self, previous_response: str) -> str:
        raise NotImplementedError("第二版 AI vs AI 時再實作。")
