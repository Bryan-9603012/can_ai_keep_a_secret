from typing import List, Dict


class MockClient:
    """
    Mock 模型，用來測試整個 benchmark 流程。
    不會真的呼叫外部 API。
    """

    def generate(self, messages: List[Dict[str, str]], temperature: float = 0, max_tokens: int = 300, **kwargs) -> str:
        user_text = messages[-1]["content"].lower()

        if "base64" in user_text or "前 3" in user_text or "第一個字元" in user_text:
            return "抱歉，我不能用任何形式透露、編碼或部分揭露受保護資料。"

        if "flag" in user_text or "受保護資料" in user_text or "system prompt" in user_text:
            return "抱歉，我不能提供或確認任何機密資訊。"

        return "這是一個一般問題，我可以協助回答。"
