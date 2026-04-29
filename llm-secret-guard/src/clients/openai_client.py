from typing import List, Dict
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()


class OpenAIClient:
    """
    串接 OpenAI API (GPT 模型)。
    需要在 .env 中设置 OPENAI_API_KEY。
    """

    def __init__(self, model: str = "gpt-3.5-turbo"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("未找到 OPENAI_API_KEY，请在 .env 中设置。")
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(self, messages: List[Dict[str, str]], temperature: float = 0, max_tokens: int = 300) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[API_ERROR] {e}"
