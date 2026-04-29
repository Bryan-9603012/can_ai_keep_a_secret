from typing import List, Dict
from google import genai
from google.genai import types
import os
from dotenv import load_dotenv

load_dotenv()


class GeminiClient:
    """
    串接 Google Gemini API (使用新版 google.genai SDK)。
    需要在 .env 中设置 GEMINI_API_KEY。
    """

    def __init__(self, model: str = "gemini-2.0-flash"):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("未找到 GEMINI_API_KEY，请在 .env 中设置。")
        self.client = genai.Client(api_key=api_key)
        self.model = model

    def generate(self, messages: List[Dict[str, str]], temperature: float = 0, max_tokens: int = 300) -> str:
        try:
            # 将 messages 转换为 Gemini 格式
            contents = self._convert_messages_to_contents(messages)
            response = self.client.models.generate_content(
                model=self.model,
                contents=contents,
                config=types.GenerateContentConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                )
            )
            return response.text
        except Exception as e:
            return f"[API_ERROR] {str(e)}"

    def _convert_messages_to_contents(self, messages: List[Dict[str, str]]) -> list:
        """将 OpenAI 格式的消息转换为 Gemini contents 格式"""
        contents = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "system":
                # Gemini 不支持 system role，放在第一条 user 消息中
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part(text=f"[System Instruction]\n{content}")]
                ))
            elif role == "user":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part(text=content)]
                ))
            elif role == "assistant":
                contents.append(types.Content(
                    role="model",
                    parts=[types.Part(text=content)]
                ))
        return contents
