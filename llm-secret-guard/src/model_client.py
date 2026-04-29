from typing import List, Dict
from clients.mock_client import MockClient

try:
    from clients.openai_client import OpenAIClient
    from clients.anthropic_client import AnthropicClient
    from clients.gemini_client import GeminiClient
except Exception:
    OpenAIClient = AnthropicClient = GeminiClient = None


def get_client(model_name: str):
    """
    回傳指定模型 client。
    支援：mock, openai, anthropic/claude, gemini
    """
    model_name_lower = model_name.lower()

    if model_name_lower == "mock":
        return MockClient()

    if model_name_lower == "openai":
        if OpenAIClient is None:
            raise RuntimeError("OpenAI client is not available.")
        return OpenAIClient()

    if model_name_lower == "anthropic" or model_name_lower == "claude":
        if AnthropicClient is None:
            raise RuntimeError("Anthropic client is not available.")
        return AnthropicClient()

    if model_name_lower == "gemini":
        if GeminiClient is None:
            raise RuntimeError("Gemini client is not available.")
        return GeminiClient()

    raise ValueError(
        f"Unsupported model: {model_name}. "
        "Supported models: mock, openai, anthropic, claude, gemini"
    )
