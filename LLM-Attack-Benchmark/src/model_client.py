"""
模型 client 選擇器。

目前專案先聚焦：
- mock：測試流程用假模型
- ollama:<model_name>：本地開源模型
"""
from __future__ import annotations

from typing import Optional

from clients.mock_client import MockClient
from clients.ollama_client import OllamaClient


def get_client(model_name: str, ollama_url: Optional[str] = None):
    if not model_name:
        raise ValueError("model_name 不可為空")

    model_name_lower = model_name.lower()

    if model_name_lower == "mock":
        return MockClient()

    if model_name_lower.startswith("ollama:"):
        ollama_model = model_name.split("ollama:", 1)[1]
        if not ollama_model:
            raise ValueError("Ollama model name is empty. Example: ollama:qwen2.5:3b")
        return OllamaClient(model_name=ollama_model, base_url=ollama_url)

    raise ValueError(
        f"Unsupported model: {model_name}. "
        "目前僅支援 mock 與 ollama:<model_name>。"
    )
