"""
模型 client 選擇器。

支援：
- mock：測試流程用假模型
- local + ollama：本地 Ollama 模型
- cloud + openai-compatible：OpenAI-compatible 雲端 / 私有端點

舊版寫法仍保留：
- --model mock
- --model ollama:<model_name>
- --model <model_name>  # 在 model_source=auto 時視為本地 Ollama
"""
from __future__ import annotations

from typing import Optional

from clients.mock_client import MockClient
from clients.ollama_client import OllamaClient
from clients.openai_compatible_client import OpenAICompatibleClient


def normalize_model_name(model_name: str, model_source: str = "auto", provider: Optional[str] = None) -> str:
    if not model_name:
        raise ValueError("model_name 不可為空")
    model_source = (model_source or "auto").lower()
    provider = (provider or "").lower()
    if model_name == "mock" or model_source == "mock":
        return "mock"
    if model_source == "cloud" or provider == "openai-compatible":
        return model_name.removeprefix("openai-compatible:").removeprefix("openai:")
    if model_name.startswith("ollama:"):
        return model_name
    if model_source in {"auto", "local"}:
        return "ollama:" + model_name
    return model_name


def get_client(
    model_name: str,
    ollama_url: Optional[str] = None,
    model_source: str = "auto",
    provider: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key_env: str = "OPENAI_API_KEY",
    request_timeout: float = 120,
    max_retries: int = 2,
    retry_backoff: float = 2,
):
    if not model_name:
        raise ValueError("model_name 不可為空")

    model_source = (model_source or "auto").lower()
    provider = (provider or "").lower()
    model_name_lower = model_name.lower()

    if model_source == "mock" or model_name_lower == "mock":
        return MockClient()

    if model_source == "cloud" or provider == "openai-compatible" or model_name_lower.startswith(("openai-compatible:", "openai:")):
        cloud_model = model_name
        for prefix in ("openai-compatible:", "openai:"):
            if cloud_model.lower().startswith(prefix):
                cloud_model = cloud_model.split(":", 1)[1]
                break
        return OpenAICompatibleClient(
            model_name=cloud_model,
            base_url=base_url or "",
            api_key_env=api_key_env,
            request_timeout=request_timeout,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
        )

    if model_source in {"auto", "local"}:
        if model_name_lower.startswith("ollama:"):
            ollama_model = model_name.split("ollama:", 1)[1]
        else:
            ollama_model = model_name
        if not ollama_model:
            raise ValueError("Ollama model name is empty. Example: ollama:qwen2.5:3b")
        return OllamaClient(model_name=ollama_model, base_url=ollama_url)

    raise ValueError(
        f"Unsupported model_source/provider: model_source={model_source}, provider={provider}. "
        "支援 mock、local/ollama、cloud/openai-compatible。"
    )
