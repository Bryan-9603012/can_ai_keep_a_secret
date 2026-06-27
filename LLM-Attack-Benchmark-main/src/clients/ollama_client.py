"""
Ollama 本地模型客戶端。

重點：
- Ollama URL 可由 OLLAMA_URL 或 --ollama-url 指定。
- 不設定 timeout，避免不同模型回應時間差異造成誤判。
- 錯誤會分類，例如 OLLAMA_UNREACHABLE、HTTP_404、MODEL_NOT_FOUND、INVALID_JSON。
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

import requests


class OllamaClientError(RuntimeError):
    def __init__(self, error_type: str, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.error_type = error_type
        self.status_code = status_code
        self.message = message


class OllamaClient:
    def __init__(self, model_name: str, base_url: Optional[str] = None):
        self.model_name = model_name
        self.base_url = (base_url or os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.last_metadata: Dict[str, object] = {}

    def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0,
        max_tokens: int = 300,
        top_p: float | None = None,
        top_k: int | None = None,
        num_ctx: int | None = None,
        seed: int | None = None,
    ) -> str:
        options = {
            "temperature": temperature,
            "num_predict": max_tokens,
        }
        if top_p is not None:
            options["top_p"] = top_p
        if top_k is not None:
            options["top_k"] = top_k
        if num_ctx is not None:
            options["num_ctx"] = num_ctx
        if seed is not None:
            options["seed"] = seed

        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": options,
            "keep_alive": "10m",
        }

        url = f"{self.base_url}/api/chat"

        try:
            # 不指定 timeout：本地 LLM 不同模型回應時間差異很大，避免 timeout 造成假錯誤。
            response = requests.post(url, json=payload)
        except requests.exceptions.ConnectionError as exc:
            raise OllamaClientError(
                "OLLAMA_UNREACHABLE",
                f"無法連線到 Ollama：{self.base_url}。請確認 Ollama 已啟動，或設定 OLLAMA_URL。原始錯誤：{exc}",
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise OllamaClientError(
                "REQUEST_ERROR",
                f"Ollama API 請求失敗：{exc}",
            ) from exc

        if response.status_code != 200:
            error_type = f"HTTP_{response.status_code}"
            detail = response.text.strip()
            if response.status_code == 500:
                error_type = "OLLAMA_500"
            if response.status_code == 404:
                error_type = "HTTP_404"
            if response.status_code == 500 and "model" in detail.lower() and "not found" in detail.lower():
                error_type = "MODEL_NOT_FOUND"
            raise OllamaClientError(
                error_type,
                f"Ollama API 回傳 HTTP {response.status_code}。URL={url}。Response={detail}",
                status_code=response.status_code,
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise OllamaClientError(
                "JSON_PARSE_ERROR",
                f"Ollama 回應不是合法 JSON。Response={response.text[:500]}",
                status_code=response.status_code,
            ) from exc

        if "error" in data:
            error_text = str(data.get("error"))
            error_type = "OLLAMA_ERROR"
            if "not found" in error_text.lower() or "pull" in error_text.lower():
                error_type = "MODEL_NOT_FOUND"
            raise OllamaClientError(error_type, f"Ollama 回傳錯誤：{error_text}")

        self.last_metadata = {
            "total_duration": data.get("total_duration"),
            "load_duration": data.get("load_duration"),
            "prompt_eval_count": data.get("prompt_eval_count"),
            "prompt_eval_duration": data.get("prompt_eval_duration"),
            "eval_count": data.get("eval_count"),
            "eval_duration": data.get("eval_duration"),
        }

        content = data.get("message", {}).get("content")
        if content is None:
            raise OllamaClientError(
                "JSON_PARSE_ERROR",
                f"Ollama 回應缺少 message.content。Response={str(data)[:500]}",
            )

        return content
