"""
OpenAI-compatible cloud model client.

This client supports cloud APIs and private endpoints that expose a
/v1/chat/completions-compatible interface. API keys are read from an environment
variable so credentials are not written into configs or reports.
"""
from __future__ import annotations

import os
import time
from typing import Dict, List, Optional

import requests


class OpenAICompatibleClientError(RuntimeError):
    def __init__(self, error_type: str, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.error_type = error_type
        self.status_code = status_code
        self.message = message


class OpenAICompatibleClient:
    def __init__(
        self,
        model_name: str,
        base_url: str,
        api_key_env: str = "OPENAI_API_KEY",
        request_timeout: float = 120,
        max_retries: int = 2,
        retry_backoff: float = 2,
    ):
        self.model_name = (model_name or "").strip()
        if not self.model_name:
            raise ValueError("Cloud model name is empty.")
        self.base_url = (base_url or "").rstrip("/")
        if not self.base_url:
            raise ValueError("Cloud base_url is required for openai-compatible provider.")
        self.api_key_env = (api_key_env or "OPENAI_API_KEY").strip()
        self.request_timeout = float(request_timeout or 120)
        self.max_retries = max(0, int(max_retries or 0))
        self.retry_backoff = max(0, float(retry_backoff or 0))
        self.last_metadata: Dict[str, object] = {}

    def _headers(self) -> Dict[str, str]:
        api_key = os.getenv(self.api_key_env, "")
        if not api_key:
            raise OpenAICompatibleClientError(
                "API_KEY_MISSING",
                f"Environment variable {self.api_key_env} is empty or not set.",
            )
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _should_retry(self, status_code: Optional[int], error_type: str) -> bool:
        if error_type in {"TIMEOUT", "NETWORK_ERROR"}:
            return True
        return status_code in {429, 500, 502, 503, 504}

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
        payload: Dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if top_p is not None:
            payload["top_p"] = top_p
        if seed is not None:
            # Some OpenAI-compatible endpoints support seed; unsupported endpoints
            # usually ignore it or return a clear 400 error.
            payload["seed"] = seed
        # top_k and num_ctx are Ollama-specific and are intentionally not sent.

        url = f"{self.base_url}/chat/completions"
        headers = self._headers()
        attempts = self.max_retries + 1
        last_exc: Exception | None = None
        start_all = time.perf_counter()

        for attempt in range(1, attempts + 1):
            start = time.perf_counter()
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=self.request_timeout)
                latency_ms = round((time.perf_counter() - start) * 1000, 2)
            except requests.exceptions.Timeout as exc:
                last_exc = OpenAICompatibleClientError("TIMEOUT", f"Cloud request timed out after {self.request_timeout}s.")
                self.last_metadata = {
                    "provider": "openai-compatible",
                    "retry_count": attempt - 1,
                    "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                    "request_timeout": self.request_timeout,
                }
                if attempt < attempts:
                    time.sleep(self.retry_backoff * attempt)
                    continue
                raise last_exc from exc
            except requests.exceptions.RequestException as exc:
                last_exc = OpenAICompatibleClientError("NETWORK_ERROR", f"Cloud API network error: {exc}")
                self.last_metadata = {
                    "provider": "openai-compatible",
                    "retry_count": attempt - 1,
                    "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                    "request_timeout": self.request_timeout,
                }
                if attempt < attempts:
                    time.sleep(self.retry_backoff * attempt)
                    continue
                raise last_exc from exc

            if response.status_code != 200:
                detail = response.text[:1000]
                if response.status_code == 401:
                    error_type = "UNAUTHORIZED"
                elif response.status_code == 403:
                    error_type = "FORBIDDEN"
                elif response.status_code == 404:
                    error_type = "MODEL_OR_ENDPOINT_NOT_FOUND"
                elif response.status_code == 429:
                    error_type = "RATE_LIMIT"
                elif response.status_code in {500, 502, 503, 504}:
                    error_type = f"HTTP_{response.status_code}"
                else:
                    error_type = f"HTTP_{response.status_code}"
                last_exc = OpenAICompatibleClientError(
                    error_type,
                    f"Cloud API returned HTTP {response.status_code}. URL={url}. Response={detail}",
                    status_code=response.status_code,
                )
                self.last_metadata = {
                    "provider": "openai-compatible",
                    "retry_count": attempt - 1,
                    "latency_ms": latency_ms,
                    "request_timeout": self.request_timeout,
                    "status_code": response.status_code,
                }
                if attempt < attempts and self._should_retry(response.status_code, error_type):
                    time.sleep(self.retry_backoff * attempt)
                    continue
                raise last_exc

            try:
                data = response.json()
            except ValueError as exc:
                raise OpenAICompatibleClientError(
                    "JSON_PARSE_ERROR",
                    f"Cloud API response is not valid JSON. Response={response.text[:500]}",
                    status_code=response.status_code,
                ) from exc

            usage = data.get("usage", {}) if isinstance(data, dict) else {}
            choices = data.get("choices", []) if isinstance(data, dict) else []
            message = choices[0].get("message", {}) if choices and isinstance(choices[0], dict) else {}
            content = message.get("content")
            if content is None:
                raise OpenAICompatibleClientError(
                    "INVALID_RESPONSE",
                    f"Cloud API response missing choices[0].message.content. Response={str(data)[:500]}",
                    status_code=response.status_code,
                )

            self.last_metadata = {
                "provider": "openai-compatible",
                "retry_count": attempt - 1,
                "latency_ms": latency_ms,
                "request_timeout": self.request_timeout,
                "total_elapsed_ms": round((time.perf_counter() - start_all) * 1000, 2),
                "status_code": response.status_code,
                "prompt_eval_count": usage.get("prompt_tokens", ""),
                "eval_count": usage.get("completion_tokens", ""),
                "total_tokens": usage.get("total_tokens", ""),
                "finish_reason": choices[0].get("finish_reason", "") if choices and isinstance(choices[0], dict) else "",
            }
            return str(content)

        if last_exc:
            raise last_exc
        raise OpenAICompatibleClientError("UNKNOWN_ERROR", "Cloud API request failed without a concrete exception.")
