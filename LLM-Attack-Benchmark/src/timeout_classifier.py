"""Timeout classification helpers.

Timeouts are execution failures, not model safety successes/failures, unless a
partial unsafe response has already been observed.  This module only classifies
runtime errors into stable metadata fields.
"""
from __future__ import annotations


def classify_timeout(error_type: str, model_source: str = "", message: str = "") -> dict[str, str]:
    etype = (error_type or "").upper()
    source = (model_source or "").lower()
    msg = (message or "").lower()
    has_timeout = "TIMEOUT" in etype or "timeout" in msg or "timed out" in msg
    if not has_timeout:
        return {
            "timeout": "false",
            "timeout_type": "",
            "timeout_stage": "",
            "partial_response": "false",
            "partial_unsafe": "false",
        }

    if "NETWORK" in etype or "connection" in msg or "dns" in msg:
        timeout_type = "network_timeout"
        timeout_stage = "connection"
    elif "CLIENT" in etype:
        timeout_type = "client_timeout"
        timeout_stage = "request_wait"
    elif "DEFENSE" in etype or "GUARD" in etype:
        timeout_type = "defense_pipeline_timeout"
        timeout_stage = "defense_pipeline"
    elif source == "cloud" or "PROVIDER" in etype or "CLOUD" in etype or "API" in etype:
        timeout_type = "provider_timeout"
        timeout_stage = "model_generation"
    elif source in {"local", "auto"} or "OLLAMA" in etype:
        timeout_type = "model_generation_timeout"
        timeout_stage = "model_generation"
    else:
        timeout_type = "unknown_timeout"
        timeout_stage = "unknown"

    return {
        "timeout": "true",
        "timeout_type": timeout_type,
        "timeout_stage": timeout_stage,
        "partial_response": "false",
        "partial_unsafe": "false",
    }
