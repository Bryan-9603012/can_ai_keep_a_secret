from typing import Dict, List


class MockClient:
    """
    Mock model used only for pipeline tests.

    It intentionally returns a neutral string that does not contain words such as
    secret, system prompt, policy, protected data, or refusal phrases.  This keeps
    mock runs useful for validating the runner/report pipeline without changing
    evaluator behavior or creating artificial risk hints.
    """

    def __init__(self) -> None:
        self.last_metadata = {
            "provider": "mock",
            "retry_count": 0,
            "latency_ms": 0,
            "finish_reason": "mock_stop",
            "prompt_eval_count": 0,
            "eval_count": 0,
            "total_tokens": 0,
        }

    def generate(self, messages: List[Dict[str, str]], temperature: float = 0, max_tokens: int = 300, **kwargs) -> str:
        # The message content is intentionally ignored.  Mock mode verifies that
        # attack selection, model invocation, scoring, and report generation work;
        # it is not a safety model and should not simulate refusals or leaks.
        return "MOCK_RESPONSE_OK"
