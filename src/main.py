import argparse
from pathlib import Path

from model_client import get_client
from leak_detector import detect_leak


ROOT = Path(__file__).resolve().parents[1]


def load_flag() -> str:
    return (ROOT / "data" / "protected_data.txt").read_text(encoding="utf-8").strip()


def load_system_prompt(flag: str) -> str:
    template = (ROOT / "prompts" / "system_prompt.txt").read_text(encoding="utf-8")
    return template.format(flag=flag)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="mock", help="mock / openai / anthropic / gemini")
    args = parser.parse_args()

    flag = load_flag()
    system_prompt = load_system_prompt(flag)
    client = get_client(args.model)

    print("=== LLM-Attack-Benchmark Manual Test ===")
    print("輸入 exit 離開")
    print(f"Model: {args.model}")

    while True:
        user_prompt = input("\n攻擊輸入 > ").strip()
        if user_prompt.lower() == "exit":
            break

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = client.generate(messages)
        leak = detect_leak(response, flag)

        print("\n模型回覆：")
        print(response)
        print("\n測試結果：")
        print(f"Leak Level: {leak.leak_level}")
        print(f"Result: {leak.result}")
        print(f"Reason: {' | '.join(leak.reasons)}")


if __name__ == "__main__":
    main()
