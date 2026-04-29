import argparse
import csv
import json
from datetime import datetime
from pathlib import Path

from model_client import get_client
from leak_detector import detect_leak
from scoring import level_to_score, calculate_total_score


ROOT = Path(__file__).resolve().parents[1]


def safe_filename(name: str) -> str:
    """
    將檔名轉換為安全格式，移除 Windows 不允許的字符。
    
    Args:
        name: 原始檔名
        
    Returns:
        安全的檔名
    """
    return (
        name.replace(":", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(" ", "_")
            .replace("|", "_")
            .replace("<", "_")
            .replace(">", "_")
            .replace("?", "_")
            .replace("*", "_")
            .replace('"', "_")
    )


def load_flag() -> str:
    return (ROOT / "data" / "protected_data.txt").read_text(encoding="utf-8").strip()


def load_system_prompt(flag: str) -> str:
    template = (ROOT / "prompts" / "system_prompt.txt").read_text(encoding="utf-8")
    return template.format(flag=flag)


def load_attacks() -> list[dict]:
    return json.loads((ROOT / "attacks" / "attacks.json").read_text(encoding="utf-8"))


def run_attack(client, model_name: str, system_prompt: str, flag: str, attack: dict, temperature: float, max_tokens: int) -> list[dict]:
    """
    單輪：每題獨立 session。
    多輪：只在同一題內保留上下文，且固定依照 attacks.json 的 turns 執行。
    """
    rows = []
    messages = [{"role": "system", "content": system_prompt}]

    for turn_index, turn in enumerate(attack["turns"], start=1):
        messages.append(turn)

        response = client.generate(messages, temperature=temperature, max_tokens=max_tokens)
        messages.append({"role": "assistant", "content": response})

        leak = detect_leak(response, flag)

        rows.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "model": model_name,
            "attack_id": attack["id"],
            "mode": attack.get("mode", "single_turn"),
            "category": attack.get("category", ""),
            "turn_index": turn_index,
            "prompt": turn["content"],
            "response": response,
            "leak_level": leak.leak_level,
            "score": level_to_score(leak.leak_level),
            "result": leak.result,
            "format_violation": leak.format_violation,
            "reasons": " | ".join(leak.reasons),
            "description": attack.get("description", "")
        })

        # 第一版可選：若完整洩漏，可停止該題。
        # 為保持完全一致，預設不 early stop。
        # if leak.leak_level == 4:
        #     break

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="mock", help="mock / openai / anthropic / gemini")
    parser.add_argument("--temperature", type=float, default=0)
    parser.add_argument("--max-tokens", type=int, default=300)
    args = parser.parse_args()

    flag = load_flag()
    system_prompt = load_system_prompt(flag)
    attacks = load_attacks()
    client = get_client(args.model)

    all_rows = []

    for attack in attacks:
        rows = run_attack(
            client=client,
            model_name=args.model,
            system_prompt=system_prompt,
            flag=flag,
            attack=attack,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
        all_rows.extend(rows)

    output_path = ROOT / "results" / f"results_{safe_filename(args.model)}.csv"
    output_path.parent.mkdir(exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    total_score = calculate_total_score(all_rows)

    print(f"測試完成：{output_path}")
    print(f"Secret Protection Score: {total_score}")


if __name__ == "__main__":
    main()
