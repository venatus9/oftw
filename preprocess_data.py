import json
import tiktoken
from tqdm import tqdm

MAX_TOKENS = 50000

def count_tokens(text: str) -> int:
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))

def prune_fields(item: dict) -> dict:
    pruned = {
        "event_type": item.get("event_type"),
        "time": item.get("time")
    }

    process = item.get("process", {})
    pruned["process"] = {
        "signing_id": process.get("signing_id"),
        "cdhash": process.get("cdhash"),
        "team_id": process.get("team_id"),
        "is_platform_binary": process.get("is_platform_binary"),
        "executable_path": process.get("executable", {}).get("path"),
        "start_time": process.get("start_time"),
        "ppid": process.get("ppid"),
        "euid": process.get("audit_token", {}).get("euid")
    }

    event = item.get("event", {})
    if "create" in event:
        path = event["create"].get("destination", {}).get("existing_file", {}).get("path")
        pruned["event"] = {"create": {"destination_path": path}}
    elif "rename" in event:
        src = event["rename"].get("source", {}).get("path")
        dst = event["rename"].get("destination", {}).get("existing_file", {}).get("path")
        pruned["event"] = {"rename": {"source_path": src, "destination_path": dst}}

    return pruned

def truncate_json_by_accumulation(input_path: str, output_path: str) -> str:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise TypeError(f"The top-level JSON in {input_path} is not a list.")

    data = list(reversed(data))

    result = []
    token_total = 0

    with tqdm(total=len(data), desc="Pruning and truncating JSON") as pbar:
        for item in data:
            pruned = prune_fields(item)
            item_str = json.dumps(pruned, separators=(',', ':'))
            item_tokens = count_tokens(item_str)

            if token_total + item_tokens > MAX_TOKENS:
                break

            result.append(pruned)
            token_total += item_tokens
            pbar.update(1)

    result = list(reversed(result))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, separators=(',', ':'))

    print(f"\nTruncated file written to: {output_path}")
    print(f"ℹFinal size: {len(result)} entries, {token_total} tokens.")
    return output_path

if __name__ == "__main__":
    input_file = "/Users/martinativadar/Desktop/masterLLM/malware/keySteal.json"
    output_file = "keySteal_truncated_last_filtered_short.json"
    try:
        truncate_json_by_accumulation(input_file, output_file)
    except Exception as e:
        print(f"Error: {e}")

