import json

with open("samples_gemini.jsonl", "r") as f:
    for idx, line in enumerate(f, 1):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[Line {idx}] JSON Decode Error: {e}")
            print(f"Line content: {line}")
            break