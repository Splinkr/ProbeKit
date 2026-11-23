"""Resume um log do logproxy: número de requisições, duração observada e User-Agents.

    python -m experiments.comparison.summarize_log reports/comparacao/sqlmap-S01.jsonl
"""

import collections
import json
import sys


def summarize(path: str) -> dict:
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    if not rows:
        return {"requests": 0, "duration_s": 0.0, "methods": {}, "user_agents": {}}
    times = [row["t"] for row in rows]
    return {
        "requests": len(rows),
        "duration_s": round(max(times) - min(times), 2),  # do 1º ao último pedido
        "methods": dict(collections.Counter(row["method"] for row in rows)),
        "user_agents": dict(collections.Counter(row["ua"] for row in rows)),
    }


if __name__ == "__main__":
    for log in sys.argv[1:]:
        print(log, json.dumps(summarize(log), ensure_ascii=False))
