"""Verifica quais regras de probekit.rules casam com as requisições registradas pelo logproxy.

ATENÇÃO: é um verificador simplificado (content, nocase, distance e pcre sobre a requisição
reconstruída). Ele NÃO substitui o Suricata/Snort: serve para checar a lógica das regras antes
de rodá-las no IDS de verdade.

    python -m experiments.ids.check_rules reports/comparacao/probekit/*.jsonl
"""

import glob
import json
import re
import sys
from pathlib import Path

RULES = Path(__file__).with_name("probekit.rules")

# Tráfego sintético para comparação: uso legítimo e o ataque clássico da Aula 07.
BENIGN = [
    ("GET /health HTTP/1.1", "Mozilla/5.0"),
    ("GET /general/json/vulnerable?term=apple&lang=en HTTP/1.1", "Mozilla/5.0"),
    ("GET /products?search=ma%C3%A7%C3%A3 HTTP/1.1", "Mozilla/5.0"),
    ("GET /search?q=select+a+book HTTP/1.1", "Mozilla/5.0"),
]
CLASSIC = [
    ("POST /rest/user/login HTTP/1.1", "Mozilla/5.0", '{"email":"\' or 1=1--","password":"x"}'),
    ("GET /rest/products/search?q=%27+or+1%3D1-- HTTP/1.1", "Mozilla/5.0", ""),
]


def parse_rules(text: str):
    rules = []
    for line in text.splitlines():
        if not line.startswith("alert"):
            continue
        rules.append({
            "sid": int(re.search(r"sid:(\d+)", line)[1]),
            "msg": re.search(r'msg:"([^"]*)"', line)[1],
            "contents": re.findall(r'content:"([^"]*)"', line),
            "pcre": re.findall(r'pcre:"/(.*)/([a-z]*)"\s*;', line),
            "nocase": "nocase" in line,
        })
    return rules


def matches(rule, raw: str) -> bool:
    haystack = raw.lower() if rule["nocase"] else raw
    for content in rule["contents"]:
        if (content.lower() if rule["nocase"] else content) not in haystack:
            return False
    for pattern, flags in rule["pcre"]:
        options = re.I if "i" in flags else 0
        if not re.search(pattern, raw, options | re.M):
            return False
    return True


def raw_request(request_line: str, user_agent: str, body: str = "") -> str:
    return f"{request_line}\r\nHost: 127.0.0.1\r\nUser-Agent: {user_agent}\r\n\r\n{body}"


def main(paths):
    rules = parse_rules(RULES.read_text(encoding="utf-8"))
    records = []
    for path in paths:
        for line in open(path, encoding="utf-8"):
            row = json.loads(line)
            records.append((Path(path).stem, raw_request(f"{row['method']} {row['path']} HTTP/1.1", row["ua"])))
    groups = {
        "ProbeKit (logs)": [raw for _, raw in records],
        "Tráfego legítimo": [raw_request(*item) for item in BENIGN],
        "Ataque clássico Aula 07": [raw_request(*item) for item in CLASSIC],
    }
    print(f"{'sid':<8}{'regra':<58}" + "".join(f"{name:<26}" for name in groups))
    for rule in rules:
        counts = [f"{sum(matches(rule, raw) for raw in raws)}/{len(raws)}" for raws in groups.values()]
        print(f"{rule['sid']:<8}{rule['msg'][:56]:<58}" + "".join(f"{value:<26}" for value in counts))
    fired = {rule["sid"] for rule in rules if any(matches(rule, raw) for _, raw in records)}
    missed = [raw for _, raw in records if not any(matches(rule, raw) for rule in rules if rule["sid"] != 1000001)]
    print(f"\nRequisições do ProbeKit sem NENHUMA regra específica: {len(missed)}/{len(records)}")
    return fired


if __name__ == "__main__":
    files = [item for arg in (sys.argv[1:] or ["reports/comparacao/probekit/*.jsonl"]) for item in glob.glob(arg)]
    main(sorted(files))
