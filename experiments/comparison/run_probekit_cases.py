"""Roda o ProbeKit em casos do laboratório e registra resultado, requisições e tempo.

Gera a coluna do ProbeKit da tabela de comparação (docs/COMPARACAO_FERRAMENTAS.md) e serve de
modelo para medir sqlmap e ZAP com o MESMO proxy de contagem (logproxy.py).

    python -m experiments.comparison.run_probekit_cases
    python -m experiments.comparison.run_probekit_cases --lab-port 8005 --proxy-port 8006

Tudo ocorre em loopback, nos laboratórios do próprio repositório.
"""

import argparse
import csv
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from experiments.comparison.logproxy import serve
from experiments.comparison.summarize_log import summarize

ROOT = Path(__file__).resolve().parents[2]

# (id, módulo, descrição, caminho, gabarito, argumentos extras do ProbeKit)
def sqli(parameter, *extra):
    return ["--module", "sqli", "--parameter", parameter, *extra]


CASES = [
    ("S01", "sqli", "JSON, LIKE", "/general/json/vulnerable?term=apple&lang=en", "vulnerável", sqli("term")),
    ("S02", "sqli", "JSON, parametrizado", "/general/json/safe?term=apple&lang=en", "seguro", sqli("term")),
    ("S03", "sqli", "HTML, LIKE", "/general/html/vulnerable?search=apple&lang=en", "vulnerável", sqli("search")),
    ("S04", "sqli", "HTML, parametrizado", "/general/html/safe?search=apple&lang=en", "seguro", sqli("search")),
    ("S05", "sqli", "texto, LIKE", "/general/text/vulnerable?keyword=apple&lang=en", "vulnerável", sqli("keyword")),
    ("S06", "sqli", "texto, parametrizado", "/general/text/safe?keyword=apple&lang=en", "seguro", sqli("keyword")),
    ("S07", "sqli", "igualdade entre aspas", "/general/quoted/vulnerable?item=Apple+Demo", "vulnerável", sqli("item", "--sqli-context", "quoted")),
    ("S08", "sqli", "igualdade, parametrizado", "/general/quoted/safe?item=Apple+Demo", "seguro", sqli("item", "--sqli-context", "quoted")),
    ("X01", "xss", "texto HTML sem escape", "/xss/html/raw?q=demo", "vulnerável", ["--module", "xss"]),
    ("X02", "xss", "texto HTML escapado", "/xss/html/escaped?q=demo", "seguro", ["--module", "xss"]),
    ("X03", "xss", "atributo sem escape", "/xss/attribute/raw?q=demo", "vulnerável", ["--module", "xss"]),
    ("X04", "xss", "atributo escapado", "/xss/attribute/escaped?q=demo", "seguro", ["--module", "xss"]),
    ("X05", "xss", "script sem escape", "/xss/script/raw?q=demo", "vulnerável", ["--module", "xss"]),
    ("X06", "xss", "script escapado", "/xss/script/escaped?q=demo", "seguro", ["--module", "xss"]),
    ("E01", "exposure", "raiz: .env e backup.sql expostos; config.ini e .bak não", "/", "2 vulneráveis, 2 seguros",
     ["--module", "exposure", "--exposure-profiles", "config", "backup", "--max-requests", "16"]),
]


def wait_port(port: int, timeout: float = 15.0):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise SystemExit(f"Laboratório não respondeu na porta {port}.")


def run_case(case, lab_port, proxy_port, out_dir: Path, xss_browser=False):
    case_id, module, _, path, _, extra = case
    log_path = out_dir / f"{case_id}.jsonl"
    log_path.unlink(missing_ok=True)
    server, log_file = serve(proxy_port, f"http://127.0.0.1:{lab_port}", str(log_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = out_dir / f"{case_id}-relatorio.json"
    extra = [*extra, "--xss-browser"] if xss_browser and module == "xss" else extra
    command = [sys.executable, "main.py", f"http://127.0.0.1:{proxy_port}{path}", *extra, "--output", str(report)]
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", env={**os.environ, "PYTHONUTF8": "1"})
    elapsed = time.monotonic() - start
    server.shutdown()
    server.server_close()
    log_file.close()
    text = result.stdout
    match = re.search(r"^(?:SQLi|XSS|Exposure): (\w+)$", text, re.M)
    outcome = match.group(1) if match else "sem_resultado"
    if module == "exposure":
        files = re.findall(r"^  Arquivo \S+: (\w+)$", text, re.M)
        outcome += " (" + ", ".join(f"{n} {k}" for k, n in sorted(
            {k: files.count(k) for k in set(files)}.items())) + ")"
    stats = summarize(str(log_path))
    return {"caso": case_id, "modulo": module, "descricao": case[2], "gabarito": case[4],
            "probekit_resultado": outcome, "requisicoes": stats["requests"],
            "tempo_s": round(elapsed, 2), "codigo_saida": result.returncode}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lab-port", type=int, default=8005)
    parser.add_argument("--proxy-port", type=int, default=8006)
    parser.add_argument("--out", default="reports/comparacao/probekit")
    parser.add_argument("--xss-browser", action="store_true",
                        help="confirma XSS no navegador (requer Node 24 e Edge/Chrome); sem isso XSS fica suspected")
    args = parser.parse_args(argv)
    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    lab = subprocess.Popen([sys.executable, "-m", "experiments.sqlite_control", "--port", str(args.lab_port)],
                           cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = []
    try:
        wait_port(args.lab_port)
        for case in CASES:
            row = run_case(case, args.lab_port, args.proxy_port, out_dir, args.xss_browser)
            rows.append(row)
            print(f"{row['caso']}: {row['probekit_resultado']:<45} {row['requisicoes']:>3} req  {row['tempo_s']:>5} s", flush=True)
    finally:
        lab.terminate()
    csv_path = out_dir / "probekit_resultados.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV: {csv_path}")


if __name__ == "__main__":
    main()
