"""Proxy de registro em loopback: conta e grava as requisições de QUALQUER ferramenta.

Uso (em um terminal, com o laboratório já rodando na porta 8005):

    python -m experiments.comparison.logproxy --listen 8006 --upstream http://127.0.0.1:8005 --log reports/comparacao/sqlmap-S01.jsonl

Aponte a ferramenta testada (ProbeKit, sqlmap, ZAP...) para http://127.0.0.1:8006/... em vez
de 8005. Cada requisição vira uma linha JSON (instante, método, caminho, User-Agent), o que
permite contar requisições e medir a duração de forma idêntica para todas as ferramentas.

Escopo: o proxy só escuta em loopback e só encaminha para um destino loopback.
"""

import argparse
import http.server
import ipaddress
import json
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LOOPBACK_NAMES = {"localhost"}


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # devolve o 3xx ao cliente, sem seguir
        return None


def make_handler(upstream: str, log_file, lock: threading.Lock):
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):  # silencia o log padrão do http.server
            pass

        def _forward(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            with lock:
                log_file.write(json.dumps({
                    "t": time.time(), "method": self.command, "path": self.path,
                    "ua": self.headers.get("User-Agent", ""), "body_bytes": length,
                }, ensure_ascii=False) + "\n")
                log_file.flush()
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {"host", "connection", "accept-encoding", "content-length"}}
            headers["Accept-Encoding"] = "identity"
            request = urllib.request.Request(upstream + self.path, data=body, headers=headers, method=self.command)
            try:
                response = opener.open(request, timeout=15)
                status, payload, reply_headers = response.status, response.read(), response.headers
            except urllib.error.HTTPError as error:
                status, payload, reply_headers = error.code, error.read(), error.headers
            except Exception:
                status, payload, reply_headers = 502, b"bad gateway", {}
            self.send_response(status)
            for name in ("Content-Type", "Content-Security-Policy", "Location", "Set-Cookie"):
                if reply_headers.get(name):
                    self.send_header(name, reply_headers[name])
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_HEAD = _forward

    return Handler


def serve(listen: int, upstream: str, log_path: str):
    parts = urllib.parse.urlsplit(upstream)
    if parts.scheme != "http" or not parts.hostname or not is_loopback(parts.hostname):
        raise SystemExit("Destino recusado: o proxy só encaminha para http em loopback.")
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    log_file = open(log_path, "a", encoding="utf-8")
    server = socketserver.ThreadingTCPServer(("127.0.0.1", listen), make_handler(upstream.rstrip("/"), log_file, threading.Lock()))
    return server, log_file


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", type=int, default=8006)
    parser.add_argument("--upstream", default="http://127.0.0.1:8005")
    parser.add_argument("--log", required=True, help="arquivo .jsonl de saída (acrescenta ao final)")
    args = parser.parse_args(argv)
    server, log_file = serve(args.listen, args.upstream, args.log)
    print(f"proxy 127.0.0.1:{args.listen} -> {args.upstream} | log: {args.log} (Ctrl+C para encerrar)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log_file.close()


if __name__ == "__main__":
    main()
