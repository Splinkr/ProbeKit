"""Site HTML mínimo para demonstrar descoberta local sem depender de uma SPA."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from urllib.parse import urlsplit

PAGES = {
    "/": '''<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Laboratório HTML</title>
      <h1>Descoberta de endpoints</h1>
      <a href="/catalog?sort=name&amp;page=1">Catálogo</a>
      <a href="/./catalog?page=1&amp;sort=name#top">Catálogo duplicado</a>
      <a href="/about">Sobre</a>
      <form method="get" action="/search">
        <input name="q"><select name="sort"><option>name</option></select>
        <input name="category" type="hidden" value="demo"><button>Buscar</button>
      </form>
      <a href="http://example.invalid/outside">Destino externo bloqueado</a>
      <a href="http://127.0.0.1:8003/outside">Outra porta bloqueada</a></html>''',
    "/catalog": '<html><a href="/details?id=1">Detalhe</a><a href="/">Início</a></html>',
    "/about": '<html><p>Dados fictícios.</p><form method="post" action="/write"><input name="value"></form></html>',
    "/details": '<html><a href="/more">Mais uma profundidade</a></html>',
    "/more": '<html><p>Fim da navegação.</p></html>',
    "/search": '<html><p>Busca fictícia, sem alterações de dados.</p></html>',
}


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        page = PAGES.get(urlsplit(self.path).path)
        body = (page or "<html>Não encontrado.</html>").encode("utf-8")
        self.send_response(200 if page else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class DemoServer(ThreadingHTTPServer):
    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Laboratório HTML local da descoberta de endpoints.")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Porta deve estar entre 1 e 65535.")
    try:
        server = DemoServer(("127.0.0.1", args.port), DemoHandler)
    except OSError as error:
        parser.exit(1, f"Não foi possível abrir a porta local: {error}\n")
    with server:
        print(f"Laboratório HTML em http://127.0.0.1:{args.port} (Ctrl+C para encerrar)", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
