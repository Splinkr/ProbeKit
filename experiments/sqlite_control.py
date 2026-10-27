"""Controle positivo e negativo SQLi, com dados fictícios compartilhados."""

import argparse
from dataclasses import dataclass
import hashlib
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import sqlite3
import threading
from urllib.parse import parse_qsl, urlsplit

VULNERABLE_PATH = "/control/vulnerable/search"
SAFE_PATH = "/control/safe/search"
RECORDS = (
    (1, "Apple Demo", "Fictional juice", None),
    (2, "Water Demo", "Fictional apple flavour", None),
    (3, "Apple Cider Demo", "Fictional cider", None),
    (4, "Orange Demo", "Fictional orange juice", None),
    (5, "Apple Archived Demo", "Fictional archived product", "2020-01-01"),
)


@dataclass(frozen=True)
class SearchRoute:
    parameter: str
    format: str
    parameterized: bool
    context: str = "like"
    behavior: str = "normal"


GENERAL_ROUTES = {
    "/general/json/vulnerable": SearchRoute("term", "json", False),
    "/general/json/safe": SearchRoute("term", "json", True),
    "/general/html/vulnerable": SearchRoute("search", "html", False),
    "/general/html/safe": SearchRoute("search", "html", True),
    "/general/text/vulnerable": SearchRoute("keyword", "text", False),
    "/general/text/safe": SearchRoute("keyword", "text", True),
    "/general/quoted/vulnerable": SearchRoute("item", "json", False, "quoted"),
    "/general/quoted/safe": SearchRoute("item", "json", True, "quoted"),
    "/general/html/unstable": SearchRoute("search", "html", True, behavior="unstable"),
    "/general/html/error": SearchRoute("search", "html", True, behavior="error"),
}


class ProductDatabase:
    def __init__(self):
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(
            "CREATE TABLE Products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, deletedAt TEXT)"
        )
        self._connection.executemany("INSERT INTO Products VALUES (?, ?, ?, ?)", RECORDS)
        self._connection.commit()
        self._connection.execute("PRAGMA query_only = ON")

    def search(self, term: str, *, parameterized: bool, context: str = "like") -> list[dict]:
        with self._lock:
            if context == "quoted":
                rows = (self._connection.execute(
                    "SELECT * FROM Products WHERE name = ? AND deletedAt IS NULL ORDER BY name", (term,)
                ) if parameterized else self._connection.execute(
                    f"SELECT * FROM Products WHERE name = '{term}' AND deletedAt IS NULL ORDER BY name"
                )).fetchall()
            elif parameterized:
                rows = self._connection.execute(
                    "SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) "
                    "AND deletedAt IS NULL) ORDER BY name", (f"%{term}%", f"%{term}%")
                ).fetchall()
            else:
                # Vulnerabilidade intencional do experimento: não reutilizar em produção.
                rows = self._connection.execute(
                    f"SELECT * FROM Products WHERE ((name LIKE '%{term}%' OR description LIKE '%{term}%') "
                    "AND deletedAt IS NULL) ORDER BY name"
                ).fetchall()
            return [dict(row) for row in rows]

    def manifest(self) -> dict:
        with self._lock:
            rows = [dict(row) for row in self._connection.execute("SELECT * FROM Products ORDER BY id")]
        encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        return {
            "application": "webvuln-sqlite-control", "sqlite_version": sqlite3.sqlite_version,
            "records": len(rows), "dataset_sha256": hashlib.sha256(encoded).hexdigest(),
        }

    def close(self) -> None:
        self._connection.close()


class ControlServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, port: int = 8001):
        super().__init__(("127.0.0.1", port), ControlHandler)
        self.database = ProductDatabase()
        # bool indica uso de parâmetros, nunca um resultado esperado do detector.
        self.routes = {VULNERABLE_PATH: False, SAFE_PATH: True}
        self.general_routes = dict(GENERAL_ROUTES)
        self.request_number = 0

    def server_close(self) -> None:
        super().server_close()
        database = getattr(self, "database", None)
        if database is not None:
            database.close()


class ControlHandler(BaseHTTPRequestHandler):
    server: ControlServer

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/health":
            self.send_json(200, {"status": "ok", **self.server.database.manifest()})
            return
        if parts.path in self.server.general_routes:
            self.general_search(parts)
            return
        if parts.path not in self.server.routes:
            self.send_json(404, {"status": "error", "message": "Unknown endpoint"})
            return
        values = [value for key, value in parse_qsl(parts.query, keep_blank_values=True) if key == "q"]
        if len(values) != 1 or len(values[0]) > 200:
            self.send_json(400, {"status": "error", "message": "Provide one q with at most 200 characters"})
            return
        try:
            data = self.server.database.search(values[0], parameterized=self.server.routes[parts.path])
            self.send_json(200, {"status": "success", "data": data})
        except sqlite3.Error as error:
            # Diagnóstico real do SQLite, com tratamento idêntico nos dois endpoints.
            self.send_json(500, {"status": "error", "error": {
                "name": getattr(error, "sqlite_errorname", type(error).__name__), "message": str(error),
            }})

    def general_search(self, parts):
        route = self.server.general_routes[parts.path]
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        values = [value for key, value in pairs if key == route.parameter]
        if len(values) != 1 or len(values[0]) > 200:
            self.send_json(400, {"status": "error", "message": "Missing, ambiguous or oversized search parameter"})
            return
        language = next((value for key, value in pairs if key == "lang"), "en")
        if route.behavior == "error":
            self.send_body(200, "text/html", "<html><title>Error</title><h1>Service unavailable</h1></html>")
            return
        try:
            rows = self.server.database.search(values[0], parameterized=route.parameterized, context=route.context)
        except sqlite3.Error as error:
            self.send_json(500, {"status": "error", "error": {
                "name": getattr(error, "sqlite_errorname", type(error).__name__), "message": str(error),
            }})
            return
        if route.format == "json":
            if route.context == "quoted":
                self.send_json(200, [{"code": row["id"], "label": row["name"]} for row in rows])
            else:
                self.send_json(200, {"items": [{"sku": f"demo-{row['id']}", "label": row["name"]} for row in rows], "language": language})
        elif route.format == "html":
            self.server.request_number += 1
            nonce = f"<p>Request {self.server.request_number}</p>" if route.behavior == "unstable" else ""
            items = "".join(f"<li>{row['id']}: {escape(row['name'])}</li>" for row in rows)
            self.send_body(200, "text/html", f"<html><title>Catalog</title><h1>Catalog {escape(language)}</h1>{nonce}<ul>{items}</ul></html>")
        else:
            items = "\n".join(f"{row['id']}: {row['name']}" for row in rows)
            self.send_body(200, "text/plain", f"Catalog {language}\n{items}")

    def send_body(self, status: int, content_type: str, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Laboratório SQLite local com buscas vulnerável e parametrizada.")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("A porta deve estar entre 1 e 65535.")
    try:
        server = ControlServer(args.port)
    except OSError as error:
        parser.exit(1, f"Não foi possível abrir a porta local: {error}\n")
    with server:
        print(f"Laboratório SQLite em http://127.0.0.1:{args.port} (Ctrl+C para encerrar)", flush=True)
        print(f"Endpoints: {VULNERABLE_PATH}?q=apple e {SAFE_PATH}?q=apple", flush=True)
        print("Perfis adicionais: /general/{json,html,text,quoted}/{vulnerable,safe}, /general/html/{unstable,error}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
