"""Páginas locais com reflexão real, escape contextual e JSON; sem efeitos privados."""

from html import escape
import json
from urllib.parse import parse_qsl

PATHS = ("/xss/html/raw", "/xss/html/escaped", "/xss/attribute/raw", "/xss/attribute/escaped",
         "/xss/json", "/xss/script/raw", "/xss/csp", "/xss/text", "/xss/script/escaped")


def landing(mixed=False):
    paths = ("/xss/html/raw?q=demo", "/xss/html/escaped?q=demo",
             "/general/json/vulnerable?term=apple", "/general/json/safe?term=apple") if mixed else tuple(path + "?q=demo" for path in PATHS[:-1])
    links = "".join(f'<li><a href="{escape(path, quote=True)}">{escape(path)}</a></li>' for path in paths)
    return '<!doctype html><meta charset="utf-8"><title>Laboratório XSS local</title><h1>Dados fictícios</h1><ul>' + links + '</ul>'


def response(path, query):
    values = [value for name, value in parse_qsl(query, keep_blank_values=True) if name == "q"]
    if len(values) != 1 or len(values[0]) > 400:
        return 400, "text/plain", "Forneça um q com até 400 caracteres.", {}
    value, headers = values[0], {}
    if path == "/xss/json":
        return 200, "application/json", json.dumps({"echo": value, "example": "fictitious"}), {"X-Content-Type-Options": "nosniff"}
    if path == "/xss/text":
        return 200, "text/plain", "Fictitious echo: " + value, {"X-Content-Type-Options": "nosniff"}
    if path.startswith("/xss/attribute/"):
        body = '<input aria-label="Fictitious echo" value="' + (escape(value, quote=True) if path.endswith("escaped") else value) + '">'
    elif path.startswith("/xss/script/"):
        encoded = json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        body = "<script>const example = " + (encoded if path.endswith("escaped") else "'" + value + "'") + ";</script><p>Fictitious script example</p>"
    else:
        body = "<p>Fictitious echo: " + (escape(value, quote=True) if path.endswith("escaped") else value) + "</p>"
    if path == "/xss/csp":
        headers["Content-Security-Policy"] = "default-src 'none'; script-src 'none'; base-uri 'none'"
    return 200, "text/html", '<!doctype html><meta charset="utf-8"><title>Local XSS example</title>' + body, headers
