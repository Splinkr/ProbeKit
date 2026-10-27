"""Artefatos exclusivamente fictícios e respostas negativas para validar exposure."""

from html import escape

CONFIG_TEXT = "# Fictitious ProbeKit configuration\nAPP_ENV=demo\nDB_HOST=fictional-local\nDB_PASSWORD=EXPOSURE_FAKE_CONFIG_7319\n"
INI_TEXT = "[database]\nhost=fictional-local\npassword=EXPOSURE_FAKE_INI_8420\n"
BACKUP_TEXT = "-- Fictitious backup; never executed\nCREATE TABLE fictional_records (id INTEGER, label TEXT);\nINSERT INTO fictional_records VALUES (1, 'EXPOSURE_FAKE_BACKUP_9531');\n"
PUBLIC_TEXT = "# README\nPublic documentation for the fictitious ProbeKit lab. No private settings.\n"
HEAD_TEXT = "ref: refs/heads/fictitious-demo\n"
SENTINELS = ("EXPOSURE_FAKE_CONFIG_7319", "EXPOSURE_FAKE_INI_8420", "EXPOSURE_FAKE_BACKUP_9531")


def response(path, sequence=0):
    root = {"/.env": CONFIG_TEXT, "/config.ini": None, "/backup.sql": BACKUP_TEXT,
            "/config.ini.bak": PUBLIC_TEXT, "/.git/HEAD": None, "/README.txt": PUBLIC_TEXT}
    if path in root:
        return (403, "text/plain", "Access denied: fictitious private file", {}) if root[path] is None else (
            200, "text/plain", root[path], {"Content-Disposition": 'attachment; filename="fictitious-artifact.txt"'})
    prefix = "/exposure-lab/"
    if not path.startswith(prefix):
        return None
    branch, _, relative = path[len(prefix):].partition("/")
    if branch == "fallback":
        return 200, "text/html", '<!doctype html><title>Catalog</title><p>Generic page: ' + escape(path) + '</p>', {}
    if branch == "error":
        return 200, "text/html", '<!doctype html><title>Error</title><p>Resource unavailable: ' + escape(path) + f'</p><p>Request {sequence}</p>', {}
    if branch == "blocked":
        return 403, "text/plain", "Access denied: fictitious private directory", {}
    if branch == "exposed":
        files = {".env": CONFIG_TEXT, "config.ini": INI_TEXT, "backup.sql": BACKUP_TEXT,
                 "config.ini.bak": INI_TEXT, ".git/HEAD": HEAD_TEXT}
        if relative in files:
            return 200, "text/plain", files[relative], {}
        return 404, "text/plain", "Not found: " + path, {}
    return 404, "text/plain", "Not found: " + path, {}
