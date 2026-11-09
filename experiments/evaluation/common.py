"""Immutable experiment files, confined paths and source fingerprints."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = ROOT / "docs/AVALIACAO_EXPERIMENTAL.md"
CASES = Path(__file__).with_name("cases.json")
ARCHIVE = ROOT / "lab/juice-shop-20.3.0_node24_win32_x64.zip"
ARCHIVE_SHA = "a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def encoded(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def put(path, data):
    """Exclusive creation: collected data and analyses are never overwritten."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encoded(data))
        stream.flush()
        os.fsync(stream.fileno())
    return path


def load(path):
    return json.loads(Path(path).read_bytes())


def confined(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Artifact path outside experiment directory")
    return path


def source_state():
    """Include dirty/untracked source, tests, locks and config; exclude generated data."""
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    files = {}
    for name in sorted(set(names)):
        path = ROOT / name
        if path.is_file() and (path.suffix in {".py", ".ps1", ".mjs", ".cjs", ".lock", ".in"}
                              or name in {"requirements.txt", "requirements-dev.txt", "pytest.ini"}):
            files[name] = digest(path)
    return {"files": files, "sha256": hashlib.sha256(encoded(files)).hexdigest()}


def seal(root):
    root = Path(root)
    files = {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob("*"))
             if p.is_file() and "runtime" not in p.relative_to(root).parts and p.name != "seal.json"}
    return put(root / "seal.json", {"artifact_schema": "1.0.0", "files": files})


def verify_seal(root):
    root = Path(root)
    data = load(root / "seal.json")
    if data.get("artifact_schema") != "1.0.0":
        raise ValueError("Unsupported experiment manifest")
    for name, expected in data["files"].items():
        if digest(confined(root, name)) != expected:
            raise ValueError("Experiment artifact hash mismatch")
    return data
