"""Serialização de metadados; o corpo HTTP permanece apenas em memória."""

import json
from pathlib import Path
import tempfile
from typing import Any, Protocol


class JsonReport(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


def write_json(report: JsonReport, destination: str | Path) -> Path:
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return output


def write_json_atomic(report: JsonReport, destination: str | Path) -> Path:
    """Checkpoint no mesmo diretório; substitui o JSON somente após fechar a escrita."""
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=output.parent,
                                         prefix=".scan-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report.to_dict(), stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return output
