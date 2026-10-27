"""Serialização de metadados; o corpo HTTP permanece apenas em memória."""

import json
from pathlib import Path
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
