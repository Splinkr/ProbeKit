"""Serialização de metadados; o corpo HTTP permanece apenas em memória."""

import json
from pathlib import Path
import tempfile
import time
from typing import Any, Protocol

from scanner.findings_report import build_findings_report


class JsonReport(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


def findings_path(destination: str | Path) -> Path:
    output = Path(destination)
    # --output findings.json continua válido e nunca é sobrescrito pelo resumo.
    name = "findings-summary.json" if output.name.casefold() == "findings.json" else "findings.json"
    return output.with_name(name)


class _Snapshot:
    def __init__(self, data: dict[str, Any]):
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        return self.data


def write_reports(report: JsonReport, destination: str | Path, *, atomic: bool = False) -> Path:
    """Grava o relatório completo intacto e o resumo derivado do mesmo snapshot."""
    data = report.to_dict()
    writer = write_json_atomic if atomic else write_json
    output = writer(_Snapshot(data), destination)
    summary = build_findings_report(data, output.name)
    write_json_atomic(_Snapshot(summary), findings_path(output))
    return output


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
        # No Windows, outro processo pode manter um handle sem compartilhamento
        # durante alguns instantes. Repete somente a substituição, nunca a rede.
        for attempt in range(4):
            try:
                temporary.replace(output)
                break
            except PermissionError as error:
                if getattr(error, "winerror", None) not in {5, 32, 33} or attempt == 3:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return output
