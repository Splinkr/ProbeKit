"""Assinaturas estruturais e controles diferenciais; não guarda chaves ou valores."""

from email.message import Message
import hashlib
from html import escape
import re
from urllib.parse import unquote, urlsplit

from scanner.exposure_models import ExposureAssessment, ExposureFeatures, ExposureResponse

SAFE_MEDIA = {"text/plain", "text/html", "application/xhtml+xml", "application/json", "application/octet-stream",
              "application/sql", "text/x-sql", "application/x-sql", "text/ini"}
BLOCKED_OR_MISSING = {401, 403, 404, 410}
HTML = re.compile(r"<(?:!doctype\s+html|html|head|body|title|script|div|p|pre|form|input|a)(?:\s|>|/)", re.I)
ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
SECTION = re.compile(r"^\[([A-Za-z0-9_. -]+)\]\s*$")


def observe(response, role):
    header = Message()
    header["Content-Type"] = response.content_type
    mime = header.get_content_type()
    try:
        text = response.body.decode(header.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        text = response.body.decode("utf-8", errors="replace")
    is_html = mime in {"text/html", "application/xhtml+xml"} or bool(HTML.search(text[:4096]))
    public = bool(re.match(r"\s*(?:#\s*)?(?:readme\b|public documentation\b|license\b)", text, re.I))
    error = bool(re.match(r"\s*(?:error\b|not found\b|access denied\b|forbidden\b|404\b|service unavailable\b)", text, re.I)
                 or re.search(r"<title>\s*(?:error\b|not found\b|forbidden\b)", text[:4096], re.I))
    assignments, sections = 0, 0
    indicators = {"credential_setting": False, "database_setting": False, "application_setting": False,
                  "sql_schema": False, "sql_data_statement": False, "git_reference": False}
    for line in text.splitlines():
        stripped = line.strip()
        section = SECTION.fullmatch(stripped)
        if section:
            sections += 1
            indicators["database_setting"] |= section[1].lower() in {"database", "db", "postgresql", "mysql"}
        assignment = ASSIGNMENT.match(stripped)
        if assignment:
            assignments += 1
            key = assignment[1].upper()
            indicators["credential_setting"] |= bool(re.search(r"(?:PASSWORD|PASSWD|SECRET|TOKEN|(?:^|_)KEY)$", key))
            indicators["database_setting"] |= key.startswith(("DB_", "DATABASE_"))
            indicators["application_setting"] |= key.startswith(("APP_", "APPLICATION_"))
    indicators["sql_schema"] = bool(re.search(r"^\s*CREATE\s+TABLE\b", text, re.I | re.M))
    indicators["sql_data_statement"] = bool(re.search(r"^\s*INSERT\s+INTO\b", text, re.I | re.M))
    indicators["git_reference"] = bool(re.fullmatch(r"\s*(?:ref:\s+refs/(?:heads|tags)/[A-Za-z0-9_./-]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s*", text))
    config = assignments >= 2 and (indicators["credential_setting"] or indicators["database_setting"])
    kind = "sql_backup" if indicators["sql_schema"] and indicators["sql_data_statement"] else "git_head" if indicators["git_reference"] else "ini" if config and sections else "dotenv" if config else "unknown"
    strong = kind != "unknown" and not public and not error
    normalized = text
    path = urlsplit(response.url).path
    # Remove somente o caminho/arquivo desta requisição, para erros que ecoam a URL.
    for token in sorted({response.url, path, unquote(path), escape(path), path.rsplit("/", 1)[-1]}, key=len, reverse=True):
        if token:
            normalized = normalized.replace(token, "<requested-path>")
    digest = hashlib.sha256(" ".join(normalized.split()).encode()).hexdigest()
    features = ExposureFeatures(kind, strong, is_html, public, error, assignments, sections, indicators, digest)
    return ExposureResponse(response.request_id, response.url, role, response.collected_at, response.status_code,
                            mime if mime in SAFE_MEDIA else "other", response.size_bytes, response.body_sha256,
                            response.elapsed_ms, features)


def assess(observations, errors, expected_kind, samples=2):
    references = [item for item in observations if item.role.startswith("reference_")]
    controls = [item for item in observations if item.role.startswith("control_")]

    def stable(items, normalized=False):
        return bool(items) and len({(item.status_code, item.content_type,
            item.features.normalized_sha256 if normalized else item.body_sha256) for item in items}) == 1

    def matches_kind(item):
        return item.features.strong_signature and (item.features.kind == expected_kind or
            expected_kind == "config_backup" and item.features.kind in {"ini", "dotenv"})

    fallback = bool(references and controls and all(any(
        item.body_sha256 == control.body_sha256 or item.features.normalized_sha256 == control.features.normalized_sha256
        for control in controls) for item in references))
    complete = len(references) == samples and len(controls) == 2 and not errors
    checks = {
        "all_requests_completed": complete,
        "references_http_200": bool(references) and all(item.status_code == 200 for item in references),
        "references_stable": len(references) == samples and stable(references),
        "controls_stable": len(controls) == 2 and stable(controls, normalized=True),
        "controls_negative": len(controls) == 2 and all(item.status_code in BLOCKED_OR_MISSING or
            item.status_code == 200 and not item.features.strong_signature for item in controls),
        "content_matches_expected": bool(references) and all(matches_kind(item) for item in references),
        "not_html_or_public_document": bool(references) and all(not item.features.is_html and not item.features.public_document and not item.features.error_like for item in references),
        "different_from_missing_paths": not fallback,
    }
    if not complete:
        outcome, reason = "inconclusive", "Coleta incompleta; faltam referências ou controles comparáveis."
    elif all(item.status_code in BLOCKED_OR_MISSING for item in references):
        outcome, reason = "not_detected", "Os caminhos testados retornaram acesso bloqueado ou arquivo ausente."
    elif not checks["references_http_200"]:
        outcome, reason = "inconclusive", "Redirect, erro HTTP ou status não suportado; não comprova exposição."
    elif fallback:
        if checks["content_matches_expected"]:
            outcome, reason = "inconclusive", "Estrutura sensível também nos caminhos inexistentes; não permite atribuir exposição a um arquivo específico."
        else:
            outcome, reason = "not_detected", "Respostas equivalentes às de caminhos inexistentes; provável fallback ou resposta genérica."
    elif not checks["content_matches_expected"]:
        outcome, reason = "not_detected", "Não há assinatura estrutural suficiente do tipo de arquivo sensível esperado."
    elif not checks["controls_negative"]:
        outcome, reason = "inconclusive", "Os controles não distinguem um arquivo específico de respostas genéricas com estrutura semelhante."
    elif all(checks.values()):
        outcome, reason = "confirmed", "Arquivo em caminho de risco acessível em referências estáveis, com estrutura compatível, sem HTML e distinto dos controles inexistentes."
    else:
        outcome, reason = "suspected", "Há estrutura de arquivo potencialmente sensível, mas instabilidade ou formato impede confirmação conservadora."
    limitations = ["Confirma acesso e estrutura do artefato; não comprova que valores são segredos válidos ou que o arquivo deva ser privado.",
                  "Catálogo e formatos limitados; não descompacta arquivos, não executa conteúdo e não testa outros diretórios."]
    limitations.extend("Critério não satisfeito: " + name for name, value in checks.items() if not value)
    return ExposureAssessment(outcome, checks, reason, limitations)
