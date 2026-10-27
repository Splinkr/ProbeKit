"""Seleção de parâmetros e sondas booleanas de leitura, independente do endpoint."""

import re
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlsplit, urlunsplit

from scanner.models import ProbeEvidence
from scanner.targets import validate_target

PAIRS = (17, 23)
EXTRA_REQUESTS = 8
CONTEXTS = ("like", "quoted")


def available_parameters(url: str) -> list[str]:
    target = validate_target(url)
    return list(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True, max_num_fields=200)))


def select_parameters(url: str, parameter: str | None = None, all_parameters: bool = False) -> list[str]:
    target = validate_target(url)
    pairs = parse_qsl(urlsplit(target).query, keep_blank_values=True, max_num_fields=200)
    names = list(dict.fromkeys(name for name, _ in pairs))
    if parameter is not None and all_parameters:
        raise ValueError("Use --parameter ou --all-parameters, não ambos.")
    if parameter is not None:
        selected = [parameter]
    elif all_parameters:
        selected = names
    elif "q" in names:
        selected = ["q"]  # Compatibilidade da CLI anterior.
    elif len(names) == 1:
        selected = names
    else:
        raise ValueError("Selecione --parameter NOME ou --all-parameters para URLs com múltiplos parâmetros.")
    if not selected:
        raise ValueError("A URL precisa conter parâmetros GET.")
    for name in selected:
        values = [value for key, value in pairs if key == name]
        if not name or len(values) != 1:
            raise ValueError(f"O parâmetro {name!r} deve existir uma única vez; repetições são ambíguas.")
        if not re.fullmatch(r"[\w -]{1,80}", values[0]) or not values[0].strip():
            raise ValueError(f"Use um valor de referência simples de 1 a 80 caracteres em {name!r}.")
    return selected


def build_probe_plan(
    url: str, samples: int, max_requests: int, *, parameter: str | None = None,
    context: str = "like", start_id: int = 1,
) -> list[ProbeEvidence]:
    target = validate_target(url)
    name = select_parameters(target, parameter)[0]
    term = next(value for key, value in parse_qsl(urlsplit(target).query, keep_blank_values=True) if key == name)
    if context not in CONTEXTS:
        raise ValueError("Contexto SQLi suportado: like ou quoted.")
    if samples < 2:
        raise ValueError("SQLi requer pelo menos duas referências (--samples 2).")
    if samples + EXTRA_REQUESTS > max_requests:
        raise ValueError(f"SQLi requer --max-requests de pelo menos {samples + EXTRA_REQUESTS} por parâmetro.")
    entries = [(f"baseline_{index + 1}", term) for index in range(samples)]
    entries.extend([("quote", term + "'"), ("escaped_quote", term + "''"), ("literal_control", term + " AND 17=17")])
    for number in PAIRS:
        for label, operand in (("true", number), ("false", number + 1)):
            value = (f"{term}%' AND ({number}={operand}) AND '%' LIKE '%"
                     if context == "like" else f"{term}' AND ({number}={operand}) AND 'x'='x")
            entries.append((f"{label}_{number}", value))
    entries.append(("recovery", term))
    return [ProbeEvidence(index, role, name, value, context=context)
            for index, (role, value) in enumerate(entries, start=start_id)]


def probe_url(target: str, value: str, parameter: str = "q") -> str:
    """Muda um único token da query; demais tokens ficam byte a byte intactos."""
    parts = urlsplit(validate_target(target))
    tokens = parts.query.split("&")
    indexes = [i for i, token in enumerate(tokens) if unquote_plus(token.partition("=")[0]) == parameter]
    if len(indexes) != 1:
        raise ValueError("O parâmetro testado deve existir uma única vez na URL.")
    tokens[indexes[0]] = quote_plus(parameter) + "=" + quote_plus(value)
    return urlunsplit(parts._replace(query="&".join(tokens)))


def prepare_parameters(url, samples, max_requests, parameter=None, all_parameters=False, context="like"):
    selected = select_parameters(url, parameter, all_parameters)
    for name in selected:
        build_probe_plan(url, samples, max_requests, parameter=name, context=context)
    required = len(selected) * (samples + EXTRA_REQUESTS)
    if required > max_requests:
        raise ValueError(f"O orçamento global requer --max-requests de pelo menos {required} para {len(selected)} parâmetro(s).")
    return selected
