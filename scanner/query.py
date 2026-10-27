"""Seleção GET genérica e substituição de um único token, sem restrições SQL."""

from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlsplit, urlunsplit

from scanner.targets import validate_target


def parameter_names(url):
    return list(dict.fromkeys(name for name, _ in parse_qsl(
        urlsplit(validate_target(url)).query, keep_blank_values=True, max_num_fields=200)))


def select_parameters(url, parameter=None, all_parameters=False):
    pairs = parse_qsl(urlsplit(validate_target(url)).query, keep_blank_values=True, max_num_fields=200)
    names = list(dict.fromkeys(name for name, _ in pairs))
    if parameter is not None and all_parameters:
        raise ValueError("Use --parameter ou --all-parameters, não ambos.")
    selected = [parameter] if parameter is not None else names if all_parameters else ["q"] if "q" in names else names if len(names) == 1 else []
    if not selected:
        raise ValueError("Selecione um parâmetro GET existente ou --all-parameters.")
    for name in selected:
        values = [value for key, value in pairs if key == name]
        if not name or len(values) != 1 or len(values[0]) > 200:
            raise ValueError(f"O parâmetro {name!r} deve ocorrer uma única vez, com até 200 caracteres.")
    return selected


def replace_parameter(url, parameter, value):
    parts = urlsplit(validate_target(url))
    tokens = parts.query.split("&")
    indexes = [index for index, token in enumerate(tokens) if unquote_plus(token.partition("=")[0]) == parameter]
    if len(indexes) != 1:
        raise ValueError("O parâmetro testado deve existir uma única vez.")
    tokens[indexes[0]] = quote_plus(parameter) + "=" + quote_plus(value)
    return urlunsplit(parts._replace(query="&".join(tokens)))
