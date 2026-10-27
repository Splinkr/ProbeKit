"""Validação e normalização de URLs restritas à própria máquina."""

from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit


class TargetError(ValueError):
    """O destino não faz parte do escopo local permitido."""


def validate_target(url: str) -> str:
    """Aceita localhost ou IP loopback; evita resolução DNS de nomes livres."""
    if any(character.isspace() or ord(character) < 32 for character in url):
        raise TargetError("A URL não pode conter espaços ou caracteres de controle.")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
        if parts.scheme not in {"http", "https"} or not host:
            raise TargetError("Informe uma URL http:// ou https:// completa.")
        if parts.username is not None or parts.password is not None:
            raise TargetError("Credenciais na URL não são permitidas.")
        if parts.fragment:
            raise TargetError("Remova o fragmento (#) da URL; ele não é enviado por HTTP.")
        if "\\" in url or "%" in host:
            raise TargetError("Host inválido ou identificador de zona não permitido.")
        if host.lower() == "localhost":
            host = "127.0.0.1"
        address = ip_address(host)
        if not address.is_loopback:
            raise TargetError("Alvo bloqueado: somente localhost ou IPs loopback são permitidos.")
        if port == 0:
            raise TargetError("A porta deve estar entre 1 e 65535.")
    except TargetError:
        raise
    except ValueError as error:
        raise TargetError("URL inválida: use localhost, 127.0.0.1 ou [::1].") from error
    authority = f"[{address}]" if address.version == 6 else str(address)
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))
