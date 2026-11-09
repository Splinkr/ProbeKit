"""Decodificação defensiva de corpos HTTP; cabeçalhos do alvo não são confiáveis."""

from email.message import Message


def decode_http_body(body: bytes, content_type: str) -> str:
    header = Message()
    header["Content-Type"] = content_type
    try:
        return body.decode(header.get_content_charset() or "utf-8", errors="replace")
    except (LookupError, UnicodeError):
        # Inclui codecs reconhecidos que não aceitam errors="replace" (ex.: idna).
        return body.decode("utf-8", errors="replace")
