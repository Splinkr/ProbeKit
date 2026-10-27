"""Catálogo fechado: no máximo cinco caminhos por diretório-base explicitamente escolhido."""

from dataclasses import dataclass
import secrets
from urllib.parse import unquote, urlsplit, urlunsplit

from scanner.targets import validate_target


@dataclass(frozen=True)
class FileSpec:
    path: str
    profile: str
    kind: str


PROFILES = {
    "config": (FileSpec(".env", "config", "dotenv"), FileSpec("config.ini", "config", "ini")),
    "backup": (FileSpec("backup.sql", "backup", "sql_backup"), FileSpec("config.ini.bak", "backup", "config_backup")),
    "repository": (FileSpec(".git/HEAD", "repository", "git_head"),),
}
DEFAULT_PROFILES = ("config",)


def select_profiles(profiles=DEFAULT_PROFILES):
    selected = tuple(dict.fromkeys(profiles))
    if not selected or any(profile not in PROFILES for profile in selected):
        raise ValueError("Perfis exposure: config, backup e repository.")
    return [spec for profile in selected for spec in PROFILES[profile]]


def base_url(url, base_path=None):
    parts = urlsplit(validate_target(url))
    path = parts.path if base_path is None else base_path
    decoded = unquote(path)
    if (parts.query and base_path is None) or not path.startswith("/") or path.startswith("//") or not path.endswith("/") or any(
        character in decoded for character in "?#\\"
    ) or any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("Exposure requer URL/diretório-base terminado em /, sem query, fragmento ou segmentos relativos.")
    return validate_target(urlunsplit(parts._replace(path=path, query="", fragment="")))


def file_url(base, spec):
    # Somente entradas do catálogo fechado, sem caminhos arbitrários ou expansões.
    if spec not in select_profiles(tuple(PROFILES)):
        raise ValueError("Caminho fora do catálogo exposure.")
    return base_url(base) + spec.path


def request_cost(samples=2):
    if samples < 2:
        raise ValueError("Exposure requer ao menos duas referências por arquivo.")
    return samples + 2


def build_plan(base, spec, samples=2):
    url = file_url(base, spec)
    parts = urlsplit(url)
    directory, _, filename = parts.path.rpartition("/")

    def missing():
        path = directory + "/.probekit-missing-" + secrets.token_hex(12) + "-" + filename
        return validate_target(urlunsplit(parts._replace(path=path)))

    return [("control_1", missing()), *[(f"reference_{index + 1}", url) for index in range(samples)], ("control_2", missing())]
