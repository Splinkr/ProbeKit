from pathlib import Path
import subprocess
import pytest


@pytest.mark.parametrize('name', ['uv.zip', 'uv/uv.exe'])
def test_corrupt_cache_is_rejected_before_use(tmp_path, name):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'not an executable or archive')
    script = Path('scripts/uv-integrity.ps1').resolve()
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
        f". '{script}'; Get-VerifiedUv -ToolsDir '{tmp_path}'"], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Integridade' in result.stderr
    assert path.read_bytes() == b'not an executable or archive'


def test_requirements_enforce_hashes_and_wheels():
    for name in ['requirements.txt', 'requirements-dev.txt']:
        text = Path(name).read_text()
        assert '--require-hashes' in text and '--only-binary=:all:' in text
