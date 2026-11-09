import hashlib
import json

import pytest

from scanner.models import ScanReport
from scanner.reporter import read_verified_reports, write_reports


def test_generation_identity_exact_hash_and_checkpoints(tmp_path):
    report = ScanReport('http://127.0.0.1/', 'fixture', {})
    output = tmp_path / 'full.json'
    write_reports(report, output)
    manifest = output.with_suffix('.json.manifest.json')
    first, summary = read_verified_reports(manifest, expected_run_id=report.run_id)
    assert summary['source_sha256'] == hashlib.sha256(output.read_bytes()).hexdigest()
    write_reports(report, output)
    second, _ = read_verified_reports(manifest)
    assert second['run_id'] == first['run_id']
    assert second['snapshot_id'] != first['snapshot_id']
    with pytest.raises(ValueError):
        read_verified_reports(manifest, expected_run_id='wrong')


def test_tampering_and_path_escape_rejected(tmp_path):
    output = tmp_path / 'full.json'
    write_reports(ScanReport('http://127.0.0.1/', 'fixture', {}), output)
    pointer = output.with_suffix('.json.manifest.json')
    manifest = json.loads(pointer.read_text())
    path = tmp_path / manifest['files']['technical']['path']
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError):
        read_verified_reports(pointer)
    manifest['files']['technical']['path'] = '../escape.json'
    pointer.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        read_verified_reports(pointer)


def test_failed_alias_leaves_verifiable_generation(tmp_path):
    output = tmp_path / 'full.json'
    (tmp_path / 'findings.json').mkdir()
    with pytest.raises(OSError):
        write_reports(ScanReport('http://127.0.0.1/', 'fixture', {}), output)
    assert read_verified_reports(output.with_suffix('.json.manifest.json'))[0]['mode'] == 'baseline'


@pytest.mark.parametrize('stage', ['technical', 'findings', 'generation_manifest', 'promote', 'pointer', 'alias', 'summary_alias'])
@pytest.mark.parametrize('interrupt', [False, True])
def test_every_failure_stage_preserves_a_committed_pair(tmp_path, monkeypatch, stage, interrupt):
    import scanner.reporter as publisher
    from pathlib import Path
    output = tmp_path / 'full.json'
    old = ScanReport('http://127.0.0.1/old', 'fixture', {})
    publisher.write_reports(old, output)
    original_write, original_atomic, original_rename = publisher._write_file, publisher._atomic_bytes, Path.rename
    def fail():
        raise KeyboardInterrupt if interrupt else OSError('injected')
    def write(path, content):
        if path.name == {'technical': 'technical.json', 'findings': 'findings.json', 'generation_manifest': 'manifest.json'}.get(stage):
            fail()
        return original_write(path, content)
    def atomic(content, path, **options):
        if path.name == {'pointer': 'full.json.manifest.json', 'alias': 'full.json', 'summary_alias': 'findings.json'}.get(stage):
            fail()
        return original_atomic(content, path, **options)
    def rename(path, target):
        if stage == 'promote':
            fail()
        return original_rename(path, target)
    monkeypatch.setattr(publisher, '_write_file', write)
    monkeypatch.setattr(publisher, '_atomic_bytes', atomic)
    monkeypatch.setattr(Path, 'rename', rename)
    current = ScanReport('http://127.0.0.1/current', 'fixture', {})
    with pytest.raises(KeyboardInterrupt if interrupt else OSError):
        publisher.write_reports(current, output)
    technical, findings = publisher.read_verified_reports(output.with_suffix('.json.manifest.json'))
    assert technical['run_id'] == (current.run_id if stage in {'alias', 'summary_alias'} else old.run_id)
    assert findings['run_id'] == technical['run_id']
    assert not list(tmp_path.rglob('.pending-*'))


def test_concurrent_processes_publish_complete_generations(tmp_path):
    import subprocess
    import sys
    code = "from scanner.models import ScanReport; from scanner.reporter import write_reports; import sys; write_reports(ScanReport('http://127.0.0.1/', 'fixture', {}),sys.argv[1])"
    output = tmp_path / 'full.json'
    workers = [subprocess.Popen([sys.executable, '-c', code, str(output)], creationflags=subprocess.CREATE_NO_WINDOW) for _ in range(2)]
    assert all(worker.wait(timeout=20) == 0 for worker in workers)
    full, findings = read_verified_reports(output.with_suffix('.json.manifest.json'))
    assert full['run_id'] == findings['run_id']
    assert len(list((tmp_path / '.probekit-evidence').glob('*/*/technical.json'))) == 2


def test_verify_cli_codes_and_legacy(tmp_path, capsys):
    from main import main
    output = tmp_path / 'full.json'
    write_reports(ScanReport('http://127.0.0.1/', 'fixture', {}), output)
    assert main(['verify-report', str(output.with_suffix('.json.manifest.json'))]) == 0
    assert main(['verify-report', str(output)]) == 1
    assert main(['verify-report', str(tmp_path / 'absent')]) == 1
    with pytest.raises(SystemExit) as error:
        main(['verify-report'])
    assert error.value.code == 2
