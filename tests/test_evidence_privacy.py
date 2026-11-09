import json
from copy import deepcopy

from scanner.models import ScanReport
from scanner.reporter import write_reports
from scanner.privacy import EvidencePolicy
import pytest


def test_shared_sentinels_and_stable_ids_without_mutation(tmp_path):
    sentinel = 'PRIVATE_SENTINEL'
    raw = {'mode': 'sqli', 'target': 'http://127.0.0.1/' + sentinel + '?' + sentinel + '=' + sentinel,
           'settings': {'parameter': sentinel, 'unknown': sentinel},
           'findings': [{'endpoint': sentinel, 'parameter': sentinel, 'rationale': sentinel}],
           'probes': [{'input_value': sentinel, 'security_headers': {'x': sentinel}}]}
    raw['observed_urls'] = [raw['target']]
    before = deepcopy(raw)
    policy = EvidencePolicy()
    first, second = policy.project(raw), policy.project(raw)
    assert sentinel not in json.dumps(first)
    assert first == second and first['target'] is None and first['target_id']
    assert first['observed_urls'] == [first['target_id']]
    assert raw == before
    assert EvidencePolicy().project(raw)['target_id'] != first['target_id']


def test_default_writer_never_serializes_raw_url(tmp_path):
    report = ScanReport('http://127.0.0.1/PRIVATE_SENTINEL?q=PRIVATE_SENTINEL', 'fixture', {})
    write_reports(report, tmp_path / 'full.json')
    for path in tmp_path.rglob('*.json'):
        assert b'PRIVATE_SENTINEL' not in path.read_bytes()


def test_restricted_masks_sensitive_values():
    result = EvidencePolicy('restricted').project({'target': 'http://a:b@127.0.0.1/path?q=demo&token=PRIVATE',
        'body': 'PRIVATE', 'headers': {'Authorization': 'PRIVATE'}})
    assert result['target'] == 'http://127.0.0.1/path?q=demo&token=%5BREDACTED%5D'
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('writer', ['write_json', 'write_json_atomic'])
@pytest.mark.parametrize('profile', ['shareable', 'restricted'])
def test_legacy_payload_writer_also_applies_privacy(tmp_path, writer, profile):
    import scanner.reporter as reporter
    payload = reporter._Snapshot({'target': 'http://127.0.0.1/private?token=PRIVATE_TOKEN',
        'body': 'PRIVATE_BODY', 'cookies': 'PRIVATE_COOKIE', 'headers': {'Authorization': 'PRIVATE_AUTH'}})
    output = tmp_path / 'legacy.json'
    getattr(reporter, writer)(payload, output, evidence_profile=profile)
    raw = output.read_text(encoding='utf-8')
    assert all(value not in raw for value in ['PRIVATE_TOKEN', 'PRIVATE_BODY', 'PRIVATE_COOKIE', 'PRIVATE_AUTH'])


@pytest.mark.parametrize('field', ['target', 'endpoint', 'url', 'page_url', 'source_page', 'parameter',
    'name', 'file_path', 'input_value', 'marker', 'rationale', 'title', 'detail', 'message', 'limitations',
    'content_type', 'module', 'kind', 'security_headers', 'unknown_future_field', 'body', 'cookies', 'headers'])
def test_shared_never_copies_untrusted_strings(field):
    result = EvidencePolicy().project({field: 'PRIVATE_SENTINEL'})
    assert 'PRIVATE_SENTINEL' not in json.dumps(result)


def test_cli_shared_failure_and_terminal_never_expose_identifiers(http_lab, tmp_path, capsys):
    from main import main
    site = http_lab.start(lambda _: http_lab.reply(body=b'large'))
    output = tmp_path / 'PRIVATE_SENTINEL.json'
    assert main([site.url + '/PRIVATE_SENTINEL?q=PRIVATE_SENTINEL', '--max-body-bytes', '1', '--output', str(output)]) == 1
    terminal = capsys.readouterr()
    assert 'PRIVATE_SENTINEL' not in terminal.out + terminal.err
    for path in tmp_path.rglob('*.json'):
        assert b'PRIVATE_SENTINEL' not in path.read_bytes()


def test_persistence_exception_does_not_print_private_details(http_lab, tmp_path, capsys, monkeypatch):
    from main import main
    site = http_lab.start(lambda _: http_lab.reply())
    def fail(*_args, **_options):
        raise OSError('PRIVATE_SENTINEL')
    monkeypatch.setattr('main.write_reports', fail)
    assert main([site.url, '--output', str(tmp_path / 'full.json'), '--interval', '0']) == 1
    terminal = capsys.readouterr()
    assert 'PRIVATE_SENTINEL' not in terminal.out + terminal.err
    assert 'Erro ao gravar' in terminal.err


def test_restricted_files_have_protected_permissions_before_content(tmp_path, monkeypatch):
    import os
    import subprocess
    import scanner.reporter as reporter
    seen = []
    original = reporter._write_file
    def write(path, content):
        if os.name == 'nt':
            result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                f"$a=Get-Acl -LiteralPath '{path.parent}'; $a.AreAccessRulesProtected; $a.Access.IdentityReference.Value"],
                capture_output=True, text=True, check=True)
            assert result.stdout.splitlines()[0] == 'True'
        else:
            assert path.parent.stat().st_mode & 0o077 == 0
        seen.append(path)
        return original(path, content)
    monkeypatch.setattr(reporter, '_write_file', write)
    report = ScanReport('http://127.0.0.1/private?token=PRIVATE_SENTINEL', 'fixture', {})
    reporter.write_reports(report, tmp_path / 'full.json', evidence_profile='restricted')
    assert len(seen) == 3
    assert all(b'PRIVATE_SENTINEL' not in path.read_bytes() for path in tmp_path.rglob('*.json'))


def test_public_findings_builder_is_shared_by_default():
    from scanner.findings_report import build_findings_report
    result = build_findings_report({'mode': 'sqli', 'findings': [{
        'category': 'sqli', 'status': 'confirmed', 'endpoint': 'http://127.0.0.1/PRIVATE_SENTINEL',
        'parameter': 'PRIVATE_SENTINEL', 'rationale': 'PRIVATE_SENTINEL', 'evidence_request_ids': [1],
        'potential_impact': 'PRIVATE_SENTINEL', 'recommended_mitigation': 'PRIVATE_SENTINEL'}]}, 'PRIVATE_SENTINEL.json')
    assert 'PRIVATE_SENTINEL' not in json.dumps(result)
    assert result['summary']['total'] == 1


def test_shared_sensitive_url_ids_match_between_technical_and_findings(tmp_path):
    from scanner.models import Finding, Confidence, FindingStatus
    from scanner.reporter import read_verified_reports
    report = ScanReport('http://127.0.0.1/private?token=PRIVATE_SENTINEL', 'fixture', {}, mode='sqli')
    report.findings.append(Finding(report.target, 'sqli', 'fixture', Confidence.HIGH,
        FindingStatus.CONFIRMED, [1], 'fixture', 'fixture', 'fixture', 'token'))
    write_reports(report, tmp_path / 'full.json')
    full, findings = read_verified_reports(tmp_path / 'full.json.manifest.json')
    assert full['findings'][0]['endpoint_id'] == findings['findings'][0]['url_id']


def test_three_module_shared_publication_matches_internal_outcomes_and_replay(sqlite_app, tmp_path):
    from scanner.pipeline import run_scan
    from scanner.reporter import read_verified_reports
    seen = []
    def save(report):
        write_reports(report, tmp_path / 'full.json')
        full, findings = read_verified_reports(tmp_path / 'full.json.manifest.json')
        assert full['analysis_summary'] == report.to_dict()['analysis_summary']
        assert full['collection_status'] == report.to_dict()['collection_status']
        seen.append((full['run_id'], full['snapshot_id']))
    report = run_scan(sqlite_app.url + '/probekit-lab', modules=('sqli', 'xss', 'exposure'),
        exposure_profiles=('config', 'backup'), interval=0, checkpoint=save)
    assert report.status == 'completed'
    assert len({run_id for run_id, _ in seen}) == 1
    assert len({snapshot for _, snapshot in seen}) == len(seen)
    full, findings = read_verified_reports(tmp_path / 'full.json.manifest.json')
    assert findings['summary']['total'] == 4
    assert {item['module'] for item in findings['findings']} == {'sqli', 'xss', 'exposure'}
    assert all(item['url'] is None and item['url_id'] for item in findings['findings'])
    from scanner.findings_report import build_findings_report
    rebuilt = build_findings_report(full, 'technical.json')
    assert rebuilt['summary'] == findings['summary']
    assert [item['url_id'] for item in rebuilt['findings']] == [item['url_id'] for item in findings['findings']]
    assert all(not response.body for analysis in report.analyses for response in analysis.responses if hasattr(response, 'body'))
