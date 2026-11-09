"""Publicação verificável por gerações imutáveis."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Protocol
from uuid import UUID, uuid4
from scanner import __version__
from scanner.findings_report import _build_findings_report as build_findings_report
from scanner.private_files import private_directory

class _Snapshot:
    def __init__(self, data):
        self.data = data
    def to_dict(self):
        return self.data

class JsonReport(Protocol):
    def to_dict(self) -> dict[str, Any]: ...

def findings_path(destination):
    output = Path(destination)
    return output.with_name('findings-summary.json' if output.name.casefold() == 'findings.json' else 'findings.json')

def manifest_path(destination):
    output = Path(destination)
    return output.with_name(output.name + '.manifest.json')

def _bytes(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _stamp(part, identity):
    part.update(identity)
    for child in part.get('analyses', []):
        _stamp(child, identity)
    if part.get('discovery') is not None:
        _stamp(part['discovery'], identity)

def _replace(source, destination):
    for attempt in range(4):
        try:
            source.replace(destination)
            return
        except PermissionError as error:
            if getattr(error, 'winerror', None) not in {5, 32, 33} or attempt == 3:
                raise
            time.sleep(0.05 * (attempt + 1))

def _write_file(path, content):
    with path.open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())

def _atomic_bytes(content, output, *, restricted=False):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    private = None
    if restricted:
        private = private_directory(output.parent / (".private-" + str(uuid4())))
    try:
        fd, name = tempfile.mkstemp(dir=private or output.parent, prefix='.scan-', suffix='.tmp')
        temporary = Path(name)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if private is not None:
            private.rmdir()
    return output

def _policy(report, evidence_profile=None):
    from scanner.privacy import EvidencePolicy
    policy = getattr(report, '_evidence_policy', None)
    if not isinstance(policy, EvidencePolicy) or (evidence_profile is not None and policy.profile != evidence_profile):
        policy = EvidencePolicy(evidence_profile or 'shareable')
        report._evidence_policy = policy
    return policy

def write_json_atomic(report: JsonReport, destination, *, evidence_profile=None):
    data = report.to_dict()
    policy = _policy(report, evidence_profile)
    if data.get('mode'):
        data = policy.project(data)
        _stamp(data, dict(run_id=str(UUID(data['run_id'])), snapshot_id=str(uuid4()),
                          producer_version=__version__, schema_version='2.0', evidence_profile=policy.profile))
    else:
        data = policy.project_payload(data)
    return _atomic_bytes(_bytes(data), Path(destination), restricted=policy.profile == 'restricted')

def write_json(report: JsonReport, destination, *, evidence_profile=None):
    return write_json_atomic(report, destination, evidence_profile=evidence_profile)

def write_reports(report: JsonReport, destination, *, atomic=False, evidence_profile=None, policy=None):
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict()
    policy = policy or _policy(report, evidence_profile)
    run_id = str(UUID(data['run_id']))
    snapshot_id = str(uuid4())
    identity = dict(run_id=run_id, snapshot_id=snapshot_id, producer_version=__version__,
                    schema_version='2.0', evidence_profile=policy.profile)
    summary = build_findings_report(data, 'technical.json', redact_urls=policy.profile == 'restricted')
    data = {**policy.project(data), **identity}
    _stamp(data, identity)
    technical = _bytes(data)
    summary = {**policy.project(summary), **identity, 'source_sha256': _sha(technical)}
    findings = _bytes(summary)
    base = output.parent.resolve()
    root = base
    for component in ('.probekit-evidence', run_id):
        root = root / component
        if root.is_symlink() or root.is_junction():
            raise OSError('Diretório de evidências redirecionado.')
        root.mkdir(exist_ok=True)
    generation = root / snapshot_id
    staging = private_directory(root / ('.pending-' + str(uuid4()))) if policy.profile == 'restricted' else Path(tempfile.mkdtemp(dir=root, prefix='.pending-'))
    manifest = {'manifest_version': '1.0', **identity, 'files': {
        key: {'path': str((generation / name).relative_to(base).as_posix()), 'sha256': _sha(content)}
        for key, name, content in (('technical', 'technical.json', technical), ('findings', 'findings.json', findings))}}
    try:
        _write_file(staging / 'technical.json', technical)
        _write_file(staging / 'findings.json', findings)
        _write_file(staging / 'manifest.json', _bytes(manifest))
        for name, content in (('technical.json', technical), ('findings.json', findings)):
            if _sha((staging / name).read_bytes()) != _sha(content):
                raise OSError('Falha na verificação da geração.')
        staging.rename(generation)
        _atomic_bytes(_bytes(manifest), manifest_path(output), restricted=policy.profile == 'restricted')
        _atomic_bytes(technical, output, restricted=policy.profile == 'restricted')
        _atomic_bytes(findings, findings_path(output), restricted=policy.profile == 'restricted')
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return output

def _read_verified_reports(path, expected_run_id=None):
    path = Path(path).resolve()
    manifest = json.loads(path.read_bytes())
    if manifest.get('manifest_version') != '1.0' or manifest.get('schema_version') != '2.0':
        raise ValueError('Manifesto ausente, legado ou incompatível; evidência não verificada.')
    if manifest.get('evidence_profile') not in {'shareable', 'restricted'}:
        raise ValueError('Perfil de evidência incompatível.')
    run_id, snapshot_id = (str(UUID(manifest[key])) for key in ('run_id', 'snapshot_id'))
    if expected_run_id is not None and expected_run_id != run_id:
        raise ValueError('Identidade da execução divergente.')
    root = path.parent / '.probekit-evidence'
    if root.resolve() != root:
        raise ValueError('Diretório de evidências redirecionado.')
    generation = root / run_id / snapshot_id
    results, contents = [], []
    for key, name in (('technical', 'technical.json'), ('findings', 'findings.json')):
        entry = manifest['files'][key]
        target = (path.parent / entry['path']).resolve()
        if not target.is_relative_to(root) or target != generation / name:
            raise ValueError('Caminho da evidência fora da geração.')
        content = target.read_bytes()
        if _sha(content) != entry['sha256']:
            raise ValueError('Hash da evidência divergente.')
        data = json.loads(content)
        for field in ('run_id', 'snapshot_id', 'producer_version', 'schema_version', 'evidence_profile'):
            if data.get(field) != manifest.get(field):
                raise ValueError('Identidade, versão ou perfil divergente.')
        def validate_children(part):
            for field in ('run_id', 'snapshot_id', 'producer_version', 'schema_version', 'evidence_profile'):
                if part.get(field) != manifest.get(field):
                    raise ValueError('Identidade de componente divergente.')
            for child in part.get('analyses', []):
                validate_children(child)
            if part.get('discovery') is not None:
                validate_children(part['discovery'])
        validate_children(data)
        results.append(data)
        contents.append(content)
    if results[1].get('source_sha256') != _sha(contents[0]):
        raise ValueError('Resumo não corresponde ao técnico.')
    generation_manifest = generation / 'manifest.json'
    if generation_manifest.resolve() != generation_manifest:
        raise ValueError('Caminho do manifesto fora da geração.')
    if json.loads(generation_manifest.read_bytes()) != manifest:
        raise ValueError('Manifestos divergentes.')
    return tuple(results)


def read_verified_reports(path, expected_run_id=None):
    try:
        return _read_verified_reports(path, expected_run_id)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise ValueError('Evidência não verificada: manifesto, identidade ou integridade inválida.') from None
