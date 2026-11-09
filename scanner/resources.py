"""Orçamentos de dados por execução; reservas precedem retenção e tráfego."""
import json
from dataclasses import asdict, is_dataclass


DEFAULTS = dict(max_urls=1000, max_candidates=2000, max_url_length=8192,
                max_metadata_bytes=8 * 1024 * 1024, max_total_body_bytes=32 * 1024 * 1024)


class ResourceLimit(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Limite configurado de dados atingido.')


class Resources:
    def __init__(self, **options):
        self.limits = {**DEFAULTS, **options}
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in self.limits.values()):
            raise ValueError('Limites de dados devem ser inteiros positivos.')
        self.urls = set()
        self.metadata_bytes = 0
        self.candidate_records = 0
        self.total_body_bytes = 0
        self.body_bytes_observed = 0
        self.body_bytes_reserved = 0
        self.rejected = {}
        self.stop_reasons = []

    def reject(self, reason):
        self.rejected[reason] = self.rejected.get(reason, 0) + 1
        if reason not in self.stop_reasons:
            self.stop_reasons.append(reason)
        return False

    def url(self, value, *, initial=False):
        if len(value.encode('utf-8')) > self.limits['max_url_length']:
            if initial:
                raise ValueError('URL inicial excede --max-url-length.')
            return self.reject('max_url_length')
        if value not in self.urls:
            if len(self.urls) >= self.limits['max_urls']:
                return self.reject('max_urls')
            if not self.reserve(value):
                return False
            self.urls.add(value)
        return True

    def reserve(self, value, *, candidate=False):
        size = len(json.dumps(value, ensure_ascii=True, default=str).encode('utf-8')) + 16
        if candidate and self.candidate_records >= self.limits['max_candidates']:
            return self.reject('max_candidates')
        if not self.reserve_bytes(size):
            return False
        self.candidate_records += int(candidate)
        return True

    def reserve_bytes(self, size):
        if self.metadata_bytes + size > self.limits['max_metadata_bytes']:
            return self.reject('max_metadata_bytes')
        self.metadata_bytes += size
        return True

    def require(self, value):
        if not self.reserve(value):
            raise ResourceLimit('max_metadata_bytes')

    def snapshot(self):
        return dict(urls=len(self.urls), metadata_bytes=self.metadata_bytes,
                    candidate_records=self.candidate_records, total_body_bytes=self.total_body_bytes,
                    body_bytes_observed=self.body_bytes_observed, body_bytes_reserved=self.body_bytes_reserved,
                    rejected=dict(self.rejected), limited=bool(self.stop_reasons))


def bind_resources(report, client):
    report._resources = client.resources
    report.settings.update(client.resources.limits)
    report.settings['request_deadline'] = client.request_deadline
    for name in ('responses', 'comparisons', 'findings', 'probes',
                 'parameter_results', 'exposure_results', 'pages', 'candidates', 'targets',
                 'ignored_targets', 'endpoints', 'analyses'):
        value = getattr(report, name, None)
        if isinstance(value, list) and not isinstance(value, BudgetList):
            setattr(report, name, BudgetList(value, client.resources, soft=name in {'ignored_targets', 'execution_errors'}))


class BudgetList(list):
    def __init__(self, values, resources, *, soft=False):
        super().__init__(values)
        self.resources, self.soft = resources, soft

    def append(self, value):
        if hasattr(value, 'to_dict'):
            metadata = value.to_dict()
        else:
            metadata = asdict(value) if is_dataclass(value) else value
        if not self.resources.reserve(metadata):
            if self.soft:
                return
            raise ResourceLimit('max_metadata_bytes')
        super().append(value)

    def extend(self, values):
        for value in values:
            self.append(value)


def release_bodies(report):
    # ResponseEvidence é imutável para os detectores. A liberação ocorre somente
    # depois da última análise/replay; metadados e hashes permanecem iguais.
    for response in report.responses:
        if hasattr(response, 'body'):
            object.__setattr__(response, 'body', b'')


def reserve_plan(client, count, target):
    """Reserva aritmética antes de materializar listas controladas por samples."""
    if not client.resources.reserve_bytes(count * (512 + len(target.encode('utf-8')))):
        raise ResourceLimit('max_metadata_bytes')
