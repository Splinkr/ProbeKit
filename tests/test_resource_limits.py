import pytest
from scanner.core import run_baseline
from scanner.discovery import discover, HtmlInventoryParser


def test_seed_length_validation_before_network(http_lab):
    site = http_lab.start(lambda _: http_lab.reply())
    with pytest.raises(ValueError):
        discover(site.url + '/' + 'x' * 100, max_url_length=20)
    assert not site.calls


def test_dense_html_is_bounded_in_parser_and_inventory(http_lab):
    body = ''.join(f'<a href="/?q={i}">x</a>' for i in range(5000)).encode()
    site = http_lab.start(lambda _: http_lab.reply(body=body, headers={'Content-Type': 'text/html'}))
    report = discover(site.url, max_candidates=12, max_urls=5, interval=0)
    assert len(report.candidates) <= 12
    assert report.to_dict()['resource_usage']['urls'] <= 5
    assert report.to_dict()['collection_status'] == 'limited'


def test_cumulative_body_and_release(http_lab):
    site = http_lab.start(lambda _: http_lab.reply(body=b'x' * 100))
    report = run_baseline(site.url, interval=0, max_total_body_bytes=150)
    assert report.to_dict()['resource_usage']['total_body_bytes'] == 151
    assert len(report.responses) == 1
    assert report.responses[0].body == b''
    assert report.responses[0].size_bytes == 100
    assert not report.execution_errors


@pytest.mark.parametrize('option', ['max_urls', 'max_candidates', 'max_url_length', 'max_metadata_bytes', 'max_total_body_bytes'])
@pytest.mark.parametrize('value', [0, -1])
def test_invalid_data_limits(option, value):
    with pytest.raises(ValueError):
        run_baseline('http://127.0.0.1/', **{option: value})


def test_metadata_limit_stops_scan_without_execution_failure_or_negative(http_lab):
    from scanner.pipeline import run_scan
    site = http_lab.start(lambda _: http_lab.reply(body=b'<a href="/?q=demo">go</a>', headers={'Content-Type': 'text/html'}))
    report = run_scan(site.url, interval=0, max_metadata_bytes=1000)
    data = report.to_dict()
    assert data['collection_status'] == 'limited'
    assert data['resource_usage']['metadata_bytes'] <= 1000
    assert not site.calls and not report.execution_errors
    assert data['analysis_summary']['evaluations'] == 0


def test_discarded_large_response_bytes_are_counted(http_lab):
    from scanner.http_client import HttpClient, HttpClientError
    site = http_lab.start(lambda _: http_lab.reply(body=b'x' * 5000))
    with HttpClient(max_body_bytes=100, interval=0) as client:
        with pytest.raises(HttpClientError) as error:
            client.get(site.url)
        assert error.value.failure.kind == 'response_too_large'
        assert client.resources.total_body_bytes == 101


@pytest.mark.parametrize('limit', ['max_body_bytes', 'max_total_body_bytes'])
def test_limits_over_one_chunk_only_read_one_detection_byte(http_lab, limit):
    from scanner.http_client import HttpClient, HttpClientError
    from scanner.resources import ResourceLimit
    site = http_lab.start(lambda _: http_lab.reply(body=b'x' * 30000))
    with HttpClient(interval=0, **{limit: 9000}) as client:
        with pytest.raises((HttpClientError, ResourceLimit)):
            client.get(site.url)
        assert client.resources.body_bytes_observed == 9001


def test_parser_limits_form_fields_before_retaining_them():
    from scanner.resources import Resources
    resources = Resources(max_candidates=5)
    parser = HtmlInventoryParser(resources)
    parser.feed('<form>' + ''.join(f'<input name="p{i}">' for i in range(1000)) + '</form>')
    parser.close()
    assert sum(len(form.fields) for form in parser.forms) <= 4
    assert resources.candidate_records == 5
    assert resources.rejected['max_candidates'] > 0


@pytest.mark.parametrize('module', ['sqli', 'xss', 'exposure'])
def test_huge_sample_plan_is_bounded_before_materialization(http_lab, monkeypatch, module):
    from scanner.core import run_sqli
    from scanner.modules.xss import run_xss
    from scanner.modules.exposure import run_exposure
    import scanner.sqli_plans as sql
    import scanner.modules.xss as xss
    import scanner.modules.exposure as exposure
    # A fronteira sentinela evita criar uma lista enorme na reprodução anterior.
    owner, name = {'sqli': (sql, 'build_probe_plan'), 'xss': (xss, 'build_plan'), 'exposure': (exposure, 'build_plan')}[module]
    original = getattr(owner, name)
    def bounded(*args, **options):
        count = options.get('samples', args[1] if module == 'sqli' else args[2])
        assert count < 100, 'Plano enorme chegou ao construtor antes do orçamento'
        return original(*args, **options)
    monkeypatch.setattr(owner, name, bounded)
    site = http_lab.start(lambda _: http_lab.reply())
    target = site.url + ('/' if module == 'exposure' else '/?q=demo')
    report = {'sqli': run_sqli, 'xss': run_xss, 'exposure': run_exposure}[module](
        target, samples=100_000_000, max_requests=1_000_000_000, max_metadata_bytes=1000, interval=0)
    assert not site.calls and not report.execution_errors
    assert report.to_dict()['collection_status'] == 'limited'
    assert report.to_dict()['analysis_summary']['evaluations'] == 0
