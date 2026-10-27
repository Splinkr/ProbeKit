"""Descoberta HTML com servidores locais e referências hostis sem tráfego externo."""

import json
from unittest.mock import Mock

import pytest

from scanner.discovery import HtmlInventoryParser, discover, normalize_url
from scanner.reporter import write_json


def html_reply(lab, text, **kwargs):
    return lab.reply(body=text.encode("utf-8"), headers={"Content-Type": "text/html; charset=utf-8"}, **kwargs)


@pytest.mark.parametrize("url,expected", [
    ("http://LOCALHOST:80/a/../b?z=2&a=1#top", "http://127.0.0.1/b?a=1&z=2"),
    ("https://[::1]:443", "https://[::1]/"),
    ("http://127.0.0.1/%7euser/%2e%2e/%61", "http://127.0.0.1/a"),
    ("http://127.0.0.1/a%2fb?q=%2f", "http://127.0.0.1/a%2Fb?q=%2F"),
    ("http://127.0.0.1/a//b?q=b&q=a&empty=", "http://127.0.0.1/a//b?empty=&q=b&q=a"),
    ("http://127.0.0.1/a/.", "http://127.0.0.1/a/"),
    ("http://127.0.0.1/a/..", "http://127.0.0.1/"),
])
def test_normalization_is_idempotent_without_changing_reserved_separators(url, expected):
    assert normalize_url(url) == expected
    assert normalize_url(expected) == expected


def test_html_parser_extracts_static_fields_without_values_or_scripts():
    parser = HtmlInventoryParser()
    parser.feed('''<base href="/app/">
      <a href="../catalog?x=1&amp;y=2">go</a><area href="/map">
      <script>fetch('/hidden-api'); var text = '<a href="/fake">';</script>
      <input form="lookup" name="outside" value="secret">
      <form id="lookup" action="/search" method="GET">
        <input name="q"><input name="token" type="hidden" value="secret">
        <input name="password" type="password" value="secret">
        <input name="ignored" disabled><input value="unnamed">
        <select name="sort"><option>name</option></select><textarea name="notes">secret</textarea>
      </form>''')
    parser.close()
    assert parser.base_href == "/app/"
    assert parser.links == ["../catalog?x=1&y=2", "/map"]
    form = parser.forms[0]
    assert form.method == "get" and form.action == "/search"
    assert {field.name for field in form.fields} == {"q", "token", "password", "sort", "notes", "outside"}
    assert "secret" not in repr(form)


def test_crawl_merges_duplicate_endpoints_and_keeps_provenance(http_lab, tmp_path):
    def respond(request):
        pages = {
            "/": '''<a href="/catalog?b=2&amp;a=1">first</a>
                <a href="/./catalog?a=1&amp;b=2#section">duplicate</a>
                <a href="/catalog?extra=3">variant</a>
                <form action="/catalog?fixed=yes"><input name="q"><input name="q"></form>
                <a href="#top">self</a>''',
            "/catalog": '<a href="/">back</a>',
        }
        return html_reply(http_lab, pages[request.path])

    site = http_lab.start(respond)
    report = discover(site.url, interval=0)
    assert len(site.calls) == 3  # Raiz e duas variantes canônicas, sem submeter o formulário.
    assert len(report.endpoints) == 2
    catalog = next(endpoint for endpoint in report.endpoints if endpoint.endpoint.endswith("/catalog"))
    assert {parameter.name for parameter in catalog.parameters} == {"a", "b", "extra", "fixed", "q"}
    assert len([parameter for parameter in catalog.parameters if parameter.name == "q"]) == 1
    assert {source.kind for source in catalog.sources} == {"html_link", "get_form"}
    data = json.loads(write_json(report, tmp_path / "inventory.json").read_text(encoding="utf-8"))
    assert data["mode"] == "discover"
    assert data["endpoints"][0]["provided_manually"]
    assert data["endpoints"][1]["discovered_automatically"]
    assert not data["endpoints"][1]["provided_manually"]
    assert all("body" not in page for page in data["pages"])


def test_get_forms_are_inventoried_but_never_submitted(http_lab):
    site = http_lab.start(lambda _: html_reply(http_lab, '''
        <form action="/search?existing=1"><input name="q" value="private-form-value"></form>
        <form method="post" action="/write"><input name="danger"></form>'''))
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1
    assert {endpoint.endpoint for endpoint in report.endpoints} == {site.url + "/", site.url + "/search"}
    assert "private-form-value" not in json.dumps(report.to_dict())
    assert report.skipped["unsupported_form_method"] == 1


@pytest.mark.parametrize("kwargs,expected_calls,reason", [
    ({"max_depth": 0}, 1, "max_depth"),
    ({"max_depth": 1}, 2, "max_depth"),
    ({"max_pages": 1}, 1, "max_pages"),
    ({"max_requests": 1}, 1, "max_requests"),
])
def test_limits_bound_navigation_and_are_reported(http_lab, kwargs, expected_calls, reason):
    site = http_lab.start(lambda req: html_reply(http_lab, f'<a href="/{req.number}">next</a>'))
    report = discover(site.url, interval=0, **kwargs)
    assert len(site.calls) == report.requests_attempted == expected_calls
    assert reason in report.stop_reasons
    assert report.to_dict()["summary"]["status"] == "limited"
    assert max(page["depth"] for page in report.pages) <= kwargs.get("max_depth", 2)


def test_page_limit_and_request_limit_differ_when_a_response_fails(http_lab):
    def respond(request):
        if request.path == "/":
            return html_reply(http_lab, '<a href="/big">big</a><a href="/small">small</a>')
        return http_lab.reply(body=b"x" * 1000) if request.path == "/big" else html_reply(http_lab, "done")

    site = http_lab.start(respond)
    report = discover(site.url, max_pages=2, max_requests=3, max_body_bytes=256, interval=0)
    assert len(site.calls) == 3 and len(report.pages) == 2
    assert len(report.errors) == 1 and report.errors[0].kind == "response_too_large"
    assert report.to_dict()["summary"]["status"] == "incomplete"


def test_breadth_first_frontier_does_not_skip_shallow_siblings(http_lab):
    pages = {"/": '<a href="/a">a</a><a href="/b">b</a>', "/a": '<a href="/deep">deep</a>', "/b": "ok"}
    site = http_lab.start(lambda req: html_reply(http_lab, pages[req.path]))
    report = discover(site.url, max_pages=3, interval=0)
    assert [request.path for request in site.calls] == ["/", "/a", "/b"]
    assert report.queued_remaining == 1


def test_same_origin_guard_rejects_external_and_other_local_targets(http_lab):
    sink = http_lab.start(lambda _: html_reply(http_lab, "should not receive traffic"))
    site = http_lab.start(lambda _: html_reply(http_lab, f'''
        <a href="http://example.invalid/external">external</a>
        <a href="http://192.0.2.1/external">external IP</a>
        <a href="{sink.url}/another-port">local other port</a>
        <a href="http://127.0.0.2:99/another-host">local other host</a>
        <a href="https://127.0.0.1/scheme">other scheme</a>
        <a href="http://user:password@localhost/">credentials</a>
        <a href="javascript:alert(1)">script</a><a href="file:///C:/secret">file</a>
        <form action="{sink.url}/form"><input name="q"></form>'''))
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1 and sink.calls == []
    assert len(report.endpoints) == 1
    assert sum(report.skipped.values()) == 9


@pytest.mark.parametrize("location", ["http://example.invalid/redirect", "/local-redirect"])
def test_redirects_are_not_followed(http_lab, location):
    site = http_lab.start(lambda _: http_lab.reply(body=b'<a href="/hidden">hidden</a>', status=302,
                         headers={"Content-Type": "text/html", "Location": location}))
    # O cliente não segue nenhum redirect; Location também não é um link HTML.
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1 and len(report.endpoints) == 1
    assert report.pages[0]["status_code"] == 302


def test_external_base_does_not_reinterpret_relative_links_as_local(http_lab):
    site = http_lab.start(lambda _: html_reply(http_lab, '<base href="http://example.invalid/"><a href="relative">link</a>'))
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1 and len(report.endpoints) == 1


def test_localhost_alias_and_protocol_relative_link_resolve_to_the_same_origin(http_lab):
    from urllib.parse import urlsplit

    site = http_lab.start(lambda request: html_reply(http_lab,
        f'<a href="//LOCALHOST:{urlsplit(site.url).port}/child#fragment">go</a>' if request.path == "/" else "done"))
    report = discover(site.url.replace("127.0.0.1", "localhost"), interval=0)
    assert [request.path for request in site.calls] == ["/", "/child"]
    assert len(report.endpoints) == 2


def test_scheme_change_is_blocked_even_with_identical_host_and_port(http_lab):
    site = http_lab.start(lambda _: html_reply(http_lab, f'<a href="{site.url.replace("http:", "https:")}/tls">go</a>'))
    report = discover(site.url, interval=0)
    assert report.requests_attempted == 1 and report.errors == []
    assert report.skipped["different_origin"] == 1


def test_local_base_and_empty_form_action_follow_document_rules(http_lab):
    def respond(request):
        return html_reply(http_lab, '<base href="/app/"><a href="child">go</a><form><input name="term"></form>') if request.path == "/" else html_reply(http_lab, "done")

    site = http_lab.start(respond)
    report = discover(site.url, interval=0)
    assert [req.path for req in site.calls] == ["/", "/app/child"]
    root = report.endpoints[0]
    assert {parameter.name for parameter in root.parameters} == {"term"}


@pytest.mark.parametrize("media,status", [("application/json", 200), ("text/plain", 200), ("text/html", 404)])
def test_non_html_and_error_documents_are_not_expanded(http_lab, media, status):
    site = http_lab.start(lambda _: http_lab.reply(body=b'<a href="/trap">trap</a>', status=status, headers={"Content-Type": media}))
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1 and len(report.endpoints) == 1


def test_http_charset_is_used_for_form_field_names(http_lab):
    site = http_lab.start(lambda _: http_lab.reply(body='<form><input name="opção"></form>'.encode("latin-1"),
                                                 headers={"Content-Type": "text/html; charset=iso-8859-1"}))
    report = discover(site.url, interval=0)
    assert report.endpoints[0].parameters[0].name == "opção"


def test_discovery_does_not_invoke_sql_detection_or_invent_api_routes(http_lab, monkeypatch):
    attack = Mock(side_effect=AssertionError("Detector não deve executar na descoberta"))
    monkeypatch.setattr("scanner.core.run_detection", attack)
    site = http_lab.start(lambda _: html_reply(http_lab, "<script>fetch('/rest/products/search?q=apple')</script>"))
    report = discover(site.url, interval=0)
    assert len(site.calls) == 1 and len(report.endpoints) == 1
    attack.assert_not_called()
