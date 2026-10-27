"""Reflexão e contexto estático; nenhum parser HTML é prova de execução JavaScript."""

from dataclasses import replace
from email.message import Message
from html import unescape
from html.parser import HTMLParser
import json
import re

from scanner.models import XssAssessment

ATTR = re.compile(r'''([^\s=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?''')
JS_TYPES = {"", "text/javascript", "application/javascript", "module"}


class ReflectionParser(HTMLParser):
    def __init__(self, marker, callback):
        super().__init__(convert_charrefs=False)
        self.marker, self.callback = marker, callback
        self.reflections = []
        self.stack = []
        self.script_type = ""
        self.active_script_marker = False

    def add(self, context, **details):
        self.reflections.append({"context": context, **details})

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text()
        for match in ATTR.finditer(raw[len(tag) + 1:]):
            name = match[1].lower()
            value = next((value for value in match.groups()[1:] if value is not None), "")
            if self.marker in value:
                context = "event_handler" if name.startswith("on") else "url_attribute" if name in {"href", "src", "action", "formaction"} else "html_attribute"
                self.add(context, tag=tag, attribute=name,
                         quote="double" if match[2] is not None else "single" if match[3] is not None else "unquoted")
        if tag == "script":
            self.script_type = dict(attrs).get("type", "") or ""
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]

    def handle_data(self, data):
        if self.marker not in data:
            return
        if "template" in self.stack:
            context = "inert_template"
        elif self.stack and self.stack[-1] == "script":
            context = "script" if self.script_type.lower().strip() in JS_TYPES else "script_data"
            if context == "script" and self.callback in data:
                self.active_script_marker = True
        elif self.stack and self.stack[-1] in {"textarea", "title"}:
            context = "html_rcdata"
        elif self.stack and self.stack[-1] == "style":
            context = "css"
        else:
            context = "html_text"
        self.add(context)

    def handle_comment(self, data):
        if self.marker in data:
            self.add("html_comment")


def inspect_response(probe, response, callback):
    media = Message()
    media["Content-Type"] = response.content_type
    content_format = media.get_content_type()
    try:
        text = response.body.decode(media.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        text = response.body.decode("utf-8", errors="replace")
    reflections, active, escaping = [], False, {}
    if probe.marker:
        if content_format == "text/html":
            parser = ReflectionParser(probe.marker, callback)
            parser.feed(text)
            parser.close()
            reflections, active = parser.reflections, parser.active_script_marker
        elif probe.marker in text:
            reflections = [{"context": "json" if content_format == "application/json" or content_format.endswith("+json") else "plain_text" if content_format == "text/plain" else "other"}]
        if probe.role == "escape" and probe.marker in text and probe.marker + "END" in text:
            section = text.split(probe.marker, 1)[1].split(probe.marker + "END", 1)[0]
            literal_section = re.sub(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);", "", section)
            escaping = {char: "literal" if char in literal_section else "html_entity" if char in unescape(section) else "removed_or_encoded"
                        for char in '<>&"\''}
    return replace(probe, response_received=True, content_format=content_format,
                   reflections=reflections, escaping=escaping, active_script_marker=active)


def assess_xss(report, parameter, callback, browser_evidence, expected_count):
    probes = {probe.role: probe for probe in report.probes if probe.parameter == parameter}
    responses = {response.request_id: response for response in report.responses}
    selected_ids = {probe.request_id for probe in probes.values()}
    markers = [probe.marker for probe in probes.values() if probe.marker]
    baselines = [probe for role, probe in probes.items() if role.startswith("baseline_") or role == "recovery"]

    def healthy(probe):
        response = responses.get(probe.request_id) if probe else None
        if not response or not 200 <= response.status_code < 300:
            return False
        if "json" in response.content_type.lower():
            try:
                payload = json.loads(response.body)
                if isinstance(payload, dict) and (payload.get("status") in ("error", "failed") or payload.get("error")):
                    return False
            except (ValueError, UnicodeError, RecursionError):
                return False
        return True

    controls_clean = bool(baselines) and all(
        healthy(probe) and not any(marker.encode() in responses[probe.request_id].body for marker in markers)
        for probe in baselines
    )
    marker_pair = all(probes.get(role) and healthy(probes[role]) and probes[role].reflections for role in ("marker_1", "marker_2"))
    marker_probes = [probes[role] for role in ("marker_1", "marker_2") if role in probes]
    early_negative = len(marker_probes) == 2 and all(not probe.reflections for probe in marker_probes)
    required_count = expected_count - 5 if early_negative else expected_count
    complete = len(probes) == required_count and "recovery" in probes and all(healthy(probe) for probe in probes.values()) and not any(error.request_id in selected_ids for error in report.errors)
    contexts = {item["context"] for role in ("marker_1", "marker_2") if role in probes for item in probes[role].reflections}
    active = any(probe.active_script_marker for role, probe in probes.items() if role.startswith("attack_"))
    escape = probes.get("escape")
    unescaped_markup = bool(escape and escape.content_format == "text/html" and escape.escaping.get("<") == "literal")
    attribute_unquoted = any(item.get("quote") == "unquoted" for role in ("marker_1", "marker_2") if role in probes for item in probes[role].reflections)
    risky = active or bool(contexts & {"script", "event_handler", "url_attribute", "css", "other"}) or unescaped_markup or attribute_unquoted
    checks = {"all_requests_completed": complete, "exclusive_markers_and_recovery": controls_clean,
              "two_marker_reflections": bool(marker_pair), "potentially_executable_context": risky,
              "browser_execution_observed": browser_evidence.get("confirmed", False)}
    limitations = ["Somente XSS refletido GET; não cobre XSS armazenado, DOM XSS, eventos que exigem interação ou todos os contextos de template/JavaScript."]
    if early_negative:
        limitations.append("Sem reflexão nos dois marcadores: cinco sondas de escape/execução foram dispensadas; referências, marcadores e recuperação foram coletados.")
    if browser_evidence.get("status") != "completed":
        limitations.append("Sem prova de execução em navegador nesta coleta: " + browser_evidence.get("status", "not_requested"))
    else:
        limitations.append("Navegador usa replay isolado das respostas HTTP com CSP preservada e rede bloqueada; não reproduz sessão autenticada ou recursos externos.")
    inconsistent = any(probe.reflections for probe in marker_probes) and not marker_pair
    if not complete or not controls_clean or inconsistent:
        outcome, rationale = "inconclusive", "Coleta incompleta, resposta inadequada ou marcador presente nos controles; não permite concluir sobre XSS refletido."
    elif not marker_pair:
        outcome, rationale = "not_detected", "Duas reflexões independentes não foram demonstradas; o plano não detectou XSS refletido."
    elif browser_evidence.get("confirmed") and risky:
        outcome, rationale = "confirmed", "Marcadores exclusivos refletidos e callback JavaScript inofensivo observado no documento principal do navegador; controle negativo não executou."
    elif risky:
        outcome, rationale = "suspected", "Reflexão em contexto potencialmente executável ou quebra estrutural de HTML; falta confirmação suficiente de execução."
    else:
        outcome, rationale = "reflected_safe", "Reflexão observada em contexto inerte ou com escape nas sondas executadas; não é garantia geral de segurança."
    return XssAssessment(outcome, checks, rationale, limitations, parameter, browser_evidence=browser_evidence)
