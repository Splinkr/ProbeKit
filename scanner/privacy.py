"""Projeções sem mutação. A chave HMAC nunca faz parte do snapshot."""
import hashlib
import hmac
import os
import re

from scanner.findings_report import _safe_url


URL_FIELDS = {'url', 'target', 'initial_url', 'endpoint', 'page_url', 'source_page', 'exposure_base_url'}
PARAM_FIELDS = {'parameter', 'name'}
PARAM_LISTS = {'parameters', 'available_parameters', 'form_parameters'}
URL_LISTS = {'observed_urls'}
OPAQUE_FIELDS = {key + '_id' for key in URL_FIELDS | PARAM_FIELDS | {'file_path'}}
PRIVATE_FIELDS = {'body', 'headers', 'cookies', 'authorization', 'set-cookie', 'cookie', 'proxy-authorization'}
OMIT = {'input_value', 'marker', 'security_headers', 'reflections', 'escaping', 'sql_error_signatures'}
TEXT = {'title', 'rationale', 'evidence', 'potential_impact', 'recommended_mitigation', 'message',
        'limitations', 'detail', 'reason', 'interpretation'}
# Somente campos estruturais conhecidos entram no compartilhável. Dicionários
# de critérios/indicadores são tratados separadamente, nunca como texto livre.
FIELDS = set('''experiment scanner_version python_version repetitions_per_endpoint positive_definition dataset_before
dataset_after runs metrics true_positive true_negative false_positive false_negative dataset_unchanged same_baseline_products expectations_matched case target
outcomes expected_outcomes expectation_matched transport_errors repetition expected_positive metric
baseline_product_count baseline_product_ids_sha256 report outcome schema_version outcome resource_limits mode target_source started_at finished_at settings summary responses errors
execution_errors comparisons findings probes assessment parameter_results exposure_results discovery
targets requests stop_reasons skipped endpoints pages candidates ignored_targets analysis_summary
collection_status url_redacted anonymized analyses resource_limits profiles store_content store_key_names store_values run_id snapshot_id producer_version evidence_profile anonymized source_report
source_sha256 report_type scan_status by_module total confirmed suspected applicable evaluations
outcomes has_inconclusive not_detected reflected_safe inconclusive status confidence category module
vulnerability_type evidence_request_ids request_id collected_at status_code content_type size_bytes
body_sha256 elapsed_ms method role response_received product_count product_ids_sha256 context features
format strategy fingerprint result_count nonempty valid error_like content_format active_script_marker
checks browser_evidence confirmed target_network_requests csp_preserved depth source sources kind
phase profile file_path expected_kind reachable requests_attempted responses_received findings errors
requests_used discovery_requests analysis_requests requests_remaining endpoints_discovered parameters_analyzed
targets_ignored unique_parameters_analyzed files_analyzed pages_fetched queued_remaining parameters
provided_manually discovered_automatically observed_urls location field_type samples timeout_seconds
max_requests interval_seconds max_body_bytes follow_redirects scope planned_requests confirmation_scope
max_depth max_pages submit_forms global_request_budget modules xss_browser exposure_profiles browser_requested
shared_global_budget required_requests remaining_requests sqli_context context baseline_request_id
compared_request_id status_changed content_type_changed size_delta_bytes body_changed sample_similarity
compared_sample_bytes strong_signature is_html public_document assignment_count section_count indicators
normalized_sha256 max_urls max_candidates max_url_length max_metadata_bytes max_total_body_bytes
request_deadline resource_usage metadata_bytes total_body_bytes urls candidate_records rejected
transport_bytes body_bytes_discarded body_bytes_observed body_bytes_reserved limited retained_body_bytes'''.split()) | URL_FIELDS | PARAM_FIELDS | PARAM_LISTS | TEXT
ENUMS = set('''sqlite_positive_negative_control general_sqli true_positive true_negative false_positive false_negative vulnerable safe baseline discover scan sqli xss exposure confirmed suspected inconclusive not_detected reflected_safe
completed incomplete interrupted limited running pending skipped failed received execution_error GET manual
automatic html_link get_form configured_profile query form same_origin_loopback loopback_only like quoted
reflected_xss file_exposure controlled_boolean_read_condition high medium low config backup dotenv git head
unknown html json text structured generic baseline_1 baseline_2 true_1 true_2 false_1 false_2 error recovery
marker_1 marker_2 escape attack_html attack_attribute attack_single attack_double reference control
not_requested not_needed unavailable verified success timeout connection_error http_error tls_error
response_too_large request_limit deadline_exceeded total_body_limit max_urls max_candidates max_url_length
max_metadata_bytes max_total_body_bytes max_pages max_depth max_requests user_interrupt checkpoint_error
insufficient_global_budget different_origin invalid_base invalid_or_non_loopback_url unsupported_form_method
no_query_parameters duplicate_target form_reference_values_unavailable discovery_transport_failure
discovery_http_error redirect_not_followed unsupported_parameter_reference outside_authorized_origin
boolean_pair_1 boolean_pair_2 ini repository git_head sql_backup config_backup control_1 control_2
reference_1 reference_2 invalid_json collection_values canonical_json unsupported unsupported_media_type
collection_ids:id normalized_text normalized_html text/html text/plain application/json
sql_injection reflected_xss sensitive_file_exposure'''.split())


class EvidencePolicy:
    def __init__(self, profile='shareable'):
        if profile not in {'shareable', 'restricted'}:
            raise ValueError('Perfil de evidência inválido.')
        self.profile = profile
        self._key = os.urandom(32)

    def identifier(self, kind, value):
        return kind + '_' + hmac.new(self._key, (kind + '\0' + str(value)).encode('utf-8'), hashlib.sha256).hexdigest()[:32]

    def label(self, kind, value):
        if value is None:
            return None
        if self.profile == 'restricted':
            return _safe_url(str(value))[0] if kind == 'url' else str(value)
        return self.identifier(kind, value)

    def project(self, data):
        return {**self.project_payload(data), 'evidence_profile': self.profile, 'anonymized': self.profile == 'shareable', 'schema_version': '2.0'}

    def project_payload(self, data):
        """Também protege payloads legados sem fabricar schema/proveniência."""
        return self._walk(data)

    def _walk(self, value, parent=''):
        if isinstance(value, list):
            if parent in URL_LISTS and self.profile == 'shareable':
                return [self.identifier('url', item) for item in value]
            if parent in PARAM_LISTS and self.profile == 'shareable':
                return [self.identifier('parameter', item) if isinstance(item, str) else self._walk(item) for item in value]
            return [self._walk(item, parent) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key.lower() in PRIVATE_FIELDS:
                    continue
                if self.profile == 'shareable':
                    if key not in FIELDS | OPAQUE_FIELDS:
                        continue
                    if key in OPAQUE_FIELDS:
                        result[key] = item if isinstance(item, str) and re.fullmatch(r'(url|parameter|path)_[a-f0-9]{32}', item) else None
                        continue
                    if key in OMIT:
                        continue
                    if key in URL_FIELDS | PARAM_FIELDS | {'file_path'}:
                        kind = 'url' if key in URL_FIELDS else 'parameter' if key in PARAM_FIELDS else 'path'
                        result[key] = None
                        existing = value.get(key + '_id')
                        result[key + '_id'] = self.identifier(kind, item) if item is not None else (
                            existing if isinstance(existing, str) and re.fullmatch(r'(url|parameter|path)_[a-f0-9]{32}', existing) else None)
                        continue
                    if key in {'checks', 'indicators'}:
                        # Nomes de critérios declarados pelo código, com booleanos somente.
                        result[key] = {name: flag for name, flag in item.items() if name in CRITERIA and isinstance(flag, bool)}
                        continue
                if self.profile == 'restricted' and key == 'input_value':
                    from scanner.findings_report import SENSITIVE_NAMES
                    normalized = re.sub(r'[^a-z0-9]', '', str(value.get('parameter', '')).lower())
                    if SENSITIVE_NAMES.search(normalized):
                        result[key] = '[REDACTED]'
                        continue
                result[key] = self._walk(item, key)
            return result
        if not isinstance(value, str):
            return value
        if self.profile == 'restricted':
            if parent in URL_FIELDS or value.startswith(('http://', 'https://')):
                return _safe_url(value)[0]
            return value
        if parent in TEXT:
            if parent == 'reason' and value in ENUMS:
                return value
            return 'Detalhes omitidos no perfil compartilhável.'
        if parent in {'baseline_product_ids_sha256', 'body_sha256', 'product_ids_sha256', 'fingerprint', 'normalized_sha256', 'source_sha256'}:
            return value if re.fullmatch('[a-f0-9]{64}', value) else None
        if parent in {'run_id', 'snapshot_id', 'producer_version', 'schema_version'}:
            return value if re.fullmatch(r'[0-9a-fA-F.\-]+(?:alpha|rc)?[.0-9]*', value) else None
        if parent in {'started_at', 'finished_at', 'collected_at'}:
            return value if re.fullmatch(r'[0-9T:+.Z\-]+', value) else None
        if parent == 'content_type':
            return value.split(';')[0].lower() if value.split(';')[0].lower() in {'text/html', 'application/xhtml+xml', 'application/json', 'text/plain', 'application/octet-stream'} else 'other'
        if parent in {'source_report', 'report_type'}:
            return value if value in {'technical.json', 'security_findings'} else None
        return value if value in ENUMS else 'omitted'


# Gerado dos nomes de critérios existentes e revisado como lista estática;
# não se expande a partir de dados coletados.
CRITERIA = set('''all_requests_completed baseline_nonempty baseline_stable recovery_matches new_sql_error
boolean_pair_1 boolean_pair_2 all_parameters_conclusive exclusive_markers_and_recovery
two_independent_markers executable_html_context browser_execution references_http_200
content_matches_expected controls_negative references_stable recovery_stable no_html_fallback
reference_recovery_match stable_references stable_recovery markers_reflected strong_signature
structured_content dotenv_assignments backup_sql git_config git_reference private_key'''.split())

CRITERIA.update(['all_requests_completed', 'application_setting', 'baseline_nonempty', 'baseline_stable', 'browser_execution_observed', 'content_matches_expected', 'controls_negative', 'controls_stable', 'credential_setting', 'database_setting', 'different_from_missing_paths', 'escaped_quote_control_empty', 'exclusive_markers_and_recovery', 'false_responses_stable', 'git_reference', 'literal_control_empty', 'new_sql_error', 'not_html_or_public_document', 'potentially_executable_context', 'recovery_matches', 'references_http_200', 'references_stable', 'sql_data_statement', 'sql_schema', 'two_marker_reflections'])
