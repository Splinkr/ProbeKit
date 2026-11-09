"""Academic Markdown generated from the verified public package only."""
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET

from experiments.evaluation.common import ROOT, load
from experiments.evaluation.generate_report import verify


def rate(item):
    return "N/D (0 no denominador)" if item["value"] is None else f'{100*item["value"]:.2f}% ({item["numerator"]}/{item["denominator"]})'


def table(groups):
    lines = ["| Domínio/condição/estrato | Slots | TP | FP | TN | FN | Suspected | Inconclusive | Não avaliados | Precisão | Recall | Especificidade | FPR | Confirmação/vulneráveis planejados |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- |"]
    for g in groups:
        if g['stratum'] == 'mitigated':
            continue
        m=g['A'];c=m['counts']
        lines.append('| '+ '/'.join([g['domain'],g['condition'],g['stratum']])+' | '+str(m['planned'])+' | '+
            ' | '.join(str(c[k]) for k in ['TP','FP','TN','FN','suspected','inconclusive','not_evaluated'])+' | '+
            ' | '.join(rate(m[k]) for k in ['precision','recall','specificity','false_positive_rate','confirmation_yield'])+' |')
    return '\n'.join(lines)


def junit(path):
    if not path or not Path(path).exists():
        return "Não executado/registro ausente."
    s=ET.parse(path).getroot().find('testsuite')
    return f"{int(s.get('tests'))-int(s.get('failures'))-int(s.get('errors'))-int(s.get('skipped'))} aprovados; {s.get('failures')} falhos; {s.get('errors')} erros; {s.get('skipped')} ignorados; {s.get('time')} s."


def render(package, output=None):
    package=Path(package).resolve();verify(package)
    metrics=load(package/'analysis/metrics.json'); rows=load(package/'analysis/rows.json')
    workflows=load(package/'analysis/workflows.json');env=load(package/'environment.json')
    repeat=load(package/'analysis/repeatability.json'); groups=metrics['groups']
    lines=['# ProbeKit — resultados experimentais PK-F3 v1.0.0', '',
        f"Campanha `{metrics['evaluation_id']}`; análise `{metrics['analysis_id']}` (versão {metrics['analysis_version']}); produto 0.2.0; coletor 1.0.0.", '',
        '## 1. Resumo da avaliação', '',
        f"Foram planejadas {metrics['planned_runs']} execuções; {metrics['verified_runs']} produziram evidência verificada. "
        f"O scanner registrou {metrics['scanner_requests']} GET; {metrics['unknown_request_runs']} execuções têm consumo desconhecido. "
        'As contagens seguintes são observações desta bateria, sem garantia universal.', '',
        '## 2. Objetivos e hipóteses', '',
        'O protocolo prévio avalia classificação, abstenção, cobertura e repetibilidade. '
        'A hipótese de benefício dos critérios diferenciais é comparada com uma heurística HTTP; '
        'a comparação não identifica causalmente o efeito isolado dos controles negativos.', '',
        '## 3. Ambiente e versões', '',
        f"HEAD registrado: `{env['head']}` com alterações locais da Fase 2. O inventário SHA-256 contém o estado exato do código e dos testes. "
        f"Python: {env['python']}; plataforma: {env['platform']}; Node: {env['node_version']}; Edge: {env.get('browser_version')}. "
        f"Requests: {env['packages'].get('requests')}; Matplotlib: {env['packages'].get('matplotlib')}. "
        'O banco original do Juice Shop não foi usado: a execução usa clone do ZIP verificado.', '',
        '## 4. Metodologia', '',
        'Protocolo e catálogo foram registrados antes da coleta formal. Foram usados comandos existentes, '
        'três repetições, servidores controlados novos e originais restritos com ACL. Nenhum classifier/payload/laboratório foi alterado. '
        'O gabarito deriva das implementações, não dos outcomes históricos. Não é estudo cego. '
        'As fórmulas e limitações estão em `protocol.md` no pacote. Cada unidade é um parâmetro ou arquivo, '
        'sem duplicar assessments agregados, findings ou checkpoints.', '',
        '## 5. Casos e gabarito', '',
        'S01–S14 cobrem LIKE/quoted, JSON/HTML/texto, consultas concatenadas e parametrizadas, múltiplos parâmetros e diagnósticos. '
        'X01–X10 cobrem contextos executáveis, escape, MIME não executável, ausência de reflexão e CSP nas condições estática/browser. '
        'E01–E18 combinam seis diretórios e três perfis. `cases.json` contém unidades, justificativas, símbolos e hashes. '
        'CSP é mitigado, fora da matriz binária; diagnósticos e Juice não são incorporados à matriz principal.', '']
    for n,module in [(6,'sqli'),(7,'xss'),(8,'exposure')]:
        lines += [f'## {n}. Resultados {module.upper()}', '', table([g for g in groups if g['module']==module]), '']
        if module == 'xss':
            lines += ['CSP é contado por outcome, sem atribuição binária. Navegador solicitado e confirmação são registros distintos.', '',
                '| Condição CSP | Avaliações | Suspected | Inconclusive | Confirmed | Browser completed | Confirmações no navegador |',
                '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
            for g in groups:
                if g['module'] != 'xss' or g['stratum'] != 'mitigated':continue
                selected = [r for r in rows if r['module']=='xss' and r['stratum']=='mitigated' and r['condition']==g['condition']]
                observed = g['A']['observed']
                lines.append('| '+g['condition']+' | '+' | '.join(str(v) for v in [g['A']['evaluated'],observed.get('suspected',0),observed.get('inconclusive',0),observed.get('confirmed',0),sum(r.get('browser_status')=='completed' for r in selected),sum(r.get('browser_confirmed') is True for r in selected)])+' |')
            lines.append('')
    lines += ['## 9. Matrizes, cobertura e abstenções', '',
        'Negativos são not_detected e, somente para XSS, reflected_safe. Suspected e inconclusive não se tornam TP/TN. '
        'Sem avaliação utilizável é not_evaluated; integridade inválida impede o uso da evidência. '
        'Recall conclusivo pode ser N/D quando todas as vulnerabilidades ficam suspeitas; '
        'o rendimento sobre vulneráveis planejados revela essa ausência de confirmação.', '',
        '| Grupo | Cobertura de unidades | Inconclusividade | Suspeitas |', '| --- | --- | --- | --- |']
    for g in groups:
        lines.append('| '+'/'.join(g[k] for k in ['domain','module','condition','stratum'])+' | '+
            ' | '.join(rate(g['A'][k]) for k in ['coverage','inconclusive_rate','suspected_rate'])+' |')
    lines += ['', '## 10. Comparação com heurística simplificada', '',
        'B compara status/tamanho/hash bruto com a primeira referência, na mesma evidência coletada. '
        'Não usa nome do caso, gabarito, URLs ou assessment; positive é predição, não confirmação. '
        'A interpretação deve considerar conjuntamente acertos, erros e abstenções.', '',
        '| Grupo | Acertos A | FP A | FN A | Suspeitas/inconclusivos A | Acertos B | FP B | FN B | Inconclusivos B |', '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for g in groups:
        if g['stratum'] == 'mitigated':
            continue
        a,b=g['A']['counts'],g['B']['counts']
        lines.append('| '+'/'.join(g[k] for k in ['domain','module','condition','stratum'])+' | '+
            ' | '.join(str(v) for v in [a['TP']+a['TN'],a['FP'],a['FN'],a['suspected']+a['inconclusive'],b['TP']+b['TN'],b['FP'],b['FN'],b['inconclusive']])+' |')
    lines += ['', '## 11. Juice Shop e integração', '',
        'O Juice Shop 20.3.0 usa JavaScript. Estes números não medem cobertura integral da aplicação. '
        'J01 é descoberta automática com catálogo Exposure configurado; J02 é uma URL manual conhecida de busca. '
        'Ausência do endpoint conhecido na descoberta não é resultado negativo do detector.', '',
        '| Caso/rep | Páginas | Endpoints | Parâmetros | Alvos | Arquivos configurados | Busca conhecida descoberta/analisada | GET | Tempo processo (s) |',
        '| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |']
    for w in workflows:
        if w['case_id'] not in ['I01','J01','J02']:continue
        d=w.get('workflow') or {}
        lines.append(f"| {w['case_id']}/{w['repetition']} | {d.get('pages','—')} | {d.get('endpoints','—')} | {d.get('parameters','—')} | {d.get('targets','—')} | {d.get('configured_file_targets','—')} | {d.get('known_search_discovered','—')}/{d.get('known_search_analyzed','—')} | {w.get('requests')} | {w.get('wall_seconds')} |")
    lines.append('')
    for w in workflows:
        if w['case_id'] not in ['I01','J01','J02']:continue
        d=w.get('workflow') or {}
        if d:
            lines += ['', f"{w['case_id']}/{w['repetition']}: requisições por fase {d['requests_by_phase']}; por módulo {d['requests_by_module']}; "
                      f"estados {d['target_statuses']}; ignorados {d['ignored_reasons']}; limites {d['stop_reasons']}; outcomes {d['analysis_summary']}.", '']
    consistent=sum(r['all_three_consistent'] for r in repeat)
    lines += ['', '## 12. Repetibilidade', '',
        f"{consistent}/{len(repeat)} combinações unidade/condição tiveram as três avaliações disponíveis e idênticas. "
        'O arquivo repeatability.json mostra frequências, ausências, mínimo/mediana/máximo e desvio amostral. '
        'Marcadores, timestamps e portas variam por construção; hashes diferentes entre repetições não provam instabilidade. '
        'Não foram calculados intervalos de confiança ou significância com n=3.', '',
        '## 13. Limitações e ameaças à validade', '',
        'Conjunto sintético e pequeno, configurações/repetições correlacionadas, conhecimento histórico e um único ambiente. '
        'A heurística não representa ZAP/Burp e difere em vários critérios. Exposure confirma estrutura de artefatos fictícios, '
        'não validade de segredos. Tempos incluem subprocesso, worker, navegador quando solicitado e gravação; caches do SO podem variar. '
        'A descoberta estática não executa JavaScript. Matrizes de diagnóstico/mitigado não substituem a principal. '
        'Hashes comprovam correspondência, não assinatura/autenticidade contra substituição de todo o pacote.', '',
        '## 14. Conclusões fundamentadas', '',
        'Os resultados demonstram somente o comportamento nas unidades/configurações registradas. '
        'O grau de confirmação, suspeita e abstenção deve ser apresentado junto às taxas conclusivas. '
        'A aplicação complexa mostra cobertura observada e o efeito de fornecer uma URL manual; não certifica segurança da aplicação. '
        'Na apresentação acadêmica, mostrar a matriz principal, abstenções, contraste A/B e descoberta automática versus manual, '
        'sem omitir diagnósticos desfavoráveis.', '',
        '## 15. Reprodução, artefatos e testes', '',
        'Usar Python/locks e estado de código registrados. Os comandos prepare/run/analyze/export/verify são descritos no README do avaliador. '
        'Cada campanha/análise usa UUID novo e não sobrescreve dados. O pacote público permite recalcular as métricas e B sem acesso aos originais restritos.', '',
        f"Pacote: `{package.relative_to(ROOT).as_posix()}`.", '',
        'Suíte anterior: '+junit(ROOT/'reports/phase3-before.xml'),
        'Testes novos finais: '+junit(ROOT/'reports/phase3-release-new.xml'),
        'Suíte final: '+junit(ROOT/'reports/phase3-release-all.xml'), '',
        f"Execuções não avaliadas/sem evidência verificada: {metrics['not_evaluated_runs']}.", '',
        'Figuras derivadas: outcomes, matrices, comparison e timings (PNG/SVG em analysis/figures). '
        'Os históricos da Fase 2 e os testes com fixtures não foram incorporados às observações desta campanha. '
        'Não houve commit, push, tag ou publicação automática.', '']
    target=Path(output or ROOT/'docs/RESULTADOS_EXPERIMENTAIS.md')
    target.write_bytes(('\n'.join(lines)+'\n').encode('utf-8'))
    return target
