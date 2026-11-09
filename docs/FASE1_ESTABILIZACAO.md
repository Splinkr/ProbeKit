# Fase 1 — Confiabilidade e estados de execução

Base: commit `2b24d23`, versão 0.1.0; checkout inicialmente limpo e 390 testes
coletados. O trabalho se restringe a R01/P1 e R02/P2. Não altera critérios de
confirmação, payloads, navegador XSS, loopback, redirects ou orçamento. Não
inclui instalação, atualização de dependências, commit ou push.

## Problemas reproduzidos antes das correções

R01 foi reproduzido inicialmente com mocks: `charset=idna` gerava `UnicodeError`,
o último checkpoint ficava `completed` e a CLI retornava 2. A regressão nova
também reproduziu o erro com um servidor HTTP loopback real e saída temporária.
Erros de processamento injetados durante descoberta/análise escapavam dos
runners. Uma segunda falha de checkpoint podia substituir o primeiro OSError.

R02: uma análise direta `inconclusive` sem erro de transporte gerava
`scan_status: completed`, sem indicar inconclusividade no resumo vazio de
achados. Essa semântica de coleta do campo antigo foi preservada; as novas
informações tornam a conclusão analítica explícita.

A primeira execução das 47 regressões iniciais registrou **42 falhas e cinco
aprovações** em 2,55 s. Parte das falhas era a ausência dos novos campos/helper;
outras demonstraram diretamente os comportamentos incorretos existentes.
Registro local: `reports/phase1-before.xml`. A revisão acrescentou casos de
interrupção em finalizadores e durante a gravação final, também reproduzidos
antes de sua correção.

## Alterações e responsabilidades

| Arquivo/grupo | Motivo da alteração |
|---|---|
| `scanner/decoding.py` | Fallback compartilhado para charset ausente/desconhecido/incompatível |
| `scanner/discovery.py`, `sqli_features.py`, `xss_analysis.py`, `exposure_analysis.py` | Usar a mesma política de decodificação; descoberta contém falhas inesperadas |
| `scanner/core.py`, `scanner/modules/{sqli,xss,exposure}.py` | Encerrar modos diretos com evidência parcial, contar tentativas reais e preservar a falha original durante finalização |
| `scanner/pipeline.py` | Finalizar somente após término normal, registrar erro de execução, separar persistência, parar alvos e preservar Ctrl+C/OSError |
| `scanner/models.py`, `scanner/exposure_models.py` | Erros de execução separados do transporte e metadados operacionais/analíticos aditivos |
| `scanner/report_state.py` | Calcular estado de coleta e contagens, sem reclassificar resultados |
| `scanner/findings_report.py` | Derivar os novos metadados do mesmo snapshot e aceitar entradas legadas |
| `main.py` | Retornar 1 e apresentar diagnóstico fixo para falhas de execução; evitar mensagem de baseline em detector sem classificação |
| Três novos arquivos de testes | Regressões de decoding, execução/finalização e relatório analítico |
| README e esta documentação | Explicar compatibilidade, comportamento e resultados da validação |

Erros de processamento são registros `execution_errors` com `phase`, `module`,
`kind: execution_error` e mensagem fixa. Não incluem corpo, traceback ou texto
da exceção. Os campos novos das dataclasses ficam ao final com defaults,
preservando chamadas posicionais existentes.

As tentativas dos modos diretos e de cada análise integrada são registradas
pelo contador do cliente, inclusive quando a resposta não chega a ser convertida
em evidência. Erros de execução não somam uma tentativa HTTP extra. SQLi e
baseline retêm a resposta recebida antes de extrair/comparar; exposure mantém
somente metadados permitidos, sem introduzir retenção de corpo no seu modelo.

Fallback de charset é uma recuperação normal: respeita encodings válidos com
substituição, e recupera LookupError/UnicodeError em UTF-8. Os caminhos JSON e
base64/replay não foram substituídos. O processamento recuperado não dispara
novas requisições nem muda a classificação por regra especial.

Exceções inesperadas encerram o restante da execução. No integrado, o alvo
ativo fica `failed` e os pendentes `skipped`, com motivo `execution_error`.
Resultados e achados anteriores permanecem. Uma avaliação que não pôde ser
calculada permanece ausente; não se fabrica um negativo ou uma confirmação.
O primeiro OSError de checkpoint continua sendo propagado, mesmo se a tentativa
final também falhar. Uma falha no avaliador não encobre KeyboardInterrupt.

## Contrato JSON aditivo

Versões de schema e campos antigos são preservados. `summary.status` e
`scan_status` continuam com a semântica histórica por modo: direto pode estar
`completed` com outcome inconclusivo; integrado continua `incomplete` nesse
caso. Falhas novas de execução são corretamente `incomplete`.

`collection_status` representa somente o estado operacional. Pode ser
`running`, `completed`, `limited`, `incomplete` ou `interrupted`. Erros HTTP ou
de processamento impedem coleta concluída; outcomes, por si sós, não alteram
esse campo.

`analysis_summary` contém:

```json
{
  "applicable": true,
  "evaluations": 2,
  "outcomes": {
    "confirmed": 1,
    "suspected": 0,
    "not_detected": 0,
    "reflected_safe": 0,
    "inconclusive": 1
  },
  "has_inconclusive": true
}
```

O exemplo é ilustrativo, não resultado de um scan. Uma confirmação permanece
em `findings`, mesmo coexistindo com uma avaliação inconclusiva. Sem achados,
`findings` continua `[]`, mas a inconclusividade permanece visível.

Contam-se resultados individuais de parâmetros/arquivos. Usa-se o assessment
agregado só quando não há individuais; no integrado, percorrem-se as análises
uma vez, sem somar as cópias consolidadas. Não se inferem avaliações a partir
dos achados. Baseline/discovery têm applicable=false e contagens zeradas;
detectores sem avaliação têm zero, sem atribuição de segurança. As contagens
representam avaliações disponíveis, não garantem cobertura dos alvos ignorados.

O resumo continua sem novas requisições e sem reclassificar detectores. Para
JSON legado, calcula as contagens com as avaliações presentes, preserva o estado
legado e mantém collection_status=null se esse dado explícito estiver ausente.

## Validação

Os testes novos incluem mocks para falhas internas e HTTP loopback real para
charset e avaliações inconclusivas. Fixtures de SQLite exercitam preservação de
resultados; os testes existentes de navegador validam o replay sem alteração.
Falhas internas são simuladas deliberadamente; não são alegações de exceções
observadas em aplicações externas.

Comandos executados, na raiz, com `PYTHONUTF8=1`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_http_decoding.py tests/test_execution_reliability.py tests/test_analysis_summary.py --tb=short --junitxml=reports/phase1-before.xml
.\.venv\Scripts\python.exe -m pytest -q tests/test_http_decoding.py tests/test_execution_reliability.py tests/test_analysis_summary.py --tb=short --junitxml=reports/phase1-new-tests.xml
.\.venv\Scripts\python.exe -m pytest -q tests/test_checkpoint_contract.py tests/test_evidence_contract.py tests/test_scan_pipeline.py tests/test_findings_report.py tests/test_cli_process_contract.py tests/test_discovery_cli.py tests/test_terminal_contract.py --tb=short --junitxml=reports/phase1-related-tests.xml
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/phase1-all-tests.xml
```

O registro `before` corresponde aos 47 casos iniciais antes das correções; não
é recriado pela última versão do código. Após completar as regressões, os
**61 testes novos passaram em 2,06 s**. Os **129 contratos existentes
relacionados passaram em 27,65 s**. A suíte completa terminou com
**451 aprovados, zero falhas, zero erros e zero ignorados em 69,29 s**,
incluindo os oito casos existentes de navegador real. Os XML ficam locais e
ignorados pelo Git; nenhuma expectativa de teste antigo foi alterada.

A comparação de AST confirmou que `assess` SQLi, `assess_xss`, `assess` exposure
e o plano XSS mantêm o mesmo conteúdo lógico do HEAD. Escopo, cliente HTTP,
planos SQLi, catálogo exposure, wrapper/helper do navegador e requisitos também
permanecem iguais, considerando os finais de linha do Git.

Estado final: **R01 corrigido e validado** por mocks, processamento HTTP local,
CLI e testes de finalização/interrupção. **R02 corrigido e validado** por
contratos sintéticos e execuções HTTP/SQLite locais, com compatibilidade da
suíte anterior e preservação dos achados. A validação não foi realizada contra
alvos externos nem representa uma medida universal de precisão dos detectores.

## Compatibilidade e riscos residuais

Códigos preservados: 0 para conclusão/limitação sem falha impeditiva; 1 para
execução, persistência ou avaliação inconclusiva; 2 para validação; 130 para
Ctrl+C tratado no scan. Charset recuperado pode concluir normalmente com 0.
Erros de callback/serialização do checkpoint são falhas de gravação, não erros
de argumentos.

As extensões JSON são aditivas; leitores que aceitam apenas uma lista rígida de
campos precisam permitir os novos metadados. Clientes Python passam a receber
relatórios incompletos em falhas inesperadas de processamento contidas pelos
runners; validação continua lançando ValueError/TargetError e persistência de
checkpoint continua propagando OSError.

Persistência depende do filesystem; encerramento forçado, uma segunda
interrupção ou disco indisponível não garantem o último checkpoint. Não há
transação conjunta dos dois JSONs, retomada, deadline total ou solução dos
outros achados da auditoria nesta fase. Nenhuma precisão universal dos
detectores foi presumida. Artefatos históricos foram preservados.
