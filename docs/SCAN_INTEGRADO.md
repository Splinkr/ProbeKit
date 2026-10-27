# Etapa 6 — Descoberta e análise SQLi integradas

`main.py scan URL` usa uma URL inicial para descobrir links HTML, selecionar
parâmetros GET e executar o detector SQLi existente. A CLI anterior, o comando
`discover` e os critérios de confirmação continuam disponíveis. Não há novas
dependências, Docker ou XSS.

## Fluxo e orçamento

`scanner/pipeline.py` orquestra `discovery.crawl()` e `modules.sqli.run_detection()`
com uma única instância de `ScopedHttpClient`. Essa instância herda os limites
do cliente existente e valida a origem antes de cada GET. Descoberta, sondas,
falhas e interrupções compartilham contador, intervalo e IDs globais.
Os arquivos de planos, extração de características e classificação SQLi da
etapa 5 não foram alterados.

Primeiro ocorre a descoberta em largura, depois a análise. O total de tentativas
das duas fases nunca ultrapassa `--max-requests`. Timeout, corpo acima do limite
e tentativa interrompida após a reserva de um ID consomem orçamento. O contador
é conservador: uma tentativa interrompida pode não ter chegado ao servidor.
Não há retries automáticos nem orçamento novo por endpoint.

Cada parâmetro exige `samples + 8` requisições, dez no padrão. Um plano só começa
se esse total couber no saldo global. Alvos restantes são registrados como
`insufficient_global_budget`, com saldo e quantidade necessária. Uma falha
interrompe o plano atual e permite tentar o próximo, se houver orçamento.
Muitos links podem consumir todo o orçamento durante a descoberta; reduza
`--max-pages` ou aumente explicitamente `--max-requests` se necessário.

| Opção | Padrão | Efeito |
| --- | --- | --- |
| `--max-depth` | 2 | Profundidade máxima de navegação e de elegibilidade dos links para SQLi |
| `--max-pages` | 20 | Quantidade máxima de respostas na descoberta; não inclui sondas SQLi |
| `--max-requests` | 100 | Tentativas HTTP globais, descoberta mais SQLi |
| `--timeout` | 5 | Segundos para conexão/inatividade de leitura, sem prazo total de transferência |
| `--interval` | 0.2 | Intervalo mínimo entre inícios, inclusive na mudança de fase |
| `--max-body-bytes` | 1048576 | Tamanho descomprimido máximo por resposta |
| `--samples` | 2 | Referências por parâmetro; mínimo 2 |
| `--sqli-context` | like | Perfil textual `like` ou `quoted`, aplicado a todos os alvos desta rodada |
| `--output` | `reports/scan-<UTC>.json` | Destino consolidado e dos checkpoints |

O limite de páginas pode deixar links sem navegação de descoberta; links já
encontrados dentro da profundidade permitida continuam elegíveis para SQLi,
sempre dentro do orçamento global. Com profundidade zero, apenas a URL inicial
é elegível. Endpoints podem aparecer no inventário mesmo quando seus links
foram ignorados por profundidade, pois os atributos HTML foram observados.

## Seleção, deduplicação e segurança

Alvos são deduplicados por URL canônica completa, parâmetro e contexto.
Fragmentos, segmentos `.` e ordens equivalentes da query não multiplicam testes.
Valores de referência diferentes continuam sendo alvos distintos. Os nomes
GET são analisados individualmente; durante cada plano os demais valores são
preservados. A normalização inicial segue o crawler existente; a substituição
de uma sonda altera somente seu parâmetro na URL já normalizada.

Referências vazias, complexas ou repetidas no parâmetro selecionado são
ignoradas com justificativa, conforme os limites da etapa 5. Parâmetros
repetidos não selecionados são mantidos. Páginas com falha de transporte,
HTTP de erro ou redirect observado na descoberta não recebem sondas.
Redirect durante uma sonda é registrado como resposta e nunca seguido.

O crawler mantém o contrato anterior: inventaria nomes de campos GET sem
coletar seus valores e sem submeter formulários. Por isso, candidatos vindos
somente de formulários ficam como `form_reference_values_unavailable`.
Não se inventam valores nem se monta uma submissão a partir da action.
Um mesmo caminho encontrado também por link com query concreta pode ser
analisado por essa origem. Ignorado não equivale a `not_detected`.

A origem autorizada é a combinação de esquema, host normalizado e porta da
URL inicial loopback. Outras portas e hosts loopback também são bloqueados.
`localhost` segue a conversão existente para `127.0.0.1`. A proteção vale na
descoberta, na seleção e em cada acesso HTTP. Não há liberação de alvos externos,
resolução variável de DNS ou redirecionamento automático.

## Relatório e interrupção

O JSON `mode: scan`, esquema `1.0`, contém:

- `initial_url`: URL inicial normalizada e configurações da rodada;
- `discovery`: inventário, parâmetros, origens, páginas e falhas observadas;
- `targets`: URLs/parâmetros deduplicados com origem e estado de execução;
- `parameter_results`: classificação, critérios, justificativa, limites e IDs;
- `analyses`: relatórios SQLi completos por alvo, incluindo sondas e evidências;
- `requests`: registro global de cada tentativa, com fase e ID;
- `summary`: consumo global, consumo por fase, saldo e quantidades;
- `ignored_targets`, `stop_reasons` e `limitations`: cobertura efetiva e motivos.

Análises automáticas têm `target_source: automatic`; a URL inicial informada
mantém a origem manual. Corpos HTTP não são persistidos. URLs e valores das
sondas ficam registrados para reprodução: use dados fictícios na query.

A CLI grava um checkpoint antes da rede, após a descoberta, após cada parâmetro
e ao finalizar. A escrita usa arquivo temporário no mesmo diretório e troca
atômica, evitando substituir um JSON válido por um arquivo parcialmente escrito.
Ao receber o primeiro Ctrl+C, tenta concluir a classificação das evidências
parciais e salvar `status: interrupted`, sem iniciar os próximos alvos.
Um plano incompleto não recebe confirmação apenas por ter sido interrompido.

Encerramento forçado, falha de disco ou interrupções adicionais durante a
gravação não garantem preservação; o último checkpoint pode não conter o
parâmetro em andamento. Não há retomada automática. Usar novamente o mesmo
`--output` inicia e substitui a rodada anterior.

Saída 0: `completed` ou `limited` por limites configurados. Saída 1: falha de
gravação, transporte ou SQLi inconclusiva (`incomplete`). Saída 2: argumentos ou
URL inicial inválidos. Saída 130: interrupção. `completed` não significa que
todos os itens do inventário eram testáveis; consulte os ignorados. Erros HTTP
observados na descoberta ficam nas evidências e nos motivos dos alvos ignorados.

## Demonstração real — Windows 11

A porta 8003 mantém esta demonstração separada das instâncias anteriores nas
portas 8001/8002 e do Juice Shop na 3000. Não inicie duas instâncias na mesma
porta. Para preparar uma cópia nova, siga o [README](../README.md).

Terminal 1, somente se o laboratório da porta 8003 estiver parado:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8003
```

Terminal 2:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8003/scan-lab --max-depth 2 --max-pages 10 --max-requests 100 --output reports/scan-demo/full.json
$scanResult = Get-Content -Raw -Encoding UTF8 reports/scan-demo/full.json | ConvertFrom-Json
$scanResult.summary | Format-List
$scanResult.parameter_results | ForEach-Object { [pscustomobject]@{ URL=$_.url; Parametro=$_.parameter; Resultado=$_.assessment.outcome } } | Format-Table
```

A página `/scan-lab` contém quatro links concretos para buscas JSON/HTML,
um link duplicado, um formulário sem referência e uma referência externa para
validar o bloqueio. A referência externa não é acessada. Uma API mencionada
somente no JavaScript também não é descoberta. Todas as buscas usam o mesmo
SQLite fictício em memória, com concatenação real ou bindings reais.

Resultado observado em 27/10/2026, entre 15:33:56 e 15:34:13 (UTC−03):

| URL, na origem `http://127.0.0.1:8003` | Parâmetro de busca | Resultado | `lang=en` |
| --- | --- | --- | --- |
| `/general/json/vulnerable?lang=en&term=apple` | term | confirmed | not_detected |
| `/general/json/safe?lang=en&term=apple` | term | not_detected | not_detected |
| `/general/html/vulnerable?lang=en&search=apple` | search | confirmed | not_detected |
| `/general/html/safe?lang=en&search=apple` | search | not_detected | not_detected |

Foram seis endpoints inventariados (incluindo a página inicial e a action do
formulário), oito parâmetros analisados, dois confirmados e seis não detectados.
O total foi **85/100 tentativas: cinco de descoberta e 80 de SQLi**. Cinco
registros foram ignorados: página sem query, dois parâmetros de link duplicado,
campo de formulário sem referência e URL externa bloqueada.

Os limites também foram demonstrados realmente:

```powershell
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8003/scan-lab --max-depth 2 --max-pages 10 --max-requests 25 --output reports/scan-demo/budget-25.json
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8003/scan-lab --max-depth 0 --max-pages 10 --max-requests 100 --output reports/scan-demo/depth-0.json
```

Com orçamento 25: exatamente 25 tentativas, cinco de descoberta e 20 de análise;
`lang` não detectado e `term` confirmado no JSON vulnerável; seis parâmetros
restantes ignorados por orçamento. Com profundidade zero: uma requisição de
descoberta e nenhuma sonda. Ambas as rodadas ficaram `limited`, com motivo.

O hash dos cinco registros permaneceu
`5a7f6cbde94c6fb8d193dc14c708adb2d425546f2ddd294c9793ff3d5864ce0a` antes e depois
das três rodadas. As duas consultas `/health` de verificação foram externas ao
orçamento de cada `scan`. A base usa `PRAGMA query_only=ON` após a inicialização.

Evidências: [rodada completa](evidencias/scan-2026-10-27/full.json),
[orçamento 25](evidencias/scan-2026-10-27/budget-25.json),
[profundidade zero](evidencias/scan-2026-10-27/depth-0.json) e
[resumo comparativo](evidencias/scan-2026-10-27/summary.json).

## Testes e limites da conclusão

```powershell
.\.venv\Scripts\python.exe -m pytest --cache-clear -q --junitxml=reports/scan-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Resultado real: **238 aprovados em 22,79 segundos**, zero falhas, erros ou
ignorados; dependências consistentes. Os 196 anteriores foram preservados e
42 casos novos em `tests/test_scan_pipeline.py` verificam orçamento em dez
limites, deduplicação, valores distintos, múltiplos parâmetros, redirects,
origem, limites de navegação, erros HTTP, timeout, interrupção, checkpoint,
formato do relatório, perfil quoted e compatibilidade das CLIs anteriores.

Interrupções foram testadas com `KeyboardInterrupt` controlado nas duas fases,
inclusive após um parâmetro concluído. O JSON parcial e a saída 130 foram
verificados; não houve pressionamento manual de Ctrl+C na rodada real acima.
O [resumo dos testes](evidencias/scan-2026-10-27/tests-summary.json) inclui hashes
dos fontes e foi derivado do [JUnit](evidencias/scan-2026-10-27/tests.xml), cujo
tempo interno foi 22,736 segundos.

O experimento confirma somente estas implementações/contextos controlados.
Não mede precisão universal. Descoberta estática não encontra necessariamente
APIs JavaScript do Juice Shop; não executa scripts, autenticação ou formulários.
Os perfis e os critérios conservadores da [etapa 5](SQLI_GENERALIZADO.md) seguem
vigentes. Não há extração adicional de dados, escrita por sondas ou XSS.
