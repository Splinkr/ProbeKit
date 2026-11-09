# ProbeKit 0.2.0 — segurança operacional e evidências

Implementação do plano aprovado PK-F2 v1.0.0, sobre `2026e83`, com
[acompanhamento v1.0.1](FASE2_PLANO.md).
Este registro distingue testes HTTP reais, falhas injetadas e observações por inspeção.
Os artefatos históricos de `docs/evidencias/` não foram reescritos.

## 1. Estado inicial

`main` em `2026e83`, árvore limpa e produto 0.1.0. O registro do planejamento tinha
161 testes selecionados aprovados em 12,67 s. A Fase 1 registrava 451 aprovados em
69,29 s, sem falhas/erros/ignorados, incluindo oito casos com navegador.

## 2. R01/R02

O fallback de charset e os erros sanitizados de execução continuam presentes.
Os estados de coleta e análise continuam separados: avaliação inconclusiva não
torna automaticamente a coleta incompleta; o estado legado do integrado conserva
sua regra. Os cinco outcomes continuam distintos, contados por avaliação, sem
duplicação do agregado. Os testes da Fase 1 fazem parte da regressão completa.

Os modelos internos preservam as referências originais para os detectores.
`to_dict()` é um snapshot interno; para persistência use os escritores com perfil.
Corpos passam a ser liberados após a última utilização, mantendo tamanho, hash,
características e IDs. XSS só libera depois da análise e eventual replay.

## 3. Reprodução e evidência anterior

Foi extraída uma cópia dos módulos do commit-base para `reports/phase2-base/`,
sem mudar o checkout, e executada uma reprodução sem HTTP. O resultado em
`reports/phase2-base-reproduction.json` confirmou:

- R03: parâmetro contendo ESC continuava ativo na saída de descoberta. O relatório
  foi fornecido como fixture para isolar a apresentação.
- R05: falha injetada na gravação do resumo deixava o técnico da segunda execução
  junto ao resumo da primeira. Não havia identidade comum.
- R07: caminho e valor GET genérico com sentinela apareciam no técnico.

R06-B foi reproduzido com servidores loopback enviando cabeçalhos/corpo continuamente:
antes do worker, os dois testes não receberam a falha esperada e demoraram 21,77 s.
R06-A inicialmente rejeitava as novas opções (três testes falhos).
Na revisão final, três testes com construtores sentinela demonstraram que planos
extremos podiam chegar à materialização antes da reserva. A reprodução limitou
o construtor para evitar uma alocação destrutiva; após a reserva antecipada,
os três módulos limitam a execução sem HTTP e sem fabricar avaliações.
Também foram reproduzidas duas ultrapassagens de fronteira (9.000 bytes podiam
consumir 16.384 antes da rejeição); a leitura agora recalcula o saldo em cada bloco.
Quatro regressões adicionais cobrem payloads legados sem `mode` nos dois escritores
avulsos e nos dois perfis. Esses payloads também passam pela política, sem fabricar
identidade/schema retrospectivos para dados genéricos.

R04 foi identificado por inspeção do bootstrap sem hashes e dos requirements sem
transitivas. Os testes de cache adulterado exercitam a proteção nova com arquivos
inofensivos; não foi executado um binário adulterado. O advisory não constitui
demonstração de exploração do scanner.

Os testes iniciais das APIs novas de R03/R05 falharam na coleta por ausência das APIs;
esses erros são registrados separadamente das reproduções funcionais acima.

## 4. Correções por risco

| Risco | Mudança | Evidência principal |
| --- | --- | --- |
| R03 | `safe_text`, `safe_print` e parser seguro; C0/C1/DEL viram escapes visíveis | Unicode, ANSI/OSC incompletos, argparse e parâmetro percent-encoded chegando original ao servidor |
| R05 | Execução/checkpoint com UUID, geração imutável, manifesto atômico, SHA dos bytes exatos e leitor verificado | Falhas e Ctrl+C em sete estágios, publicação concorrente por processos, adulteração e caminhos fora da geração |
| R07 | Perfil compartilhável padrão, restrito explícito, HMAC só em memória, lista permitida e ACL | Sentinelas em campos conhecidos/desconhecidos, falhas, correlação dos IDs, reconstrução offline e proteção antes da escrita |
| R06 | Cotas de dados, reservas antes de acrescentar registros, liberação de corpos, worker e deadline | HTML denso/formulários, quotas, gzip, bytes descartados, fluxo lento, cancelamento, ausência de retry e próximo GET |
| R04 | Verificação uv, locks com hashes, somente wheels e Requests 2.34.2 | Cache ZIP/EXE inválido rejeitado, cache real validado, instalação separada e `pip check` |

SQLi, XSS, Exposure, loopback, mesma origem, GET, redirects, TLS, cookies, proxies,
payloads e orçamento de requisições conservam os critérios anteriores. Nove arquivos
foram comparados com a base. Oito permaneceram integralmente idênticos:
`sqli_classification.py`, `sqli_features.py`, `xss_analysis.py`,
`exposure_analysis.py`, `exposure_profiles.py`, `targets.py`, `xss_browser.py` e
`scripts/confirm-xss.mjs`. Em `sqli_plans.py`, a validação passou a construir
apenas as duas referências mínimas; o plano real é reservado aritmeticamente
antes de materializar listas grandes. A AST de `build_probe_plan` e `probe_url`
permaneceu idêntica. Registro: `reports/phase2-detector-invariants.json`.
A AST de `scanner.modules.xss.build_plan` também permaneceu idêntica: são onze
verificações de invariantes no total.

## 5. Arquivos e justificativa

- `main.py`, `scanner/terminal.py`: opções novas, verificação offline, diagnóstico fixo
  de persistência, apresentação conforme perfil e neutralização dos controles.
- `scanner/reporter.py`, `scanner/findings_report.py`: projeção única, identidades,
  publicação por geração, hash, aliases e verificação. O construtor público de
  achados usa perfil compartilhável por padrão e aceita snapshots já anonimizados.
- `scanner/privacy.py`, `scanner/private_files.py`: campos permitidos, HMAC e
  diretórios privados criados com ACL protegida no Windows, modo 0700 no POSIX.
- `scanner/models.py`, `scanner/exposure_models.py`, `scanner/report_state.py`:
  identidade aditiva, consumo e indicação de limites sem confundir outcomes.
- `scanner/resources.py`, `scanner/discovery.py`, `scanner/pipeline.py`: reservas,
  parser limitado, deduplicação, interrupção por quota e integração dos componentes.
- `scanner/http_client.py`, `scanner/transport.py`, `scanner/transport_worker.py`:
  fronteira supervisionada, JSON/base64 em memória, TLS/escopo preservados, prazo
  total e encerramento do processo e threads antes de continuar.
- `scanner/core.py`, `scanner/modules/{sqli,xss,exposure}.py`: propagação das cotas,
  tratamento separado de limites e liberação de bytes após uso.
- `scripts/setup-python.ps1`, `scripts/uv-integrity.ps1`: verificação antes da
  extração/reutilização do uv. `requirements*.in` são entradas revisáveis;
  `requirements*.lock` fixam transitivas e hashes; `requirements*.txt` mantêm os
  comandos de instalação existentes, exigindo hashes e wheels.
- `experiments/run_control.py`, `experiments/run_general_sqli.py`: a mesma política
  nos relatórios e resumos experimentais; perfil restrito explicitável para reprodução.
- Seis arquivos `tests/test_{safe_presentation,report_integrity,evidence_privacy,
  resource_limits,request_deadline,bootstrap_integrity}.py`: regressões da fase.
  Os testes antigos foram migrados apenas para perfis explícitos, nomes de
  manifestos/schema e a fronteira de injeção; contagens e outcomes não foram relaxados.
- `README.md`, `docs/TESTES.md`, este documento e `FASE2_PLANO.md`: comportamento,
  migração e resultados. `scanner/__init__.py`: versão do produto.

## 6. Comandos e resultados

Os resultados intermediários, incluindo falhas reais, estão na tabela do plano.
A candidata foi instalada em `.venv-phase2`, preservando a `.venv` anterior:

```powershell
.\.venv\Scripts\python.exe -m venv .venv-phase2
.\.venv-phase2\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.txt
.\.venv-phase2\Scripts\python.exe -m pip check
.\.venv-phase2\Scripts\python.exe -m pytest -q --junitxml=reports/phase2-all-locked-env.xml
```

Instalação concluída; `pip check`: `No broken requirements found`.
Python 3.13.9/Windows x64; Requests 2.34.2, urllib3 2.8.0, certifi 2026.10.23,
charset-normalizer 3.5.2, idna 3.20, pytest 8.4.2. Transitivas de teste mantidas:
colorama 0.4.6, iniconfig 2.3.1, packaging 26.3, pluggy 1.7.0 e Pygments 2.21.0.

Suíte da candidata: **531 aprovados, 0 falhos, 0 erros, 0 ignorados, 0 não executados**,
181,17 s. Navegador real disponível; os oito casos existentes executaram.
Revisão posterior de publicação/privacidade: **86 aprovados**, 18,15 s, incluindo
o novo caso de IDs de URL sensível. O fechamento da versão final é registrado
ao término em `FASE2_PLANO.md` e `TESTES.md`.

Fechamento do produto 0.2.0, após as revisões de fronteira e escritores legados:

| Ambiente | Aprovados | Falhos | Erros | Ignorados | Não executados | Tempo |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `.venv` original, Requests 2.32.5 preservado | 543 | 0 | 0 | 0 | 0 | 196,81 s |
| `.venv-phase2`, locks e Requests 2.34.2 | 543 | 0 | 0 | 0 | 0 | 196,30 s |

São 451 casos anteriores e 92 novos. Os oito casos existentes de navegador real
executaram nos dois ambientes. As execuções finais usaram:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/phase2-release-original.xml
.\.venv-phase2\Scripts\python.exe -m pytest -q --junitxml=reports/phase2-release-locked.xml
```

`git diff --check` passou, assim como onze invariantes de código/payloads.

`InlineTransport` é injetado explicitamente nos testes antigos que substituem
Requests no processo pai. Esses casos simulam falhas; não demonstram um timeout
do SO. Os demais testes de transporte, CLI em subprocesso e deadline usam HTTP
real com `ProcessTransport`. Os testes de publicação simulam falhas de I/O e
interrupção; não simulam falha física do disco ou desligamento do computador.

## 7. Schema 2.0 e manifesto 1.0

`write_reports(report, output, evidence_profile=...)` aceita o argumento anterior
`atomic`; todas as escritas agora são atômicas individualmente. Cria:

```text
full.json                                  alias técnico
findings.json                              alias resumido
full.json.manifest.json                     referência principal
.probekit-evidence/<run_id>/<snapshot_id>/
  technical.json
  findings.json
  manifest.json
```

`--output findings.json` usa `findings-summary.json` para o resumo.

Campos comuns: `schema_version: "2.0"`, `run_id` UUID estável por execução,
`snapshot_id` UUID por publicação/checkpoint, `producer_version`, `evidence_profile`
e `anonymized`. Os componentes da geração têm a mesma identidade. O resumo tem
`source_report: "technical.json"` relativo à geração e `source_sha256` dos bytes
UTF-8 exatos do técnico, incluindo indentação e newline final.

O manifesto contém `manifest_version: "1.0"`, a identidade/perfil/versão e
`files.technical`/`files.findings`, cada um com `path` relativo e `sha256`.
O diretório é preparado, os arquivos são fechados/sincronizados/verificados, a
geração é promovida e o manifesto principal é substituído atomicamente. Só então
são atualizados os aliases. Não há promessa de transação conjunta dos aliases.
Falha depois do commit do manifesto pode retornar erro com uma geração válida já
publicada; ela é preservada. Publicações concorrentes usam gerações diferentes;
a última troca do manifesto vence.

```powershell
.\.venv-phase2\Scripts\python.exe main.py scan http://127.0.0.1:8001/probekit-lab --modules sqli xss exposure --output reports/fase2/full.json
.\.venv-phase2\Scripts\python.exe main.py verify-report reports/fase2/full.json.manifest.json
```

API offline: `read_verified_reports(manifest_path, expected_run_id=None)` retorna
`(technical, findings)`. Confere caminhos confinados, IDs de todos os componentes,
versões, perfil, hashes e correspondência do resumo. `verify-report` retorna 0
para evidência válida, 1 para falha de leitura/integridade e 2 para argumentos.
Use `--expected-run-id UUID` para exigir uma execução específica.

Os campos da Fase 1 (`collection_status`, `analysis_summary`, outcomes e erros
sanitizados) conservam seus significados. Entradas legadas continuam aceitas pelo
construtor de achados: contagens disponíveis são calculadas e coleta desconhecida
fica `null`. Não se fabricam UUID/hash retrospectivos. Um JSON avulso/legado não
passa pelo verificador de manifesto. `write_json`/`write_json_atomic` publicam um
arquivo atômico com perfil e identidade, mas não publicam uma dupla verificável.
Payloads genéricos sem `mode` recebem a proteção dos campos, sem inferir identidade.

## 8. Política de privacidade

| Campo/dado | Compartilhável, padrão | Restrito, explícito |
| --- | --- | --- |
| URL, endpoint, caminho e nome de parâmetro | Campo original nulo; `*_id` opaco, estável na execução | Preservado; credenciais, fragmentos e valores GET sensíveis mascarados |
| Listas de nomes de parâmetros | IDs opacos | Nomes originais |
| Payload/valor de referência/marcador XSS | Omitido | Preservado para reprodução; entrada de parâmetro sensível mascarada |
| Cabeçalhos técnicos CSP/disposição | Omitidos | Preservados quando permitidos pelo coletor |
| Título, explicação, detalhe e limitação textual | Texto fixo; motivos estruturados conhecidos preservados | Texto original do detector |
| IDs de requisição, papel da sonda, status, tamanho, tempo e hashes | Preservados por lista permitida | Preservados |
| Outcomes, contagens, verificações booleanas conhecidas | Preservados | Preservados |
| Campo futuro/desconhecido | Omitido | Pode permanecer; trate todo o perfil como restrito |
| Corpo HTTP, cookies, autenticação e valores/chaves de arquivos Exposure | Nunca persistidos | Nunca persistidos |

IDs usam HMAC-SHA256 truncado a 128 bits, com chave aleatória por execução só em
memória. A chave não é serializada. Execuções diferentes não compartilham IDs;
requisições e avaliações mantêm sua correlação por IDs numéricos. Hashes de corpo
continuam metadados de evidência; contagens, tempos e correlação também revelam
características da coleta. Compartilhável não é uma garantia de anonimato absoluto.

O terminal usa a mesma chave da publicação e neutraliza controles em ambos os
perfis. Destinos de arquivo fornecidos pelo usuário também aparecem como IDs no
perfil compartilhável; use `--output` para escolher um caminho conhecido. Erros de
persistência são fixos e não reproduzem caminhos/texto arbitrário de exceções.
Erros de argumentos no padrão compartilham apenas a orientação de uso; o perfil
restrito pode mostrar diagnóstico detalhado, sempre com controles escapados.

`restricted` cria diretórios temporários exclusivos com ACL protegida de Owner
Rights/SYSTEM antes de escrever; os arquivos herdam essa proteção e a conservam
ao serem promovidos no mesmo volume. No POSIX, diretórios 0700 e temporários 0600.
Falha ao estabelecer a proteção interrompe a gravação. Isso não é criptografia:
outros processos da mesma conta/administradores continuam fora dessa barreira.

## 9. Limites e prazo

| Opção | Padrão | Unidade/escopo |
| --- | ---: | --- |
| `--max-urls` | 1000 | URLs únicas da execução, incluindo sondas |
| `--max-candidates` | 2000 | Reservas de candidatos/proveniências/parser/alvos |
| `--max-url-length` | 8192 | Bytes UTF-8 por URL/referência |
| `--max-metadata-bytes` | 8388608 | Reservas conservadoras dos dados controlados |
| `--max-total-body-bytes` | 33554432 | Bytes descomprimidos observados + reservas de cancelamento |
| `--request-deadline` | 15 | Segundos por GET após prontidão do worker |

Valores positivos; `--timeout` mantém conexão/inatividade, `--interval` mantém o
intervalo mínimo, e páginas/profundidade/requisições/corpo individual mantêm seus
limites. Seed acima do comprimento é validação antes da rede. Referências
descobertas excedentes são omitidas com contagem/motivo. Metadados são reservados
antes de reter registros, inclusive no parser; contagens de rejeições não criam
uma lista ilimitada. `resource_usage` e `resource_limits` mostram consumo/motivos.
Uma quota esgotada usa `ResourceLimit`, não `execution_error`; coleta pode ser
`limited`, e a análise parcial conserva inconclusividade. Nenhum alvo omitido
é contado como negativo.

`total_body_bytes = body_bytes_observed + body_bytes_reserved`. Blocos descartados
também contam. Em cancelamento, a supervisão drena os frames completos e reserva
até um bloco para uma leitura/frame parcial cujo tamanho exato ficou desconhecido.
O teto pode demandar um byte extra para reconhecer ultrapassagem; ele é contado,
não retido, e impede nova coleta ao alcançar o orçamento. RSS inclui estruturas
do Python, bibliotecas, buffers de decompressor, SO e navegador; não é esse contador.

O Requests define `timeout` por inatividade, não duração total de download.
O worker usa Requests sem proxies/cookies/redirects, revalida loopback e envia
frames JSON limitados a 64 KiB, com corpo base64 só em memória. O supervisor mata
e espera o worker e encerra leitores/escritores antes de retornar falha
`deadline_exceeded`. Não refaz o GET. Pode criar outro worker para uma próxima
tentativa permitida. A inicialização do processo, escalonamento do SO, I/O de
evidências e navegador não têm garantia de tempo real.

## 10. Limitações e resolução parcial

R03–R07 foram implementados dentro dos contratos descritos e são validados por
testes específicos e regressão. Permanecem limites explícitos:

- Aliases podem divergir; só o manifesto/leitor verificado oferece a dupla correta.
- Hashes não autenticam o produtor contra substituição de todo o conjunto.
- Sem coleta automática de gerações, o disco pode encher; persistência falha de
  forma explícita. Não há promessa de durabilidade física contra falta de energia.
- Metadados são um orçamento conservador; cancelamentos podem reservar mais bytes
  que os observados. Um limite atingido pode reduzir cobertura e deixar análises
  inconclusivas. Não é um limite de RSS/tempo total do scan.
- O ambiente validado dos locks é Python 3.13/Windows x64; outras plataformas não
  receberam a mesma validação. A `.venv` original foi preservada com Requests
  2.32.5; use `.venv-phase2` ou instale os novos requirements para usar 2.34.2.
- O perfil restrito exige revisão antes de compartilhar e pode conter referências
  de reprodução privadas. Compartilhável mantém metadados e correlação da execução.
- Não foi executada uma auditoria de ausência de todas as vulnerabilidades de todas
  as transitivas; esta fase trata os advisories e a integridade especificados.

## 11. Git e versionamento

Produto final 0.2.0; schema 2.0; manifesto 1.0; plano aprovado PK-F2 v1.0.0,
registro consolidado v1.0.1.
As mudanças ficam no working tree para revisão. Não foram feitos commit, push,
tag, publicação ou remoção de artefatos históricos. HEAD permanece `2026e83`.

## 12. Fontes de integridade e dependências

uv 0.9.7, ZIP Windows x64:
`5d250c32d3604e28dbe18dc65c668ff628c53e00dde2c642576e831e4a60da64`.
`uv.exe`, derivado desse ZIP verificado:
`83e0f3a8b7aaf0224fe7e915c3249b085b41c7a1ab00aeba95fc52c05334a3db`.
O cache real passou pelo novo `Get-VerifiedUv` antes de retornar `uv 0.9.7`.
Fontes: [release oficial](https://github.com/astral-sh/uv/releases/tag/0.9.7) e
[metadados oficiais dos assets](https://api.github.com/repos/astral-sh/uv/releases/tags/0.9.7).

Requests 2.34.2 veio do índice oficial e teve o wheel verificado pelos locks.
[Release oficial](https://github.com/psf/requests/releases/tag/v2.34.2).
[GHSA-gc5v-m9x4-r6x2](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2)
afeta versões anteriores a 2.33.0 no uso de `extract_zipped_paths`; não foi
demonstrada exploração no fluxo do scanner.
[Timeout do Requests](https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts).


## Inventário final para revisão

40 arquivos rastreados alterados e 18 novos; 58 no total.

```text
README.md
docs/FASE2_PLANO.md
docs/FASE2_SEGURANCA.md
docs/TESTES.md
experiments/run_control.py
experiments/run_general_sqli.py
main.py
requirements-dev.in
requirements-dev.lock
requirements-dev.txt
requirements.in
requirements.lock
requirements.txt
scanner/__init__.py
scanner/core.py
scanner/discovery.py
scanner/exposure_models.py
scanner/findings_report.py
scanner/http_client.py
scanner/models.py
scanner/modules/exposure.py
scanner/modules/sqli.py
scanner/modules/xss.py
scanner/pipeline.py
scanner/privacy.py
scanner/private_files.py
scanner/report_state.py
scanner/reporter.py
scanner/resources.py
scanner/sqli_plans.py
scanner/terminal.py
scanner/transport.py
scanner/transport_worker.py
scripts/setup-python.ps1
scripts/uv-integrity.ps1
tests/conftest.py
tests/test_analysis_summary.py
tests/test_bootstrap_integrity.py
tests/test_checkpoint_contract.py
tests/test_cli_process_contract.py
tests/test_discovery_cli.py
tests/test_discovery_contract.py
tests/test_evidence_contract.py
tests/test_evidence_privacy.py
tests/test_execution_reliability.py
tests/test_exposure_contract.py
tests/test_findings_report.py
tests/test_general_sqli.py
tests/test_report_integrity.py
tests/test_request_deadline.py
tests/test_resource_limits.py
tests/test_safe_presentation.py
tests/test_scan_pipeline.py
tests/test_scope_contract.py
tests/test_sqlite_evaluation_contract.py
tests/test_terminal_contract.py
tests/test_transport_contract.py
tests/test_xss_contract.py
```
