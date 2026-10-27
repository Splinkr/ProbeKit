# Etapa 7 — XSS refletido com confirmação opcional

O módulo `xss` analisa parâmetros GET locais independentemente do SQLi.
Identifica reflexão, registra contexto e escape, e distingue essas observações
de execução JavaScript. `--xss-browser` habilita confirmação por replay isolado
em Edge/Chrome local. Não há novos pacotes Python/npm nem downloads automáticos.

## Arquitetura e evidências

| Arquivo | Responsabilidade |
| --- | --- |
| `scanner/modules/xss.py` | Marcadores exclusivos, plano HTTP, execução e achados XSS |
| `scanner/query.py` | Seleção GET genérica e substituição de um parâmetro preservando os demais |
| `scanner/xss_analysis.py` | Contextos HTML, escape e critérios conservadores |
| `scanner/xss_browser.py` | Disponibilidade, limites e validação da evidência do navegador |
| `scripts/confirm-xss.mjs` | Perfil temporário, replay CDP, CSP e callbacks reais |
| `experiments/xss_lab.py` | Respostas vulneráveis/corrigidas com dados fictícios |
| `scanner/pipeline.py` | SQLi/XSS no mesmo cliente, orçamento, sequência de IDs e checkpoints |

Os arquivos do módulo SQLi, seus planos, características, classificação e
orquestração direta não foram alterados. O cliente HTTP passou a preservar
somente os cabeçalhos de segurança necessários ao replay: CSP, CSP Report-Only,
Content-Disposition e X-Content-Type-Options. Cookies e autenticação não são
copiados para o navegador nem registrados nos relatórios.

Por parâmetro, o plano máximo usa `samples + 8` GETs, dez no padrão:
duas referências, dois marcadores alfanuméricos distintos, uma sonda de escape,
quatro sondas limitadas de execução e recuperação. Os marcadores usam nonce
aleatório de 96 bits por parâmetro/execução. Precisam estar ausentes nas
referências e recuperação; ambos devem aparecer em suas respostas de teste.
Reflexões inconsistentes ou marcadores nos controles tornam a coleta inconclusiva.

O parser registra texto HTML, atributos e sua delimitação, atributos de URL,
handlers de eventos, script JavaScript, script de dados, textarea/title,
comentários, template e CSS. Não é um parser universal de JavaScript/DOM.
A sonda de escape registra `<`, `>`, `&`, aspas simples e duplas como literais,
entidades HTML ou removidos/codificados; entidades numéricas também são tratadas.
Um script reconhecido pelo parser continua sendo apenas indício estático.

As sondas JavaScript chamam exclusivamente uma função de marcador criada pelo
protocolo do navegador. Não leem cookies, credenciais, armazenamento, conteúdo
privado ou arquivos; não usam exfiltração, alteração do banco ou operações
destrutivas. Não há `alert()` nem dependência de interação do usuário.

## Classificação

| Resultado | Evidência necessária |
| --- | --- |
| `confirmed` | Controles completos e limpos, duas reflexões independentes e callback real do marcador no documento principal do navegador; o controle negativo não executou |
| `suspected` | Contexto potencialmente executável ou quebra estrutural de HTML, sem prova suficiente de execução; inclui bloqueio por CSP |
| `reflected_safe` | Reflexão inerte ou escapada nas sondas/contextos observados; não é declaração geral de segurança |
| `not_detected` | Marcadores não refletidos nas respostas comparáveis desta coleta |
| `inconclusive` | Falha, resposta inadequada, controles contaminados ou reflexão inconsistente |

Sem navegador, uma reflexão potencialmente executável permanece `suspected`.
Reflexão isolada não confirma XSS. JSON com MIME JSON e texto com MIME text/plain
não são tratados como execução JavaScript. Se o navegador estiver indisponível,
falhar ou exceder seu prazo, o relatório mantém a suspeita e registra a limitação.
Um resultado negativo no navegador também não elimina uma suspeita estática.

Quando os dois marcadores não aparecem, o detector dispensa as cinco sondas de
escape/execução e faz a recuperação: são `samples + 3` GETs, cinco no padrão.
Essa decisão depende das respostas, não do nome do endpoint. Evita enviar
sondas executáveis a buscas que não refletem a entrada.

## Como a confirmação é isolada

O navegador é opcional e precisa estar instalado. A rodada foi validada com
**Edge 156.0.4314.42 e Node 24.19.0**. O helper usa WebSocket nativo do Node;
versões sem esse recurso são registradas como indisponíveis/erro. O modo HTTP
não depende de Node ou navegador.

Cada confirmação cria um perfil temporário, sem usar o perfil do usuário,
extensões, cookies ou login. O navegador recebe as respostas HTTP já coletadas,
com bytes, URL, tipo de conteúdo e cabeçalhos de segurança preservados.
O protocolo intercepta a navegação e fornece esses bytes, sem repetir o GET
ao servidor. As demais requisições de página são abortadas. Um proxy local
sem encaminhamento e uma CSP adicional restritiva bloqueiam recursos/conexões.
Essa política adicional não relaxa a CSP original. Downloads são negados.

Um controle negativo e quatro respostas de sondas são reproduzidos em páginas
novas. A confirmação requer um evento real `Runtime.bindingCalled`, com nome
e valor exclusivos, no contexto padrão do frame principal. A evidência inclui
versão do navegador, request ID HTTP original, marcador, hash dos bytes,
resultado de cada replay, preservação da CSP e política de rede. O wrapper
confere os marcadores, IDs e hashes antes de aceitar a prova.

É uma confirmação de execução **no replay isolado da resposta**, sem sessão
autenticada ou recursos externos. Não equivale a navegar a aplicação completa
com estado do usuário. O navegador usa seu canal de controle WebSocket local;
esse canal não é uma requisição de teste ao alvo. O orçamento contabiliza GETs
ao alvo; os replays enviam zero novos GETs ao alvo. Um teste real verificou
que nem o servidor testado nem outra porta local recebem requisições extras.

O helper fecha seu navegador e tenta remover o perfil temporário. Prazos são
limitados; em falha forçada, o wrapper encerra somente a árvore do helper que
criou. Ctrl+C durante a confirmação pode aguardar o prazo de limpeza. Término
forçado não garante remoção imediata do diretório temporário.

## CLI, orçamento e JSON

`--module xss` mantém `--parameter` e `--all-parameters`. O scanner aceita um
parâmetro escolhido com até 200 caracteres de referência, inclusive vazio,
desde que apareça uma única vez. Os demais parâmetros são preservados.
Sem seleção, usa `q`, se existir, ou o único parâmetro disponível.

`scan --modules sqli xss` executa ambos. O padrão antigo de `scan` continua
sendo somente SQLi. A deduplicação inclui URL canônica, parâmetro, módulo e
contexto; a ordem dos módulos é a informada. Descoberta e detectores usam o
mesmo contador e orçamento, incluindo falhas de transporte.

Antes de iniciar um plano, são necessários `samples + 8` GETs de saldo; essa
reserva é conservadora mesmo quando depois há interrupção por não reflexão.
Um saldo menor pode ficar sem uso, com `insufficient_global_budget` registrado.
No comando direto, o orçamento mínimo cobre o máximo de todos os parâmetros.

O JSON direto XSS usa `mode: xss`, esquema `1.3`. Registra sondas, marcadores,
reflexões, escape, critérios, justificativa, limites e `browser_evidence`.
Achados têm categoria `xss` e status distinto entre suspeita/confirmação.
O relatório consolidado preserva `analyses` e acrescenta `module` aos resultados
e tentativas de análise. `parameters_analyzed` conta avaliações por módulo;
`unique_parameters_analyzed` conta pares URL/parâmetro distintos. Não grava
corpos HTTP. Checkpoints e códigos de saída seguem a etapa 6; suspeita ou
reflexão inerte concluída não são falhas de transporte.

## Reproduzir no Windows 11

O laboratório novo usa a porta 8004; as instâncias anteriores foram mantidas.
Inicie abaixo somente se essa porta estiver livre. O ambiente Python existente
é suficiente; `--xss-browser` usa o Edge/Chrome e Node já instalados.

Terminal 1:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8004
```

Terminal 2, comparar reflexão, confirmação e escape:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8004/xss/html/raw?q=demo" --module xss --output reports/xss-demo/raw-without-browser.json
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8004/xss/html/raw?q=demo" --module xss --xss-browser --output reports/xss-demo/raw-confirmed.json
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8004/xss/html/escaped?q=demo" --module xss --xss-browser --output reports/xss-demo/escaped-direct.json
```

Fluxos completos e limite global:

```powershell
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8004/xss-lab --modules xss --xss-browser --max-depth 2 --max-pages 12 --max-requests 100 --output reports/xss-demo/xss-scan.json
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8004/combined-lab --modules sqli xss --xss-browser --max-requests 100 --output reports/xss-demo/combined.json
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8004/combined-lab --modules sqli xss --xss-browser --max-requests 25 --output reports/xss-demo/budget-25.json
```

Controle adicional de escape JavaScript, informado manualmente (não é link da landing):

```powershell
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8004/xss/script/escaped?q=demo" --module xss --xss-browser --output reports/xss-demo/script-escaped.json
```

## Resultados reais de 27/10/2026

A rodada XSS entre 16:06:50 e 16:07:23 (UTC−03) usou **89/100 GETs**:
nove de descoberta e 80 de análise, com oito parâmetros `q=demo` na origem
`http://127.0.0.1:8004`.

| Endpoint | Contexto | Resultado observado |
| --- | --- | --- |
| `/xss/html/raw` | HTML sem escape | confirmed por callback no replay |
| `/xss/html/escaped` | Texto HTML escapado | reflected_safe |
| `/xss/attribute/raw` | Atributo sem escape de aspas | confirmed por callback no replay |
| `/xss/attribute/escaped` | Atributo com escape | reflected_safe |
| `/xss/json` | application/json | reflected_safe |
| `/xss/script/raw` | String dentro de script | confirmed por callback no replay |
| `/xss/csp` | HTML bruto com script-src 'none' | suspected; nenhum callback executou |
| `/xss/text` | text/plain | reflected_safe |

O comando direto sem navegador para HTML bruto produziu `suspected`, com dez
GETs. O exemplo escapado direto produziu `reflected_safe`, também com dez.
O HTML bruto direto com navegador produziu `confirmed`, com dez GETs.
No controle adicional `/xss/script/escaped`, o JavaScript recebeu uma string
JSON com aspas e delimitadores HTML codificados: nenhum callback executou,
mas o detector manteve `suspected` por sua análise estática ampla do contexto
script. É um falso positivo no nível de suspeita, registrado como limitação;
não houve confirmação falsa nem ajuste de critérios para ocultar o resultado.
O fluxo misto usou **75/100 GETs**, cinco de descoberta e 70 de análise:
um SQLi confirmado, um XSS confirmado, cinco `not_detected` e um `reflected_safe`.
Foram oito avaliações sobre quatro pares URL/parâmetro distintos. Duas análises
XSS de buscas SQLi terminaram após cinco GETs por ausência de reflexão.

Com limite 25, foram exatamente **25/25 GETs** e seis avaliações restantes
ignoradas. A regressão direta do Juice Shop continuou `confirmed`, com dez GETs.
Os oito relatórios versionados somam 239 GETs; houve ainda três consultas de
integridade `/health` (antes, após a primeira rodada e após os controles
adicionais). O resumo preserva a primeira e a última. A base manteve cinco registros e SHA-256
`5a7f6cbde94c6fb8d193dc14c708adb2d425546f2ddd294c9793ff3d5864ce0a` antes/depois.

Foram oito sessões de confirmação, com 40 replays, incluindo oito controles
negativos. Nenhum controle negativo executou. Os replays não enviaram GETs ao
alvo. Contar replays executados não equivale a contar vulnerabilidades distintas.

Evidências: [rodada XSS](evidencias/xss-2026-10-27/xss-scan.json),
[sem navegador](evidencias/xss-2026-10-27/raw-without-browser.json),
[confirmação direta](evidencias/xss-2026-10-27/raw-confirmed.json),
[controle JavaScript escapado](evidencias/xss-2026-10-27/script-escaped.json),
[fluxo misto](evidencias/xss-2026-10-27/combined.json),
[limite 25](evidencias/xss-2026-10-27/budget-25.json) e
[resumo completo](evidencias/xss-2026-10-27/summary.json).

## Testes e limitações

```powershell
.\.venv\Scripts\python.exe -m pytest --cache-clear -q --junitxml=reports/xss-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Resultado real: **286 aprovados em 56,09 segundos**, zero falhas, erros ou
ignorados; dependências consistentes. São 48 casos novos, incluindo seis
casos com navegador real, contextos, entidades numéricas, marcadores preexistentes,
respostas JSON/texto, CSP, orçamento misto, ausência de dependências opcionais,
redirects, interrupção e compatibilidade. Sem navegador instalado, os seis
casos de navegador são explicitamente ignorados, não apresentados como aprovados.

O teste antigo que considerava `--module xss` inválido passou a verificar
`--module unsupported`: o contrato de rejeitar módulos desconhecidos permanece,
enquanto XSS agora é uma opção autorizada. Os demais testes anteriores continuam
passando. [JUnit](evidencias/xss-2026-10-27/tests.xml) e
[resumo com hashes](evidencias/xss-2026-10-27/tests-summary.json) foram preservados;
o tempo interno XML foi 56,004 segundos.

Não há garantia universal: são perfis limitados de XSS refletido GET. Não se
testam XSS armazenado, DOM XSS, todos os escapes JavaScript, eventos com interação,
sessões autenticadas ou recursos externos. A descoberta continua HTML estática;
o navegador de confirmação não é um crawler JavaScript. Não há Docker nem
exposição de arquivos.
