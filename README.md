# ProbeKit (WebVuln Scanner)

Ferramenta CLI em Python para o trabalho de SIN 451 — Segurança da Informação
(UFV). Inclui referências HTTP, descoberta HTML, SQLi e XSS refletido por
parâmetro GET e exposição de arquivos, com validação em laboratórios locais
e Juice Shop.

## Ambiente

Windows 11, Python 3.13 e Node.js 24. O laboratório usa OWASP Juice Shop 20.3.0
diretamente com Node.js, sem Docker. Instalações e relatórios locais ficam fora
do Git. Consulte [o progresso](docs/PROGRESSO.md).

Com Python disponível:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

O executável do ambiente pode ser chamado diretamente, sem ativação e sem
alterar a política de execução do PowerShell. Para npm, use `npm.cmd`.

Se Python não estiver instalado, o script abaixo baixa uv 0.9.7 e Python 3.13.9
em `.tools/`, cria `.venv/` e instala as dependências. Ele também aceita
`-PythonExe C:\caminho\python.exe` para usar uma instalação existente.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-python.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-juice-shop.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/start-juice-shop.ps1
```

O parâmetro de política vale apenas para o processo chamado. O laboratório
fica em `lab/` e escuta em `127.0.0.1:3000`. Consulte
[as instruções do laboratório](lab/README.md) para execução em segundo plano.

## Executar

Para demonstrar os três módulos no Windows 11, inicie o laboratório em um
PowerShell e mantenha-o aberto:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8005
```

Em outro PowerShell, na mesma pasta:

```powershell
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 100 --output reports/exposure-demo/three-modules.json
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/exposure-demo/files.json
```

Na execução real, o fluxo usou **92/100 GETs** e confirmou SQLi, XSS e dois
arquivos fictícios. Arquivo bloqueado, documento público e páginas de fallback
não foram confirmados. O [roteiro exposure](docs/EXPOSICAO_ARQUIVOS.md) traz
perfis, controles negativos, critérios, evidências e limitações. São no máximo
cinco caminhos de um catálogo fechado, sem conteúdo dos arquivos no JSON.
`--xss-browser` requer Node.js e Edge/Chrome locais; sem confirmação no
navegador, a reflexão executável permanece suspeita.

Para descobrir endpoints e executar SQLi a partir de uma URL inicial:

```powershell
.\.venv\Scripts\python.exe main.py scan http://localhost:8003/scan-lab --max-depth 2 --max-pages 10 --max-requests 100 --output reports/scan-demo/full.json
```

O [roteiro integrado](docs/SCAN_INTEGRADO.md) mostra como iniciar o SQLite na
porta 8003, reproduzir a demonstração e interromper preservando resultados.
Descoberta e análise compartilham o orçamento; o JSON reúne inventário,
resultados por parâmetro, evidências e alvos ignorados com seus motivos.

Para XSS, com o laboratório da porta 8004 iniciado:

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:8004/xss/html/raw?q=demo" --module xss --xss-browser --output reports/xss-demo/raw-confirmed.json
.\.venv\Scripts\python.exe main.py scan http://localhost:8004/combined-lab --modules sqli xss --xss-browser --max-requests 100 --output reports/xss-demo/combined.json
```

O [roteiro XSS](docs/XSS_REFLETIDO.md) inclui inicialização, controles negativos,
contextos e evidências reais. Sem `--xss-browser`, reflexão potencialmente
executável permanece suspeita. A confirmação opcional usa Edge/Chrome e Node
locais já instalados, com perfil temporário, replay e rede bloqueada. Não há
novas dependências Python/npm. O padrão de `scan` permanece somente SQLi.

Para partir de uma URL inicial e inventariar links e formulários GET:

```powershell
.\.venv\Scripts\python.exe main.py discover http://localhost:8002 --max-depth 3 --max-pages 10 --max-requests 10 --output reports/discover-html.json
```

O [roteiro da descoberta](docs/DESCOBERTA.md) mostra como iniciar o laboratório
HTML local, interpretar as origens e demonstrar os limites. A descoberta não
executa payloads nem presume encontrar APIs internas do Juice Shop.

Em outro terminal, com o Juice Shop iniciado:

```powershell
.\.venv\Scripts\python.exe main.py http://localhost:3000 --samples 3 --output reports/juice-shop-baseline.json
.\.venv\Scripts\python.exe main.py "http://localhost:3000/rest/products/search?q=apple" --output reports/search-baseline.json
.\.venv\Scripts\python.exe main.py --help
```

Cada execução faz GETs de referência no mesmo endpoint. A primeira resposta
é a base das comparações seguintes. O relatório inclui horário UTC, método,
URL, status HTTP, tipo de conteúdo, bytes descomprimidos, SHA-256 do corpo,
tempo de resposta, diferenças e erros. No modo padrão `baseline`, `findings`
fica vazio. Para o detector SQLi:

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:3000/rest/products/search?q=apple" --module sqli --output reports/demo-sqli.json
```

O detector executa dez GETs com referências, controles, dois pares booleanos
e recuperação por parâmetro. Registra payloads, características, hashes,
assinaturas SQL e a classificação `confirmed`, `suspected`, `not_detected` ou
`inconclusive`. O [roteiro original](docs/DEMONSTRACAO_SQLI.md) contém
a validação manual do Juice Shop. A [etapa 5](docs/SQLI_GENERALIZADO.md) documenta
os critérios atuais, formatos, seleção de parâmetros e resultados reais.

Com o laboratório SQLite iniciado (`python -m experiments.sqlite_control`):

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/html/vulnerable?search=apple&lang=en" --module sqli --all-parameters --max-requests 20 --output reports/general-multiple.json
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/html/safe?search=apple&lang=en" --module sqli --parameter search --output reports/general-safe.json
```

`--parameter` escolhe um campo; `--all-parameters` avalia cada campo de forma
independente e preserva os demais. `--sqli-context like` é o padrão;
`--sqli-context quoted` cobre igualdade textual entre aspas simples.

Para avaliar falsos positivos, há uma aplicação SQLite local com buscas por
concatenação e por bindings sobre a mesma base fictícia. O experimento executa
o mesmo detector nos dois endpoints e gera JSON separado por repetição.
Consulte [o controle positivo e negativo](docs/CONTROLE_NEGATIVO.md) para iniciar
o servidor e reproduzir a avaliação, sem Docker ou dependências adicionais.

Por padrão são duas referências, timeout de conexão/leitura de 5 segundos,
intervalo mínimo de 0,2 segundo entre inícios, orçamento de 10 requisições e
limite de 1 MiB descomprimido por resposta. Use `--samples`, `--timeout`,
`--interval`, `--max-requests` e `--max-body-bytes` para ajustar. A quantidade
de referências deve caber no orçamento. Não há retries automáticos; a primeira
falha interrompe a coleta do parâmetro atual e ainda gera JSON com os dados
já obtidos. No modo SQLi com vários parâmetros, os próximos podem ser avaliados
dentro do mesmo orçamento global.

Códigos de saída:

| Código | Significado |
| --- | --- |
| 0 | Referências recebidas e relatório gravado |
| 1 | Falha de transporte, limite de resposta, gravação ou análise inconclusiva |
| 2 | Argumentos inválidos ou destino bloqueado antes da rede |
| 130 | Interrupção do scan, com preservação parcial quando possível |

Uma resposta 4xx/5xx comprova conectividade HTTP e é preservada como evidência.
Ela não confirma vulnerabilidade e não é confundida com falha de conexão.

## Escopo e limites atuais

- Apenas `localhost` e IPs loopback são aceitos; IPs de LAN também são bloqueados.
  `localhost` é convertido para `127.0.0.1`, evitando resolução DNS variável.
  IPv6 literal `[::1]` é aceito pelo scanner; o laboratório fornecido usa IPv4.
- Redirecionamentos são registrados como respostas 3xx e nunca seguidos.
  Proxies e credenciais do ambiente são desativados, certificados TLS são
  verificados e cookies não são reutilizados entre referências.
- Corpos HTTP, cookies e cabeçalhos de autenticação não são gravados no JSON.
  A URL completa, incluindo parâmetros, é registrada para reprodução; não
  forneça segredos nos parâmetros da URL.
- O hash e o tamanho cobrem o corpo completo recebido. A similaridade usa
  somente os primeiros 16 KiB e não deve ser interpretada como detector.
- Timeout limita conexão e inatividade da leitura, não o tempo total de uma
  resposta enviada lentamente. Respostas acima do limite são descartadas e
  registradas como erro, sem comparar conteúdo parcial.
- O módulo SQLi aceita caminhos GET locais com parâmetros de referência simples,
  selecionados individualmente. Exige pelo menos duas referências e orçamento
  global `quantidade_de_parâmetros * (samples + 8)`. Cobre condições textuais
  entre aspas em LIKE ou igualdade, com confirmação booleana auxiliada por erro;
  não cobre SQLi numérica, temporal ou UNION e não tem garantia universal.
  A descoberta HTML é um comando separado e fica na mesma origem loopback.
  Não há autenticação.
  Não há opção para liberar destinos externos.
- XSS refletido distingue reflexão inerte, suspeita e execução confirmada no
  replay isolado. Não cobre XSS armazenado, DOM XSS ou todos os eventos/contextos.
  JSON refletido não é prova de execução. Um navegador indisponível não produz
  confirmação; as limitações ficam no relatório.
- Exposure usa catálogo pequeno e controles inexistentes, em um diretório-base
  configurável, depois dos parâmetros no fluxo integrado. Confirma acesso e
  estrutura do artefato, sem verificar validade de segredos ou sua política de
  privacidade. Não cobre todos os nomes/formatos e não executa arquivos.

## Arquitetura e verificação

| Arquivo | Responsabilidade |
| --- | --- |
| `main.py` | CLI, validação de argumentos e saída no terminal |
| `scanner/targets.py` | Validação e normalização de destinos locais |
| `scanner/http_client.py` | GETs, isolamento de sessão, limites e erros |
| `scanner/models.py` | Evidências, comparações, achados e relatório |
| `scanner/analyzer.py` | Comparação observacional de respostas |
| `scanner/core.py` | Orquestração das referências |
| `scanner/reporter.py` | Serialização JSON sem corpos HTTP |
| `scanner/discovery.py` | Crawler HTML, normalização e inventário com origem |
| `scanner/pipeline.py` | Fluxo scan com origem, orçamento e IDs compartilhados; resultados parciais |
| `scanner/modules/` | Módulos específicos de detecção |
| `scanner/modules/sqli.py` | Execução do plano SQLi e associação das evidências ao parâmetro |
| `scanner/sqli_plans.py` | Seleção, preservação da query, sondas e orçamento global |
| `scanner/sqli_features.py` | Características de JSON, HTML e texto e assinaturas SQL |
| `scanner/sqli_classification.py` | Critérios diferenciais, justificativa e limitações |
| `scanner/modules/xss.py` | Marcadores, controles e execução XSS independente |
| `scanner/query.py` | Manipulação GET genérica para XSS |
| `scanner/xss_analysis.py` | Contexto de reflexão, escape e classificação XSS |
| `scanner/xss_browser.py` e `scripts/confirm-xss.mjs` | Replay isolado e callbacks reais com rede bloqueada |
| `scanner/modules/exposure.py` | Execução independente da verificação de arquivos |
| `scanner/exposure_profiles.py` | Catálogo fechado, diretório-base e controles inexistentes |
| `scanner/exposure_analysis.py` | Estrutura de conteúdo, fallback, estabilidade e classificação |
| `scanner/exposure_models.py` | Evidências de exposição sem corpo, chaves ou valores |
| `experiments/sqlite_control.py` | Controles SQLite e página `/scan-lab` para o fluxo completo |
| `experiments/xss_lab.py` | Exemplos de reflexão, escape, atributo, script, JSON e CSP |
| `experiments/exposure_lab.py` | Configuração e backup fictícios, bloqueio, fallback, erro e arquivo público |
| `experiments/run_control.py` | Repetições e métricas do experimento |
| `experiments/run_general_sqli.py` | Matriz por nome de parâmetro, formato e contexto |
| `experiments/html_discovery.py` | Aplicação HTML local para demonstrar descoberta |

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

A suíte passou em **344 testes** e inclui fluxo integrado, orçamento, interrupção, descoberta HTML, HTTP,
escopo local, SQLi, XSS, exposure, checkpoints Windows e confirmações reais em navegador isolado.
O resultado atual e a contagem estão em [docs/TESTES.md](docs/TESTES.md).
Ela não depende de sites públicos ou do Juice Shop. Organização, comandos e
resultado desta execução estão em [docs/TESTES.md](docs/TESTES.md). A validação
histórica das etapas iniciais permanece em [docs/VALIDACAO.md](docs/VALIDACAO.md).
