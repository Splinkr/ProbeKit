# Descoberta de endpoints e parâmetros HTTP

O comando `discover` recebe uma URL inicial e faz navegação HTML em largura.
Usa o cliente HTTP existente, [HTMLParser](https://docs.python.org/3.13/library/html.parser.html)
e [urllib.parse](https://docs.python.org/3.13/library/urllib.parse.html), sem novas
dependências, Docker ou navegador automatizado. Não invoca detectores nem gera
payloads de ataque. Na etapa de descoberta, a lógica de confirmação SQLi não
foi alterada. A generalização posterior está documentada na
[etapa 5](SQLI_GENERALIZADO.md). O fluxo integrado está na
[etapa 6](SCAN_INTEGRADO.md); a [etapa 7](XSS_REFLETIDO.md) acrescentou XSS e
elevou o total atual a 286 testes. Este roteiro continua válido.

## Demonstração no Windows 11

O ambiente `.venv` existente é suficiente. Em um terminal, caso o laboratório
HTML ainda não esteja ativo:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.html_discovery --port 8002
```

O servidor escuta somente em `127.0.0.1:8002`. Use Ctrl+C para encerrá-lo quando
estiver em primeiro plano. Não inicie uma segunda instância na mesma porta.

Em outro terminal, execute a descoberta completa do laboratório:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe main.py discover http://localhost:8002 --max-depth 3 --max-pages 10 --max-requests 10 --output reports/discover-html.json
$inventory = Get-Content -Raw -Encoding UTF8 reports/discover-html.json | ConvertFrom-Json
$inventory.summary | Format-List
$inventory.endpoints | Format-Table method, endpoint, provided_manually, discovered_automatically
$inventory.endpoints | Where-Object endpoint -Like '*/search' | ConvertTo-Json -Depth 8
```

Para demonstrar a interrupção por limites:

```powershell
.\.venv\Scripts\python.exe main.py discover http://localhost:8002 --max-depth 1 --max-pages 2 --max-requests 2 --output reports/discover-limited.json
```

A sintaxe anterior permanece válida:

```powershell
.\.venv\Scripts\python.exe main.py http://localhost:3000 --samples 2
.\.venv\Scripts\python.exe main.py "http://localhost:3000/rest/products/search?q=apple" --module sqli --output reports/sqli.json
.\.venv\Scripts\python.exe main.py discover --help
```

Descoberta e SQLi são execuções separadas. O crawler não transforma endpoints
encontrados em alvos de ataque automaticamente.

## Inventário e normalização

São extraídos links de `<a href>` e `<area href>` e formulários GET, inclusive
aqueles sem atributo `method`. Campos nomeados de `input`, `select`, `textarea`
e `button` são registrados; campos explicitamente `disabled` são ignorados.
O atributo `form="id"` permite associar campos externos ao formulário. O parser
não replica um DOM nem todas as regras de submissão de um navegador.

Formulários são **inventariados sem submissão**. Seus valores padrão, senhas e
conteúdo de textarea não são enviados nem gravados. Formulários POST ou com
outros métodos são ignorados e contabilizados. Campos informam nome, localização
(`query` ou `form`) e tipo de campo quando aplicável.

Referências relativas são resolvidas, inclusive `<base href>`. Uma base externa
mantém suas referências relativas fora do escopo, sem reinterpretá-las como locais.
Uma action ausente ou vazia aponta para a própria página.

A normalização:

- Converte `localhost` para `127.0.0.1`, sem resolver nomes arbitrários por DNS.
- Remove fragmentos e portas padrão; preserva a distinção entre HTTP e HTTPS.
- Resolve segmentos `.`/`..`, normaliza escapes percentuais e codifica Unicode.
- Ordena nomes de query; preserva campos vazios e a ordem dos valores repetidos.
- Preserva separadores reservados codificados, caixa do caminho e barras repetidas.

Cada combinação GET + caminho absoluto aparece uma vez no inventário. Os
parâmetros e as origens são unidos; variantes de query ficam em `observed_urls`.
A fila elimina URLs canônicas repetidas, incluindo fragmentos e ordens distintas
dos nomes de query. Variantes com valores diferentes podem ser visitadas sob os
mesmos limites, embora pertençam ao mesmo endpoint.

Cada endpoint informa:

| Campo | Significado |
| --- | --- |
| `method` / `endpoint` | Método GET e URL absoluta sem query |
| `parameters` | Nomes e localização dos parâmetros observados |
| `observed_urls` | Variantes normalizadas encontradas |
| `sources` | `manual`, `html_link` ou `get_form`, página de origem e profundidade |
| `provided_manually` | O endpoint foi fornecido como URL inicial |
| `discovered_automatically` | Há uma referência HTML ou formulário para o endpoint |

Um endpoint pode ter ambas as flags quando a URL inicial reaparece em um link.
Novos relatórios baseline/SQLi também incluem `target_source: manual`, pois esses
modos recebem um alvo explícito, sem descoberta automática. Evidências históricas
permanecem intactas.

`pages` registra as respostas recebidas, profundidade, status, hash e tamanho;
corpos HTML não são exportados. URLs observadas conservam valores da query para
reprodução; não coloque segredos nesses valores. Parâmetros de formulários não
incluem valores. Inventariar uma referência não confirma que o endpoint respondeu
nem que ele é vulnerável; os destinos dos formulários podem nem ser requisitados.

## Limites e segurança

| Opção | Padrão | Semântica |
| --- | --- | --- |
| `--max-depth` | 2 | Máximo de arestas de links navegadas; URL inicial tem profundidade 0 |
| `--max-pages` | 20 | Máximo de respostas completas recebidas, incluindo respostas não HTML |
| `--max-requests` | 20 | Máximo de tentativas HTTP, incluindo falhas de transporte |
| `--timeout` | 5 | Timeout de conexão/inatividade de leitura, em segundos |
| `--interval` | 0.2 | Intervalo mínimo entre inícios de requisições |
| `--max-body-bytes` | 1048576 | Limite descomprimido por resposta |

Links e formulários observados na página de fronteira ainda entram no inventário;
seus links não são navegados além de `max-depth`. Por isso o número de endpoints
pode ser maior que o de páginas visitadas. Falhas não contam como resposta
completa, mas consomem requisições. A fila continua pelos outros links enquanto
os orçamentos permitirem. Não há retries automáticos.

Somente IPs loopback são permitidos, e a navegação fica restrita ao mesmo
**esquema, host normalizado e porta efetiva** da URL inicial. Isso também bloqueia
outros IPs loopback e outras portas da própria máquina. Credenciais em URL,
esquemas como `javascript:`/`file:`, destinos de LAN e hosts externos são rejeitados.
O cliente mantém proxies do ambiente desativados e não reutiliza cookies.

Nenhum redirecionamento HTTP é seguido, nem mesmo local. O destino de um header
Location não é interpretado como link. Expansão ocorre somente para respostas
2xx `text/html` ou `application/xhtml+xml`, usando charset HTTP ou UTF-8 como
fallback. HTML em respostas 3xx/4xx/5xx não é expandido.

O resumo indica `completed`, `limited` ou `incomplete`. `stop_reasons` identifica
os limites; `skipped` contabiliza referências rejeitadas. Falhas incluem detalhes
estruturados em `errors`. Código de saída 0 significa inventário gravado, mesmo
limitado; 1 indica erro de transporte/gravação; 2 indica argumentos ou URL inicial
inválidos. Os mesmos limites de timeout do cliente anterior continuam válidos.

## Resultados reais — 27/10/2026

A demonstração completa começou às 14h54min59 (America/Sao_Paulo): **6 endpoints,
5 páginas, 5 requisições e zero erros**. A referência duplicada do catálogo foi
normalizada em uma única URL. A busca `/search` entrou via formulário, com
parâmetros `q`, `sort` e `category`, sem ser submetida. Um host externo e uma
porta diferente foram rejeitados; um formulário POST foi ignorado.

Na demonstração limitada: **5 endpoints observados, 2 páginas e 2 requisições**,
com `max_depth`, `max_pages` e `max_requests` registrados como limites atingidos.
Inventários reais preservados:

- [Execução completa](evidencias/discovery-2026-10-27/full.json).
- [Execução limitada](evidencias/discovery-2026-10-27/limited.json).
- [Resultado automatizado](evidencias/discovery-2026-10-27/tests.json).

## Testes e limites de cobertura

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/discovery-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

**164 testes passaram em 13,52 segundos**, incluindo os 123 anteriores e 41
casos novos de descoberta/CLI. Cobrem páginas HTML locais, deduplicação,
formulários, charset, origem manual/automática, navegação em largura, limites,
coleta parcial, outras portas/hosts/esquemas, redirects, `<base>` externo,
não execução do detector e compatibilidade da CLI. As dependências passaram na
verificação; `scanner/modules/sqli.py` permaneceu sem alterações.

O crawler não executa JavaScript, não usa navegador, não submete formulários,
não autentica e não procura APIs por listas de caminhos. **Não se presume que
ele descubra as APIs internas do Juice Shop.** APIs sem links ou formulários no
HTML recebido e rotas exclusivas do JavaScript/fragmentos podem não aparecer.
Uma referência conhecida fornecida manualmente permanece manual no relatório.
