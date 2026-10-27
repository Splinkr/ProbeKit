# Etapa 5 — SQL Injection por parâmetro e formato

A generalização mantém a CLI, o cliente HTTP, o crawler e os experimentos
anteriores. Não há dependências novas. O detector aceita caminhos GET locais
arbitrários, seleciona um parâmetro por vez e aplica controles independentes.
A confirmação no Juice Shop foi reproduzida após a mudança.

## Arquitetura e seleção

| Componente | Responsabilidade |
| --- | --- |
| `scanner/sqli_plans.py` | Descobrir nomes na query, validar seleção/orçamento, gerar sondas e substituir somente o parâmetro selecionado |
| `scanner/http_client.py` | GET com timeout, orçamento, limite de corpo e escopo loopback; permanece compartilhado com os demais comandos |
| `scanner/sqli_features.py` | Extrair características de JSON, HTML e texto e reconhecer assinaturas SQL |
| `scanner/sqli_classification.py` | Comparar referências, controles e pares booleanos; justificar a classificação |
| `scanner/modules/sqli.py` | Executar um plano e associar evidências e achados ao parâmetro |
| `scanner/core.py` | Orquestrar parâmetros com um único orçamento HTTP global |
| `experiments/run_general_sqli.py` | Executar a matriz local e registrar resultados observados e expectativas separadamente |

Use `--parameter NOME` ou `--all-parameters`. Sem essas opções, `q` continua
sendo escolhido quando existe, por compatibilidade; uma URL com um único
parâmetro também é aceita. Vários parâmetros sem `q` exigem seleção explícita.
O parâmetro selecionado deve ocorrer uma única vez. Repetições de outros
parâmetros são preservadas. Os demais tokens da query mantêm valores, ordem,
codificação e campos sem valor. Cada plano recomeça na URL original.

O valor inicial precisa ser simples: de 1 a 80 letras, números, sublinhados,
espaços ou hífens, sem ser apenas espaços. Valores vazios, com aspas ou sintaxe
complexa são rejeitados antes da rede. Escolha uma busca com resultado conhecido:
uma referência vazia não permite avaliar este método.

O perfil padrão `--sqli-context like` cobre a condição textual `LIKE '%valor%'`.
O perfil `--sqli-context quoted` cobre igualdade textual como `name = 'valor'`.
O contexto é informado explicitamente; o detector não infere a consulta SQL.
Estes perfis não cobrem SQLi numérica, temporal, UNION, autenticação ou escrita.
As assinaturas reconhecidas são `SQLITE_ERROR`, `SQLITE_MISUSE` e
`SequelizeDatabaseError`; outros bancos podem exigir extensões verificadas.

## Controles e critérios

Por parâmetro, o plano padrão executa dez GETs: duas referências, aspas simples,
aspas duplicadas, texto literal de controle, dois pares booleanos distintos
(`17=17`/`17=18` e `23=23`/`23=24`) e recuperação da referência. São repetições
de referência e de comportamento com constantes diferentes, sem retries.
Os predicados usam apenas `AND`, restringindo a busca original; não há UNION,
comentários, consultas empilhadas, alteração do banco ou extração adicional.

| Resultado | Critério |
| --- | --- |
| `confirmed` | Todas as requisições concluídas; referências não vazias e estáveis; recuperação igual; erro SQL novo na sonda de aspas com HTTP >= 400; controles benignos negativos e saudáveis; dois pares verdadeiro/falso coerentes; falsas estáveis |
| `suspected` | Erro SQL diferencial específico ou pelo menos um par booleano coerente, mas falta algum controle necessário à confirmação |
| `inconclusive` | Sem indício específico suficiente e com coleta incompleta, referência vazia/instável, página de erro, sonda rejeitada ou formato incompatível |
| `not_detected` | Coleta comparável concluída sem evidência suficiente neste plano; não comprova ausência de SQLi |

Suspeita pode coexistir com limitações de estabilidade/coleta: o relatório
expõe cada critério que falhou. Erro HTTP genérico, variação de tamanho, hash
bruto ou conteúdo diferente não confirmam SQLi. Mesmo pares coerentes sem
o erro SQL diferencial exigido permanecem apenas como suspeita.

Para JSON, são reconhecidas listas na raiz ou em `data`, `items` e `results`.
Quando há identificadores únicos `id`, `sku` ou `code`, compara-se o conjunto
ordenado de identidades; mudanças apenas na ordem ou nos metadados externos
não representam mudança do conjunto. Sem esses identificadores, comparam-se
valores canônicos. Outros JSONs usam representação canônica completa.
Não se removem arbitrariamente timestamps. JSON inválido, erro explícito ou
resposta fora de 2xx não servem como controles saudáveis.

Para HTML, compara-se texto normalizado, excluindo `script` e `style`; para
texto simples, normalizam-se espaços. Duas respostas falsas precisam coincidir,
divergir da referência e coincidir com os controles benignos. Páginas de erro
reconhecidas, inclusive com HTTP 200, invalidam a comparação. Essa heurística
não reconhece todas as páginas de erro nem interpreta universalmente resultados
HTML. Conteúdo visível instável permanece na comparação e pode torná-la
inconclusiva. Há hashes das características, sem persistir os corpos.

## Orçamento, segurança e relatório

O orçamento global mínimo é `quantidade_de_parâmetros * (samples + 8)`.
Com duas referências são dez requisições por parâmetro; para dois parâmetros,
informe `--max-requests 20`. Seleção e orçamento são validados antes da rede.
Os limites anteriores continuam disponíveis: `--timeout`, `--interval`,
`--max-body-bytes`, `--samples` e `--max-requests`. Padrões: 5 segundos de
conexão/inatividade de leitura, intervalo de 0,2 segundo, 1 MiB por resposta.
O timeout não é um prazo total para respostas enviadas lentamente.

Somente loopback, redirects desativados, sem proxies do ambiente ou reutilização
de cookies. Uma falha HTTP de transporte interrompe o parâmetro atual, mantém
as evidências parciais e permite avaliar os próximos dentro do orçamento.
Não há integração automática do inventário `discover` com a execução SQLi.

O JSON SQLi usa esquema `1.2`: `settings.available_parameters`, `parameters`,
`context` e `planned_requests`; `parameter_results` contém classificação,
critérios, justificativa, limitações e IDs por parâmetro. Cada sonda registra
parâmetro, contexto, valor de teste, características e assinaturas SQL. Cada
achado informa `parameter`. Os campos legados de produtos e `assessment`
permanecem disponíveis.

Em vários parâmetros, `assessment` resume por prioridade `confirmed`,
`suspected`, `inconclusive`, `not_detected`. Isso não atribui a mesma conclusão
a todos: consulte `parameter_results`. A CLI retorna 1 se qualquer parâmetro
for inconclusivo ou houver falha; 2 para argumentos/destinos inválidos; 0 para
análise concluída, inclusive suspeita. URLs e valores das sondas são registrados;
use dados fictícios e não coloque segredos na query.

## Resultados reais de 27/10/2026

Rodada entre 15:15:57 e 15:16:26 (UTC−03), Python 3.13.9, SQLite 3.50.4,
Juice Shop 20.3.0 com Node.js 24. Endpoints SQLite na origem
`http://127.0.0.1:8001`; nas linhas com `{vulnerable,safe}`, ambos foram testados.

| Endpoint e query | Formato/perfil | Classificações observadas |
| --- | --- | --- |
| `/control/{vulnerable,safe}/search?q=apple` | JSON / like | `q`: confirmed / not_detected |
| `/general/json/{vulnerable,safe}?term=apple&lang=en` | JSON / like | `term`: confirmed / not_detected |
| `/general/html/{vulnerable,safe}?search=apple&lang=en` | HTML / like | `search`: confirmed / not_detected |
| `/general/text/{vulnerable,safe}?keyword=apple&lang=en` | Texto / like | `keyword`: confirmed / not_detected |
| `/general/quoted/{vulnerable,safe}?item=Apple+Demo` | JSON / quoted | `item`: confirmed / not_detected |
| `/general/html/vulnerable?search=apple&lang=en`, ambos os parâmetros | HTML / like | `search`: confirmed; `lang`: not_detected |
| `/general/html/unstable?search=apple` | HTML / like | `search`: inconclusive — contador visível muda a cada resposta |
| `/general/html/error?search=apple` | HTML / like | `search`: inconclusive — página de erro com HTTP 200 |
| `/general/json/vulnerable?term=apple`, perfil incompatível | JSON / quoted | `term`: suspected — erro SQL, sem pares confirmatórios |
| `http://127.0.0.1:3000/rest/products/search?q=apple` | JSON / like | `q`: confirmed — regressão Juice Shop |

Foram 15 execuções, 16 avaliações de parâmetros e 160 GETs do detector, além
dos dois GETs de integridade do SQLite: sete avaliações `confirmed`, seis
`not_detected`, duas `inconclusive` e uma `suspected`. Há caminhos repetidos
com parâmetros/perfis diferentes; esses totais não são uma medida de precisão
universal nem uma contagem de vulnerabilidades distintas.

A base fictícia compartilhada manteve cinco registros e SHA-256
`5a7f6cbde94c6fb8d193dc14c708adb2d425546f2ddd294c9793ff3d5864ce0a` antes/depois.
O servidor usa SQLite em memória com `PRAGMA query_only=ON`. Os endpoints
vulneráveis executam concatenação real; os seguros usam bindings reais, com
o mesmo conjunto e condições. A classificação não consulta o nome das rotas.
O teste automatizado que troca a implementação SQL verifica que expectativas
do experimento não sobrescrevem a conclusão observada.

Evidências versionadas: [resumo da rodada](evidencias/general-sqli-2026-10-27/summary.json),
[dois parâmetros](evidencias/general-sqli-2026-10-27/multiple-parameters.json),
[controle seguro](evidencias/general-sqli-2026-10-27/json-safe.json) e
[Juice Shop](evidencias/general-sqli-2026-10-27/juice-shop.json).
A mesma pasta contém um JSON por execução. Os relatórios históricos anteriores
não foram substituídos.

## Reproduzir no Windows 11

Execute a partir da raiz. Se a instância SQLite já estiver ativa, utilize-a;
inicie o servidor abaixo somente quando a porta estiver livre. Para preparar
um ambiente novo, siga a instalação do [README](../README.md).

Terminal 1 (manter aberto):

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8001
```

Terminal 2, demonstração com parâmetros independentes:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/html/vulnerable?search=apple&lang=en" --module sqli --all-parameters --max-requests 20 --output reports/demo-general-multiple.json
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/html/safe?search=apple&lang=en" --module sqli --parameter search --output reports/demo-general-safe.json
```

Outros formatos e igualdade textual:

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/json/vulnerable?term=apple&lang=en" --module sqli --parameter term --output reports/demo-general-json.json
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/text/vulnerable?keyword=apple&lang=en" --module sqli --parameter keyword --output reports/demo-general-text.json
.\.venv\Scripts\python.exe main.py "http://localhost:8001/general/quoted/vulnerable?item=Apple+Demo" --module sqli --parameter item --sqli-context quoted --output reports/demo-general-quoted.json
```

Executar toda a matriz SQLite (14 execuções), incluindo as limitações esperadas:

```powershell
.\.venv\Scripts\python.exe -m experiments.run_general_sqli --base-url http://127.0.0.1:8001 --output-dir reports/general-sqli
```

Para repetir também a regressão Juice Shop, inicie-o, caso esteja parado, e
aguarde sua inicialização. Depois use o comando da rodada real:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/start-juice-shop.ps1 -Background
.\.venv\Scripts\python.exe -m experiments.run_general_sqli --base-url http://127.0.0.1:8001 --juice-shop-url "http://localhost:3000/rest/products/search?q=apple" --output-dir reports/general-sqli
```

`summary.json` registra observado e esperado em campos separados. O script
retorna 1 se divergem, se houver erro de transporte ou alteração da base.
`status: completed` significa rodada coletada; não significa que todos os
casos sejam conclusivos. Inconclusivos e suspeita são resultados esperados
explicitamente nesta matriz. Pode-se selecionar casos com `--case json-safe`.

O comando antigo continua funcionando:

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:3000/rest/products/search?q=apple" --module sqli --output reports/juice-shop-regression.json
```

## Testes automatizados

```powershell
.\.venv\Scripts\python.exe -m pytest --cache-clear -q --junitxml=reports/general-sqli-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Resultado real: **196 aprovados em 15,71 segundos**, zero falhas, erros ou
ignorados; dependências consistentes. São os 164 testes anteriores e 32 novos
em `tests/test_general_sqli.py`. Estes cobrem consultas SQLite reais nos
quatro formatos/contextos, parâmetros múltiplos, preservação da query,
orçamento, nomes/caminhos arbitrários, CLI/JSON, instabilidade, erros,
normalização e honestidade do experimento. Não dependem do Juice Shop ativo.

O [resumo dos testes](evidencias/general-sqli-2026-10-27/tests-summary.json)
foi extraído do [JUnit](evidencias/general-sqli-2026-10-27/tests.xml) e inclui
hashes dos arquivos de teste. O tempo interno JUnit foi 15,639 segundos;
o pytest informou 15,71 segundos incluindo seu processamento adicional.
Não foi medida cobertura percentual. Nenhum teste usa alvos externos,
Docker, XSS ou operações de modificação/exfiltração de dados.
