# Demonstração curta — ProbeKit

Roteiro de aproximadamente cinco minutos, com dados exclusivamente fictícios.
Use Windows 11, ambiente Python preparado pelo [README](../README.md) e dois
terminais PowerShell abertos na raiz do repositório. Para confirmar XSS,
tenha Node.js 24 e Edge/Chrome instalados. Não é necessário Juice Shop ou Docker.

## 1. Iniciar o laboratório

No primeiro terminal, mantenha o servidor aberto:

```powershell
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8005
```

O servidor escuta somente em `127.0.0.1`. Se a porta estiver ocupada, use outra
nos dois terminais. A página `/probekit-lab` liga buscas SQLite por concatenação
e bindings, reflexão HTML direta e escapada e documentação pública. O catálogo
de arquivos é verificado separadamente, sem depender de links visíveis.

## 2. Descobrir e analisar com os três módulos

No segundo terminal:

```powershell
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 100 --output reports/demo/three-modules.json
```

No laboratório fornecido, a execução real na instalação limpa da etapa 9
produziu **92 GETs** e:

| Módulo | confirmed | suspected | inconclusive | not_detected | reflected_safe |
| --- | --- | --- | --- | --- | --- |
| SQLi | 1 | 0 | 0 | 3 | 0 |
| XSS | 1 | 0 | 0 | 2 | 1 |
| exposure | 2 | 0 | 0 | 2 | 0 |

Mostre os resultados efetivamente impressos pelo scan. A confirmação SQLi
refere-se à consulta vulnerável; a busca com bindings não foi confirmada.
XSS exige o callback inofensivo observado; HTML escapado ficou `reflected_safe`.
Exposure confirmou configuração e backup fictícios; arquivo bloqueado e
documentação pública não foram confirmados. São 12 avaliações (oito de
parâmetros/módulos e quatro arquivos), não 92 vulnerabilidades.

Sem navegador/Node, omita `--xss-browser`. Nesse caso, a expectativa empírica
é XSS `suspected`, mantendo o controle escapado `reflected_safe`. Não apresente
essa execução como XSS confirmado.

## 3. Consultar evidências e orçamento

```powershell
$demoReport = Get-Content -Raw -Encoding UTF8 reports/demo/three-modules.json | ConvertFrom-Json
$demoReport.summary | Format-List
$demoReport.exposure_results | Select-Object url, @{Name='resultado'; Expression={$_.assessment.outcome}}
```

Abra no JSON uma avaliação de cada módulo: mostre critérios, IDs, justificativa
e limitações. Arquivos não têm conteúdo ou valores sensíveis no relatório.
Para mostrar orçamento compartilhado, repita com destino diferente:

```powershell
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 84 --output reports/demo/budget-84.json
```

A referência real foi 84/84 GETs, dois arquivos analisados e dois backups
ignorados por saldo. O resumo deve indicar alvos não concluídos; não são
`not_detected`. Como controle adicional opcional, todos os status abaixo são
200, mas o conteúdo é fallback HTML:

```powershell
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/exposure-lab/fallback/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/demo/fallback.json
```

A referência foi quatro `not_detected`, sem exposição confirmada.

## 4. Encerrar e explicar limites

Use Ctrl+C no servidor do primeiro terminal. No `scan`, Ctrl+C preserva um
checkpoint quando possível e retorna 130. Não sobrescreva evidências históricas
de `docs/evidencias/`; os comandos usam apenas `reports/demo/`.

Explique os limites: descoberta HTML estática; SQLi textual em perfis
LIKE/igualdade entre aspas; XSS confirmado somente com navegador isolado;
catálogo de cinco caminhos exposure. Resultados negativos não garantem
segurança universal, e exposição estrutural não comprova que existam segredos
válidos. Os resultados desta etapa de preparação estão registrados em
[PUBLICACAO.md](PUBLICACAO.md).
