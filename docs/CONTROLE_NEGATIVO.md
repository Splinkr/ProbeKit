# Controle positivo e negativo SQLi — SQLite local

O experimento compara duas implementações de busca sobre a **mesma conexão e
mesma tabela SQLite em memória**. Usa apenas Python e sua biblioteca padrão,
sem Docker ou novas dependências. O servidor escuta exclusivamente em
`127.0.0.1:8001`, separado do Juice Shop na porta 3000.

## Desenho experimental

| Endpoint | Implementação | Hipótese registrada |
| --- | --- | --- |
| `/control/vulnerable/search?q=apple` | Concatenação nos dois LIKEs | Controle positivo: detectar SQLi |
| `/control/safe/search?q=apple` | Dois placeholders `?` e bindings | Controle negativo: não sinalizar SQLi |

A base contém cinco produtos fictícios: três correspondem a `apple`, um a
outro termo e um produto arquivado é excluído pelo filtro `deletedAt`. Um dos
três resultados corresponde somente pela descrição. Dados, ordenação, filtro
e estrutura JSON são compartilhados; muda a construção da consulta.
O banco é preenchido uma vez e recebe `PRAGMA query_only = ON`. Ao reiniciar,
os mesmos dados são recriados em memória.

O [servidor](../experiments/sqlite_control.py) executa SQL real e não reconhece
payloads para escolher respostas. Um único handler trata os dois caminhos.
Exceções do SQLite retornam HTTP 500 com o nome real do erro, obtido de
`sqlite_errorname`; a aplicação não fabrica `SQLITE_ERROR` para a sonda.
A consulta segura vincula o termo aos placeholders conforme o mecanismo de
[binding do sqlite3](https://docs.python.org/3.13/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

No scanner, a mudança funcional se limita a aceitar os dois caminhos locais
adicionais. **Payloads, critérios, confiança e classificação são os mesmos do
Juice Shop.** A função `assess()` não foi alterada. Cada execução usa as dez
requisições do [roteiro SQLi](DEMONSTRACAO_SQLI.md): duas referências, aspa,
escape, controle textual, dois pares booleanos e recuperação.

## Execução no Windows 11

O ambiente `.venv` existente é suficiente. Se precisar prepará-lo:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-python.ps1
```

Em um terminal, inicie o servidor, caso ainda não esteja executando:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8001
```

O processo fica em primeiro plano; use Ctrl+C para encerrar. Não inicie outra
instância se a porta já estiver ocupada. Em outro terminal, confira a identidade
do laboratório e execute três repetições por endpoint:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
Invoke-RestMethod http://127.0.0.1:8001/health
.\.venv\Scripts\python.exe -m experiments.run_control --base-url http://127.0.0.1:8001 --repetitions 3 --output-dir reports/sqlite-control
$summary = Get-Content -Raw -Encoding UTF8 reports/sqlite-control/summary.json | ConvertFrom-Json
$summary.runs | Format-Table repetition, endpoint, outcome, findings, metric
$summary.metrics | Format-List
```

São 60 GETs de teste e duas consultas `/health` para verificar identidade e hash
da base antes/depois. Cada execução mantém o orçamento de dez requisições e
intervalo mínimo de 0,2 segundo. A classificação é lida do scanner, sem ser
substituída a partir das hipóteses. São gerados arquivos separados:

```text
reports/sqlite-control/
  vulnerable-01.json
  safe-01.json
  vulnerable-02.json
  safe-02.json
  vulnerable-03.json
  safe-03.json
  summary.json
```

Use outro `--output-dir` para preservar uma rodada anterior. O resumo referencia
somente a rodada atual; arquivos antigos no diretório não entram nas métricas.
Para executar separadamente pela CLI original:

```powershell
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8001/control/vulnerable/search?q=apple" --module sqli --output reports/control-vulnerable.json
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8001/control/safe/search?q=apple" --module sqli --output reports/control-safe.json
```

## Resultados reais de 27/10/2026

Execução entre 11h52min26 e 11h52min37 (America/Sao_Paulo), com Python 3.13.9,
SQLite 3.50.4 e código do experimento no commit `5f8d507`.
O ajuste operacional `57bebdd` acrescenta porta exclusiva no Windows e trata
conflitos de inicialização, sem alterar SQL, dados, payloads ou classificação.
O [resumo real preservado](evidencias/sqlite-control-2026-10-27/summary.json)
referencia os seis relatórios completos, também versionados.

| Controle | Repetições | Resultado em cada repetição | Achados por execução |
| --- | --- | --- | --- |
| Concatenação | 3 | `confirmed`, confiança `high` | 1 |
| Parametrização | 3 | `not_detected` | 0 |

Comportamentos observados em todas as repetições:

| Sonda | Concatenação | Parametrização |
| --- | --- | --- |
| Referências e recuperação | HTTP 200, 3 produtos | HTTP 200, mesmos 3 produtos |
| Aspa isolada | HTTP 500, `SQLITE_ERROR` real | HTTP 200, 0 produtos |
| Escape e controle textual | HTTP 200, 0 produtos | HTTP 200, 0 produtos |
| Duas condições verdadeiras | HTTP 200, os mesmos 3 produtos | HTTP 200, 0 produtos |
| Duas condições falsas | HTTP 200, 0 produtos | HTTP 200, 0 produtos |

No endpoint parametrizado toda a expressão é texto de busca; não há o contraste
verdadeiro/falso requerido para SQLi. Referências normais continuam válidas,
estáveis e não vazias: o resultado não é falha de conectividade nem abstenção.

SHA-256 da base completa, igual antes e depois:
`5a7f6cbde94c6fb8d193dc14c708adb2d425546f2ddd294c9793ff3d5864ce0a`.
SHA-256 dos IDs de referência ordenados `[1,2,3]`, igual nos seis testes:
`a615eeaee21de5179de080de8c3052c8da901138406ba71c38c032845f7d54f4`.
Os relatórios individuais guardam URLs, payloads, horários, status, tempos,
contagens, hashes e critérios; os corpos HTTP não são persistidos.

| Métrica observada | Quantidade |
| --- | --- |
| Verdadeiros positivos | 3 |
| Verdadeiros negativos | 3 |
| Falsos positivos | 0 |
| Falsos negativos | 0 |
| Inconclusivos | 0 |

A definição de sinalização positiva inclui **`confirmed` e `suspected`**:
uma suspeita no endpoint parametrizado também contaria como falso positivo.
`not_detected` é negativo. Erros de transporte e `inconclusive` são abstenções,
nunca verdadeiros negativos. Serviço incompatível ou indisponível gera resumo
`incomplete`, sem inventar execuções. `completed` significa coleta concluída,
mesmo se surgirem falsos positivos/negativos.

O Juice Shop foi reavaliado depois do controle: dez respostas, todos os critérios
satisfeitos e SQLi `confirmed`, sem erros de transporte. Evidência:
[juice-shop-regression.json](evidencias/sqlite-control-2026-10-27/juice-shop-regression.json).

## Testes automatizados e limites

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

Na validação original, **101 testes passaram**. Essa suíte foi posteriormente
substituída integralmente: a [suíte reconstruída](TESTES.md) passou em **123 testes**,
com dependências consistentes. Os testes usam essa aplicação real em porta efêmera
e verificam:

- Igualdade das respostas normais e filtro do registro arquivado.
- Erro SQLite real na concatenação e aspa tratada como dado no binding.
- Classificação positiva/negativa, plano idêntico e base preservada após sondas.
- Repetições, arquivos individuais, resumo e contagem de inconclusivos.
- Inversão das implementações entre os caminhos: o resultado acompanha o SQL
  executado, e o resumo registra resultados contrários às hipóteses como falso
  positivo/falso negativo. O nome do caminho não determina a classificação.
- Reavaliação dos contratos anteriores e bloqueio de alvos externos.

O teste de porta ocupada também passou. No Windows, o laboratório configura
`SO_EXCLUSIVEADDRUSE` antes do bind para impedir duas instâncias na mesma porta,
conforme o [comportamento documentado do Winsock](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).

São repetições determinísticas de **duas implementações** com poucos dados,
não seis aplicações independentes nem uma estimativa estatística de precisão
geral. `not_detected` demonstra que este plano não sinalizou a consulta
parametrizada; não comprova segurança universal. O perfil ainda depende de JSON
de produtos, parâmetro `q`, sintaxe LIKE e erro SQL diferencial para confirmação.
Sem as evidências exigidas, a conclusão permanece suspeita ou inconclusiva.
XSS não faz parte do experimento.
