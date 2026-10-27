# WebVuln Scanner

Ferramenta CLI em Python para o trabalho de SIN 451 — Segurança da Informação
(UFV). Inclui o núcleo de referências HTTP e um MVP SQLi controlado para a
busca de produtos do Juice Shop local.

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
e recuperação. Registra payloads, contagens, hashes dos conjuntos de produtos,
assinaturas SQL e a classificação `confirmed`, `suspected`, `not_detected` ou
`inconclusive`. O [roteiro da demonstração](docs/DEMONSTRACAO_SQLI.md) contém
os comandos completos, a validação manual e a evidência real.

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
falha interrompe a coleta e ainda gera JSON com os dados já obtidos.

Códigos de saída:

| Código | Significado |
| --- | --- |
| 0 | Referências recebidas e relatório gravado |
| 1 | Falha de transporte, limite de resposta, gravação ou SQLi inconclusiva |
| 2 | Argumentos inválidos ou destino bloqueado antes da rede |

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
- O módulo SQLi aceita `/rest/products/search`, `/control/vulnerable/search` e
  `/control/safe/search`, com um único `q` de referência simples. Exige pelo menos
  duas referências e orçamento `samples + 8`.
  Não há descoberta automática, autenticação, XSS ou exposição de arquivos.
  Não há opção para liberar destinos externos.

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
| `scanner/modules/` | Módulos específicos de detecção |
| `scanner/modules/sqli.py` | Plano SQLi, interpretação semântica e classificação |
| `experiments/sqlite_control.py` | Servidor dos controles SQLite locais |
| `experiments/run_control.py` | Repetições e métricas do experimento |

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

A suíte automatizada foi reconstruída: **123 testes passaram**, cobrindo HTTP,
escopo local, evidências, classificação SQLi, SQLite real e CLI em subprocessos.
Ela não depende de sites públicos ou do Juice Shop. Organização, comandos e
resultado desta execução estão em [docs/TESTES.md](docs/TESTES.md). A validação
histórica das etapas iniciais permanece em [docs/VALIDACAO.md](docs/VALIDACAO.md).
