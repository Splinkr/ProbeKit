# ProbeKit

Scanner acadêmico de aplicações web locais, desenvolvido para SIN 451 —
Segurança da Informação (UFV). Oferece descoberta HTML, SQL Injection por
parâmetro GET, XSS refletido e exposição de arquivos com controles negativos.
Os relatórios JSON registram evidências e limites de cada conclusão.

O escopo é exclusivamente loopback autorizado. Não há opção para liberar
alvos externos, autenticação, operações de escrita ou execução de arquivos
encontrados. Os laboratórios fornecidos usam dados fictícios e dispensam Docker.

## Requisitos e instalação no Windows 11

| Componente | Uso |
| --- | --- |
| Python 3.13 com pip | CLI, SQLite do laboratório e testes; validado com 3.13.9 |
| `requests==2.32.5` | Única dependência Python direta de execução |
| `pytest==8.4.2` | Avaliação automatizada; instala também as dependências de execução |
| Node.js 24 e Edge/Chrome | Opcionais: confirmação XSS em navegador; validados com Node 24.19.0 e Edge 156 |
| Git | Opcional para obter o código e consultar o histórico; um ZIP do repositório também funciona |

Clone ou extraia o repositório e abra o PowerShell na raiz, onde está `main.py`.
Não reutilize ambientes virtuais de outra máquina. Para instalar e avaliar:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --help
```

Se o launcher `py` não estiver disponível, confirme `python --version` e use
`python -m venv .venv`. Para apenas executar, instale `requirements.txt` em
vez de `requirements-dev.txt`. O pip pode precisar de rede para baixar os
pacotes; os scans e testes acessam somente laboratórios locais.

Não é necessário ativar `.venv`, alterar a política global do PowerShell,
instalar pacotes npm ou baixar um navegador pelo ProbeKit. Para a confirmação
opcional, `node --version` deve mostrar 24.x; Edge/Chrome deve estar instalado
no local padrão ou disponível no PATH. Sem esses programas, os candidatos XSS
permanecem suspeitos e as demais análises funcionam.

O bootstrap opcional `scripts/setup-python.ps1` aceita `-PythonExe` ou baixa
Python 3.13.9 via uv em `.tools/`. O procedimento acima é suficiente com Python
instalado. O Juice Shop é um alvo adicional, não um requisito do scanner:
consulte [lab/README.md](lab/README.md) antes de usar seus scripts de instalação.

## Primeira demonstração: três módulos

No primeiro PowerShell, na raiz do projeto:

```powershell
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8005
```

No segundo PowerShell, na mesma pasta:

```powershell
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 100 --output reports/demo/three-modules.json
```

O servidor deve permanecer aberto; use Ctrl+C nele quando terminar. Se a porta
8005 estiver ocupada, escolha outra no servidor e em todas as URLs. O
[roteiro curto](docs/DEMONSTRACAO.md) inclui comparação dos controles e leitura
do JSON. O resultado real da etapa 8 foi 92/100 GETs e quatro avaliações
confirmadas: uma SQLi, uma XSS e dois arquivos fictícios. Isso é uma referência
do laboratório, não uma classificação imposta pelo roteiro.

Ao final de `scan`, o terminal mostra resultados individuais, consumo e uma
tabela por módulo com `confirmed`, `suspected`, `inconclusive`, `not_detected`
e `reflected_safe`. A contagem usa avaliações de parâmetros/arquivos, não
requisições nem apenas achados. Alvos não concluídos ficam separados; zero
confirmações não significa que todos os alvos foram analisados.

## Comandos e exemplos

Os exemplos abaixo usam o laboratório da porta 8005 já iniciado. URLs com
`&` devem ficar entre aspas no PowerShell.

```powershell
# Referências HTTP, sem detector (modo padrão)
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/health --samples 2 --output reports/demo/baseline.json

# Somente inventário HTML, sem sondas de ataque
.\.venv\Scripts\python.exe main.py discover http://127.0.0.1:8005/probekit-lab --max-depth 2 --max-pages 10 --max-requests 10 --output reports/demo/discovery.json

# SQLi: selecionar um parâmetro e preservar os demais
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8005/general/json/vulnerable?term=apple&lang=en" --module sqli --parameter term --output reports/demo/sqli.json
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8005/general/json/safe?term=apple&lang=en" --module sqli --all-parameters --max-requests 20 --output reports/demo/sqli-safe.json

# XSS: candidato HTML e controle com escape
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8005/xss/html/raw?q=demo" --module xss --xss-browser --output reports/demo/xss.json
.\.venv\Scripts\python.exe main.py "http://127.0.0.1:8005/xss/html/escaped?q=demo" --module xss --output reports/demo/xss-safe.json

# Exposure: diretório-base explícito e catálogo fechado
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/demo/exposure.json

# Fluxo integrado: o padrão continua sendo somente SQLi
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/scan-lab --max-requests 100 --output reports/demo/sqli-scan.json
.\.venv\Scripts\python.exe main.py --version
.\.venv\Scripts\python.exe main.py discover --help
.\.venv\Scripts\python.exe main.py scan --help
```

## Opções e orçamento

| Opção | Comandos e padrão |
| --- | --- |
| `--module baseline/sqli/xss/exposure` | Execução direta; padrão `baseline` |
| `--modules sqli xss exposure` | `scan`; selecione um ou mais; padrão somente `sqli`; aceita também o alias `--module` |
| `--parameter NOME` / `--all-parameters` | SQLi/XSS direto; opções mutuamente exclusivas; os demais valores GET são preservados |
| `--sqli-context like/quoted` | SQLi direto e `scan`; padrão `like`; `quoted` cobre igualdade textual entre aspas simples |
| `--xss-browser` | XSS direto ou `scan` com XSS; confirmação opcional por replay isolado |
| `--exposure-profiles config backup repository` | Exposure direto ou `scan` com exposure; padrão somente `config` |
| `--exposure-base-path /diretorio/` | Somente `scan` com exposure; base padrão `/` na mesma origem |
| `--samples N` | Referências por análise; padrão 2; baseline aceita 1, detectores exigem pelo menos 2 |
| `--max-requests N` | Orçamento: direto 10, `discover` 20, `scan` 100; no scan é global |
| `--max-depth N` / `--max-pages N` | `discover` e `scan`; padrões 2 e 20; limitam a descoberta HTML |
| `--timeout SEGUNDOS` | Todos os comandos; conexão/inatividade de leitura; padrão 5 |
| `--interval SEGUNDOS` | Todos; intervalo mínimo entre inícios de GETs; padrão 0,2 |
| `--max-body-bytes N` | Todos; limite descomprimido por resposta; padrão 1.048.576 bytes |
| `--output ARQUIVO` | JSON; padrão `reports/<modo>-<horário UTC>.json` |
| `--help` / `--version` | Ajuda em todos os comandos; versão pela CLI principal |

Na execução direta, selecione um parâmetro, todos ou forneça uma URL com um
único parâmetro. Por compatibilidade, `q` é escolhido quando presente e não há
seleção explícita. SQLi aceita referência simples de 1–80 caracteres; XSS,
até 200 caracteres. Parâmetros repetidos com o mesmo nome são rejeitados.

SQLi reserva `samples + 8` GETs por parâmetro. XSS reserva o mesmo máximo,
podendo encerrar com cinco no padrão se não houver reflexão. Exposure usa
`samples + 2` por arquivo: quatro no padrão. Os perfis contêm cinco caminhos:
`config` (`.env`, `config.ini`), `backup` (`backup.sql`, `config.ini.bak`) e
`repository` (`.git/HEAD`). `config backup` requer 16 GETs na execução direta.

No scan, descoberta e módulos compartilham um cliente, contador e origem
(esquema, host e porta). O plano só começa se seu máximo cabe no saldo.
Exposure roda uma vez ao final dos parâmetros, na base configurada. Um saldo
insuficiente ignora alvos com motivo no JSON; não os converte em negativos.

## Interpretação, JSON e códigos de saída

| Resultado | Significado |
| --- | --- |
| `confirmed` | Evidências satisfizeram os critérios do módulo; em exposure, comprova acesso/estrutura, não validade de segredos ou política de privacidade |
| `suspected` | Há indícios específicos, mas não confirmação suficiente |
| `inconclusive` | Dados, estabilidade, formato ou controles não permitem concluir |
| `not_detected` | As sondas executadas não demonstraram a vulnerabilidade; não comprova segurança |
| `reflected_safe` | XSS: reflexão inerte ou escapada nas sondas executadas; não é garantia geral de segurança |

O relatório consolidado reúne `discovery`, `parameter_results`,
`exposure_results`, `analyses`, `requests`, `ignored_targets`, limites e
justificativas. As origens distinguem alvos manuais, descoberta automática e
perfis configurados. São gravados checkpoints no início, após a descoberta,
após análises e ao finalizar/interromper quando possível. O resumo de terminal
não substitui as evidências nem altera o JSON.

| Código de saída | Significado |
| --- | --- |
| 0 | Execução concluída ou limitada sem erro; consulte resultados e alvos ignorados |
| 1 | Falha HTTP de transporte/tamanho, gravação ou análise inconclusiva |
| 2 | Argumentos inválidos ou escopo bloqueado antes da execução |
| 130 | `scan` interrompido por Ctrl+C, com checkpoint parcial quando possível |

Encontrar uma vulnerabilidade não gera código de saída especial. Uma resposta
HTTP 4xx/5xx não equivale a falha de transporte e não comprova vulnerabilidade.
O campo `summary.status` do scan distingue `completed`, `limited`,
`incomplete` e `interrupted`. Código 0 também pode conter suspeitas ou alvos
ignorados; examine as classificações individuais.

## Arquitetura e limitações reais

| Componente | Responsabilidade e limite |
| --- | --- |
| `discover` | HTML estático: links e formulários GET; não executa JavaScript, não coleta valores de campos nem submete formulários; não presume descobrir APIs do Juice Shop |
| SQLi | Planos, execução, características JSON/HTML/texto e classificação separados; condições booleanas textuais entre aspas simples em LIKE/igualdade, com controles e erro SQL diferencial |
| XSS | Marcadores exclusivos, escape e contexto; confirmação somente com callback inofensivo no replay local de navegador, preservando CSP e bloqueando rede |
| exposure | Cinco caminhos, repetições e controles inexistentes; diferencia estrutura de arquivo, HTML, erro, fallback e documento público; não executa/descompacta conteúdo |
| Núcleo compartilhado | CLI, validação loopback, cliente HTTP, orçamento global, modelos, JSON e apresentação; [arquitetura detalhada](docs/ARQUITETURA.md) |

Não há cobertura universal. SQLi não cobre contextos numéricos, temporais,
UNION ou todos os bancos; sua confirmação exige controles estritos e pode
abster-se em casos reais. XSS não cobre XSS armazenado, DOM XSS nem todos os
eventos; um navegador ausente/bloqueado mantém a suspeita. Há um falso positivo
de suspeita conhecido em string JavaScript escapada, sem execução confirmada.
Exposure pode perder outros nomes/formatos e não distingue sozinho um exemplo
de configuração intencionalmente público de um artefato privado.

Apenas `localhost` e IPs loopback são aceitos; `localhost` é normalizado para
`127.0.0.1`. Redirecionamentos nunca são seguidos. Proxies/credenciais do
ambiente são desativados, cookies não são reutilizados e TLS é verificado.
Timeout não é um prazo total para uma resposta que continua enviando bytes.
Não há retries HTTP; no Windows apenas a substituição do checkpoint pode ser
repetida em caso de bloqueio transitório. Encerramento forçado pode perder o
último resultado ainda não persistido.

Corpos HTTP não são serializados. Exposure também omite nomes reais de chaves,
valores, trechos e cabeçalhos arbitrários. Os outros módulos conservam URLs,
payloads e alguns cabeçalhos técnicos de resposta (por exemplo CSP); esses
metadados podem conter dados específicos do alvo. Não forneça segredos nas
URLs e revise relatórios antes de compartilhá-los. `.gitignore` não remove
arquivos já rastreados nem substitui essa revisão.

## Testes, evidências e avaliação

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/publication-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Os testes usam servidores loopback efêmeros e SQLite, sem depender do Juice
Shop ou de sites públicos. Sete casos usam navegador real e podem ser
ignorados se Node/navegador não estiverem disponíveis. A contagem e o resultado
atual estão em [docs/TESTES.md](docs/TESTES.md). Os relatórios históricos em
`docs/evidencias/` usam somente os laboratórios e foram preservados, inclusive
tentativas parciais identificadas; novos relatórios locais ficam em `reports/`.

- [Roteiro curto dos três módulos](docs/DEMONSTRACAO.md)
- [Preparação para publicação e instalação limpa](docs/PUBLICACAO.md)
- [Descoberta](docs/DESCOBERTA.md), [SQLi](docs/SQLI_GENERALIZADO.md), [XSS](docs/XSS_REFLETIDO.md) e [exposure](docs/EXPOSICAO_ARQUIVOS.md)
- [Controles SQLite](docs/CONTROLE_NEGATIVO.md), [fluxo integrado](docs/SCAN_INTEGRADO.md) e [progresso](docs/PROGRESSO.md)

O repositório ainda não contém arquivo de licença; a escolha pelo responsável
permanece pendente antes da publicação com termos de reutilização definidos.
