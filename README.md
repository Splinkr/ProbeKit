# ProbeKit

Scanner acadêmico de aplicações web locais, desenvolvido para SIN 451 —
Segurança da Informação (UFV). Oferece descoberta HTML, SQL Injection por
parâmetro GET, XSS refletido e exposição de arquivos com controles negativos.
Os relatórios JSON registram evidências e limites de cada conclusão.

O escopo é exclusivamente loopback autorizado. Não há opção para liberar
alvos externos, autenticação, operações de escrita ou execução de arquivos
encontrados. Os laboratórios fornecidos usam dados fictícios e dispensam Docker.

## Propósito, utilidade e diferencial

O ProbeKit existe para **classificar com evidência**, e não apenas listar suspeitas.
Em vez de responder só "vulnerável" ou "não vulnerável", cada alvo recebe uma de
cinco classes (`confirmed`, `suspected`, `inconclusive`, `not_detected` e
`reflected_safe`), obtida por comparação diferencial entre respostas de referência,
sondas e controles negativos; o relatório mostra quais critérios foram satisfeitos e
o que **não** foi possível concluir.

- **Para quem:** ensino e estudo de varredura de vulnerabilidades em laboratório
  controlado (gabarito conhecido, evidência reprodutível) e triagem rápida da própria
  aplicação em desenvolvimento, em loopback.
- **Diferencial:** `confirmed` só com todos os critérios e controles; abstenção
  explícita (`suspected`/`inconclusive`); evidência com manifesto e hashes, sem gravar
  corpos, cookies ou valores; escopo seguro por construção. Na campanha formal, uma
  heurística simples sobre a mesma evidência gerou 39 falsos positivos em exposição,
  18 em SQLi e 15 em cada condição de XSS; o ProbeKit não gerou nenhum confirmado, ao
  custo de abstenções declaradas.
- **O que não é:** não substitui sqlmap, OWASP ZAP ou Burp Suite (somente GET, sem
  autenticação, sem extração de dados, descoberta HTML estática).

Detalhes: [propósito e diferencial](docs/PROPOSITO_E_DIFERENCIAL.md),
[modelo de detecção e evolução](docs/MODELO_DE_DETECCAO.md),
[impacto e mitigação](docs/IMPACTO_E_MITIGACAO.md),
[detectabilidade e regras de IDS](docs/DETECTABILIDADE_IDS.md) e
[comparação com sqlmap e ZAP](docs/COMPARACAO_FERRAMENTAS.md).

## Como o ProbeKit decide

| Módulo | Evidência exigida para `confirmed` |
| --- | --- |
| SQLi | referências estáveis; aspa escapada e controle literal sem efeito; dois pares booleanos (verdadeiro igual à referência, falso vazio); erro SQL diferencial; recuperação igual à referência |
| XSS | marcador ausente nos controles; duas reflexões independentes; contexto potencialmente executável; execução do callback observada no navegador |
| exposure | HTTP 200 estável, estrutura compatível com o tipo do arquivo, não-HTML e diferente dos caminhos inexistentes de controle |

Sem todos os critérios, o resultado é `suspected` (há indício específico) ou
`inconclusive` (não há como concluir); `not_detected` nunca prova ausência de
vulnerabilidade. [Fluxo completo e evolução planejada](docs/MODELO_DE_DETECCAO.md).

## Requisitos e instalação no Windows 11

| Componente | Uso |
| --- | --- |
| Python 3.13 com pip | CLI, SQLite do laboratório e testes; validado com 3.13.9 |
| `requests==2.34.2` | Dependência HTTP; transitivas e hashes nos locks |
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
do JSON. O resultado real, reproduzido na instalação limpa da etapa 9, foi
92/100 GETs e quatro avaliações confirmadas: uma SQLi, uma XSS e dois arquivos
fictícios. Isso é uma referência
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

Cada gravação pela CLI também gera `findings.json` no mesmo diretório do
relatório técnico, sem novas requisições ou alteração das classificações.
Por exemplo, `--output reports/demo/full.json` produz `full.json` completo e
`reports/demo/findings.json` resumido. A versão 0.2.0 publica uma geração
imutável e `full.json.manifest.json`; use o manifesto para ler/verificar a dupla.
O perfil padrão `--evidence-profile shareable` anonimiza URLs, caminhos e
parâmetros por IDs opacos. O terminal também aplica o perfil; forneça `--output`
para escolher um caminho conhecido. `--evidence-profile restricted` preserva
detalhes de reprodução com permissões restritas e exige revisão antes de compartilhar.
O resumo contém somente `confirmed` e `suspected`, com módulo, tipo,
confiança disponível e IDs das requisições. Os detalhes dependem do perfil.
`summary` conta
achados deduplicados por módulo/URL/parâmetro/status; repetições unem os IDs.
Sem achados, `findings` é `[]` e as contagens são zero.

O campo `source_report` identifica `technical.json` dentro da geração e
`source_sha256` verifica seus bytes exatos. `run_id` identifica a execução;
`snapshot_id`, o checkpoint. O manifesto também verifica hashes, perfil e versão;
`scan_status` mantém o estado legado do relatório técnico. Nos modos diretos,
`completed` pode indicar coleta concluída com avaliação `inconclusive`; no
`scan`, a regra legada continua marcando essa avaliação como `incomplete`.
Os campos abaixo, introduzidos na Fase 1, mantêm sua semântica no schema 2.0:

- `collection_status`: estado operacional `running`, `completed`, `limited`,
  `incomplete` ou `interrupted`, independente dos outcomes dos detectores.
- `analysis_summary`: `applicable`, `evaluations`, contagens em `outcomes` para
  as cinco classificações e `has_inconclusive`. Conta avaliações individuais,
  sem duplicar o `assessment` agregado ou inferir avaliações de achados.

Esses campos estão no JSON técnico e no resumo, derivados do mesmo snapshot.
Baseline e descoberta têm `applicable: false`; um detector sem avaliação tem
zero avaliações, sem ser considerado negativo. Uma coleta `completed` com
`has_inconclusive: true` não é uma conclusão de segurança. Uma confirmação
continua no resumo quando outra avaliação é inconclusiva. Ao converter JSON
legado sem os campos novos, o resumo calcula as contagens disponíveis e usa
`collection_status: null`, sem adivinhar o estado operacional.

Os checkpoints atualizam também o resumo: uma lista vazia em execução parcial
não comprova segurança. Corpos, cookies, autenticação e valores/chaves encontrados
por Exposure nunca são persistidos. No padrão compartilhável, textos livres,
payloads e cabeçalhos técnicos são omitidos; no restrito, credenciais de URL e
valores reconhecidamente sensíveis são mascarados. Outros detalhes restritos
podem conter informações privadas.

`findings.json` representa a última gravação naquele diretório. Para preservar
resumos de várias execuções, use diretórios diferentes em `--output`. Se o próprio
relatório técnico se chamar `findings.json`, o resumo se chamará
`findings-summary.json`, preservando o destino solicitado e a compatibilidade da CLI.
As funções de baixo nível `write_json`/`write_json_atomic` gravam um JSON atômico
com perfil; `write_reports` publica a geração e o manifesto usados pela CLI.
Os aliases tradicionais podem divergir após uma falha ou concorrência. Verifique:

```powershell
.\.venv\Scripts\python.exe main.py verify-report reports/demo/full.json.manifest.json
```

O verificador é offline: 0 válido, 1 falha de integridade/leitura, 2 argumentos.
Schema novo: 2.0; protocolo de manifesto: 1.0. Detalhes e migração:
[Fase 2](docs/FASE2_SEGURANCA.md), [plano versionado](docs/FASE2_PLANO.md).

| Código de saída | Significado |
| --- | --- |
| 0 | Execução concluída ou limitada sem erro; consulte resultados e alvos ignorados |
| 1 | Falha HTTP de transporte/tamanho, processamento, gravação ou análise inconclusiva |
| 2 | Argumentos inválidos ou escopo bloqueado antes da execução |
| 130 | `scan` interrompido por Ctrl+C, com checkpoint parcial quando possível |

Encontrar uma vulnerabilidade não gera código de saída especial. Uma resposta
HTTP 4xx/5xx não equivale a falha de transporte e não comprova vulnerabilidade.
O campo `summary.status` do scan distingue `completed`, `limited`,
`incomplete` e `interrupted`. Código 0 também pode conter suspeitas ou alvos
ignorados; examine as classificações individuais.

A decodificação de HTML/texto respeita o charset válido informado pelo alvo,
incluindo UTF-8, Latin-1 e Windows-1252. Charset ausente, desconhecido ou codec
incompatível com a decodificação usa UTF-8 com substituição; fallback recuperado
não é erro nem gera nova requisição. JSON e o replay XSS mantêm seus caminhos.

Uma exceção inesperada durante processamento encerra novos alvos e preserva as
evidências anteriores. O técnico registra `execution_errors` com fase, módulo,
tipo fixo e mensagem sanitizada, separados de erros HTTP e sem duplicar tentativas.
No `scan`, o alvo ativo fica `failed`, os seguintes `skipped`, com motivo
`execution_error`, e o checkpoint final fica `incomplete` quando pode ser gravado.
Falhas HTTP já tratadas mantêm sua política de continuidade. Ctrl+C mantém o
tratamento próprio e o código 130; uma falha de finalização não o substitui por
erro de argumento. Falhas de gravação continuam sendo erros: se o filesystem
impedir a escrita, a persistência do último estado não é garantida.
Detalhes e validação: [correções da Fase 1](docs/FASE1_ESTABILIZACAO.md).

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

Há limites adicionais em todos os comandos: `--max-urls 1000`,
`--max-candidates 2000`, `--max-url-length 8192`, `--max-metadata-bytes 8388608`,
`--max-total-body-bytes 33554432` e `--request-deadline 15`. O último limita
o GET completo em um worker isolado; `--timeout` continua limitando inatividade.
Metadados usam reservas conservadoras, e os corpos são liberados depois do uso,
incluindo replay XSS. Consulte `resource_usage`/`resource_limits`: limites podem
reduzir cobertura e deixar avaliações inconclusivas; não são um teto de RSS.

O perfil restrito pode conter URLs, payloads e CSP específicos do alvo. Revise
antes de compartilhar. O compartilhável preserva metadados/correlação da coleta;
não promete anonimato absoluto. `.gitignore` não remove
arquivos já rastreados nem substitui essa revisão.

## Testes, evidências e avaliação

A suíte completa da Fase 3 usa o ambiente isolado da avaliação, que inclui
Matplotlib. Prepare-o pelos [comandos do avaliador](experiments/evaluation/README.md),
preservando os ambientes existentes.

```powershell
.\.venv-evaluation\Scripts\python.exe -m pytest -q --junitxml=reports/evaluation-tests.xml
.\.venv-evaluation\Scripts\python.exe -m pip check
```

Os testes usam servidores loopback efêmeros e SQLite, sem depender do Juice
Shop ou de sites públicos. Oito casos usam navegador real e podem ser
ignorados se Node/navegador não estiverem disponíveis. A contagem e o resultado
atual estão em [docs/TESTES.md](docs/TESTES.md). A Fase 2 acrescenta regressões
de apresentação, publicação, privacidade, limites e bootstrap. Os relatórios históricos em
`docs/evidencias/` usam somente os laboratórios e foram preservados, inclusive
tentativas parciais identificadas; novos relatórios locais ficam em `reports/`.

- [Roteiro curto dos três módulos](docs/DEMONSTRACAO.md)
- [Avaliação experimental Fase 3: protocolo](docs/AVALIACAO_EXPERIMENTAL.md), [resultados](docs/RESULTADOS_EXPERIMENTAIS.md), [pacote verificável](docs/evidencias/fase3/README.md) e [comandos do avaliador](experiments/evaluation/README.md)
- [Preparação para publicação e instalação limpa](docs/PUBLICACAO.md)
- [Descoberta](docs/DESCOBERTA.md), [SQLi](docs/SQLI_GENERALIZADO.md), [XSS](docs/XSS_REFLETIDO.md) e [exposure](docs/EXPOSICAO_ARQUIVOS.md)
- [Controles SQLite](docs/CONTROLE_NEGATIVO.md), [fluxo integrado](docs/SCAN_INTEGRADO.md) e [progresso](docs/PROGRESSO.md)
- [Propósito e diferencial](docs/PROPOSITO_E_DIFERENCIAL.md), [modelo de detecção](docs/MODELO_DE_DETECCAO.md), [impacto e mitigação](docs/IMPACTO_E_MITIGACAO.md), [detectabilidade e regras de IDS](docs/DETECTABILIDADE_IDS.md), [comparação com sqlmap e ZAP](docs/COMPARACAO_FERRAMENTAS.md) e [roteiro da apresentação](docs/ROTEIRO_APRESENTACAO.md)
- [Índice de todos os documentos](docs/README.md)

O repositório ainda não contém arquivo de licença; a escolha pelo responsável
permanece pendente antes da publicação com termos de reutilização definidos.
