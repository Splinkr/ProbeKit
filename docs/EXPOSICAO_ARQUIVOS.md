# Etapa 8 — Exposição de arquivos

O módulo independente `exposure` verifica um catálogo pequeno de artefatos em
uma origem loopback autorizada. Usa estrutura do conteúdo, repetições e dois
caminhos inexistentes por arquivo. HTTP 200 e nome/extensão, isoladamente,
não produzem confirmação. SQLi e XSS mantêm seus planos e classificadores.

## Arquitetura e catálogo

| Arquivo | Responsabilidade |
| --- | --- |
| `scanner/exposure_profiles.py` | Catálogo fechado, diretório-base e plano de controles/referências |
| `scanner/modules/exposure.py` | Execução HTTP e associação das evidências ao arquivo |
| `scanner/exposure_analysis.py` | Características estruturais, comparação e classificação |
| `scanner/exposure_models.py` | Objetos de evidência sem corpo, valores ou cabeçalhos arbitrários |
| `scanner/pipeline.py` | Mesmo cliente, origem, IDs, orçamento e checkpoints dos três módulos |
| `experiments/exposure_lab.py` | Artefatos e respostas fictícios usados no laboratório SQLite existente |

| Perfil | Caminhos relativos | Estrutura reconhecida |
| --- | --- | --- |
| `config` (padrão) | `.env`, `config.ini` | Atribuições de configuração; INI com seções |
| `backup` | `backup.sql`, `config.ini.bak` | SQL com CREATE TABLE e INSERT INTO; backup de configuração |
| `repository` | `.git/HEAD` | Referência Git ou identificador hexadecimal de 40/64 caracteres |

Há **no máximo cinco caminhos**, em um único diretório-base escolhido. Não há
wordlist livre, recursão de diretórios, extensão automática, descompactação,
execução de arquivos nem validação/extração de credenciais. Perfis repetidos
são deduplicados. O conteúdo recebido é analisado em memória dentro do limite
de bytes do cliente HTTP; o relatório recebe somente objetos de metadados.

Para configuração, exige-se pelo menos duas atribuições e indicador de banco
ou de configuração de credencial. As chaves são examinadas transitoriamente,
sem guardar seus nomes ou valores. Os indicadores serializados pertencem a
uma lista fixa de booleanos. SQL exige as duas estruturas de instrução,
sem executar ou registrar as instruções, tabelas ou registros encontrados.
As assinaturas cobrem somente os formatos descritos nesta tabela.

## Plano e critérios

Cada arquivo usa a sequência: controle inexistente 1, `samples` referências
ao caminho e controle inexistente 2. Os controles têm nomes aleatórios
distintos, no mesmo diretório do arquivo, preservando seu nome como sufixo.
São `samples + 2` requisições: **quatro no padrão**, oito para `config`,
16 para `config backup` e 20 para os três perfis.

São comparados status, MIME, tamanho, hash SHA-256, estrutura e indícios de
HTML/documento público/erro. A comparação de fallback também usa hash de texto
normalizado, substituindo somente URL/caminho/nome da própria requisição e
normalizando espaços. Não remove números, timestamps ou conteúdo variável
arbitrário. Detecta, por exemplo, um erro que ecoa o caminho inexistente.

| Resultado | Critério |
| --- | --- |
| `confirmed` | Coleta completa; referências HTTP 200 idênticas em status/MIME/hash; assinatura do tipo esperado; conteúdo sem HTML/documento público/erro; controles estáveis negativos e distintos do arquivo |
| `suspected` | Estrutura compatível e controles negativos, mas instabilidade das referências/controles ou conteúdo HTML impede confirmação |
| `inconclusive` | Coleta incompleta; redirect/status não suportado; controles sem capacidade de distinguir o arquivo; ou estrutura compatível também retornada nos caminhos inexistentes |
| `not_detected` | Caminhos bloqueados/ausentes (401/403/404/410), resposta genérica equivalente sem estrutura compatível ou ausência de assinatura suficiente |

Controles negativos podem ser 401/403/404/410 ou HTTP 200 sem assinatura
estrutural. Um controle com erro 500 ou redirect não sustenta confirmação.
Se qualquer caminho retorna a mesma estrutura potencialmente sensível, o
resultado é inconclusivo quanto à existência daquele arquivo específico.
Uma página de erro dinâmica sem estrutura de arquivo continua sem confirmação.
`not_detected` não comprova segurança nem cobre formatos não reconhecidos.

**`confirmed` confirma acesso e estrutura de um artefato em caminho de risco.**
Não afirma que seu conteúdo contém segredos válidos nem que a política da
aplicação exige privacidade. Essa distinção consta em cada avaliação.

## Integração e evidências mínimas

`--module exposure` recebe uma URL de diretório terminada em `/`, sem query.
`scan --modules exposure` mantém a descoberta HTML e usa `/` como base dos
perfis; `--exposure-base-path /diretorio/` escolhe outra base na mesma origem.
Profundidade e páginas limitam o crawler; o catálogo de arquivos é separado.
URLs externas, caminhos relativos/ambíguos e mudanças de origem são bloqueados.
Todos os redirecionamentos permanecem desativados, inclusive entre origens
locais. Não há cookies, autenticação, proxies do ambiente ou acesso externo.

No fluxo misto, os módulos por parâmetro executam primeiro, na ordem da CLI;
`exposure` executa uma vez ao final, sem multiplicar perfis pelos parâmetros
descobertos. A origem dos seus alvos é `configured_profile`, diferente de
`automatic` ou `manual`. O padrão de `scan` continua somente SQLi.

Cada plano só começa quando cabe inteiro no saldo global. O cliente existente
aplica timeout, intervalo, limite de bytes descomprimidos e orçamento às três
análises e à descoberta. Não há retries HTTP. SQLi/XSS mantêm a reserva
conservadora de dez requisições por parâmetro, mesmo quando XSS pode encerrar
antes por ausência de reflexão. Os limites não garantem tempo total de parede
para servidores que mantêm a conexão ativa enviando bytes lentamente.

O JSON consolidado separa `parameter_results` de `exposure_results` e informa
`files_analyzed`, requisições, alvos ignorados, critérios, justificativa e
limitações. Arquivo não é contabilizado como parâmetro GET. As observações
exposure contêm URL fixa do catálogo/controle, método, papel, horário, status,
MIME de lista permitida, tamanho, hashes, duração, contagens e booleanos.
Não contêm corpo, trecho de arquivo, chave real, valor, branch Git, instrução
SQL ou cabeçalho arbitrário. MIME desconhecido é registrado como `other`.
O terminal também não imprime conteúdo dos artefatos.

`scan` preserva checkpoints atômicos e trata Ctrl+C com código 130. No Windows,
um bloqueio transitório ao substituir o arquivo permite até quatro tentativas
locais, com espera total máxima de 0,3 segundo, sem repetir GETs. Falha
persistente retorna erro, mantém o checkpoint anterior e não autoriza afirmar
que o scan concluiu. Encerramento forçado pode perder a coleta mais recente.

## Demonstração no Windows 11

No primeiro PowerShell, na raiz do projeto (a porta 8005 deve estar livre):

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m experiments.sqlite_control --port 8005
```

O servidor escuta exclusivamente em `127.0.0.1`. Não é necessário Docker.
Em outro PowerShell:

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/exposure-demo/files.json
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 100 --output reports/exposure-demo/three-modules.json
```

A confirmação XSS requer Node.js e Edge ou Chrome instalados. Usa o replay
isolado existente, com CSP e bloqueio de rede, sem novos GETs ao alvo.
Sem esses programas, omita `--xss-browser`: a reflexão executável permanece
`suspected`; SQLi e exposure continuam funcionando.

Para reproduzir controles negativos, cobertura dos formatos e limite global:

```powershell
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/exposure-lab/fallback/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/exposure-demo/fallback.json
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/exposure-lab/error/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/exposure-demo/custom-error.json
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/exposure-lab/blocked/ --module exposure --exposure-profiles config backup --max-requests 16 --output reports/exposure-demo/blocked.json
.\.venv\Scripts\python.exe main.py http://127.0.0.1:8005/exposure-lab/exposed/ --module exposure --exposure-profiles config backup repository --max-requests 20 --output reports/exposure-demo/all-formats.json
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules sqli xss exposure --exposure-profiles config backup --xss-browser --max-requests 84 --output reports/exposure-demo/budget-84.json
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/exposure-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Para testar somente os arquivos de um subdiretório a partir da página inicial:

```powershell
.\.venv\Scripts\python.exe main.py scan http://127.0.0.1:8005/probekit-lab --modules exposure --exposure-profiles config backup --exposure-base-path /exposure-lab/exposed/ --max-requests 22 --output reports/exposure-demo/subdirectory.json
```

Esse último comando ilustra uma opção validada pela suíte; não integra a
rodada manual versionada abaixo. Os comandos anteriores foram executados.

## Resultados observados e limitações

Os resultados desta rodada estão nos JSONs e no
[resumo verificável](evidencias/exposure-2026-10-27/summary.json), com hashes.
O laboratório usa exclusivamente configurações, backup SQL e metadados Git
fictícios. O SQL do backup é texto e nunca é executado.

| Execução | Resultado observado | GETs |
| --- | --- | --- |
| Raiz, `config backup` | `.env` e `backup.sql` confirmed; `config.ini` bloqueado e `config.ini.bak` com documentação pública not_detected | 16/16 |
| `/exposure-lab/fallback/` | Quatro not_detected apesar de todos os status 200 e caminhos ecoados no HTML | 16/16 |
| `/exposure-lab/error/` | Quatro not_detected; erro HTML 200 com contador dinâmico | 16/16 |
| `/exposure-lab/blocked/` | Quatro not_detected, acesso 403 | 16/16 |
| `/exposure-lab/exposed/`, três perfis | Cinco confirmed: dotenv, INI, backup SQL, backup INI e referência Git | 20/20 |
| Fluxo com três módulos | SQLi confirmed, XSS confirmed por callback real e dois arquivos confirmed | 92/100 |
| Fluxo com orçamento 84 | SQLi/XSS e `.env` confirmed; `config.ini` not_detected; dois backups ignorados por saldo | 84/84 |
| Regressão Juice Shop local: `/rest/products/search?q=apple` | SQLi confirmed, critérios preservados | 10/10 |

O fluxo completo inventariou seis endpoints, analisou quatro parâmetros
distintos em oito avaliações SQLi/XSS e quatro arquivos. Foram seis GETs de
descoberta e 86 de análise, com quatro achados confirmados. A documentação
pública `/README.txt` foi descoberta sem parâmetros e não recebeu sondas;
também não integra o catálogo de exposição. Além disso, o conteúdo público
servido sob `config.ini.bak` foi avaliado e permaneceu negativo.

Os controles SQLi parametrizado e XSS com HTML escapado não foram confirmados.
A integridade dos cinco registros SQLite foi comparada por `/health` antes
e depois; o hash permaneceu igual. Nenhum valor fictício dos arquivos apareceu
nos relatórios de exposição ou consolidados. Os testes também verificam que
chaves, nomes SQL/Git e cabeçalhos com marcadores privados são excluídos.

Uma primeira tentativa de cada scan misto falhou ao substituir um checkpoint
no Windows (`WinError 5`). A coleta parou após 76 GETs, antes de exposure.
Esses dois JSONs anteriores à correção estão identificados em
`failed-attempts/`, com a advertência de que o status antigo `completed` não
comprova conclusão: havia alvos pendentes e a CLI retornou erro de gravação.
Depois da correção de persistência, os dois comandos foram repetidos; os
resultados completos são os das linhas 92/100 e 84/84. Não houve alteração
dos critérios dos detectores para produzir os resultados.

Os oito relatórios completos somam 270 GETs. As duas tentativas anteriores
somam 152 e houve três consultas de integridade `/health`: **425 GETs nesta
rodada manual**, incluindo os dez da regressão no Juice Shop local.
Os testes automatizados são contabilizados separadamente. Os replays XSS
não enviaram novos GETs aos alvos.

O catálogo pequeno reduz cobertura por escolha: não procura outros nomes,
arquivos compactados, diretórios adicionais, arquivos autenticados, conteúdo
binário ou formatos arbitrários. Aplicações podem retornar exemplos de
configuração ou SQL publicamente de propósito; estrutura e caminho não
permitem inferir sua política de confidencialidade. Esse é um possível falso
positivo de interpretação e exige revisão humana. Instabilidade pode manter
um arquivo real como suspeito. Uma assinatura não reconhecida pode produzir
falso negativo. Não se mede precisão universal a partir deste laboratório.

A suíte desta etapa inclui os 286 testes anteriores, 54 de exposure e quatro
de persistência de checkpoints: **344 passaram em 58,26 segundos**, sem falhas,
erros ou ignorados. Houve sete casos com navegador real. `pip check` passou.
Casos com navegador podem ser ignorados em
máquinas sem Node e navegador; o resultado desta máquina está no
[resumo JUnit](evidencias/exposure-2026-10-27/tests-summary.json).
