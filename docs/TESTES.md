# Suíte automatizada reconstruída

Estado atual após a etapa 8: **344 testes aprovados** (286 anteriores e 58 novos),
sem falhas, erros ou ignorados. Resultado real: 58,26 segundos; dependências
consistentes. Roteiro e evidências em [EXPOSICAO_ARQUIVOS.md](EXPOSICAO_ARQUIVOS.md).
A etapa 7 passou com 286 testes em 56,09 segundos, conforme [XSS_REFLETIDO.md](XSS_REFLETIDO.md).
A etapa 6 passou com 238 testes, conforme [SCAN_INTEGRADO.md](SCAN_INTEGRADO.md).
A etapa 5 passou com 196 testes, conforme [SQLI_GENERALIZADO.md](SQLI_GENERALIZADO.md).
A etapa de descoberta passou com 164 testes, conforme [DESCOBERTA.md](DESCOBERTA.md).
O registro abaixo documenta a reconstrução anterior.

Para reproduzir a suíte atual:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/exposure-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Os 54 casos de `tests/test_exposure_contract.py` incluem configuração, INI,
backup SQL e referência Git fictícios; páginas 200 genéricas, erro personalizado,
bloqueio, documento público, MIME enganoso, instabilidade, redirecionamentos,
sigilo de valores/chaves/cabeçalhos, orçamento compartilhado, interrupção e CLI.
O teste do fluxo com três módulos usa confirmação XSS real no navegador.
Os quatro casos de `tests/test_checkpoint_contract.py` verificam bloqueio
transitório e persistente no Windows, preservação do JSON anterior e estado
incompleto quando a gravação falha antes do fim da análise. Os treze módulos
e quantidades constam no [resumo JUnit da etapa 8](evidencias/exposure-2026-10-27/tests-summary.json).
Os 286 testes anteriores foram preservados. Nenhum critério SQLi/XSS foi alterado.

Os 48 casos da etapa 7 em `tests/test_xss_contract.py` incluem reflexão, contexto,
escape, controles, seis casos com navegador real, bloqueio de rede, CSP,
limites compartilhados SQLi/XSS e interrupção. O controle JavaScript escapado
não executou, mas permaneceu suspeito; esse falso positivo de suspeita é
documentado. Não houve confirmação falsa dos controles seguros.
O teste antigo de rejeição de `--module xss` foi atualizado para um módulo
desconhecido (`unsupported`), pois XSS agora é um comando válido.
Os onze módulos e suas quantidades constam no
[resumo JUnit da etapa 7](evidencias/xss-2026-10-27/tests-summary.json).

Os 42 casos de `tests/test_scan_pipeline.py` verificam o fluxo real HTML/SQLite,
orçamento compartilhado, deduplicação, redirecionamentos, falhas HTTP,
timeout, interrupção nas duas fases, persistência atômica e compatibilidade.
Os dez módulos e suas quantidades constam no
[resumo JUnit da etapa 6](evidencias/scan-2026-10-27/tests-summary.json).

Na etapa anterior, os 32 casos de `tests/test_general_sqli.py` verificaram múltiplos parâmetros,
JSON/HTML/texto, LIKE/igualdade, controles parametrizados reais, respostas
instáveis, páginas de erro, limites, CLI e resultados empíricos sem forçar
expectativas. Os nove módulos e suas quantidades constam no
[resumo JUnit versionado](evidencias/general-sqli-2026-10-27/tests-summary.json).

Em 27/10/2026, a suíte anterior foi removida e substituída por testes organizados
pelos contratos públicos do projeto. O arquivo `conftest.py` também foi refeito.
O código de produção e os relatórios empíricos históricos foram preservados.

## Executar

```powershell
Set-Location -LiteralPath 'C:\Pessoal\Portfolio\SIN451'
.\.venv\Scripts\python.exe -m pytest --cache-clear -q --junitxml=reports/rebuilt-tests.xml
.\.venv\Scripts\python.exe -m pip check
```

Resultado real desta reconstrução: **123 testes passaram em 8,20 segundos**,
sem falhas, erros ou testes ignorados. A verificação das dependências passou.
Ambiente: Python 3.13.9 e pytest 8.4.2 no Windows.

O resultado JUnit fica em `reports/rebuilt-tests.xml`. O
[resumo versionado](evidencias/rebuilt-tests-2026-10-27.json) foi extraído desse
arquivo e inclui quantidades por módulo, horário e hashes SHA-256 dos arquivos
de teste. O tempo interno registrado no XML é 8,105 segundos; a saída do pytest
registrou 8,20 segundos incluindo seu processamento adicional.

## Organização

| Arquivo | Casos | Contratos verificados |
| --- | --- | --- |
| `tests/test_scope_contract.py` | 40 | URLs locais, rejeição antes da rede, orçamento e plano de sondas |
| `tests/test_transport_contract.py` | 22 | HTTP real, status, redirect, cookies, proxy, timeout, gzip e limites |
| `tests/test_evidence_contract.py` | 8 | Comparação, coleta parcial, serialização, UTF-8 e exclusão de corpos/segredos |
| `tests/test_sqli_decision_contract.py` | 21 | Confirmação, suspeita, não detecção, inconclusivo e identidade dos produtos |
| `tests/test_sqlite_evaluation_contract.py` | 16 | Aplicação SQLite real, controles, repetições, métricas e integridade da base |
| `tests/test_cli_process_contract.py` | 16 | CLI em subprocessos reais, códigos de saída e correspondência com o JSON |

As fixtures HTTP usam portas efêmeras no loopback, registram requisições e
encerram seus servidores ao terminar. Os testes SQLite iniciam a aplicação
`experiments.sqlite_control`, sem duplicar a consulta SQL dentro da suíte.
O Juice Shop e a instância fixa na porta 8001 não precisam estar executando.

Para verificar que a classificação não depende dos nomes das rotas, a suíte
troca as implementações SQL entre os caminhos e observa a inversão dos
resultados. Também executa o plano com duas e três referências. Coletas
inconclusivas não são contadas como verdadeiros negativos.

As decisões puras usam evidências sintéticas identificadas como fixtures; não
são apresentadas como resultados reais do alvo. As verificações HTTP, SQLite
e CLI executam código e comunicação locais reais. Nenhum teste acessa sites
públicos ou implementa XSS.

## Limites da verificação

Esta execução valida a nova suíte contra a versão atual do código. Não mede
cobertura percentual nem precisão geral do detector. Ela não substitui os
experimentos manuais no Juice Shop nem a avaliação empírica repetida descrita
em [CONTROLE_NEGATIVO.md](CONTROLE_NEGATIVO.md). Os números anteriores de 57,
81 e 101 testes são registros históricos das suítes substituídas; o total
da reconstrução é 123; com descoberta foram 164; a etapa 5 elevou o total a 196,
e a etapa 6 a 238; a etapa 7 chegou a 286; a etapa 8, a 344.
