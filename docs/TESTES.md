# Suíte automatizada reconstruída

Estado atual após a etapa de descoberta: **164 testes aprovados** (123 anteriores
e 41 novos), sem falhas ou ignorados. Resultado e roteiro em
[DESCOBERTA.md](DESCOBERTA.md). O registro abaixo documenta a reconstrução anterior.

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
da reconstrução é 123; com os testes de descoberta, o total atual é 164.
