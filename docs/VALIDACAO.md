# Validação das etapas 1 e 2

Execução em 27/10/2026, Windows 11, fuso America/Sao_Paulo.

## Ambiente verificado

| Componente | Versão |
| --- | --- |
| Python | 3.13.9, instalado localmente em `.tools/python/` |
| Node.js | 24.19.0 |
| npm | 11.17.0, via `npm.cmd` |
| Git | 2.55.0.windows.3 |
| requests | 2.32.5 |
| pytest | 8.4.2 |
| OWASP Juice Shop | 20.3.0, pacote Windows x64 para Node.js 24 |

Ambiente virtual criado em `.venv/`. Dependências instaladas com
`python -m pip install -r requirements-dev.txt`.

O SHA-256 do ZIP correspondeu ao informado pela API oficial de releases:
`a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57`.
A extração final com `zipfile` preservou todas as 45.183 entradas do arquivo.
O processo Node foi executado diretamente, sem Docker. A consulta
`Get-NetTCPConnection -LocalPort 3000 -State Listen` confirmou a escuta em
`127.0.0.1:3000`.

## Referências reais do Juice Shop

```powershell
.\.venv\Scripts\python.exe main.py http://localhost:3000 --samples 3 --output reports/juice-shop-baseline.json
```

Coleta inicial registrada em `2026-10-27T14:26:00+00:00` (11h26 em São Paulo):

| Referência | HTTP | Tamanho | Tempo |
| --- | --- | --- | --- |
| 1 | 200 | 10.017 bytes | 21,709 ms |
| 2 | 200 | 10.017 bytes | 2,825 ms |
| 3 | 200 | 10.017 bytes | 2,564 ms |

SHA-256 comum às três respostas:
`058098398f45719a42fa8e21860a34a7d11d135e0cb781da751e419530372b73`.
As comparações não identificaram alterações de status, conteúdo ou tamanho.
Nenhum achado de vulnerabilidade foi produzido. Tempos podem variar em novas
execuções. O relatório completo fica em `reports/`, fora do Git.

## Testes automatizados

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

Resultado: **57 testes passaram**. A verificação das dependências não encontrou
incompatibilidades. Cobertura funcional dos cenários:

- URLs loopback IPv4/IPv6, normalização de localhost, rejeição de alvos externos,
  LAN, credenciais, nomes ambíguos e URLs inválidas antes da rede.
- GET real em servidor local, preservação de HTTP 500, bloqueio de redirects,
  isolamento de cookies e desativação de proxy do ambiente.
- Timeout antes dos cabeçalhos e durante leitura do corpo, falhas de conexão e
  TLS, intervalo mínimo e limites de requisições e bytes.
- Comparação de status, tipo de conteúdo, tamanho, SHA-256 e amostra de conteúdo.
  Respostas diferentes não geram achados automaticamente.
- CLI, códigos de saída, gravação de JSON, falha de gravação e contratos de achados.
  Corpos HTTP e cookies não são persistidos.

Além dos testes, a CLI foi executada contra `http://127.0.0.1:1` com timeout de
0,2 segundo: retornou código 1 e gerou `reports/connection-failure.json` com erro
`timeout`. A entrada `http://example.com` retornou código 2 na validação, sem
executar requisições.

## Limitações

Esta entrega contém referências e análise observacional. SQLi, XSS, exposição
de arquivos e descoberta automática ainda não foram implementados. A comparação
não diferencia conteúdo dinâmico benigno de uma falha de segurança. Similaridade
usa uma amostra de 16 KiB; hash e tamanho usam o corpo completo. Não se segue
redirecionamento, mesmo local. Timeout não é um prazo total de execução.

Desafios opcionais do Juice Shop relacionados a Alchemy e LLM emitiram avisos
por falta de configuração. Eles não impediram a execução HTTP desta etapa.
