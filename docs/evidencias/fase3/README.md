# Evidências experimentais PK-F3

Campanha `05c7eb64-2f81-4ac6-bc83-9aa3048b8db5`, protocolo/catálogo 1.0.0,
ProbeKit 0.2.0. Apenas evidências compartilháveis; originais privados não estão aqui.

**Análise selecionada: 1.0.3 — `dfde5155-4920-465b-bced-6b3ff7405a3e`.**

- [Manifesto de hashes](05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e/seal.json)
- [Métricas e denominadores](05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e/analysis/metrics.json)
- [Unidades e outcomes](05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e/analysis/results.csv)
- [Registro e vínculos de snapshots](05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e/registry.json)
- [Repetibilidade](05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e/analysis/repeatability.json)
- [Relatório acadêmico](../../RESULTADOS_EXPERIMENTAIS.md) e [reprodução](../../../experiments/evaluation/README.md)

O pacote contém protocolo, catálogo com gabarito independente, ambiente sanitizado,
hashes de fontes, 165 pares de relatórios verificados, dados de análise, três CSV
e oito figuras PNG/SVG. São 1.011 arquivos no selo; o próprio selo não se inclui.
Catálogo e protocolo mantêm rotas relativas/entradas fictícias de reprodução.
Relatórios e tabelas omitem URLs operacionais, payloads e caminhos pessoais.

```powershell
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation verify docs/evidencias/fase3/05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e
```

As análises anteriores estão **substituídas** e são preservadas somente
localmente, fora do versionamento Git, para auditoria. Os diretórios continuam
no disco e estão listados no `.gitignore`; nenhum arquivo foi apagado.
O commit contém apenas o pacote final selecionado acima.

| Versão | Analysis ID | Correção posterior |
| --- | --- | --- |
| 1.0.0 | `51cb802e-7557-4fe2-ad26-c2901dbb2601` | Excluir integração do gráfico de tempos diretos |
| 1.0.1 | `77dc33b9-751e-425d-9094-1c985d93357d` | Taxas mitigadas calculadas pelos outcomes, sem atribuição binária |
| 1.0.2 | `c4f326b9-ddea-454a-b065-55ee043e746e` | Fortalecer vínculos campanha/análise/snapshot e tratamento de assessment ausente; métricas desta campanha iguais às da 1.0.3 |

Não usar os derivados antigos como resultados finais. O verificador atual rejeita
as taxas incompatíveis de 1.0.0/1.0.1; todos os bytes históricos foram preservados. Nenhuma
resposta ou classificação do scanner mudou, e não houve nova coleta nas correções.
Os hashes comprovam correspondência, sem assinatura/autenticidade contra
substituição integral. Este pacote foi preparado localmente, sem publicação.
