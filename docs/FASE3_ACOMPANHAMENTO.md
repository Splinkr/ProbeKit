# PK-F3 — acompanhamento v1.0.1

Plano PK-F3 1.0.0; produto **0.2.0**, sem promoção de versão. Protocolo, catálogo,
coletor e formato experimental 1.0.0; análise selecionada **1.0.3**.
Base HEAD `2026e837c95552e40af365cb718dba577b9f8323`, com 58 alterações locais da
Fase 2 já existentes e preservadas. Sem commit, push, tag ou publicação.

| Subfase | Estado e evidência |
| --- | --- |
| F3.1 | Concluída: ambiente/locks conferidos, protocolo e gabarito registrados antes da coleta; suíte de referência 543/543 |
| F3.2 | Concluída: cinco comandos do avaliador, testes de fórmulas, integridade, privacidade e exportação offline; primeira suíte 568/568 antes da coleta |
| F3.3 | Concluída: 156 execuções diretas, 195 unidades-repetições, três rodadas, nenhum caso faltante |
| F3.4 | Concluída: três integrados controlados e seis Juice Shop; clone com 45.183 arquivos conferidos, banco original preservado |
| F3.5 | Concluída: matrizes/abstenções/A-B/repetibilidade e oito figuras; correções derivadas versionadas; reprodução pública offline 11/11 idêntica |
| F3.6 | Concluída: relatório com 15 tópicos, pacote sanitizado verificado, suíte final 578/578 e auditoria de preservação |

Campanha `05c7eb64-2f81-4ac6-bc83-9aa3048b8db5`: 165/165 execuções verificadas,
1.761 GET do scanner e três GET prévios de versão. Teto planejado: 2.040 GET.
Todos os resultados, inclusive suspeitas e inconclusivos, foram preservados.
Nenhuma indisponibilidade de dependência, navegador ou serviço impediu casos.
Saída textual dos subprocessos foi descartada; códigos de retorno, tempos e
relatórios são os registros operacionais disponíveis.

| Versão da análise | Analysis ID | Estado/motivo |
| --- | --- | --- |
| 1.0.0 | `51cb802e-7557-4fe2-ad26-c2901dbb2601` | Preservada, substituída: gráfico atribuía duração integrada ao último módulo |
| 1.0.1 | `77dc33b9-751e-425d-9094-1c985d93357d` | Preservada, substituída: taxa mitigada usava células binárias em vez dos outcomes |
| 1.0.2 | `c4f326b9-ddea-454a-b065-55ee043e746e` | Preservada: taxas mitigadas corretas; substituída para registrar verificador e extrator fortalecidos |
| 1.0.3 | `dfde5155-4920-465b-bced-6b3ff7405a3e` | Selecionada: vínculos campanha/análise/snapshot e ausência de assessment verificados; resultados desta campanha idênticos à 1.0.2 |

As correções não mudaram protocolo, rótulos, respostas, assessments ou linhas
extraídas; não dispararam nova coleta. Matrizes e métricas não mitigadas foram
comparadas e permaneceram idênticas. O inventário do código da análise fica em
`analysis-source-state.json`, separado daquele congelado antes da coleta.
O verificador atual rejeita os derivados 1.0.0/1.0.1 com taxas incompatíveis;
seus arquivos não foram reescritos para obter aprovação.

| Validação real | Aprovados | Falhos | Erros | Ignorados | Não executados | Tempo pytest |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Referência, `phase3-before.xml` | 543 | 0 | 0 | 0 | 0 | 192,94 s |
| Primeiros testes, `phase3-new-first.xml` | 25 | 0 | 0 | 0 | 0 | 9,02 s |
| Relacionados, `phase3-related.xml` | 75 | 0 | 0 | 0 | 0 | 16,95 s |
| Completa pré-coleta, `phase3-precollection-all-tests.xml` | 568 | 0 | 0 | 0 | 0 | 177,51 s |
| Hash/IDs adicionais, `phase3-new-final.xml` | 28 | 0 | 0 | 0 | 0 | 5,68 s |
| Completa intermediária, `phase3-all-tests.xml` | 571 | 0 | 0 | 0 | 0 | 196,96 s |
| Correção de tempos, `phase3-analysis-patch-tests.xml` | 29 | 0 | 0 | 0 | 0 | 9,49 s |
| Completa intermediária, `phase3-final-tests.xml` | 572 | 0 | 0 | 0 | 0 | 199,48 s |
| Reprodução da falha mitigada, `phase3-mitigated-before.xml` | 0 | 1 | 0 | 0 | 29 desmarcados | 0,27 s |
| Testes novos finais, `phase3-accepted-new.xml` | 30 | 0 | 0 | 0 | 0 | 8,61 s |
| Completa intermediária, `phase3-accepted-all.xml` | 573 | 0 | 0 | 0 | 0 | 200,99 s |
| Reprodução de vínculos, `phase3-identity-before.xml` | 0 | 3 | 0 | 0 | 29 desmarcados | 25,43 s |
| Verificador corrigido, `phase3-verifier-new.xml` | 32 | 0 | 0 | 0 | 0 | 23,97 s |
| Reprodução parcial, `phase3-partial-before.xml` | 1 | 2 | 0 | 0 | 32 desmarcados | 0,26 s |
| Novos finais, `phase3-release-new.xml` | 35 | 0 | 0 | 0 | 0 | 20,64 s |
| Completa final, `phase3-release-all.xml` | **578** | **0** | **0** | **0** | **0** | **210,64 s** |

Os oito testes existentes de navegador real executaram. Logs/JUnit locais em
`reports/phase3-*`; tempos JUnit incluem uma janela ligeiramente diferente.
Testes com fixtures não integram a campanha científica. As expectativas dos
testes antigos, classificadores, payloads, controles e laboratórios não foram
alteradas nesta fase. A regressão mitigada falhou antes da correção e passou depois.

Comandos finais:

```powershell
.\.venv-evaluation\Scripts\python.exe -m pytest -q tests/test_experimental_evaluation.py --junitxml=reports/phase3-release-new.xml
.\.venv-evaluation\Scripts\python.exe -m pytest -q --junitxml=reports/phase3-release-all.xml
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation verify docs/evidencias/fase3/05c7eb64-2f81-4ac6-bc83-9aa3048b8db5-dfde5155-4920-465b-bced-6b3ff7405a3e
.\.venv-evaluation\Scripts\python.exe -m pip check
git diff --check
```

Instalação em `.venv-evaluation`, com hashes/wheels; `pip check` sem conflitos.
Matplotlib 3.11.2/Agg compatível neste ambiente. `.venv` e `.venv-phase2` preservadas.
Auditoria: 165 relatórios verificados, 1.011 arquivos selados; nenhum campo proibido
não vazio encontrado nas evidências. Conferidos 38 arquivos protegidos e banco
original inalterados; portas dos laboratórios sem escutas. Reprodução das três
tabelas/oito figuras a partir do pacote público com HTTP bloqueado: 11/11 iguais.
Todas as 78 fontes pré-existentes inventariadas fora do avaliador e de seu teste
também foram comparadas e preservadas. Auditoria final em
`reports/phase3-release-audit.json`. Os três vínculos incompatíveis falharam antes
da correção; os casos parciais reproduziram duas falhas e um inconclusivo preservado.
Todos passaram no bloco final de 35 testes. Dos processos científicos, 159 saíram
com código 0 e seis com 1 (S12/S13 inconclusivos); nenhum teve erro inesperado.

Arquivos novos: `experiments/evaluation/` (coletor, catálogo, extrator, métricas,
heurística, análise/exportação/verificação, gerador acadêmico e lock),
`tests/test_experimental_evaluation.py`, protocolo, este acompanhamento,
relatório e `docs/evidencias/fase3/`. README e índice de testes recebem links.
Originais privados e clone ficam ignorados pelo Git em `reports/evaluation/`.

Limitações observadas: suspeitas em XSS seguro, abstenções SQLi diagnósticas,
ausência de confirmação XSS estática/CSP e descoberta estreita no Juice Shop.
Repetibilidade 84/84 não equivale a correção nem a independência estatística.
O conjunto sintético, n=3 e ambiente único não sustentam precisão universal ou
causalidade isolada dos controles negativos. Detalhes e números completos:
[resultados](RESULTADOS_EXPERIMENTAIS.md), [protocolo](AVALIACAO_EXPERIMENTAL.md)
e [pacote selecionado](evidencias/fase3/README.md).
