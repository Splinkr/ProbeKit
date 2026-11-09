# ProbeKit — PK-F2 v1.0.1

Base: `2026e83`, árvore limpa, produto `0.1.0`. Data: 2026-11-09.
Objetivo: R03–R07, sem ampliar detecção, payloads ou destinos autorizados.
Controle: patch para revisão textual, minor para abordagem compatível, major para escopo/garantias.
Versões do produto são marcos de implementação; não são tags nem commits.

Plano aprovado: v1.0.0. Revisão de acompanhamento: v1.0.1, que consolida o registro
de implementação e validação, sem mudar escopo ou garantias. Mudanças de estado
e resultados são histórico de execução; alterações futuras de abordagem seguem
as regras de versionamento acima.

| Subfase | Escopo | Marco | Estado |
| --- | --- | --- | --- |
| F2.1 | R03: apresentação segura | 0.2.0-alpha.1 | Implementada; testes de apresentação aprovados |
| F2.2 | R05: gerações e manifesto | 0.2.0-alpha.2 | Implementada; falhas por estágio e concorrência aprovadas |
| F2.3 | R07: perfis e ACL | 0.2.0-alpha.3 | Implementada; sentinelas e permissões aprovadas |
| F2.4 | R06-A: dados e retenção | 0.2.0-alpha.4 | Implementada; limites e retenção aprovados |
| F2.5 | R06-B: transporte isolado | 0.2.0-alpha.5 | Implementada; deadline, cancelamento e reinício aprovados |
| F2.6 | R04: bootstrap e locks | 0.2.0-rc.1 | Implementada e validada, incluindo instalação isolada e regressão completa |
| Fechamento | Regressão e documentação | 0.2.0 | Concluído: 543 testes aprovados em cada ambiente |

## Sequência e gates

R03 → R05 → R07 → R06-A → R06-B → R04. Houve validação relacionada entre as entregas.
Os marcos alpha não foram gravados como releases intermediárias; o produto usa a versão candidata
durante a integração e só recebe `0.2.0` depois dos gates.

1. R03: `safe_text` e parser protegem controles C0/C1/DEL; Unicode legítimo e GET permanecem originais.
2. R05: UUID de execução/checkpoint; técnico e resumo têm schema 2.0; manifesto 1.0 é o ponto de publicação.
3. R07: `shareable` padrão, `restricted` explícito; HMAC por execução só em memória; ACL antes da escrita.
4. R06-A: limites de URL, candidatos, metadados e corpos; reservas anteriores à retenção; nenhum omitido vira negativo.
5. R06-B: worker Python reutilizável, IPC JSON limitado, deadline total de GET, encerramento antes de continuar.
6. R04: uv 0.9.7 verificado antes de extrair/executar; Requests 2.34.2; locks transitivos com hashes e wheels.

## Registro de testes

Os XML ficam em `reports/phase2-*.xml` (diretório ignorado pelo Git). Números são casos do pytest,
não somas de verificações internas. Uma falha de coleta não equivale a um caso funcional aprovado.

| Registro | Aprovados | Falhos | Erros | Ignorados | Tempo |
| --- | ---: | ---: | ---: | ---: | ---: |
| R03 antes: API ausente | 0 | 0 | 1 de coleta | 0 | 0,30 s |
| R03 e terminal | 15 | 0 | 0 | 0 | 1,00 s |
| R05 antes: leitor ausente | 0 | 0 | 1 de coleta | 0 | 0,27 s |
| R05 e checkpoints iniciais | 7 | 0 | 0 | 0 | 0,90 s |
| R07 antes de integrar política ao writer | 2 | 1 | 0 | 0 | 0,26 s |
| R07, R05 e checkpoints | 10 | 0 | 0 | 0 | 1,11 s |
| R06-A antes | 0 | 3 | 0 | 0 | 0,45 s |
| R06-A e relacionados, primeira rodada | 72 | 1 | 0 | 0 | 11,43 s |
| R06-B antes do isolamento | 0 | 2 | 0 | 0 | 21,77 s |
| R06-A/B iniciais | 5 | 0 | 0 | 0 | 2,94 s |
| R04 antes de exigir hashes nos requirements | 2 | 1 | 0 | 0 | 1,53 s |
| Primeira integração completa | 431 | 36 | 0 | 0 | 206,13 s |
| Relacionados após migração inicial | 184 | 9 | 0 | 0 | 67,52 s |
| Novos ampliados, primeira rodada | 62 | 0 | 0 | 0 | 7,12 s |
| Relacionados corrigidos | 95 | 0 | 0 | 0 | 27,77 s |
| Novos ampliados | 80 | 0 | 0 | 0 | 10,78 s |
| Segunda integração completa | 525 | 6 | 0 | 0 | 172,29 s |
| Contratos de schema/limites/apresentação corrigidos | 43 | 0 | 0 | 0 | 4,21 s |
| Gates na venv candidata | 122 | 0 | 0 | 0 | 18,57 s |
| Suíte completa da candidata | 531 | 0 | 0 | 0 | 181,17 s |
| Revisão de snapshots/privacidade | 86 | 0 | 0 | 0 | 18,15 s |
| Suíte no ambiente original, antes da revisão de alocação | 532 | 0 | 0 | 0 | 171,79 s |
| Planos extremos, antes da reserva antecipada | 0 | 3 | 0 | 0 | 0,46 s |
| Reserva de planos e regressões relacionadas | 123 | 0 | 0 | 0 | 31,07 s |
| Novos testes finais | 85 | 0 | 0 | 0 | 13,32 s |
| Revisão completa, ambiente original | 536 | 0 | 0 | 0 | 174,91 s |
| Revisão completa, locks | 536 | 0 | 0 | 0 | 175,42 s |
| Fronteira acima de um bloco, antes da correção | 0 | 2 | 0 | 0 | 1,13 s |
| Fronteiras, deadline, transporte e integridade | 67 | 0 | 0 | 0 | 12,98 s |
| Privacidade após revisão | 32 | 0 | 0 | 0 | 4,41 s |
| Novos testes com fronteiras | 87 | 0 | 0 | 0 | 13,75 s |
| Argumentos/perfil efetivo | 8 | 0 | 0 | 0 | 0,70 s |
| Integração completa, ambiente original | 539 | 0 | 0 | 0 | 193,60 s |
| Integração completa, locks | 539 | 0 | 0 | 0 | 194,61 s |
| Escritores legados sem mode, antes da proteção | 0 | 4 | 0 | 0 | 0,39 s |
| Escritores legados, privacidade e regressões | 88 | 0 | 0 | 0 | 33,87 s |
| Conjunto completo de testes novos | 92 | 0 | 0 | 0 | 17,01 s |
| Fechamento, ambiente original | 543 | 0 | 0 | 0 | 196,81 s |
| Fechamento, ambiente com locks | 543 | 0 | 0 | 0 | 196,30 s |

**Resultado final:** 451 casos anteriores + 92 novos = 543 casos por execução.
Zero não executados em ambas as suítes finais; os oito casos existentes de
navegador real executaram. Não somar as duas execuções como casos distintos.
JUnit: `reports/phase2-release-original.xml` e `reports/phase2-release-locked.xml`.
Todos os estados de R03–R07 foram fechados dentro das garantias documentadas;
R01/R02 continuam aprovados. `git diff --check` passou. HEAD segue `2026e83`,
sem conteúdo staged, commit, push ou tag; as alterações estão disponíveis para revisão.

As seis falhas da segunda integração eram expectativas de schema 1.0 em entradas legadas:
a projeção nova usa 2.0, preservando `collection_status=null` e a contagem das avaliações disponíveis.
As expectativas foram migradas com justificativa no teste. Os critérios de classificação não foram relaxados.

Nas rodadas seletivas `-k huge`, `-k over_one` e `-k legacy_payload`, ficaram fora
da seleção 16, 19 e 32 casos, respectivamente; esses casos foram executados nas
rodadas completas. As falhas de coleta iniciais não executaram os casos dos arquivos.
As rodadas completas não tiveram casos ignorados, desmarcados ou não executados.

## Decisões de implementação e limites

- Metadados usam reservas conservadoras e listas com orçamento. `metadata_bytes` mede o custo reservado
  dos dados controlados, não RSS nem tamanho exato do arquivo JSON final.
- `total_body_bytes` soma bytes descomprimidos observados e reservas após cancelamentos. Um bloco parcial
  pode se perder com o encerramento do worker; a reserva máxima de um bloco impede ignorar esse consumo
  ao reiniciar. Ambos os componentes são expostos separadamente.
- Para detectar ultrapassagem de corpo, pode ser lido um byte adicional ao teto; ele é contado e não retido.
- O worker anuncia prontidão antes do controle de intervalo. Inicialização do processo não é tempo de rede.
- A reserva de planos usa aritmética antes de materializar listas grandes. A validação SQLi
  monta só o plano mínimo; a geração efetivamente enviada mantém samples e payloads originais.
- A anonimização acontece na projeção; os classificadores recebem os valores originais.
- `InlineTransport` é uma fronteira injetada explicitamente apenas nos testes que simulam Requests no pai.
  CLI em subprocesso, transporte real e testes novos de deadline usam `ProcessTransport`.
- Não há coleta automática de gerações antigas. Aliases são independentes, e o manifesto não é assinatura digital.

Detalhes de formato, privacidade, reprodução, comandos e riscos: [FASE2_SEGURANCA.md](FASE2_SEGURANCA.md).

Sem commit, push, tag ou publicação automática.
