# ProbeKit — protocolo PK-F3 v1.0.0

Registro anterior à coleta formal. Produto avaliado: ProbeKit 0.2.0 sobre HEAD
`2026e83`, com alterações locais da Fase 2 preservadas. O estado exato será fixado
por inventário SHA-256 de código, laboratórios, avaliador, testes e configurações.
Cada campanha guardará cópias imutáveis deste protocolo e do catálogo versionado.

## Objetivos e hipóteses

Avaliar classificação, abstenções, cobertura e repetibilidade, sem exigir resultados
favoráveis. H1: casos estáveis suportados permitem distinguir referências vulneráveis
e seguras. H2: os critérios completos podem reduzir falsos positivos em comparação
com diferenças HTTP simples; a comparação não isola causalmente só os controles.
H3: descoberta HTML estática tem cobertura limitada sobre uma SPA. H4: resultados
estáveis se repetem, enquanto diagnósticos podem aumentar suspeitas/inconclusividade.
Há conhecimento histórico dos testes; não se trata de estudo cego ou amostra externa.

## Gabarito e casos

`experiments/evaluation/cases.json`, versão 1.0.0, contém IDs, unidades, contexto,
perfil, orçamento e gabarito `vulnerable`, `safe` ou `mitigated`, com fonte, símbolo
descrito e SHA-256. O gabarito provém de consultas concatenadas/bindings, escapes,
tipos MIME/nosniff, CSP e definição dos artefatos fictícios. Não é copiado dos
outcomes esperados nos scripts históricos, nem inferido da saída do scanner.

- S01–S14: legado; JSON/HTML/texto; LIKE/quoted; múltiplos parâmetros; instabilidade;
  erro; contexto incompatível. `lang` é unidade segura independente da busca.
- X01–X10: HTML/atributo/script sem escape, versões escapadas, JSON/texto, saúde sem
  reflexão e CSP. Duas condições: estática e navegador solicitado.
- E01–E18: exposto, raiz mista, bloqueado, inexistente, fallback e erro, com os perfis
  config/backup/repository. Documentação pública é negativa, mesmo com HTTP 200.
- I01: integração controlada; J01: descoberta integrada do Juice Shop; J02: SQLi em
  URL fornecida manualmente. Esses grupos não duplicam a matriz direta principal.

Principal: casos estáveis suportados. Diagnóstico: S12–S14 e E16–E18. Mitigado:
X10/CSP, fora da matriz binária. Aplicação/integração: I01/J01/J02 separados.
São 52 configurações diretas, 156 execuções e 195 unidades-repetições. Mais três
I01 e seis Juice Shop: total de 165 execuções planejadas, três rodadas em ordem fixa.

## Ambiente e limites

Windows x64/Python 3.13.9, Requests 2.34.2 e dependências dos locks da Fase 2.
Node 24.x e Edge local para replay. Versões efetivas, hashes dos locks e do código
serão guardados antes da coleta. Gráficos: Matplotlib 3.11.2/Agg em venv separada.
Não modificar ambientes existentes. Não atualizar detector, payload ou laboratório.

samples=2; intervalo 0,2 s; timeout 5 s; deadline 15 s; corpo individual 1 MiB;
1000 URLs, 2000 reservas de candidatos, URL 8192 bytes, metadados 8 MiB e corpos
acumulados 32 MiB. SQLi/XSS: 10 GET por unidade (20 no SQLi múltiplo). Exposure:
8/8/4 para config/backup/repository. Integrados: profundidade 2, 20 páginas, 100 GET.
Máximo planejado: 2040 GET do scanner. Testes e pré-verificações são separados.

Novo ControlServer original por execução, loopback efêmero e base original somente
leitura. Verificar manifestos da base antes/depois sem HTTP adicional. Juice Shop
20.3.0: clone privado do ZIP SHA-256
`a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57`, sem usar o banco
atual. Reusar Node/preloader loopback, porta 3000, verificar PID/escuta/versão e
aguardar até 120 s. Reiniciar somente o clone entre rodadas: o laboratório faz sua
inicialização normal. J01 usa / e três módulos, sem navegador; J02 usa a busca
manual q=apple/contexto like. Não trocar referência se o resultado for desfavorável.

## Extração e fórmulas

Uma linha por evaluation_id/case_id/condition/repetition/unit_id. Contar resultados
individuais de parâmetros/arquivos, nunca agregado, achado ou checkpoint duplicado.
Confirmado: TP em vulnerável, FP em seguro. Negativo: not_detected (e reflected_safe
somente em XSS), dando TN/FN conforme gabarito. Suspected e inconclusive separados.
Sem avaliação utilizável: not_evaluated com motivo. Coleta incompleta não apaga uma
avaliação explicitamente inconclusiva ou uma confirmação anterior.

Precisão=TP/(TP+FP); recall=TP/(TP+FN); especificidade=TN/(TN+FP);
FPR=FP/(FP+TN); cobertura=avaliações disponíveis/planejadas; inconclusividade e
suspeitas=respectivas quantidades/avaliações disponíveis; rendimento de confirmação
=TP/vulneráveis planejados. Denominador zero: null com motivo, sem 0%/100% inventado.
Exibir numeradores/denominadores e contagens por verdade/outcome, detector, condição
e estrato. Não agregar condições correlacionadas em uma precisão universal.

## Comparação B pré-definida

Usar a primeira referência legítima (baseline_1/reference_1) da unidade e comparar
com as outras respostas coletadas pela tupla status/tamanho/SHA-256 bruto do corpo.
Qualquer diferença: positive; nenhuma diferença com evidência completa: negative;
evidência parcial/insuficiente: inconclusive. A função não recebe URLs, nome do caso,
gabarito nem assessment. Positivo B é predição heurística, não confirmação real.
Não executar sondas diferentes nem replay adicional para essa comparação.

## Repetibilidade, integridade e privacidade

Não descartar resultados desfavoráveis nem refazer automaticamente execuções.
Ausência do navegador antes da condição browser: not_evaluated. Falha durante uma
execução: preservar outcome e evidência disponíveis. Falhas do Juice não bloqueiam
os laboratórios independentes. Registrar todas as ausências e motivos.
Calcular frequência modal/consistência das três repetições, mínimo, mediana, máximo
e desvio amostral de tempo/requisições quando n>=2. Sem inferência estatística/IC
com n=3. Tempos de processo são monotônicos, separados dos timestamps do scanner.

Originais restricted com ACL; read_verified_reports e identidades/hashes fixados
em registro experimental. Dados e análises não sobrescritos. Exportação shareable
offline, tabelas com campos permitidos e pacote público verificável. Nunca persistir
corpos HTTP, cookies/autenticação ou valores Exposure; nunca exportar stdout/stderr
bruto, payloads, marcadores, caminhos pessoais ou URLs operacionais.
Cobertura de Juice é inventário observado, não percentual de toda a aplicação.

Critérios/metodologia não mudam após resultados: nova metodologia requer protocolo
e campanha novos. Correções de extrator geram nova versão/análise, sem alterar raw.
Não realizar commit, push, tag ou publicação automática.
