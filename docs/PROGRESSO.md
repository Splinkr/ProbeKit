# Etapas do MVP

## Etapa 1 — Preparação

- [x] Verificar Python, Node.js, npm e Git.
- [x] Preparar ambiente virtual Python.
- [x] Criar repositório e estrutura inicial.
- [x] Instalar dependências Python.
- [x] Instalar e executar OWASP Juice Shop com Node.js, sem Docker.
- [x] Confirmar acesso em localhost:3000 (HTTP 200).

## Etapa 2 — Núcleo do scanner

- [x] Criar CLI com argparse.
- [x] Implementar cliente HTTP com requests, timeout e erros tratados.
- [x] Implementar comparação de respostas HTTP.
- [x] Criar modelos de achados e evidências.
- [x] Restringir alvos a loopback por padrão.
- [x] Executar referências e gerar relatório JSON.

## Etapa 3 — Primeiro módulo funcional

- [x] Selecionar `/rest/products/search?q=apple` no Juice Shop local.
- [x] Registrar referências e controles de sintaxe e texto.
- [x] Implementar dois pares booleanos somente de leitura.
- [x] Comparar HTTP e conjuntos de produtos para reduzir falsos positivos.
- [x] Classificar confirmado, suspeito, não detectado ou inconclusivo.
- [x] Validar manualmente o comportamento no alvo local.
- [x] Testar cenários vulneráveis e parametrizados com SQLite real.

## Etapas 4 e 5 — Relatório e demonstração do MVP

- [x] Registrar payloads, contagens, hashes, erros SQL e critérios no JSON.
- [x] Vincular achado às evidências e descrever impacto e mitigação.
- [x] Criar roteiro Windows 11 e script reproduzível de demonstração.
- [x] Preservar evidência real sem corpos HTTP ou segredos.
- [x] Diferenciar confirmação booleana de erro SQL isolado e coleta inconclusiva.

Roteiro: [DEMONSTRACAO_SQLI.md](DEMONSTRACAO_SQLI.md).
XSS, exposição de arquivos e descoberta automática permanecem fora desta etapa.

## Avaliação empírica — controle negativo

- [x] Criar servidor SQLite local com dados fictícios compartilhados.
- [x] Expor consultas equivalentes por concatenação e parametrização.
- [x] Usar o mesmo detector, sem modificar seus critérios ou payloads.
- [x] Executar três repetições por endpoint e preservar seis relatórios JSON.
- [x] Verificar equivalência das referências e integridade da base antes/depois.
- [x] Testar classificação pela implementação SQL, independente do nome da rota.
- [x] Revalidar o Juice Shop e os testes existentes.
- [x] Documentar resultados reais, métricas e limitações da amostra.

Resultado: 3 positivos confirmados, 3 negativos sem achados e zero falsos
positivos/negativos ou inconclusivos nesta rodada. São duas implementações
controladas; a conclusão não deve ser generalizada a qualquer aplicação.
Roteiro: [CONTROLE_NEGATIVO.md](CONTROLE_NEGATIVO.md).

## Reconstrução da suíte automatizada

- [x] Remover os testes anteriores e refazer as fixtures.
- [x] Recriar testes de escopo, HTTP, evidências, classificação e avaliação SQLite.
- [x] Executar a CLI em subprocessos e conferir os JSONs gerados.
- [x] Executar integralmente a nova suíte, com cache de coleta limpo.
- [x] Registrar o resultado real e manter os relatórios empíricos históricos.

Resultado: 123 aprovados, zero falhas, erros ou ignorados; produção preservada.
Detalhes: [TESTES.md](TESTES.md).

## Etapa 4 — Descoberta de endpoints

- [x] Inspecionar arquitetura e confirmar os testes existentes antes de modificar.
- [x] Implementar crawler HTML em largura na mesma origem loopback.
- [x] Extrair links, query strings, formulários GET e campos nomeados.
- [x] Normalizar URLs e deduplicar endpoints e navegação.
- [x] Registrar método, parâmetros e origem manual/automática no inventário JSON.
- [x] Aplicar limites configuráveis de profundidade, respostas e requisições.
- [x] Bloquear outros hosts/portas e manter todos os redirects desativados.
- [x] Adicionar `discover` preservando a CLI anterior e a confirmação SQLi.
- [x] Demonstrar em aplicação HTML local e executar os 164 testes.

Roteiro e evidências reais: [DESCOBERTA.md](DESCOBERTA.md).
APIs internas do Juice Shop não são presumidas como descobertas pelo HTML.

## Etapa 5 — Generalização SQLi

- [x] Inspecionar a arquitetura, CLI, testes, relatórios e experimentos existentes.
- [x] Separar planos, execução HTTP, características de resposta e classificação.
- [x] Selecionar parâmetros GET individuais ou todos, preservando os demais.
- [x] Suportar características de JSON, HTML e texto com controles conservadores.
- [x] Oferecer perfis textuais LIKE e igualdade entre aspas, documentando limites.
- [x] Registrar critérios, parâmetro, contexto, justificativa e limitações em JSON.
- [x] Manter orçamento global, escopo loopback e comandos anteriores.
- [x] Ampliar o SQLite com nomes, formatos, instabilidade e página de erro.
- [x] Executar 15 análises reais e preservar 15 relatórios e o resumo da rodada.
- [x] Reconfirmar o Juice Shop e executar integralmente os 196 testes.

Resultado da rodada: 16 avaliações de parâmetros; sete confirmed, seis
not_detected, duas inconclusive e uma suspected. São 160 requisições do
detector; a base SQLite permaneceu igual. Os controles seguros não foram
classificados como vulneráveis. Sem novas dependências, Docker ou XSS.
Roteiro, contextos suportados e evidências: [SQLI_GENERALIZADO.md](SQLI_GENERALIZADO.md).

## Etapa 6 — Integração da descoberta com SQLi

- [x] Inspecionar a arquitetura e executar os 196 testes anteriores antes de editar.
- [x] Adicionar `scan` preservando baseline, discover e SQLi direto.
- [x] Compartilhar cliente HTTP, orçamento, intervalo e IDs entre as duas fases.
- [x] Selecionar e deduplicar parâmetros com referência concreta e preservar os demais.
- [x] Manter os critérios SQLi, os perfis e o bloqueio de redirecionamentos.
- [x] Revalidar esquema, host e porta antes de cada GET da execução integrada.
- [x] Consolidar inventário, classificações, evidências, consumo, ignorados e limitações.
- [x] Persistir checkpoints atômicos e resultados de interrupções controladas.
- [x] Criar `/scan-lab` com links HTML para endpoints SQLite reais.
- [x] Demonstrar o fluxo completo e os limites de orçamento e profundidade.
- [x] Executar os 238 testes e verificar dependências.

Resultado real: seis endpoints inventariados, oito parâmetros analisados,
dois confirmed e seis not_detected; 85/100 requisições (5 de descoberta, 80 SQLi).
Com orçamento 25, uso exato de 25 e seis parâmetros ignorados por saldo.
Com profundidade zero, uma requisição e nenhuma sonda. Base fictícia inalterada.
Sem novas dependências, Docker, XSS ou acesso externo.
Roteiro e evidências: [SCAN_INTEGRADO.md](SCAN_INTEGRADO.md).

## Etapa 7 — XSS refletido

- [x] Inspecionar a arquitetura e executar os 238 testes anteriores antes de editar.
- [x] Criar módulo XSS independente sem alterar os arquivos do módulo SQLi.
- [x] Analisar marcadores exclusivos, contexto e escape com controles/referências.
- [x] Separar reflexão inerte, suspeita e execução confirmada.
- [x] Oferecer confirmação opcional por callback real em replay isolado com CSP.
- [x] Bloquear tráfego de página e usar perfil temporário sem dados do usuário.
- [x] Adicionar `--module xss` e `scan --modules sqli xss` com orçamento único.
- [x] Registrar evidências e limitações em relatórios individuais e consolidados.
- [x] Criar laboratório de HTML, atributos, script, JSON, texto e controles CSP.
- [x] Executar oito demonstrações reais, incluindo Juice Shop e limite 25.
- [x] Executar 286 testes, seis casos com navegador real, e verificar dependências.

Rodada XSS: 89/100 GETs, três confirmed, quatro reflected_safe e um suspected
por CSP. Fluxo misto: 75/100 GETs; SQLi e XSS confirmados em seus respectivos
controles vulneráveis. Oito relatórios, 239 GETs, oito sessões e 40 replays;
base fictícia inalterada. HTML/atributos escapados e JSON não foram confirmados.
O controle adicional de string JavaScript escapada permaneceu suspected sem
execução: falso positivo de suspeita documentado, sem ajuste artificial.
Roteiro, comandos e evidências: [XSS_REFLETIDO.md](XSS_REFLETIDO.md).

## Etapa 8 — Exposição de arquivos

- [x] Inspecionar arquitetura, executar os 286 testes anteriores e preservar SQLi/XSS.
- [x] Criar módulo independente exposure com catálogo fechado de cinco caminhos.
- [x] Selecionar perfis config, backup e repository em um diretório-base local.
- [x] Comparar referências repetidas e dois controles inexistentes por arquivo.
- [x] Analisar estrutura, MIME, HTML, documento público, erros e fallback.
- [x] Documentar critérios confirmed, suspected, inconclusive e not_detected.
- [x] Serializar somente metadados, contagens e indicadores fixos, sem valores/chaves/conteúdo.
- [x] Integrar CLI e scan com origem, IDs, orçamento e checkpoints compartilhados.
- [x] Ampliar o laboratório SQLite com artefatos fictícios e controles negativos.
- [x] Executar oito demonstrações completas, incluindo três módulos e regressão Juice Shop.
- [x] Corrigir bloqueio transitório de checkpoint no Windows, preservando evidências das tentativas anteriores.
- [x] Executar 344 testes e verificar dependências, sem novas instalações.

Fluxo completo: seis endpoints, oito avaliações de quatro parâmetros e quatro
arquivos; 92/100 GETs (6 descoberta, 86 análise); SQLi, XSS e dois arquivos
confirmed. Com limite 84, consumo 84 e dois arquivos ignorados por saldo.
Fallback HTML 200, erro personalizado, acesso bloqueado e documento público
não foram confirmados. Cinco formatos/caminhos fictícios confirmados no
controle positivo adicional. Dados SQLite inalterados e nenhum valor de
arquivo registrado nos JSONs. Limitações de cobertura e política de privacidade
documentadas; sem mudança dos critérios SQLi/XSS, Docker ou acesso externo.
Roteiro e evidências reais: [EXPOSICAO_ARQUIVOS.md](EXPOSICAO_ARQUIVOS.md).
