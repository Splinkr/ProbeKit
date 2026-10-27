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
