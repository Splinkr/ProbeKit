# Etapas do MVP

## Etapa 1 — Preparação

- [ ] Verificar Python, Node.js, npm e Git.
- [ ] Preparar ambiente virtual Python.
- [x] Criar repositório e estrutura inicial.
- [ ] Instalar dependências Python.
- [ ] Instalar e executar OWASP Juice Shop com Node.js, sem Docker.
- [ ] Confirmar acesso em localhost:3000.

## Etapa 2 — Núcleo do scanner

- [ ] Criar CLI com argparse.
- [ ] Implementar cliente HTTP com requests, timeout e erros tratados.
- [ ] Implementar comparação de respostas HTTP.
- [ ] Criar modelos de achados e evidências.
- [ ] Restringir alvos a loopback por padrão.
- [ ] Executar referências e gerar relatório JSON.

Os módulos SQLi, XSS e exposição de arquivos pertencem às próximas etapas.
Diferenças entre respostas não confirmam vulnerabilidades.
