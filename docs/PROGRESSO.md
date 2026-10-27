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

Os módulos SQLi, XSS e exposição de arquivos pertencem às próximas etapas.
Diferenças entre respostas não confirmam vulnerabilidades.
