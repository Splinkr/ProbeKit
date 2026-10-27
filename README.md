# WebVuln Scanner

Ferramenta CLI em Python para o trabalho de SIN 451 — Segurança da Informação
(UFV). O desenvolvimento inicial cobre preparação e núcleo de requisições de
referência. Os módulos de detecção serão desenvolvidos posteriormente.

## Ambiente

Windows 11, Python 3.13 e Node.js 24. O laboratório usa OWASP Juice Shop 20.3.0
diretamente com Node.js, sem Docker. Instalações e relatórios locais ficam fora
do Git. Consulte [o progresso](docs/PROGRESSO.md).

Com Python disponível:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

O executável do ambiente pode ser chamado diretamente, sem ativação e sem
alterar a política de execução do PowerShell. Para npm, use `npm.cmd`.
