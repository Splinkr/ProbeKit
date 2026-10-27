# Laboratório local

Distribuição: `juice-shop-20.3.0_node24_win32_x64.zip`, publicada pelo projeto
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop/releases/tag/v20.3.0).

SHA-256 informado pela API de releases do GitHub:

```text
a25fc33b3b3565aae52381f63e6c9727790f67e8443ead02803a8eec7bdb7f57
```

O pacote oficial já contém as dependências e o frontend compilado. Não é
necessário compilar a aplicação com npm. A execução utiliza o Node.js 24.

Siga o [guia oficial de distribuição pré-compilada](https://pwning.owasp-juice.shop/companion-guide/local/part1/running.html).
Arquivos baixados, banco de dados e logs não são versionados.

Instalação e execução em PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/setup-juice-shop.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/start-juice-shop.ps1
```

A opção `-ExecutionPolicy Bypass` se aplica somente ao processo chamado.
Não altera a política global. Prepare o ambiente Python antes da instalação.
A extração usa `zipfile` para preservar os dois nomes Unicode que o `tar.exe`
nativo omite neste pacote.

O script de início carrega `scripts/loopback-only.cjs` antes da aplicação,
restringindo a escuta TCP a `127.0.0.1:3000`. O código da distribuição permanece
intacto. Com execução em primeiro plano, use Ctrl+C para encerrar.

Para segundo plano, acrescente `-Background`. O PID fica em
`lab/juice-shop.pid` e os logs em `lab/juice-shop.stdout.log` e
`lab/juice-shop.stderr.log`. Confirme o PID antes de encerrá-lo.

Os desafios opcionais de Alchemy/Web3 e LLM exigem serviços adicionais.
Eles não são necessários para as referências HTTP desta etapa.
