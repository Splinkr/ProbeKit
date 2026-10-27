# Preparação para publicação e avaliação

O ProbeKit é executado a partir da raiz do código com `python main.py`.
Não há pacote PyPI ou instalador `pip install .`. Os arquivos de requisitos
instalam suas dependências. A instalação comum e os exemplos estão no
[README](../README.md); o [roteiro curto](DEMONSTRACAO.md) usa somente o
laboratório SQLite fornecido, Node/navegador opcionais e dados fictícios.

## Dependências e reprodução

`requirements.txt` fixa Requests 2.32.5, única dependência Python direta de
execução. `requirements-dev.txt` inclui esse arquivo e fixa pytest 8.4.2.
SQLite, parser HTML e CLI usam a biblioteca padrão. O helper XSS usa apenas
módulos nativos do Node.js 24 e um Edge/Chrome previamente instalado.
Não foram adicionadas dependências nesta etapa.

As dependências transitivas são resolvidas pelo pip e não têm lock completo
no repositório. A instalação é reproduzível pelo procedimento documentado;
isso não garante identidade binária de todas as dependências em qualquer
data/plataforma. O ambiente efetivamente avaliado deve ser registrado com
`pip list`, `pip check`, versão do Python, Node e navegador.

Para avaliar uma cópia limpa dos arquivos versionados, sem copiar `.venv`,
`lab`, caches ou relatórios locais, use o PowerShell na raiz do repositório:

```powershell
$taskCheck = Join-Path (Get-Location).Path ('.tools\publication-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $taskCheck | Out-Null
$taskArchive = Join-Path $taskCheck 'probekit.zip'
$taskSource = Join-Path $taskCheck 'source copy'
git archive HEAD --format=zip --output=$taskArchive
Expand-Archive -LiteralPath $taskArchive -DestinationPath $taskSource
py -3.13 -m venv (Join-Path $taskSource '.venv')
Push-Location -LiteralPath $taskSource
try {
    .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
    .\.venv\Scripts\python.exe -m pip check
    .\.venv\Scripts\python.exe main.py --help
    .\.venv\Scripts\python.exe main.py discover --help
    .\.venv\Scripts\python.exe main.py scan --help
    .\.venv\Scripts\python.exe -m pytest -q --junitxml=reports/publication-tests.xml
} finally {
    Pop-Location
}
```

Se não houver launcher `py`, use o caminho de um Python 3.13 instalado para
criar a venv. O nome `source copy` inclui espaço de propósito. Não é necessário
apagar a cópia ao final; ela fica em `.tools/`, fora do Git. O arquivo ZIP
contém o estado de HEAD, portanto faça os commits desejados antes de criá-lo.
Na avaliação desta etapa, os wheels foram obtidos com `pip download` e a
instalação isolada usou `--no-index --find-links` sobre esses mesmos wheels.
Isso impede que o teste da instalação dependa de pacotes do ambiente original.

## Arquivos e metadados compartilhados

`.gitignore` exclui ambientes virtuais, ferramentas e laboratório instalados,
dependências Node, caches Python/pytest/análise, build/dist, logs, PIDs,
temporários/checkpoints temporários e arquivos usuais de segredos/chaves.
`reports/` é local; a exceção é `.gitkeep`. Arquivos `.env.example` podem ser
versionados se contiverem apenas exemplos fictícios revisados.

As evidências de `docs/evidencias/` são parte intencional da avaliação.
Não foram apagadas ou substituídas na preparação. Incluem controles negativos
e tentativas históricas incompletas, explicitamente identificadas. XMLs JUnit
históricos podem conter nome de máquina e horários locais; os relatórios
também incluem URLs, payloads e cabeçalhos técnicos de resposta. São metadados
dos laboratórios, não corpos de arquivo ou credenciais reais.

Exposure serializa somente uma lista permitida de metadados e indicadores,
sem chaves reais, valores ou trechos dos artefatos. Os demais modos preservam
mais metadados para reprodução. Antes de versionar uma nova evidência, revise
URLs, query strings, nomes de máquina, caminhos locais e cabeçalhos conforme
o ambiente. Não use valores privados nas URLs. Ignore patterns e buscas por
tokens conhecidos não garantem ausência de qualquer segredo.

Comandos úteis de revisão:

```powershell
git status --short
git ls-files
git diff --check
git ls-files .venv .tools reports lab
```

No último comando, os arquivos esperados são apenas `reports/.gitkeep` e
`lab/README.md`. A lista de arquivos rastreados, e não só a árvore local,
determina o que será incluído no arquivo de publicação. Se algum segredo real
for identificado, ignorá-lo não o remove do histórico; a correção exige uma
ação específica. Esta revisão não detectou credenciais reais nos padrões
verificados e não é uma auditoria completa de histórico ou dependências.

## Pendências e limites da entrega

- O responsável ainda precisa escolher uma licença: não existe `LICENSE` no repositório. Nenhum termo de reutilização foi inventado nesta etapa.
- A validação se concentra em Windows 11, Python 3.13 e Node.js 24. Outras versões/plataformas não foram certificadas.
- A confirmação XSS depende da disponibilidade e das políticas do navegador local. Sem prova suficiente, o resultado continua suspeito.
- O bootstrap com downloads de Python/uv e a reinstalação do Juice Shop são alternativas históricas; não são necessários para a instalação limpa com Python disponível.
- Não há cobertura universal nem medição ampla de precisão. Consulte os limites específicos dos módulos no [README](../README.md).
