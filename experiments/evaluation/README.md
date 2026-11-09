# Avaliador PK-F3 1.0.0

Avalia ProbeKit 0.2.0 sem alterar núcleo, payloads, controles ou laboratórios.
Protocolo prévio: [AVALIACAO_EXPERIMENTAL.md](../../docs/AVALIACAO_EXPERIMENTAL.md).
Coletor/protocolo/catálogo/formato 1.0.0; derivação selecionada 1.0.3. As correções
de derivação preservam raw e geram outro analysis_id. O
[índice de evidências](../../docs/evidencias/fase3/README.md) identifica a análise
vigente e as substituídas, sem sobrescrever seus arquivos.

Ambiente Windows x64/Python 3.13.9. Preserve `.venv` e `.venv-phase2`:

```powershell
.\.venv-phase2\Scripts\python.exe -m venv .venv-evaluation
.\.venv-evaluation\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r experiments/evaluation/requirements.lock
.\.venv-evaluation\Scripts\python.exe -m pip check
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation prepare
```

`prepare` cria campanha UUID com ACL privada, agenda completa, catálogo/protocolo,
ambiente e hashes do código. Extrai/verifica um clone do ZIP aprovado, sem copiar
o banco original. A cópia tem 320 MiB de conteúdo/45 mil arquivos, mais overhead.
O comando imprime o diretório da campanha; use esse valor nos seguintes comandos:

```powershell
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation run reports/evaluation/EVALUATION_ID
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation analyze reports/evaluation/EVALUATION_ID
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation export reports/evaluation/EVALUATION_ID --analysis reports/evaluation/EVALUATION_ID/analyses/ANALYSIS_ID
.\.venv-evaluation\Scripts\python.exe -m experiments.evaluation.run_evaluation verify docs/evidencias/fase3/EVALUATION_ID-ANALYSIS_ID
```

Somente `run` acessa os alvos, exclusivamente loopback. Instalação de dependências
é separada. A porta 3000 deve estar livre; nenhum serviço alheio é encerrado.
Cada repetição Juice usa inicialização normal do clone, que recria seu próprio
banco. O servidor controlado é novo por execução. Browser ausente não é negativo.
Não editar código/catalogo/protocolo durante a coleta. Campanhas iniciadas não
podem ser sobrescritas ou repetidas automaticamente. Uma nova tentativa requer
outra campanha; resultados anteriores não são apagados.

`analyze`, `export` e `verify` são offline. Análises usam UUID novo e não alteram raw.
Originais restricted e runtime ficam em reports, ignorados pelo Git. Exportação
usa a projeção shareable existente. O pacote contém manifesto de hashes, evidências
verificáveis, tabelas, critérios e figuras, sem corpos, cookies, autenticação,
payloads, marcadores, caminhos pessoais ou URLs operacionais. O catálogo inclui
rotas relativas fictícias necessárias à reprodução, não endereços da execução.

A heurística B recebe somente observações HTTP e referências de requisição. O
gabarito está em cases.json, com fontes/hash/símbolos independentes da classificação.
Não usar o avaliador SQLi histórico para a matriz nova: aquele contabiliza suspeita
como positivo e segue outra definição. A comparação atual mantém abstenções.

Após exportar, o relatório acadêmico pode ser gerado a partir do pacote verificado:

```powershell
.\.venv-evaluation\Scripts\python.exe -c "from uuid import uuid4; from experiments.evaluation.academic import render; render('docs/evidencias/fase3/EVALUATION_ID-ANALYSIS_ID', output='reports/academic-'+str(uuid4())+'.md')"
```

O gerador produz a base tabular. A discussão interpretativa do relatório final
foi revisada com os casos observados; use saída separada para preservar essa revisão.

Para reproduzir as três tabelas e oito figuras **somente pelo pacote público**,
sem originais nem coleta, substitua o identificador abaixo e execute na raiz:

```powershell
@'
import csv
from uuid import uuid4
from experiments.evaluation.common import ROOT, load, digest
from experiments.evaluation.generate_report import verify, csv_file, figures
from experiments.evaluation.metrics import grouped
from scanner.http_client import HttpClient
def no_http(*args, **kwargs):
    raise AssertionError('Offline reproduction attempted HTTP')
HttpClient.get = no_http
package = ROOT / 'docs/evidencias/fase3/EVALUATION_ID-ANALYSIS_ID'
verify(package)
output = ROOT / 'reports/phase3-reproduction' / str(uuid4())
output.mkdir(parents=True)
rows = load(package / 'analysis/rows.json')
groups = grouped(rows)
matrices = [{**{k:g[k] for k in ('domain','module','condition','stratum')},
             'method':m, **g[m]['counts']} for g in groups for m in ('A','B')]
for name, data in [('results.csv', rows), ('comparison.csv', rows),
                   ('confusion-matrices.csv', matrices)]:
    with (package / 'analysis' / name).open(encoding='utf-8') as stream:
        columns = next(csv.reader(stream))
    csv_file(output / name, data, columns)
figures(output / 'figures', groups, rows)
for file in output.rglob('*'):
    if file.is_file():
        assert digest(file) == digest(package / 'analysis' / file.relative_to(output))
print(output)
'@ | .\.venv-evaluation\Scripts\python.exe -B -
```

Essa reprodução foi executada na campanha entregue: 11/11 arquivos idênticos
byte a byte no ambiente/lock registrados. Outra versão de renderizador pode
produzir bytes diferentes, mesmo com números iguais; confira primeiro os dados.

Não há commit, push, tag ou publicação automática. Hashes comprovam correspondência,
não autenticidade contra substituição integral dos arquivos. A suíte usa fixtures
separadas, que nunca entram como observações da campanha.
