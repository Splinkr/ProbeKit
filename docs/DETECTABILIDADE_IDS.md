> Este documento reproduz seções do **relatório técnico** do trabalho (`RELATORIO_TECNICO.docx`). Referências do tipo "Seção N" apontam para as seções do relatório.

# 8. Detectabilidade e transparência do tráfego

## 8.1 A observação do professor

O professor observou que o ProbeKit usa requisições HTTP convencionais. A observação pode ser lida de duas formas, e este relatório responde às duas: (a) como **limitação de cobertura** (só GET, sem POST, cabeçalhos ou autenticação; ver Seção 4.5), e (b) como **questão de detectabilidade** (o que um defensor enxerga quando o ProbeKit roda). Esta seção trata da segunda.

## 8.2 O perfil de tráfego real do ProbeKit

Para descrever o tráfego sem suposições, as 15 execuções de referência (Seção 9.3) passaram por um proxy de registro em loopback que gravou cada requisição (156 no total).

| Aspecto | Observado |
| --- | --- |
| Protocolo e método | HTTP/1.1, somente GET, biblioteca `requests`, sem redirecionamentos |
| `User-Agent` | `WebVulnScanner/0.2.0` em 156 de 156 requisições |
| Ritmo | intervalo mínimo de 0,2 s (cerca de 5 requisições por segundo); 10 requisições por parâmetro de SQLi |
| Assinatura de SQLi | aspa simples (`%27`) seguida de `AND` e de uma comparação entre parênteses, com números fixos 17 e 23: `...%27+AND+%2817%3D17%29+AND+%27%25%27+LIKE+%27%25` |
| Assinatura de XSS | marcador `WVX` + 24 caracteres hexadecimais + letra da sonda, e callback `globalThis.wvxss_<hex>` |
| Assinatura de exposição | caminhos de controle `/.probekit-missing-<24 hex>-<arquivo>` e os cinco caminhos do catálogo |

## 8.3 Uma decisão de projeto: transparência

O ProbeKit **não** tenta se disfarçar. Ele se identifica no `User-Agent`, usa um ritmo previsível e marcadores reconhecíveis, e não implementa as técnicas de evasão citadas na Aula 04 (fragmentação, *decoys*, falsificação de porta de origem). A escolha é coerente com o objetivo didático e com o escopo loopback: um scanner de ensino deve ser auditável e fácil de reconhecer. A consequência é que ele é **trivial de detectar**, o que é desejável para o defensor e útil para ensinar detecção.

## 8.4 Regras de detecção (estilo Aula 07) e verificação

A partir das requisições reais, foram escritas oito regras no estilo Snort/Suricata da Aula 07 (arquivo `experiments/ids/probekit.rules`, Apêndice B). O script `experiments/ids/check_rules.py` verifica quais regras casam com as requisições registradas, com um tráfego legítimo sintético e com o ataque clássico da Aula 07. É uma **simulação de casamento de conteúdo**, não o Suricata em si.

| Regra | Requisições do ProbeKit (156) | Tráfego legítimo (4) | Ataque clássico (2) |
| --- | ---: | ---: | ---: |
| `User-Agent: WebVulnScanner/` | 156 | 0 | 0 |
| SQLi: aspa + `AND` + comparação | 32 | 0 | 0 |
| SQLi: contexto `LIKE` | 24 | 0 | 0 |
| XSS: callback `globalThis.wvxss_` | 24 | 0 | 0 |
| XSS: marcador `WVX` | 42 | 0 | 0 |
| Exposição: caminho `.probekit-missing` | 8 | 0 | 0 |
| Exposição: arquivo sensível do catálogo | 8 | 0 | 0 |
| Exemplo da Aula 07 (`or 1=1`) | **0** | 0 | 1 |

Três lições. **Primeira:** a regra de exemplo da Aula 07 **não** detecta o ProbeKit (0 de 156), porque ele nunca envia a cadeia `or 1=1`; as sondas usam outras condições, e só regras escritas a partir do tráfego real casam. **Segunda:** a mesma regra detecta o ataque clássico no corpo de um POST (1 de 2), mas não quando a cadeia chega codificada na URL (`or+1%3D1`): uma assinatura sobre bytes brutos depende da codificação, o que reforça o aviso da Aula 07 sobre os limites de uma regra simples e sobre a necessidade de normalizar o conteúdo (por exemplo, usar o buffer decodificado do IDS). **Terceira:** regras específicas cobrem todas as 156 requisições sem nenhum alarme no tráfego legítimo sintético, mas identificam *essa ferramenta*, e não a **classe** de ataque; para a classe, regras mais genéricas (aspa, `AND`, comparação) trazem mais falsos positivos e exigem ajuste fino contínuo.

## 8.5 Execução no Suricata ou Snort

Para fechar a demonstração com o IDS de verdade, captura-se o tráfego do laboratório no Wireshark (filtro de captura `host 127.0.0.1 and port 8005`, como na Aula 07) e processa-se o arquivo de captura com o Suricata e as regras acima (procedimento no arquivo `docs/DETECTABILIDADE_IDS.md`). Resultado da execução: **[PREENCHER: alertas por `sid` registrados no `fast.log` do Suricata/Snort]**.

## 8.6 Resposta ao professor

As requisições são convencionais **por escolha**: a ferramenta é didática, segura e auditável, e não pretende ser furtiva. Isso tem duas consequências, ambas documentadas: limita a cobertura atual (só GET, ver roadmap na Seção 4.6) e faz com que o tráfego seja facilmente reconhecível por um IDS, o que foi demonstrado com regras derivadas do próprio tráfego.


## 8.7 Procedimento para executar as regras no Suricata (ou Snort)

Pré-requisitos: Wireshark com Npcap (no Windows, instale com a opção do adaptador de captura de loopback), Suricata instalado e o laboratório rodando (`python -m experiments.sqlite_control --port 8005`).

1. **Capturar o tráfego.** No Wireshark, escolha a interface de loopback (`Npcap Loopback Adapter` no Windows, `lo` no Linux) e use o filtro de captura da Aula 07: `host 127.0.0.1 and port 8005`.
2. **Gerar o tráfego do ProbeKit** diretamente contra o laboratório (porta 8005), por exemplo:
   ```
   python main.py "http://127.0.0.1:8005/general/json/vulnerable?term=apple&lang=en" --module sqli --parameter term
   python main.py "http://127.0.0.1:8005/xss/html/raw?q=demo" --module xss
   python main.py http://127.0.0.1:8005/ --module exposure --exposure-profiles config backup
   ```
3. **Parar a captura** e salvar como `captura-probekit.pcapng`. Para ver o conteúdo em texto claro, use *Follow TCP Stream* (Aula 07) e o filtro de exibição `http`.
4. **Rodar o Suricata sobre o arquivo de captura**, carregando somente as regras do ProbeKit:
   ```
   suricata -c <caminho>\suricata.yaml -r captura-probekit.pcapng -S experiments/ids/probekit.rules -l logs-suricata
   ```
   No Snort 3 o equivalente é `snort -c snort.lua -R experiments/ids/probekit.rules -r captura-probekit.pcapng -A alert_fast` (confira a sintaxe da sua versão).
5. **Ler os alertas** em `logs-suricata/fast.log` (e `eve.json`) e contar por `sid`. Compare com a tabela da Seção 8.4: a regra 1000201 (User-Agent) deve casar todas as requisições do ProbeKit; a 1000001 (exemplo da Aula 07) não deve casar nenhuma.
6. **Registrar** no relatório (Seção 8.5) os alertas obtidos e eventuais diferenças em relação à simulação (`experiments/ids/check_rules.py`), explicando-as. Por exemplo, o Suricata pode agrupar ou reordenar segmentos TCP, e um buffer decodificado (`http.uri`) exige trocar o conteúdo das regras pelas formas decodificadas.

**Tarefa da Aula 07 (opcional):** rode também a regra de exemplo da aula contra uma requisição de login do Juice Shop com o payload de SQL Injection no corpo, e compare com o resultado do ProbeKit.
