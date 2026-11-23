# Roteiro da apresentação

Apresentação breve (cerca de 12 minutos, 10 slides) com demonstração ao vivo. **Os slides de comparação (9) e de detectabilidade (8) só ficam completos depois de preencher os itens `[PREENCHER]` do relatório.** Os números abaixo vêm de `docs/RESULTADOS_EXPERIMENTAIS.md`.

| # | Slide | Tempo | O que dizer e mostrar |
| --- | --- | ---: | --- |
| 1 | Problema | 0:45 | Scanners listam achados que exigem triagem; um "positivo" sem evidência perde credibilidade (Aula 03). Pergunta do trabalho: dá para um scanner dizer **o que provou e o que não pôde concluir**? |
| 2 | Propósito e diferencial | 1:00 | Cinco classes (`confirmed`, `suspected`, `inconclusive`, `not_detected`, `reflected_safe`); controles negativos; abstenção; evidência com hash; escopo loopback. O que **não** é: substituto de sqlmap/ZAP. |
| 3 | Arquitetura e salvaguardas | 1:00 | Figura 1 (`docs/figuras/fig1_arquitetura.png`); GET only, sem redirecionamento, orçamento de requisições, sem gravar corpos. |
| 4 | Modelo de detecção | 1:30 | Figura 2; plano de sondas do SQLi (`samples + 8`: aspa, aspa escapada, controle literal, 2 pares booleanos, recuperação); critérios de cada módulo. |
| 5 | Demonstração ao vivo | 2:30 | Subir o laboratório; rodar o scan integrado dos três módulos; mostrar `confirmed` na rota vulnerável e `not_detected` na parametrizada; abrir `findings.json`. **Plano B:** capturas de tela e `reports/demo/three-modules.json` já gerado. |
| 6 | Resultados | 1:30 | Matriz principal: SQLi 18/18 e exposição 21/21 confirmados, 0 FP; XSS 9/9 só com navegador (0/9 sem). Mostrar **também** as abstenções: S12/S13 inconclusivos, S14 e X06 suspeitos, Juice Shop automático 0 parâmetros vs. manual 3/3. Sem omitir diagnósticos desfavoráveis. |
| 7 | Impacto e mitigação | 1:15 | Tabela das 3 falhas (C/I/A, OWASP A03/A05); mitigação primária de cada uma; par vulnerável/seguro do laboratório (concatenação vs. bindings) como prova. |
| 8 | Detectabilidade | 1:00 | Requisições convencionais **por escolha**; perfil do tráfego (UA `WebVulnScanner/0.2.0`, números 17/23, marcador `WVX`); regras estilo Aula 07 e a lição de que `or 1=1` não detecta o ProbeKit. |
| 9 | Comparação com sqlmap e ZAP | 1:15 | Tabela qualitativa + tabela empírica preenchida; heurística B (39/18/15/15 FP) como linha de base; o que cada ferramenta faz melhor. |
| 10 | Limites, evolução e conclusão | 1:00 | Limites (só GET, sem numérico/temporal/UNION, sem XSS armazenado/DOM); roadmap (POST/JSON, descoberta com JS, classificador estatístico); aprendizados. |

## Perguntas que o professor pode fazer

- **Qual a utilidade, se existem sqlmap e ZAP?** Ensino e triagem local com evidência explícita e abstenção; não pretende substituí-los. Ver slide 2 e a Seção 9.
- **Por que só requisições GET convencionais?** Escolha de projeto (segurança, auditabilidade, escopo loopback), com custo de cobertura; roadmap prevê POST, JSON e cabeçalhos. E é fácil de detectar, como mostra a Seção 8.
- **Qual o modelo de detecção e como evolui?** Regras diferenciais com controles e abstenção (Seção 4); evolução em curto, médio e longo prazo (Seção 4.6).
- **O que significa `not_detected`?** O plano executado não demonstrou a falha; **não** prova ausência de vulnerabilidade.
- **Por que 0 de 9 XSS sem navegador?** Sem prova de execução, a ferramenta só pode suspeitar; o replay no navegador promove a `confirmed`.
- **Por que X06 fica `suspected` se é seguro?** Limitação declarada do detector (JavaScript escapado em contexto `script`); não é confirmação, mas é uma abstenção que custa.
- **É seguro rodar?** Só aceita loopback, só GET, sem redirecionamentos, com orçamento de requisições; testar sistemas de terceiros sem autorização é crime (Lei 12.737/2012).
