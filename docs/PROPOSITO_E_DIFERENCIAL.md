> Este documento reproduz seções do **relatório técnico** do trabalho (`RELATORIO_TECNICO.docx`). Referências do tipo "Seção N" apontam para as seções do relatório.

# 1. Introdução e propósito

## 1.1 O problema

Ferramentas de varredura automática produzem listas de achados que, em geral, exigem triagem humana: um item pode ser prova, indício ou ruído, e a saída nem sempre deixa claro qual dos três. A Aula 03 já separa o *vulnerability scan* (varredura superficial, que lista vulnerabilidades conhecidas) do pentest (que explora e mede o impacto real), e a Aula 07 mostra o mesmo problema visto da defesa: uma regra simples demais gera falsos positivos e, quando o analista passa a ignorá-la, a detecção se perde. Quando um resultado "positivo" não carrega a evidência que o justifica, o relatório perde credibilidade.

## 1.2 A proposta do ProbeKit

O ProbeKit é um scanner acadêmico de aplicações web locais, desenvolvido para a disciplina SIN 451 (UFV). Em vez de responder apenas "vulnerável" ou "não vulnerável", ele responde a três perguntas: **o que foi provado, com qual evidência e o que não foi possível concluir**. Para isso, cada alvo recebe uma de cinco classificações (`confirmed`, `suspected`, `inconclusive`, `not_detected` e, em XSS, `reflected_safe`), obtida por comparação diferencial entre respostas de referência, sondas de ataque e controles negativos.

Ele cobre três tipos de falha, atendendo ao requisito do enunciado de explorar três tipos distintos:

1. **SQL Injection** em parâmetros GET (condições booleanas e erro SQL diferencial);
2. **Cross-Site Scripting refletido**, com confirmação opcional de execução em navegador real;
3. **Exposição de arquivos sensíveis** (`.env`, `config.ini`, `backup.sql`, `config.ini.bak`, `.git/HEAD`), com controles de caminhos inexistentes.

## 1.3 Utilidade e público

- **Ensino.** Os laboratórios locais têm gabarito conhecido (versões vulnerável e segura de cada caso), de modo que o estudante vê a ferramenta acertar, abster-se e errar, e entende por que. As evidências são reprodutíveis e verificáveis por hash.
- **Triagem local de aplicações em desenvolvimento.** Pode ser usado como teste rápido de regressão contra a própria aplicação rodando em loopback, antes de uma análise mais profunda com outras ferramentas.
- **Experimentação.** O pacote de avaliação (165 execuções, 1.011 arquivos selados) permite estudar o efeito de critérios diferenciais e de abstenção sobre falsos positivos.

## 1.4 O que o ProbeKit não é

O ProbeKit não pretende substituir sqlmap, OWASP ZAP ou Burp Suite. Ele só envia requisições GET, não cobre POST, JSON, cabeçalhos, cookies ou autenticação, não extrai dados de bancos e não executa JavaScript na descoberta. O escopo é exclusivamente loopback: não existe opção para liberar alvos externos. Essas restrições são decisões de projeto, adequadas a uma ferramenta didática que deve ser segura por construção (a Aula 03 lembra que testar sem autorização é crime, Lei 12.737/2012).

## 1.5 Diferencial

| Característica | Como aparece no ProbeKit |
| --- | --- |
| Afirmação condicionada à evidência | `confirmed` só ocorre quando **todos** os critérios do módulo são satisfeitos |
| Controles negativos embutidos | aspas escapadas e controle literal (SQLi); marcador ausente nos controles (XSS); caminhos inexistentes (exposição) |
| Abstenção explícita | `suspected` e `inconclusive` em vez de forçar sim/não; abstenção nunca é contada como acerto |
| Evidência reprodutível e segura | relatório JSON com manifesto e hashes; corpos, cookies e valores encontrados não são gravados |
| Escopo seguro por construção | somente loopback, somente GET, sem redirecionamentos, orçamento de requisições |

O efeito prático desse desenho foi medido: numa heurística simples usada como comparação (Seção 9.2), o critério "mudou em relação à primeira resposta" produziu, nos casos seguros da matriz principal, 39 falsos positivos em exposição, 18 em SQLi e 15 em cada condição de XSS, contra nenhum falso positivo confirmado do ProbeKit sobre a mesma evidência.
