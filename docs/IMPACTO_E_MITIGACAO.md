> Este documento reproduz seções do **relatório técnico** do trabalho (`RELATORIO_TECNICO.docx`). Referências do tipo "Seção N" apontam para as seções do relatório.

# 6. Impacto e consequências

## 6.1 O que foi demonstrado e o que poderia ocorrer em um sistema real

Nos laboratórios o impacto real é nulo: os dados são fictícios e o banco do laboratório opera em modo somente leitura. A tabela separa o que o ProbeKit **provou** do que a mesma falha **poderia causar** num sistema real, com base no material da Aula 06.

| Falha | O que o ProbeKit demonstrou | Impacto potencial em um sistema real | Princípios afetados | OWASP Top 10:2021 |
| --- | --- | --- | --- | --- |
| SQL Injection | alteração da lógica de uma consulta de leitura por condições injetadas; dados, credenciais e escrita **não** foram testados | leitura de dados além do pretendido, contorno de autenticação, alteração ou remoção de dados, indisponibilidade; em configurações permissivas, execução de comandos no servidor | confidencialidade, integridade e disponibilidade | A03 Injection |
| XSS refletido | execução de um callback JavaScript inofensivo no documento da página (replay em navegador isolado); nenhum dado privado acessado | roubo de cookie ou token e sequestro de sessão, captura de teclas, redirecionamento para phishing e ações realizadas "como" a vítima dentro de uma origem confiável | confidencialidade e integridade | A03 Injection |
| Exposição de arquivos | acesso HTTP a arquivo com estrutura de configuração, backup SQL ou referência Git; validade dos segredos **não** avaliada | vazamento de credenciais de banco e APIs, de dados em backups e de código-fonte ou histórico (`.git`), que facilitam ataques posteriores | confidencialidade, e integridade e disponibilidade se as credenciais forem válidas | A05 Security Misconfiguration |

## 6.2 Severidade

O ProbeKit não calcula severidade: o CVSS (Aula 05) depende de vetor de ataque, complexidade, privilégios, interação do usuário e impacto sobre C, I e A, e esses fatores só existem no contexto de uma aplicação real. Como orientação qualitativa: uma SQLi em rota pública, sem autenticação e com acesso a dados sensíveis tende a cair nas faixas alta ou crítica; o XSS refletido exige interação da vítima (clicar num link) e costuma ficar entre média e alta conforme o que a sessão expõe; um `.env` exposto vale mais ou menos conforme as credenciais ainda funcionem, o que o ProbeKit deliberadamente não verifica.

## 6.3 Cenário encadeado (didático)

As três falhas se combinam. Um arquivo de configuração exposto (reconhecimento, fase 1 da Cyber Kill Chain, Aula 02) pode revelar credenciais e tecnologias; uma SQLi numa rota pública (técnica T1190, *Exploit Public-Facing Application*) permite ler dados pela própria aplicação; e um XSS refletido permite capturar a sessão de um usuário privilegiado, que então age com credenciais válidas (T1078). O dano total supera o de cada falha isolada, o que justifica corrigir todas, e não apenas a mais grave.

## 6.4 Limites desta análise

O ProbeKit comprova **que** uma falha é explorável no laboratório; ele não mede o valor dos dados, a validade dos segredos nem a probabilidade de exploração. Essas medidas exigem o contexto do sistema real e devem ser feitas por quem o opera, com autorização.


# 7. Medidas de mitigação

## 7.1 Mitigação por tipo de falha

| Falha | Mitigação primária | Camadas adicionais | Evidência no laboratório |
| --- | --- | --- | --- |
| SQL Injection | consultas parametrizadas (*prepared statements*), que separam código SQL de dado | ORM configurado, validação por lista de permissão (nunca a única), privilégio mínimo da conta do banco, não expor erros SQL ao cliente, WAF como defesa em profundidade | as rotas parametrizadas ficaram `not_detected` em 18 de 18 casos, e as concatenadas, `confirmed` em 18 de 18 |
| XSS refletido | codificação de saída contextual (HTML, atributo, JavaScript, URL) | frameworks que escapam por padrão, evitar `innerHTML`, Content Security Policy, cookie de sessão `HttpOnly` | rotas com escape ficaram `reflected_safe` ou `not_detected` (15 de 15 negativos decididos); com CSP, os 3 replays não observaram execução |
| Exposição de arquivos | não publicar arquivos sensíveis no diretório servido | bloquear no servidor web padrões como arquivos ocultos, `.git`, `*.sql` e `*.bak`; segredos fora do código (variáveis de ambiente ou gerenciador de segredos); **rotacionar** qualquer segredo que tenha sido exposto | caminhos bloqueados (401, 403, 404) ou sem estrutura sensível: 54 de 54 negativos na matriz principal e 15 de 15 nos diagnósticos |

## 7.2 A mitigação aplicada nos próprios laboratórios

O laboratório SQLite mostra a diferença em duas linhas. A versão vulnerável **concatena** o termo na consulta; a segura usa **parâmetros vinculados**:

```
# vulnerável (concatenação)
f"SELECT * FROM Products WHERE ((name LIKE '%{term}%' OR description LIKE '%{term}%') AND deletedAt IS NULL) ORDER BY name"

# seguro (bindings)
"SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL) ORDER BY name", (f"%{term}%", f"%{term}%")
```

Com a segunda forma, a aspa e as condições enviadas pelo ProbeKit viram apenas texto da busca, e as respostas das sondas booleanas deixam de se distinguir dos controles; por isso o resultado é `not_detected`. No XSS, a versão segura passa a saída por `html.escape` antes de devolvê-la. Esses pares vulnerável e seguro são a **prova empírica** de que a mitigação funciona contra as sondas do ProbeKit.

## 7.3 Ressalvas

`not_detected` não prova ausência de vulnerabilidade: significa que o plano executado não demonstrou a falha. Nos laboratórios o gabarito é conhecido, e por isso a leitura é válida; em uma aplicação real, a mitigação deve ser verificada também por revisão de código e por outras ferramentas (Seção 9). O caso X06, em que o JavaScript escapado corretamente continua `suspected`, é um exemplo de limitação do detector, e não de falha da mitigação.

## 7.4 Mitigação no processo e papel da detecção

Corrigir o código é prevenção; detectar tentativas é complementar. O ProbeKit pode ser executado como teste de regressão local após cada correção, e o tráfego dele (e de ataques reais parecidos) pode ser reconhecido por um IDS, como mostra a Seção 8. Como em toda defesa em camadas (Aula 07), nenhuma camada basta sozinha.
