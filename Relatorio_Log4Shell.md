# Análise da falha Log4Shell (CVE-2021-44228)

> **Trabalho 2 – Análise de Falhas Famosas de Segurança**  
> **Disciplina:** [preencher]  
> **Integrantes:** [preencher – mínimo 3 e máximo 5]  
> **Professor(a):** [preencher]  
> **Data:** [preencher]

## 1. Contextualização do caso

Log4Shell é o nome dado à vulnerabilidade **CVE-2021-44228**, encontrada no Apache Log4j 2, uma biblioteca Java de código aberto usada para registrar mensagens de log. O componente diretamente afetado é o `log4j-core`; aplicações que incluem somente `log4j-api`, sem o núcleo, não são afetadas por essa falha específica. Como o Log4j estava incorporado direta ou indiretamente em muitos produtos Java, a exposição não se limitava a um único fabricante ou serviço: cada organização precisava descobrir se seus sistemas e dependências incluíam uma versão vulnerável.

A falha foi divulgada publicamente em **9 de dezembro de 2021** e recebeu severidade máxima, **CVSS 3.1: 10,0**. O NVD descreve versões vulneráveis a partir de Log4j 2.0-beta9 e antes das versões de correção correspondentes; para as linhas mais usadas à época, isso incluía versões anteriores a 2.15.0 (Java 8 ou posterior). A Apache também publicou correções para linhas antigas compatíveis com Java 6 e Java 7. [Apache Logging Services – CVE-2021-44228](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228) · [NVD – CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

## 2. Descrição do problema

A vulnerabilidade permitia que um atacante remoto, em determinadas aplicações e configurações, provocasse **execução remota de código (RCE)** no processo Java que usava Log4j. O ataque podia começar com uma requisição ou outro dado controlado pelo atacante — por exemplo, um cabeçalho HTTP, parâmetro de URL, nome de usuário ou texto de chat — que a aplicação registrasse no log.

O impacto imediato podia ser a conexão do servidor vulnerável a uma infraestrutura externa controlada pelo atacante e, em cenários exploráveis, a execução de código com as permissões do processo da aplicação. Isso transformava uma função de registro de eventos em um possível ponto de entrada para comprometer o servidor.

## 3. Consequências

O risco dependia da exposição e das permissões do sistema atingido. Um servidor comprometido poderia permitir:

- leitura de dados acessíveis à aplicação, inclusive informações de clientes e segredos em variáveis de ambiente;
- alteração ou exclusão de dados e instalação de ferramentas maliciosas;
- interrupção do serviço, persistência no ambiente e movimentação para outros sistemas da rede;
- roubo de credenciais, extorsão ou implantação de ransomware;
- custos de resposta, indisponibilidade, investigação e recuperação, além de danos reputacionais.

A exploração foi observada em larga escala. A CISA e agências parceiras alertaram sobre varreduras e exploração ativa, e incluíram a vulnerabilidade em seu catálogo de falhas conhecidamente exploradas. A Cloudflare registrou tentativas ainda em **1º de dezembro de 2021**, antes da divulgação pública, e observou tentativas de exploração nove minutos depois da divulgação. Esses dados demonstram atividade de ataque, mas **não representam uma contagem mundial de vítimas**. Não há um total único e confiável de usuários ou organizações comprometidos atribuível à vulnerabilidade: Log4Shell era uma falha compartilhada por muitos produtos, e o resultado variava conforme cada implantação. [CISA – Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [Cloudflare – exploração antes da divulgação e padrões de ataque](https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/)

## 4. Como a falha ocorreu

### Linha do tempo resumida

| Data | Evento |
|---|---|
| 1º de dezembro de 2021 | A Cloudflare observou tentativas limitadas de teste da vulnerabilidade em tráfego monitorado. |
| 9 de dezembro de 2021 | A vulnerabilidade e uma prova de conceito foram divulgadas publicamente; tentativas de exploração começaram rapidamente. |
| 10 de dezembro de 2021 | A falha foi registrada no NVD como CVE-2021-44228, com severidade crítica. |
| 10–17 de dezembro de 2021 | A correção inicial foi seguida por novas correções para casos residuais e outras falhas relacionadas no Log4j. |
| Após a divulgação | Organizações tiveram de localizar Log4j em aplicações, produtos e dependências transitivas, aplicar correções dos fornecedores e investigar possível comprometimento. |

A data de 1º de dezembro é uma observação da telemetria da Cloudflare; não significa que todos os ataques tenham começado nesse dia. [Cloudflare](https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) · [CISA – alerta conjunto AA21-356A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)

### Vetor de ataque e sequência

O vetor principal era uma entrada de texto controlável remotamente que chegava a um sistema que a registrava com Log4j. A sequência típica era:

1. O atacante enviava uma requisição com uma cadeia de caracteres especialmente construída em um campo que seria registrado.
2. O aplicativo passava esse valor para Log4j.
3. Em versões afetadas, o mecanismo de *lookups* interpretava determinadas expressões dentro da mensagem, inclusive referências JNDI.
4. A referência podia fazer o servidor vulnerável consultar um endpoint externo, como um serviço LDAP controlado pelo atacante.
5. Em ambientes suscetíveis, essa interação podia resultar em carregamento e execução de código remoto no contexto do processo Java.

O padrão de ataque explorava uma referência JNDI a um endpoint externo (por exemplo, LDAP). O exemplo é conceitual; a exploração real dependia do produto e do ambiente. O atacante não precisava necessariamente estar autenticado na aplicação: a avaliação CVSS do NVD registra vetor de rede, baixa complexidade e ausência de privilégios requeridos. Ainda assim, a exploração dependia de condições do produto e do ambiente, como o uso de uma versão afetada e o processamento de conteúdo controlado pelo atacante. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) · [Apache Logging Services](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228)

## 5. Análise técnica da vulnerabilidade

**Tecnologias envolvidas:** Java, Apache Log4j 2, mecanismo de *lookups* do Log4j, JNDI (*Java Naming and Directory Interface*) e protocolos de diretório/rede como LDAP.

**Classificação:** injeção de expressão ou *lookup* em conteúdo de log, com potencial de execução remota de código. O identificador associado é **CWE-917**, uso impróprio de sintaxe de expressão em uma consulta ou comando. **CVE-2021-44228** identifica essa vulnerabilidade específica. O NVD atribui **CVSS 3.1 10,0 (Crítica)**, com vetor `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) · [MITRE CWE-917](https://cwe.mitre.org/data/definitions/917.html)

O defeito central estava na avaliação de referências JNDI presentes em mensagens ou parâmetros de log sem proteção suficiente contra endpoints controlados pelo atacante. A funcionalidade de *lookups*, criada para resolver valores em configurações e mensagens, fazia com que dados registrados pudessem ser tratados como instruções para buscar informações externas. Assim, o conteúdo nem sempre era tratado como texto inerte.

A falha ficou especialmente perigosa por combinar três fatores: o Log4j era uma dependência comum e muitas vezes indireta; aplicações frequentemente registravam entradas externas; e a exploração podia ocorrer pela rede sem autenticação em configurações suscetíveis. Encontrar o arquivo vulnerável também era difícil: ele poderia estar empacotado dentro de um JAR, WAR, contêiner ou produto de terceiros.

A primeira correção pública, Log4j 2.15.0, não cobria todos os cenários. A Apache documentou a **CVE-2021-45046** para configurações não padrão em que a correção era incompleta, além de outras falhas relacionadas descobertas durante a resposta. Portanto, instalar apenas a primeira correção não era suficiente para encerrar a investigação: era necessário seguir os avisos da Apache e dos fornecedores dos produtos afetados. [Apache Logging Services – avisos de segurança](https://logging.apache.org/log4j/2.x/security.html)

## 6. Medidas corretivas e preventivas

### Correção e resposta

- Identificar todas as ocorrências de Log4j, inclusive dependências transitivas e bibliotecas empacotadas em produtos de terceiros.
- Atualizar para uma versão corrigida e ainda suportada, conforme a orientação atual da Apache e do fornecedor da aplicação. A versão 2.15.0 foi a correção inicial para CVE-2021-44228, mas teve limitações; a escolha não deve parar nessa versão histórica. Para produtos de terceiros, aplicar a atualização publicada pelo fabricante.
- Se a atualização imediata não for possível, seguir a mitigação temporária indicada pelo fornecedor e pela Apache, restringir a saída de rede do servidor e reduzir o acesso ao serviço exposto. Mitigações temporárias não substituem a atualização.
- Verificar logs, conexões de saída, processos, arquivos e contas para identificar tentativas e possíveis sinais de comprometimento. Se houver indícios de execução, tratar o caso como incidente, conter o sistema, preservar evidências, trocar credenciais e avaliar a reconstrução a partir de uma base confiável.
- Repetir a verificação após a atualização e acompanhar avisos para CVEs relacionadas, como CVE-2021-45046 e CVE-2021-45105.

### Prevenção e lições aprendidas

- Manter inventário de dependências e gerar SBOMs para localizar componentes vulneráveis, inclusive os que chegam por dependências indiretas.
- Automatizar análise de dependências e alertas de CVE no desenvolvimento e na integração contínua.
- Manter um processo de resposta a vulnerabilidades com responsáveis, priorização por risco e capacidade de aplicar correções rapidamente.
- Restringir conexões de saída de servidores e executar aplicações com o menor privilégio possível, limitando o impacto caso uma dependência seja explorada.
- Tratar dados externos como dados, não como expressões executáveis; evitar recursos de interpretação dinâmica quando não forem necessários.
- Usar WAF e regras de detecção como camadas auxiliares. Elas podem reduzir tentativas, mas não substituem a correção: variações e ofuscação do payload podem contornar filtros.

## 7. Conclusão

Log4Shell mostrou como uma falha em uma biblioteca compartilhada pode se tornar um problema sistêmico quando o componente está presente em muitos produtos e interpreta conteúdo externo durante o registro de logs. O caso reforça que segurança depende também de conhecer as dependências, acompanhar avisos, corrigir rapidamente e verificar se a correção chegou a todas as aplicações e produtos afetados.

A principal lição é que a resposta não termina ao instalar uma atualização: é preciso identificar a extensão da exposição, investigar sinais de exploração, aplicar correções subsequentes quando necessário e reduzir o impacto potencial por meio de menor privilégio e segmentação de rede.

## Referências

1. Apache Logging Services. **CVE-2021-44228 – Apache Log4j Security**. https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44228
2. National Vulnerability Database (NIST). **CVE-2021-44228 Detail**. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
3. Cybersecurity and Infrastructure Security Agency (CISA). **Mitigating Log4Shell and Other Log4j-Related Vulnerabilities (AA21-356A)**. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
4. CISA. **Known Exploited Vulnerabilities Catalog**. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
5. Cloudflare. **Exploitation of Log4j CVE-2021-44228 before public disclosure and evolution of evasion and exfiltration**. https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/
6. MITRE. **CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement**. https://cwe.mitre.org/data/definitions/917.html

---

*Observação para apresentação: o enunciado sugere 10–15 minutos e a participação de todos os integrantes. O grupo pode dividir as seções entre os apresentadores e usar o fluxo técnico e a linha do tempo como apoio visual.*
