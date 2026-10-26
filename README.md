# Playbooker

**Resposta a incidentes (SOAR) em Python, num mundo simulado.** Recebe alertas das outras ferramentas, escolhe o **playbook** certo e executa a resposta (bloquear um IP, desativar uma conta, isolar um host, abrir um chamado),
com **simulação por padrão**, **aprovação humana**, **política de segurança** que nenhum playbook contorna, **desfazer** e **trilha de auditoria encadeada por hash**. Sem dependências externas.

> **Nada aqui toca a rede nem o sistema operacional.** As ações só alteram um arquivo JSON (o "mundo simulado") com bloqueios, contas, hosts e chamados. Um teste vigia o código-fonte: nenhum módulo de rede, nenhum programa externo, nenhum `eval`.

```bash
python app.py demo                          # percorre tudo com dados fictícios: simulação, aprovações, recusas, desfazer e auditoria
python app.py playbooks validate            # o que um revisor conferiria
python app.py playbooks test                # 19 testes dos 5 playbooks
python app.py world init                    # cria world.json (dados fictícios)
python app.py run samples/alerts.jsonl                    # SIMULAÇÃO: nada é gravado
python app.py run samples/alerts.jsonl --apply            # aplica no mundo simulado
python app.py approve R0001 bloquear --by ana             # aprovação humana
python app.py rollback R0001 --by ana --reason "falso positivo"
python app.py verify                        # confere a trilha de auditoria
```

## Por que isso importa

Automatizar resposta é perigoso: uma regra errada **bloqueia o cliente, derruba o servidor ou desativa a conta do diretor**. O que distingue um SOAR de um script que bloqueia IP é o que ele faz para **limitar o dano**:
raio de impacto, aprovação, recusas, desfazer e prova do que aconteceu. É isso que este projeto pratica.

## O modelo de segurança

| Risco | Defesa |
|---|---|
| A automação age sem ninguém ver | **Simulação por padrão** (`run` sem `--apply` não grava nada, nem o banco). Ações de risco **médio e alto** esperam **aprovação humana** |
| Uma pessoa só decide algo grave | Ação de **alto risco** pede **duas pessoas diferentes**. **Quem iniciou a execução não aprova** o próprio passo (separação de funções) |
| Um playbook com defeito derruba o ambiente | A **política** recusa, antes de pedir aprovação a quem quer que seja: IP interno, rede maior que /24, conta de emergência, host protegido (controlador de domínio), ativo crítico, conta ou host desconhecido |
| Uma avalanche de alertas vira uma avalanche de ações | **Deduplicação** do mesmo alerta, **limite por hora** de cada ação e uma **chave de desligamento** (`automation_enabled: false`) |
| Rodar duas vezes faz duas vezes | **Idempotência**: o mesmo efeito já aplicado vira "já aplicado", sem aprovação e sem repetir |
| A ação foi um erro | **Desfazer** em ordem inversa; as ações **irreversíveis** (aviso enviado, sessão encerrada) são apontadas, não escondidas |
| Alguém mexe no histórico | **Trilha de auditoria com hash encadeado**: alterar, apagar ou inserir registro quebra a corrente (`verify`). Triggers impedem UPDATE e DELETE pelo programa |
| Um playbook muda enquanto espera aprovação | A execução guarda a impressão digital do playbook: se mudou, ela é **abortada** |
| Texto do alerta vira código | Condições são interpretadas por um avaliador **sem `eval`**; o texto do alerta nunca é reinterpretado como modelo; caracteres de controle são removidos |

## Um playbook

```yaml
id: bloquear-origem-forca-bruta
trigger:
    source: [logwatch, loginguard, sshoney]
    min_severity: high
    message_contains: [força bruta, brute force]
inputs:
    ip: ip
steps:
    - id: reputacao                         # consulta primeiro: decida com evidência
      action: enrich_ip
      params: {ip: '{{ alert.ip }}'}
    - id: bloquear
      action: block_ip
      params: {ip: '{{ alert.ip }}', hours: 24}
      when: "steps.reputacao.score >= 70 or alert.severity == 'critical'"
      on_failure: continue                  # se a política recusar, o resto segue
    - id: chamado
      action: open_ticket
      params: {title: 'Força bruta vinda de {{ alert.ip }}', severity: '{{ alert.severity }}', body: '{{ alert.message }}'}
x_tests:                                    # playbooks têm testes, como regras de detecção
    - name: recusa bloquear um IP interno mesmo em alerta crítico
      alert: {source: logwatch, severity: critical, message: 'Força bruta SSH de 10.0.4.12', ip: 10.0.4.12}
      expect: {bloquear: refused, chamado: planned}
```
O validador (`playbooks validate`) cobra o que um revisor cobraria: ação que age em todo alerta sem condição, passo de risco médio ou alto sem consulta antes, referência a um passo que ainda não rodou, playbook sem testes.

## As ações

| Ação | Risco | Desfaz? | O que faz |
|---|---|---|---|
| `enrich_ip`, `lookup_user`, `lookup_host` | leitura | n/a | consultam o inventário; nunca alteram nada |
| `open_ticket` | baixo | sim (cancela) | abre um chamado; o mesmo conteúdo não abre dois |
| `notify` | baixo | **não** | avisa um canal; mensagem enviada não volta |
| `block_ip` | médio | sim | bloqueia IP ou rede por algumas horas |
| `revoke_sessions` | médio | **não** | encerra sessões; elas não voltam |
| `disable_account` | alto | sim | desativa uma conta (duas aprovações) |
| `isolate_host` | alto | sim | isola um host (duas aprovações) |

Estados de um passo: feito, planejado (simulação), aguardando aprovação, ignorado (a condição deu falso), **recusado** (a política), negado, falhou, já aplicado, desfeito, **não desfeito** (irreversível).

## A trilha de auditoria (e o que ela NÃO garante)

Cada registro carrega o hash do anterior. `verify` recalcula tudo e acusa registro alterado, apagado no meio ou corrente quebrada. **O limite, dito com todas as letras:** quem tem acesso ao arquivo pode apagar os
**últimos** registros sem quebrar a corrente, ou refazê-la inteira. Para isso existe a **âncora** (`anchor ARQ`): o último hash, guardado **fora** do banco (outra máquina, um cofre, um commit assinado). Com ela,
`verify --anchor` detecta também o apagamento do fim e a reescrita. Em produção, envie os registros a um sistema externo.

## Comandos

| Comando | O que faz |
|---|---|
| `playbooks list / validate / explain ID / test` | lista, valida, explica passo a passo e roda os testes |
| `run ALERTAS [--apply] [--operator NOME] [--only ID]` | processa alertas (JSONL ou JSON) |
| `runs` / `show R0001` | lista e mostra execuções |
| `approve R0001 PASSO --by NOME` / `deny ...` | aprova ou nega (a negativa exige motivo e aborta a execução) |
| `rollback R0001 --by NOME --reason TEXTO` | desfaz o que foi aplicado |
| `audit` / `verify [--anchor ARQ]` / `anchor ARQ` | auditoria e sua verificação |
| `world init/show`, `policy init/show` | o mundo simulado e a política de segurança |

## Testes

```bash
python -m unittest discover -s tests -v
```
**117 testes**: o avaliador de condições (21 formas legítimas e 44 tentativas de abuso recusadas), as ações e suas recusas, a política, o mundo simulado (gravação atômica), a trilha (7 formas de adulteração
detectadas, o apagamento do fim só com âncora), o motor (simulação sem rastro, aprovações, separação de funções, deduplicação, idempotência, limite por hora, chave de desligamento, desfazer em ordem inversa),
a linha de comando e os cenários da demonstração. Foram **validados por mutação**: quebrei o código em **29 pontos** (tirei a política, a aprovação, a idempotência, o hash...) e confirmei que falham.
O processo achou um **defeito real**: o avaliador recusava uma barra invertida escapada seguida de letra (`'a\\b'`), e uma lacuna de teste: o `in` com dado ausente.

## Limitações (leia)

- **É um mundo simulado.** Um conector real precisa de autenticação, segredos, tempo limite, novas tentativas e outro modelo de ameaça: **não** é só trocar o arquivo por uma API.
- **As identidades não são autenticadas.** `--by ana` é uma declaração: a separação de funções vale tanto quanto a identificação por trás dela. Em produção, a aprovação precisa vir de um provedor de identidade.
- Os alertas precisam trazer os campos que o playbook exige. O feed agregado do RuleForge, por exemplo, **não traz o nome do host**: o alerta de ransomware casa com o playbook, mas a execução fica **bloqueada** ("falta o campo host"). Alertas reais precisam ser enriquecidos antes.
- Um processo por vez, sem travas de concorrência. O banco e o mundo não estão na mesma transação: uma queda entre os dois pode deixar o mundo adiante da auditoria (o mundo é gravado de forma atômica, mas separado).
- Uma aprovação pendente **espera para sempre**: não há prazo nem aviso a quem deveria aprovar.
- A linguagem de condições é mínima de propósito (comparações, `in`, `and`, `or`, `not`). Isso a torna segura, e também limitada.
- A auditoria **não é à prova de adulteração** contra quem tem o arquivo (veja a âncora).

## Ideias para evoluir
Prazo para aprovações, identidade autenticada, conectores reais (com a revisão de segurança que isso exige), um painel de aprovações no Venator, execução em várias etapas com tempo limite e novas tentativas.

## Estrutura
```
app.py
soar/
  expr.py      condições e modelos SEM eval
  playbook.py  leitura, validação (lint) e gatilho dos playbooks
  actions.py   as 9 ações: planejar, aplicar e desfazer
  policy.py    a política de segurança
  world.py     o mundo simulado (gravação atômica)
  store.py     execuções, aprovações e a trilha de auditoria encadeada
  engine.py    o motor: simulação, aprovação, idempotência, desfazer, testes de playbook
  report.py  cli.py  yamlite.py
playbooks/     5 playbooks, cada um com testes
samples/       alertas, mundo simulado e política de exemplo (fictícios)
tests/         117 testes
```

## Ecossistema
Recebe alertas dos feeds de [detection-rules-engine](https://github.com/Brenno-Figueiredo/detection-rules-engine), [threat-intel-enricher](https://github.com/Brenno-Figueiredo/threat-intel-enricher),
[loginguard](https://github.com/Brenno-Figueiredo/loginguard) e [logwatch](https://github.com/Brenno-Figueiredo/logwatch), e complementa o [incident-register](https://github.com/Brenno-Figueiredo/incident-register) e o
[venator](https://github.com/Brenno-Figueiredo/venator).
