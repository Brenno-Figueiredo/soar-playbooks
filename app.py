#!/usr/bin/env python3
"""Playbooker - resposta a incidentes (SOAR) em um mundo SIMULADO. Exemplos:
    python app.py demo                                   # percorre tudo com dados fictícios
    python app.py playbooks validate                     # o que um revisor conferiria
    python app.py playbooks test                         # os testes de cada playbook
    python app.py world init                             # cria world.json (dados fictícios)
    python app.py run samples/alerts.jsonl               # SIMULAÇÃO: nada é gravado
    python app.py run samples/alerts.jsonl --apply       # aplica no mundo simulado
    python app.py approve R0001 bloquear --by ana        # aprovação humana
    python app.py rollback R0001 --by ana --reason "falso positivo"
    python app.py verify                                 # confere a trilha de auditoria
"""
import sys

from soar.cli import main

if __name__ == "__main__":
    sys.exit(main())
