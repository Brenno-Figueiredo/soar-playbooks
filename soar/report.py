"""Saídas de terminal: execuções, trilha de auditoria, mundo simulado e validação dos playbooks."""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, List

from .playbook import Issue

ANSI = {"ok": "\033[32m", "bad": "\033[1;31m", "warn": "\033[33m", "dim": "\033[2m", "b": "\033[1m", "x": "\033[0m"}
STATE_PT = {"done": "feito", "planned": "planejado", "waiting": "aguardando aprovação", "skipped": "ignorado", "refused": "RECUSADO", "denied": "negado", "failed": "FALHOU",
            "noop": "já aplicado", "rolled_back": "desfeito", "pending": "pendente", "irreversible": "não desfeito"}
RUN_PT = {"running": "em andamento", "waiting_approval": "aguardando aprovação", "completed": "concluída", "stopped": "parada pela política", "failed": "falhou", "aborted": "abortada",
          "blocked": "bloqueada", "rolled_back": "desfeita"}
RISK_PT = {"read": "leitura", "low": "baixo", "medium": "médio", "high": "alto"}
TONE = {"done": "ok", "planned": "b", "waiting": "warn", "skipped": "dim", "refused": "bad", "denied": "bad", "failed": "bad", "noop": "dim", "rolled_back": "warn", "irreversible": "warn", "pending": "dim"}


def _p(color: bool):
    return (lambda t, k: f"{ANSI[k]}{t}{ANSI['x']}") if color else (lambda t, k: t)


def _alert_line(alert: Dict[str, Any]) -> str:
    extra = " ".join(f"{k}={alert[k]}" for k in ("ip", "user", "host") if alert.get(k))
    return f"{alert.get('source', '?')} · {alert.get('severity', '?')} · \"{str(alert.get('message', ''))[:70]}\"" + (f" · {extra}" if extra else "")


def render_run(d: Dict[str, Any], color: bool = False, hints: bool = True) -> str:
    p = _p(color)
    tone = "ok" if d["state"] == "completed" else "warn" if d["state"] in ("waiting_approval", "rolled_back") else "bad" if d["state"] in ("failed", "stopped", "aborted", "blocked") else "b"
    lines = [f"{p(d['label'], 'b')}  {d['playbook']}  {p('[' + RUN_PT.get(d['state'], d['state']) + ']', tone)}  ({'simulação: nada foi gravado' if d['mode'] == 'dry' else 'aplicada no mundo simulado'}) · operador: {d['operator']}",
             f"    alerta: {_alert_line(d['alert'])}"]
    if d["note"]:
        lines.append(f"    {d['note']}")
    for i, s in enumerate(d["steps"], 1):
        lines.append(f"    {i}. {s['step_id']:<14} {s['action']:<16} {RISK_PT.get(s['risk'], s['risk']):<8} {p('[' + STATE_PT.get(s['state'], s['state']) + ']', TONE.get(s['state'], 'b'))}")
        if s["note"]:
            lines.append(p(f"         {s['note']}", "dim"))
    for a in d["approvals"]:
        lines.append(p(f"    {'aprovado' if a['decision'] == 'approve' else 'negado'} por {a['approver']} (passo {a['step_id']})" + (f": {a['reason']}" if a["reason"] else ""), "dim"))
    if hints and d["state"] == "waiting_approval":
        for s in d["steps"]:
            if s["state"] == "waiting":
                lines.append(p(f"    Para continuar: python app.py approve {d['label']} {s['step_id']} --by NOME", "warn"))
    return "\n".join(lines)


def render_runs(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "Nenhuma execução."
    lines = [f"{'EXECUÇÃO':<9}{'PLAYBOOK':<30}{'ESTADO':<24}{'MODO':<8}{'CRIADA (UTC)':<22}OBSERVAÇÃO"]
    for r in rows:
        lines.append(f"R{r['id']:04d}    {r['playbook']:<30}{RUN_PT.get(r['state'], r['state']):<24}{r['mode']:<8}{r['created']:<22}{r['note'][:60]}")
    return "\n".join(lines)


def render_audit(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "A trilha de auditoria está vazia."
    lines = [f"{'#':>4}  {'HORA (UTC)':<21}{'QUEM':<12}{'EVENTO':<20}{'EXEC':<7}{'PASSO':<14}DETALHE"]
    for r in rows:
        data = json.loads(r["data"])
        detail = ", ".join(f"{k}={v}" for k, v in data.items() if not isinstance(v, (dict, list)))[:60]
        lines.append(f"{r['seq']:>4}  {r['ts']:<21}{r['actor'][:11]:<12}{r['event']:<20}{('R%04d' % r['run_id']) if r['run_id'] else '-':<7}{(r['step_id'] or '-'):<14}{detail}")
    return "\n".join(lines)


def render_world(w: Dict[str, Any], now_iso: str = "") -> str:
    blocks = {k: v for k, v in w["blocklist"].items() if not now_iso or v.get("expires", "") > now_iso}
    off = [u for u, e in w["directory"].items() if not e.get("active", True)]
    iso = [h for h, e in w["hosts"].items() if e.get("isolated")]
    tickets = [t for t in w["tickets"] if t.get("status") == "open"]
    lines = ["MUNDO SIMULADO",
             f"  IPs bloqueados ({len(blocks)}): " + (", ".join(f"{k} (até {v['expires']})" for k, v in blocks.items()) or "nenhum"),
             f"  contas desativadas ({len(off)}): " + (", ".join(off) or "nenhuma"),
             f"  hosts isolados ({len(iso)}): " + (", ".join(iso) or "nenhum"),
             f"  chamados abertos ({len(tickets)}): " + ("; ".join(f"{t['id']} [{t['severity']}] {t['title'][:40]}" for t in tickets) or "nenhum"),
             f"  avisos enviados: {len(w['notifications'])}"]
    return "\n".join(lines)


def render_issues(issues: List[Issue], n: int, color: bool = False) -> str:
    p = _p(color)
    c = Counter(i.severity for i in issues)
    lines = [p("VALIDAÇÃO DOS PLAYBOOKS", "b"), f"{n} playbook(s) · {c.get('error', 0)} erro(s) · {c.get('warning', 0)} aviso(s) · {c.get('info', 0)} observação(ões)", ""]
    tone = {"error": "bad", "warning": "warn", "info": "dim"}
    for i in sorted(issues, key=lambda x: ({"error": 0, "warning": 1, "info": 2}[x.severity], x.playbook)):
        lines.append(f"{p({'error': 'ERRO', 'warning': 'aviso', 'info': 'info'}[i.severity].ljust(5), tone[i.severity])} {i.code} {i.playbook}: {i.message}")
    if not issues:
        lines.append(p("Nenhum problema encontrado.", "ok"))
    return "\n".join(lines)


def run_summary(results: List[Any]) -> str:
    """Conta execuções distintas: o mesmo alerta reenviado aponta para a execução que já existia e não é uma execução nova."""
    distinct = [r for r in results if not r.duplicate]
    dups = len(results) - len(distinct)
    c = Counter(r.state for r in distinct)
    return f"{len(distinct)} execução(ões): " + ", ".join(f"{RUN_PT.get(k, k)} {v}" for k, v in sorted(c.items())) + (f" · {dups} alerta(s) duplicado(s)" if dups else "")
