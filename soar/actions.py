"""As ações. Cada uma sabe: PLANEJAR (o que faria, qual o raio de impacto, se já está feito, se a política recusa), APLICAR e DESFAZER.
Só mexem no mundo simulado. Ações 'read' nunca alteram nada."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

RISK_ORDER = ("read", "low", "medium", "high")
USER_OK = re.compile(r"^[A-Za-z0-9_.\-@]{1,64}$")
HOST_OK = re.compile(r"^[A-Za-z0-9_.\-]{1,63}$")
SEVERITIES = ("low", "medium", "high", "critical")
CHANNELS = ("soc", "gestor", "ti")


class ActionError(ValueError):
    """Parâmetro inválido ou situação que impede a ação."""


@dataclass
class Plan:
    summary: str
    effect: Dict[str, Any] = field(default_factory=dict)
    noop: bool = False                                  # já está como o playbook quer: nada a fazer
    refusal: str = ""                                   # a política (ou a segurança) recusa
    blast: Dict[str, Any] = field(default_factory=dict)  # raio de impacto, para o humano que aprova ler


@dataclass
class Applied:
    output: Dict[str, Any]
    undo: Optional[Dict[str, Any]]


@dataclass(frozen=True)
class ActionSpec:
    name: str
    risk: str
    reversible: bool
    about: str
    required: Tuple[str, ...]
    optional: Tuple[str, ...]
    plan: Callable
    apply: Callable
    undo: Callable


def clean_text(value: Any, limit: int) -> str:
    """Texto vindo de um alerta é dado, nunca instrução: tira caracteres de controle, junta espaços e corta."""
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


def idempotency_key(action: str, params: Dict[str, Any]) -> str:
    return hashlib.sha256((action + "|" + json.dumps(params, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()[:20]


def _iso(ctx, delta: timedelta = timedelta(0)) -> str:
    return (ctx["now"] + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ip(value: Any):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise ActionError(f"endereço IP inválido: {clean_text(value, 40)!r}") from None


def _user(value: Any) -> str:
    v = str(value).strip()
    if not USER_OK.match(v):
        raise ActionError(f"identificador de usuário inválido: {clean_text(value, 40)!r}")
    return v


def _host(value: Any) -> str:
    v = str(value).strip()
    if not HOST_OK.match(v):
        raise ActionError(f"nome de host inválido: {clean_text(value, 40)!r}")
    return v


def _find(mapping: Dict[str, Any], name: str) -> Optional[str]:
    return next((k for k in mapping if k.lower() == name.lower()), None)


# ---- leitura -------------------------------------------------------------------------------------------------------------------------
def _enrich_plan(p, world, ctx):
    ip = _ip(p["ip"])
    entry = world["intel"].get(str(ip))
    score = entry.get("score") if isinstance(entry, dict) and isinstance(entry.get("score"), int) else None
    rep = "desconhecido" if score is None else "ruim" if score >= 70 else "suspeito" if score >= 40 else "limpo"
    return Plan(f"consultar a reputação de {ip}", {"ip": str(ip), "known": score is not None, "score": score, "reputation": rep, "tags": list((entry or {}).get("tags", []))})


def _lookup_plan(p, world, ctx):
    user = _user(p["user"])
    key = _find(world["directory"], user)
    e = world["directory"].get(key, {}) if key else {}
    return Plan(f"consultar o usuário {user}", {"user": user, "known": bool(key), "privileged": bool(e.get("privileged")), "active": bool(e.get("active", True)), "department": e.get("department", "")})


def _lookup_host_plan(p, world, ctx):
    host = _host(p["host"])
    key = _find(world["hosts"], host)
    e = world["hosts"].get(key, {}) if key else {}
    return Plan(f"consultar o host {host}", {"host": host, "known": bool(key), "criticality": e.get("criticality", ""), "isolated": bool(e.get("isolated"))})


def _read_apply(plan_fn):
    return lambda p, world, ctx: Applied(plan_fn(p, world, ctx).effect, None)


# ---- bloquear IP ---------------------------------------------------------------------------------------------------------------------
def _net(value: Any):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=True)
    except ValueError:
        raise ActionError(f"endereço ou rede inválido (rede com bits de host?): {clean_text(value, 40)!r}") from None


def _hours(p, ctx) -> int:
    h = p.get("hours", 24)
    if isinstance(h, bool) or not isinstance(h, int) or not 1 <= h <= ctx["policy"].block_hours_max:
        raise ActionError(f"'hours' deve ser um inteiro de 1 a {ctx['policy'].block_hours_max}")
    return h


def _block_plan(p, world, ctx):
    net, hours, pol = _net(p["ip"]), _hours(p, ctx), ctx["policy"]
    blast = {"enderecos": net.num_addresses}
    limit = pol.max_block_prefix_v4 if net.version == 4 else pol.max_block_prefix_v6
    if pol.is_protected_net(net):
        return Plan(f"bloquear {net}", blast=blast, refusal=f"{net} é (ou contém) uma faixa protegida: interna, de loopback, de gerenciamento ou reservada")
    if net.prefixlen < limit:
        return Plan(f"bloquear {net}", blast=blast, refusal=f"rede grande demais (/{net.prefixlen}); a política só permite /{limit} ou menor, por causa do raio de impacto ({net.num_addresses} endereços)")
    cur = world["blocklist"].get(str(net))
    active = bool(cur) and cur.get("expires", "") > _iso(ctx)
    return Plan(f"bloquear {net} por {hours} h", {"bloqueado": str(net), "horas": hours}, noop=active, blast=blast)


def _block_apply(p, world, ctx):
    net, hours = _net(p["ip"]), _hours(p, ctx)
    prev = world["blocklist"].get(str(net))
    world["blocklist"][str(net)] = {"expires": _iso(ctx, timedelta(hours=hours)), "reason": clean_text(p.get("reason", "bloqueio automático"), 200), "run": ctx["run"]}
    return Applied({"bloqueado": str(net), "horas": hours}, {"net": str(net), "previous": prev})


def _block_undo(u, world, ctx):
    if u["previous"] is None:
        world["blocklist"].pop(u["net"], None)
    else:
        world["blocklist"][u["net"]] = u["previous"]
    return f"desbloqueado {u['net']}"


# ---- contas --------------------------------------------------------------------------------------------------------------------------
def _account_refusal(user, world, ctx) -> str:
    if ctx["policy"].is_protected_account(user):
        return f"'{user}' é uma conta protegida (emergência ou serviço): só um humano mexe nela, fora do playbook"
    if not _find(world["directory"], user):
        return f"'{user}' não existe no diretório: a automação nunca age sobre uma conta que não conhece"
    return ""


def _disable_plan(p, world, ctx):
    user = _user(p["user"])
    refusal = _account_refusal(user, world, ctx)
    if refusal:
        return Plan(f"desativar a conta {user}", refusal=refusal)
    e = world["directory"][_find(world["directory"], user)]
    return Plan(f"desativar a conta {user}", {"desativada": user, "privilegiada": bool(e.get("privileged"))}, noop=not e.get("active", True), blast={"privilegiada": bool(e.get("privileged"))})


def _disable_apply(p, world, ctx):
    user = _find(world["directory"], _user(p["user"]))
    prev = world["directory"][user].get("active", True)
    world["directory"][user]["active"] = False
    return Applied({"desativada": user}, {"user": user, "previous_active": prev})


def _disable_undo(u, world, ctx):
    world["directory"][u["user"]]["active"] = u["previous_active"]
    return f"conta {u['user']} reativada"


def _revoke_plan(p, world, ctx):
    user = _user(p["user"])
    refusal = _account_refusal(user, world, ctx)
    if refusal:
        return Plan(f"encerrar as sessões de {user}", refusal=refusal)
    n = int(world["directory"][_find(world["directory"], user)].get("sessions", 0))
    return Plan(f"encerrar as sessões de {user}", {"sessoes_encerradas": n}, noop=n == 0, blast={"sessoes": n})


def _revoke_apply(p, world, ctx):
    user = _find(world["directory"], _user(p["user"]))
    n = int(world["directory"][user].get("sessions", 0))
    world["directory"][user]["sessions"] = 0
    return Applied({"sessoes_encerradas": n}, None)                      # sessões encerradas não voltam: é irreversível


def _no_undo(u, world, ctx):
    return "não desfeito (ação irreversível)"


# ---- hosts ---------------------------------------------------------------------------------------------------------------------------
def _isolate_plan(p, world, ctx):
    host, pol = _host(p["host"]), ctx["policy"]
    key = _find(world["hosts"], host)
    if pol.is_protected_host(host):
        return Plan(f"isolar o host {host}", refusal=f"'{host}' é um host protegido (ex.: controlador de domínio): isolá-lo derruba o ambiente")
    if not key:
        return Plan(f"isolar o host {host}", refusal=f"'{host}' não existe no inventário: a automação nunca age sobre um host que não conhece")
    crit = world["hosts"][key].get("criticality", "low")
    if crit == "critical" and not pol.isolate_critical:
        return Plan(f"isolar o host {host}", blast={"criticidade": crit}, refusal=f"'{host}' é um ativo crítico: isolar exige decisão humana, fora do playbook")
    return Plan(f"isolar o host {host}", {"isolado": host, "criticidade": crit}, noop=bool(world["hosts"][key].get("isolated")), blast={"criticidade": crit})


def _isolate_apply(p, world, ctx):
    key = _find(world["hosts"], _host(p["host"]))
    prev = bool(world["hosts"][key].get("isolated"))
    world["hosts"][key]["isolated"] = True
    return Applied({"isolado": key}, {"host": key, "previous": prev})


def _isolate_undo(u, world, ctx):
    world["hosts"][u["host"]]["isolated"] = u["previous"]
    return f"host {u['host']} reconectado"


# ---- chamado e aviso -----------------------------------------------------------------------------------------------------------------
def _ticket_fields(p):
    sev = str(p.get("severity", "medium"))
    if sev not in SEVERITIES:
        raise ActionError(f"'severity' deve ser: {', '.join(SEVERITIES)}")
    title, body = clean_text(p["title"], 120), clean_text(p.get("body", ""), 1000)
    if not title:
        raise ActionError("o título do chamado está vazio")
    tid = "TCK-" + hashlib.sha1(f"{title}|{sev}|{body}".encode()).hexdigest()[:8].upper()
    return tid, title, sev, body


def _ticket_plan(p, world, ctx):
    tid, title, sev, _ = _ticket_fields(p)
    exists = any(t.get("id") == tid and t.get("status") == "open" for t in world["tickets"])
    return Plan(f"abrir o chamado {tid}: {title}", {"chamado": tid, "severidade": sev}, noop=exists)


def _ticket_apply(p, world, ctx):
    tid, title, sev, body = _ticket_fields(p)
    world["tickets"].append({"id": tid, "title": title, "severity": sev, "body": body, "status": "open", "run": ctx["run"], "created": _iso(ctx)})
    return Applied({"chamado": tid}, {"id": tid})


def _ticket_undo(u, world, ctx):
    for t in world["tickets"]:
        if t.get("id") == u["id"] and t.get("status") == "open":
            t["status"] = "cancelled"                                          # o chamado não some: fica cancelado, com rastro
    return f"chamado {u['id']} cancelado"


def _notify_fields(p):
    ch = str(p["channel"])
    if ch not in CHANNELS:
        raise ActionError(f"'channel' deve ser: {', '.join(CHANNELS)}")
    msg = clean_text(p["message"], 500)
    if not msg:
        raise ActionError("a mensagem está vazia")
    return ch, msg


def _notify_plan(p, world, ctx):
    ch, msg = _notify_fields(p)
    return Plan(f"avisar o canal '{ch}'", {"canal": ch})


def _notify_apply(p, world, ctx):
    ch, msg = _notify_fields(p)
    world["notifications"].append({"channel": ch, "message": msg, "run": ctx["run"], "ts": _iso(ctx)})
    return Applied({"canal": ch}, None)                                      # mensagem enviada não volta: irreversível


ACTIONS: Dict[str, ActionSpec] = {s.name: s for s in [
    ActionSpec("enrich_ip", "read", True, "Consulta a reputação de um IP no inventário de inteligência. Não altera nada.", ("ip",), (), _enrich_plan, _read_apply(_enrich_plan), _no_undo),
    ActionSpec("lookup_user", "read", True, "Consulta o usuário no diretório (existe, é privilegiado, está ativo). Não altera nada.", ("user",), (), _lookup_plan, _read_apply(_lookup_plan), _no_undo),
    ActionSpec("lookup_host", "read", True, "Consulta o host no inventário (existe, criticidade, se já está isolado). Não altera nada.", ("host",), (), _lookup_host_plan, _read_apply(_lookup_host_plan), _no_undo),
    ActionSpec("open_ticket", "low", True, "Abre um chamado (o mesmo conteúdo não abre dois). O desfazer cancela o chamado.", ("title",), ("severity", "body"), _ticket_plan, _ticket_apply, _ticket_undo),
    ActionSpec("notify", "low", False, "Avisa um canal (soc, gestor ou ti). Mensagem enviada não volta: é irreversível.", ("channel", "message"), (), _notify_plan, _notify_apply, _no_undo),
    ActionSpec("block_ip", "medium", True, "Bloqueia um IP ou rede por algumas horas. Recusa faixas internas e redes grandes demais.", ("ip",), ("hours", "reason"), _block_plan, _block_apply, _block_undo),
    ActionSpec("revoke_sessions", "medium", False, "Encerra as sessões de um usuário. Sessões encerradas não voltam: é irreversível.", ("user",), (), _revoke_plan, _revoke_apply, _no_undo),
    ActionSpec("disable_account", "high", True, "Desativa uma conta. Recusa contas protegidas e desconhecidas.", ("user",), (), _disable_plan, _disable_apply, _disable_undo),
    ActionSpec("isolate_host", "high", True, "Isola um host da rede. Recusa hosts protegidos, desconhecidos e ativos críticos.", ("host",), (), _isolate_plan, _isolate_apply, _isolate_undo),
]}
