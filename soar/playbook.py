"""Playbooks: leitura, validação (lint), gatilho e testes. Um playbook é código: tem revisão, validação e testes, como uma regra de detecção."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import expr, yamlite
from .actions import ACTIONS, RISK_ORDER

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INPUT_TYPES = ("ip", "user", "host", "text")
WELL_KNOWN = {"source", "severity", "message", "ts", "rule", "type"}
MAX_FILE = 200 * 1024
MAX_STEPS = 20
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,60}$")
STEP_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
TOP_KEYS = {"id", "name", "description", "trigger", "inputs", "steps", "x_tests"}
STEP_KEYS = {"id", "action", "params", "when", "approval", "on_failure", "description"}


class PlaybookError(ValueError):
    pass


@dataclass(frozen=True)
class Step:
    id: str
    action: str
    params: Dict[str, Any]
    when: Optional[str] = None
    approval: str = "auto"                    # auto: a política decide pelo risco | required: sempre pede aprovação
    on_failure: str = "stop"                  # stop | continue
    description: str = ""


@dataclass
class Playbook:
    path: str
    id: str
    name: str
    description: str
    sources: List[str]
    min_severity: Optional[str]
    contains: List[str]
    inputs: Dict[str, str]
    steps: List[Step]
    tests: List[Dict[str, Any]]
    fingerprint: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Issue:
    severity: str          # error | warning | info
    code: str
    message: str
    playbook: str = ""
    path: str = ""


def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    items = v if isinstance(v, list) else [v]
    if not all(isinstance(i, str) and i.strip() for i in items):
        raise PlaybookError("o gatilho deve ser texto ou uma lista de textos")
    return [i.strip() for i in items]


def parse_playbook(text: str, path: str = "") -> Playbook:
    if len(text.encode("utf-8", "ignore")) > MAX_FILE:
        raise PlaybookError("playbook grande demais (limite de 200 KB)")
    try:
        doc = yamlite.load(text)
    except yamlite.YamlError as exc:
        raise PlaybookError(f"YAML inválido: {exc}") from None
    if not isinstance(doc, dict):
        raise PlaybookError("o playbook deve ser um mapa (chave: valor)")
    if set(doc) - TOP_KEYS:
        raise PlaybookError(f"chave desconhecida: {', '.join(sorted(set(doc) - TOP_KEYS))}")
    pid = str(doc.get("id") or "")
    if not ID_RE.match(pid):
        raise PlaybookError("'id' precisa ter 3 a 61 caracteres: letras minúsculas, números e hífen")
    trig = doc.get("trigger") or {}
    if not isinstance(trig, dict) or set(trig) - {"source", "min_severity", "message_contains"}:
        raise PlaybookError("'trigger' aceita: source, min_severity e message_contains")
    minsev = trig.get("min_severity")
    if minsev is not None and minsev not in SEV_RANK:
        raise PlaybookError(f"'min_severity' deve ser: {', '.join(SEV_RANK)}")
    inputs = doc.get("inputs") or {}
    if not isinstance(inputs, dict) or any(t not in INPUT_TYPES or not re.match(r"^[a-z][a-z0-9_]*$", str(n)) for n, t in inputs.items()):
        raise PlaybookError(f"'inputs' deve mapear nomes para tipos ({', '.join(INPUT_TYPES)})")
    raw_steps = doc.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise PlaybookError("o playbook precisa de 'steps' (uma lista não vazia)")
    if len(raw_steps) > MAX_STEPS:
        raise PlaybookError(f"passos demais (limite de {MAX_STEPS})")
    steps = []
    for i, s in enumerate(raw_steps, 1):
        if not isinstance(s, dict) or set(s) - STEP_KEYS:
            raise PlaybookError(f"passo #{i}: aceita {', '.join(sorted(STEP_KEYS))}")
        sid = str(s.get("id") or "")
        if not STEP_RE.match(sid):
            raise PlaybookError(f"passo #{i}: 'id' inválido (minúsculas, números e _; começa com letra)")
        if not isinstance(s.get("action"), str):
            raise PlaybookError(f"passo '{sid}': falta 'action'")
        params = s.get("params") or {}
        if not isinstance(params, dict):
            raise PlaybookError(f"passo '{sid}': 'params' deve ser um mapa")
        when = s.get("when")
        if when is not None:
            try:
                expr.parse(when)
            except expr.ExprError as exc:
                raise PlaybookError(f"passo '{sid}': condição inválida: {exc}") from None
        if s.get("approval", "auto") not in ("auto", "required"):
            raise PlaybookError(f"passo '{sid}': 'approval' deve ser auto ou required")
        if s.get("on_failure", "stop") not in ("stop", "continue"):
            raise PlaybookError(f"passo '{sid}': 'on_failure' deve ser stop ou continue")
        steps.append(Step(sid, s["action"], params, when, s.get("approval", "auto"), s.get("on_failure", "stop"), str(s.get("description") or "")))
    tests = doc.get("x_tests") or []
    if not isinstance(tests, list) or not all(isinstance(t, dict) and isinstance(t.get("alert"), dict) and t.get("name") for t in tests):
        raise PlaybookError("'x_tests' deve ser uma lista de testes, cada um com 'name' e 'alert'")
    return Playbook(path, pid, str(doc.get("name") or pid), str(doc.get("description") or "").strip(), _as_list(trig.get("source")), minsev, _as_list(trig.get("message_contains")),
                    {str(k): v for k, v in inputs.items()}, steps, tests, hashlib.sha256(text.encode("utf-8")).hexdigest()[:16], doc)


def load_dir(path: str) -> Tuple[List[Playbook], List[Tuple[str, str]]]:
    pbs, errors = [], []
    files = [path] if os.path.isfile(path) else sorted(os.path.join(r, f) for r, _, fs in os.walk(path) for f in fs if f.lower().endswith((".yml", ".yaml")))
    if not os.path.exists(path):
        raise FileNotFoundError(f"não encontrei '{path}'")
    for p in files:
        try:
            with open(p, encoding="utf-8-sig") as f:
                pbs.append(parse_playbook(f.read(), p))
        except (PlaybookError, OSError) as exc:
            errors.append((os.path.basename(p), str(exc)))
    seen = {}
    for pb in pbs:
        if pb.id in seen:
            errors.append((os.path.basename(pb.path), f"id repetido '{pb.id}' (já usado em {os.path.basename(seen[pb.id])})"))
        seen.setdefault(pb.id, pb.path)
    return [pb for pb in pbs if seen[pb.id] == pb.path], errors


def matches(pb: Playbook, alert: Dict[str, Any]) -> bool:
    """Todas as condições do gatilho precisam valer (E)."""
    if pb.sources and str(alert.get("source", "")).lower() not in {s.lower() for s in pb.sources}:
        return False
    if pb.min_severity and SEV_RANK.get(str(alert.get("severity", "")).lower(), -1) < SEV_RANK[pb.min_severity]:
        return False
    if pb.contains:
        msg = str(alert.get("message", "")).lower()
        if not any(c.lower() in msg for c in pb.contains):
            return False
    return True


def lint(pb: Playbook) -> List[Issue]:
    out: List[Issue] = []
    add = lambda sev, code, msg: out.append(Issue(sev, code, msg, pb.id, pb.path))  # noqa: E731
    seen: List[str] = []
    mutating, read_before = 0, False
    for st in pb.steps:
        spec = ACTIONS.get(st.action)
        if st.id in seen:
            add("error", "E101", f"passo '{st.id}' repetido")
        if not spec:
            add("error", "E102", f"passo '{st.id}': ação desconhecida '{st.action}' (use: {', '.join(sorted(ACTIONS))})")
        else:
            missing, extra = [k for k in spec.required if k not in st.params], [k for k in st.params if k not in spec.required + spec.optional]
            if missing:
                add("error", "E103", f"passo '{st.id}': faltam parâmetros de {st.action}: {', '.join(missing)}")
            if extra:
                add("error", "E103", f"passo '{st.id}': parâmetros desconhecidos para {st.action}: {', '.join(extra)}")
        refs = expr.template_paths(st.params) + (expr.paths_in(expr.parse(st.when)) if st.when else [])
        for path in refs:
            try:
                parts = expr.check_path(path)
            except expr.ExprError as exc:
                add("error", "E104", f"passo '{st.id}': {exc}")
                continue
            if parts[0] == "steps" and parts[1] not in seen:
                add("error", "E105", f"passo '{st.id}': usa '{path}', mas o passo '{parts[1]}' não vem antes dele")
            if parts[0] == "alert" and parts[1] not in pb.inputs and parts[1] not in WELL_KNOWN:
                add("warning", "W110", f"passo '{st.id}': usa 'alert.{parts[1]}', que não está em 'inputs' nem é um campo padrão: se o alerta não trouxer, o passo falha")
        if spec and spec.risk in ("medium", "high"):
            mutating += 1
            if not st.when:
                add("warning", "W101", f"passo '{st.id}' ({spec.risk}) age em TODO alerta que casar com o gatilho: considere uma condição (when) baseada em evidência")
            if not read_before:
                add("warning", "W102", f"passo '{st.id}' ({spec.risk}) vem sem nenhuma consulta (enrich_ip, lookup_user) antes: decida com evidência")
            if spec.risk == "high" and st.on_failure == "continue":
                add("info", "I101", f"passo '{st.id}' é de alto risco com on_failure=continue: confira que o resto do playbook é seguro se ele for recusado")
        if spec and spec.risk == "read":
            read_before = True
            if st.approval == "required":
                add("info", "I102", f"passo '{st.id}': aprovação em uma ação só de leitura não tem efeito")
        seen.append(st.id)
    if mutating > 3:
        add("warning", "W106", f"{mutating} passos que alteram algo numa execução só: o raio de impacto é grande")
    if not (pb.sources or pb.min_severity or pb.contains):
        add("warning", "W103", "o gatilho não tem nenhuma condição: o playbook dispara para TODO alerta")
    if not pb.tests:
        add("warning", "W104", "playbook sem testes (x_tests)")
    if not pb.description:
        add("info", "W105", "falta a descrição")
    return out
