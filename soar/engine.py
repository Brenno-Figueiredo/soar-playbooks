"""O motor: executa playbooks passo a passo, com simulação, aprovação humana, política de segurança, idempotência e desfazer.

Modos: 'dry' = simulação: NADA é gravado (nem o banco, nem o mundo); 'apply' = aplica no mundo simulado, grava o banco e a auditoria."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from . import expr
from .actions import ACTIONS, HOST_OK, USER_OK, ActionError, clean_text, idempotency_key
from .playbook import Playbook, Step, matches
from .policy import Policy
from .store import Store, canonical, parse_label, run_label
from .world import clone, default_world, load_world, save_world, validate_world

ALERT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")
MAX_ALERT_KEYS = 40
TERMINAL_RUN = ("completed", "stopped", "failed", "aborted", "blocked", "rolled_back")


class SoarError(ValueError):
    """Pedido inválido para o motor (execução inexistente, aprovação fora de hora, etc.)."""


@dataclass
class RunResult:
    run_id: int
    label: str
    playbook: str
    state: str
    note: str = ""
    duplicate: bool = False


def clean_alert(alert: Any) -> Dict[str, Any]:
    """O alerta vem de fora: só passam chaves simples e valores escalares, com texto limpo e limitado. Estruturas aninhadas são descartadas."""
    if not isinstance(alert, dict):
        raise SoarError("o alerta deve ser um objeto JSON")
    out: Dict[str, Any] = {}
    for k, v in alert.items():
        if len(out) >= MAX_ALERT_KEYS:
            break
        if not isinstance(k, str) or not ALERT_KEY.match(k):
            continue
        if isinstance(v, str):
            out[k] = clean_text(v, 500)
        elif isinstance(v, (bool, int, float)) or v is None:
            out[k] = v
    return out


def alert_hash(alert: Dict[str, Any]) -> str:
    """O mesmo alerta reenviado (só muda a hora) tem o mesmo hash: é o que permite não abrir duas execuções para ele."""
    return hashlib.sha256(canonical({k: v for k, v in alert.items() if k != "ts"}).encode()).hexdigest()[:20]


def validate_inputs(pb: Playbook, alert: Dict[str, Any]) -> str:
    import ipaddress
    for name, kind in pb.inputs.items():
        v = alert.get(name)
        if v in (None, ""):
            return f"falta o campo '{name}' no alerta (o playbook precisa dele)"
        s = str(v).strip()
        ok = True
        if kind == "ip":
            try:
                ipaddress.ip_address(s)
            except ValueError:
                ok = False
        elif kind == "user":
            ok = bool(USER_OK.match(s))
        elif kind == "host":
            ok = bool(HOST_OK.match(s))
        if not ok:
            return f"o campo '{name}' não é um {kind} válido: {clean_text(v, 40)!r}"
    return ""


class Soar:
    def __init__(self, db_path: str = "soar.db", world_path: Optional[str] = None, policy: Optional[Policy] = None, playbooks: Optional[List[Playbook]] = None,
                 mode: str = "dry", clock: Optional[Callable[[], datetime]] = None, world: Optional[Dict[str, Any]] = None):
        if mode not in ("dry", "apply"):
            raise SoarError("modo deve ser 'dry' ou 'apply'")
        if mode == "apply" and not world_path:
            raise SoarError("o modo apply precisa de um arquivo de mundo simulado")
        self.mode = mode
        self.store = Store(":memory:" if mode == "dry" else db_path)
        self.world_path = world_path
        self.policy = policy or Policy()
        self.playbooks = {pb.id: pb for pb in (playbooks or [])}
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._fixed_world = clone(validate_world(world)) if world is not None else None
        self.world: Dict[str, Any] = {}
        self._load_world()

    def close(self) -> None:
        self.store.close()

    # ---- utilidades -----------------------------------------------------------------------------------------------------------------
    def now(self) -> datetime:
        return self.clock()

    def _iso(self, dt: Optional[datetime] = None) -> str:
        return (dt or self.now()).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _load_world(self) -> None:
        if self._fixed_world is not None:
            if not self.world:
                self.world = clone(self._fixed_world)
        elif self.world_path:
            self.world = load_world(self.world_path)
        else:
            self.world = default_world()

    def _save_world(self) -> None:
        if self.mode == "apply" and self.world_path:
            save_world(self.world_path, self.world)

    def _audit(self, actor: str, event: str, run_id: int, step_id: Optional[str], data: Dict[str, Any]) -> None:
        self.store.audit(actor, event, run_id, step_id, data, self._iso())

    # ---- início ---------------------------------------------------------------------------------------------------------------------
    def handle_alert(self, alert: Dict[str, Any], operator: str = "automacao", only: Optional[str] = None) -> List[RunResult]:
        alert = clean_alert(alert)
        return [self.start(pb, alert, operator) for pb in sorted(self.playbooks.values(), key=lambda p: p.id) if (only is None or pb.id == only) and matches(pb, alert)]

    def start(self, pb: Playbook, alert: Dict[str, Any], operator: str = "automacao") -> RunResult:
        alert = clean_alert(alert)
        ah, now = alert_hash(alert), self._iso()
        since = self._iso(self.now() - timedelta(hours=self.policy.dedupe_hours))
        dup = self.store.find_recent(pb.id, ah, self.mode, since)
        if dup:
            self._audit(operator, "run_deduplicated", dup, None, {"playbook": pb.id, "motivo": f"mesmo alerta nas últimas {self.policy.dedupe_hours} h"})
            r = self.store.get_run(dup)
            return RunResult(dup, run_label(dup), pb.id, r["state"], f"duplicado: o mesmo alerta já gerou a execução {run_label(dup)}", duplicate=True)
        missing = validate_inputs(pb, alert)
        if len(pb.steps) > self.policy.max_steps_per_run:
            missing = missing or f"o playbook tem {len(pb.steps)} passos; a política permite {self.policy.max_steps_per_run}"
        rid = self.store.create_run(pb.id, pb.fingerprint, alert, ah, self.mode, operator, "blocked" if missing else "running", missing, now)
        self.store.add_steps(rid, [(s.id, s.action, ACTIONS[s.action].risk if s.action in ACTIONS else "high") for s in pb.steps])
        self._audit(operator, "run_started", rid, None, {"playbook": pb.id, "mode": self.mode, "alert_source": alert.get("source", ""), "alert_severity": alert.get("severity", "")})
        if missing:
            for st in self.store.get_steps(rid):
                self.store.set_step(rid, st["idx"], state="skipped", note="execução bloqueada")
            self._audit(operator, "run_blocked", rid, None, {"motivo": missing})
            return RunResult(rid, run_label(rid), pb.id, "blocked", missing)
        return self.advance(rid)

    # ---- avanço ---------------------------------------------------------------------------------------------------------------------
    def advance(self, run_id: int) -> RunResult:
        run = self.store.get_run(run_id)
        if not run:
            raise SoarError(f"execução {run_label(run_id)} não existe")
        label, pb = run_label(run_id), self.playbooks.get(run["playbook"])
        if run["state"] in TERMINAL_RUN:
            return RunResult(run_id, label, run["playbook"], run["state"], run["note"])
        if pb is None or pb.fingerprint != run["pb_hash"]:
            return self._finish(run, "aborted", "o playbook mudou ou sumiu desde o início desta execução: faça uma nova execução com o playbook atual", "run_aborted")
        self._load_world()
        alert, spec_steps = json.loads(run["alert"]), {s.id: s for s in pb.steps}
        steps = self.store.get_steps(run_id)
        outputs = {st["step_id"]: json.loads(st["output"] or "{}") for st in steps if st["state"] in ("done", "planned", "noop")}
        stop: Optional[str] = None
        final = "completed"
        problems = 0
        for st in steps:
            if st["state"] not in ("pending", "waiting"):
                continue
            if stop:
                self.store.set_step(run_id, st["idx"], state="skipped", note=stop)
                continue
            step = spec_steps[st["step_id"]]
            rctx = {"alert": alert, "steps": outputs, "run": {"id": label, "operator": run["operator"], "mode": self.mode}}
            outcome = self._run_step(run, st, step, rctx, label)
            if outcome["state"] in ("done", "planned", "noop"):
                outputs[step.id] = outcome.get("output", {})
            if outcome["state"] == "waiting":
                return self._finish(run, "waiting_approval", outcome["note"], None)
            if outcome["state"] in ("refused", "failed"):
                problems += 1
                if step.on_failure == "stop":
                    stop = f"parado: o passo '{step.id}' foi {'recusado' if outcome['state'] == 'refused' else 'falho'}"
                    final = "failed" if outcome["state"] == "failed" else "stopped"
        note = f"{problems} passo(s) recusado(s) ou falho(s) (o playbook seguiu)" if problems and final == "completed" else (stop or "")
        return self._finish(run, final, note, "run_finished")

    def _finish(self, run: Dict[str, Any], state: str, note: str, event: Optional[str]) -> RunResult:
        self.store.set_run(run["id"], state, note, self._iso())
        if event:
            self._audit(run["operator"], event, run["id"], None, {"state": state, "note": note})
        return RunResult(run["id"], run_label(run["id"]), run["playbook"], state, note)

    def _set(self, run_id: int, st: Dict[str, Any], state: str, note: str = "", **extra: Any) -> Dict[str, Any]:
        self.store.set_step(run_id, st["idx"], state=state, note=note, **extra)
        return {"state": state, "note": note, **({"output": json.loads(extra["output"])} if "output" in extra else {})}

    def _run_step(self, run: Dict[str, Any], st: Dict[str, Any], step: Step, rctx: Dict[str, Any], label: str) -> Dict[str, Any]:
        rid, actor = run["id"], run["operator"]
        spec = ACTIONS[step.action]
        try:
            if step.when and not expr.evaluate(step.when, rctx):
                return self._set(rid, st, "skipped", f"condição falsa: {step.when}")
            params = expr.render(step.params, rctx)
        except (expr.ExprError, expr.TemplateError) as exc:
            return self._fail(run, st, step, f"expressão: {exc}")
        actx = {"policy": self.policy, "now": self.now(), "run": label}
        if spec.risk != "read" and not self.policy.automation_enabled:
            return self._refuse(run, st, step, "a automação está desligada pela política (chave de desligamento)")
        try:
            plan = spec.plan(params, self.world, actx)
        except (ActionError, KeyError, TypeError) as exc:
            return self._fail(run, st, step, str(exc))
        pj = canonical(params)
        if plan.refusal:
            return self._refuse(run, st, step, plan.refusal, params=pj)
        if spec.risk == "read":
            try:
                res = spec.apply(params, self.world, actx)
            except (ActionError, KeyError) as exc:
                return self._fail(run, st, step, str(exc))
            return self._set(rid, st, "done", plan.summary, params=pj, output=canonical(res.output))
        key = idempotency_key(step.action, params)
        need_n = 2 if spec.risk in self.policy.two_person_for else 1
        needs_approval = step.approval == "required" or spec.risk in self.policy.approval_required_for
        if self.mode == "dry":
            note = plan.summary + (" (já está assim: nada a fazer)" if plan.noop or key in self.world["applied_keys"] else "")
            if needs_approval:
                note += f" · exigiria {need_n} aprovação(ões)"
            if plan.blast:
                note += f" · raio: {_blast(plan.blast)}"
            return self._set(rid, st, "planned", note, params=pj, output=canonical({"planejado": True, **plan.effect}), idem=key)
        if plan.noop or key in self.world["applied_keys"]:
            self._audit(actor, "step_noop", rid, step.id, {"action": step.action, "motivo": "já aplicado"})
            return self._set(rid, st, "noop", "já estava aplicado: nada foi feito (idempotência)", params=pj, output=canonical(plan.effect), idem=key)
        if needs_approval:
            granted = {a["approver"] for a in self.store.approvals(rid, step.id) if a["decision"] == "approve"}
            if len(granted) < need_n:
                first = st["state"] != "waiting"
                note = f"aguardando {need_n - len(granted)} de {need_n} aprovação(ões) · {plan.summary}" + (f" · raio: {_blast(plan.blast)}" if plan.blast else "")
                self._set(rid, st, "waiting", note, params=pj, idem=key)
                if first:
                    self._audit(actor, "approval_requested", rid, step.id, {"action": step.action, "risk": spec.risk, "aprovacoes_necessarias": need_n, "raio": plan.blast})
                return {"state": "waiting", "note": note}
        since = self._iso(self.now() - timedelta(hours=1))
        limit = self.policy.rate_limit_per_hour.get(step.action)
        if limit and self.store.count_events("step_applied", since, step.action) >= limit:
            return self._refuse(run, st, step, f"limite de taxa: {limit} execução(ões) de {step.action} por hora já foram atingidas", params=pj)
        try:
            res = spec.apply(params, self.world, actx)
            self.world["applied_keys"][key] = {"run": label, "step": step.id, "ts": self._iso()}
            self._save_world()
        except (ActionError, KeyError) as exc:
            return self._fail(run, st, step, str(exc))
        self._audit(actor, "step_applied", rid, step.id, {"action": step.action, "risk": spec.risk, "params": params, "output": res.output, "aprovadores": sorted({a["approver"] for a in self.store.approvals(rid, step.id) if a["decision"] == "approve"})})
        return self._set(rid, st, "done", plan.summary, params=pj, output=canonical(res.output), undo=canonical(res.undo) if res.undo is not None else None, idem=key)

    def _refuse(self, run, st, step, why, params: str = "{}") -> Dict[str, Any]:
        self._audit(run["operator"], "step_refused", run["id"], step.id, {"action": step.action, "motivo": why})
        return self._set(run["id"], st, "refused", why, params=params)

    def _fail(self, run, st, step, why) -> Dict[str, Any]:
        self._audit(run["operator"], "step_failed", run["id"], step.id, {"action": step.action, "motivo": why})
        return self._set(run["id"], st, "failed", why)

    # ---- aprovação ------------------------------------------------------------------------------------------------------------------
    def approve(self, label: str, step_id: str, by: str, reason: str = "") -> RunResult:
        run, st = self._waiting(label, step_id)
        by = _person(by)
        if by.lower() == run["operator"].lower():
            raise SoarError(f"'{by}' iniciou esta execução e não pode aprovar o próprio passo (separação de funções)")
        if any(a["approver"].lower() == by.lower() and a["decision"] == "approve" for a in self.store.approvals(run["id"], step_id)):
            raise SoarError(f"'{by}' já aprovou este passo: duas aprovações precisam ser de pessoas diferentes")
        self.store.add_approval(run["id"], step_id, by, "approve", clean_text(reason, 200), self._iso())
        self._audit(by, "approval_granted", run["id"], step_id, {"motivo": clean_text(reason, 200)})
        return self.advance(run["id"])

    def deny(self, label: str, step_id: str, by: str, reason: str) -> RunResult:
        run, st = self._waiting(label, step_id)
        by, reason = _person(by), clean_text(reason, 200)
        if len(reason) < 5:
            raise SoarError("explique o motivo da negativa (mínimo de 5 caracteres)")
        self.store.add_approval(run["id"], step_id, by, "deny", reason, self._iso())
        self.store.set_step(run["id"], st["idx"], state="denied", note=f"negado por {by}: {reason}")
        for other in self.store.get_steps(run["id"]):
            if other["state"] in ("pending", "waiting"):
                self.store.set_step(run["id"], other["idx"], state="skipped", note="execução abortada pela negativa")
        self._audit(by, "approval_denied", run["id"], step_id, {"motivo": reason})
        return self._finish(run, "aborted", f"negado por {by}: {reason}", "run_aborted")

    def _waiting(self, label: str, step_id: str):
        run = self.store.get_run(parse_label(label))
        if not run:
            raise SoarError(f"execução {label} não existe")
        if run["state"] != "waiting_approval":
            raise SoarError(f"a execução {label} não está aguardando aprovação (estado: {run['state']})")
        st = next((s for s in self.store.get_steps(run["id"]) if s["step_id"] == step_id), None)
        if not st or st["state"] != "waiting":
            raise SoarError(f"o passo '{step_id}' não está aguardando aprovação nesta execução")
        return run, st

    # ---- desfazer -------------------------------------------------------------------------------------------------------------------
    def rollback(self, label: str, by: str, reason: str) -> RunResult:
        run = self.store.get_run(parse_label(label))
        if not run:
            raise SoarError(f"execução {label} não existe")
        by, reason = _person(by), clean_text(reason, 200)
        if len(reason) < 5:
            raise SoarError("explique o motivo de desfazer (mínimo de 5 caracteres)")
        if run["state"] == "rolled_back":
            raise SoarError(f"a execução {label} já foi desfeita")
        done = [s for s in self.store.get_steps(run["id"]) if s["state"] == "done" and s["risk"] != "read"]
        if not done:
            raise SoarError(f"a execução {label} não aplicou nada que possa ser desfeito")
        self._load_world()
        self._audit(by, "rollback_started", run["id"], None, {"motivo": reason})
        actx, irreversible = {"policy": self.policy, "now": self.now(), "run": label}, []
        for st in reversed(done):
            spec = ACTIONS[st["action"]]
            if st["undo"] is None:
                irreversible.append(st["step_id"])
                self.store.set_step(run["id"], st["idx"], state="irreversible", note="não foi desfeito: a ação é irreversível")
                self._audit(by, "step_irreversible", run["id"], st["step_id"], {"action": st["action"]})
                continue
            msg = spec.undo(json.loads(st["undo"]), self.world, actx)
            self.world["applied_keys"].pop(st["idem"], None)                 # a ação pode ser aplicada de novo depois
            self._save_world()
            self.store.set_step(run["id"], st["idx"], state="rolled_back", note=msg)
            self._audit(by, "step_rolled_back", run["id"], st["step_id"], {"action": st["action"], "resultado": msg})
        for st in self.store.get_steps(run["id"]):
            if st["state"] in ("pending", "waiting"):
                self.store.set_step(run["id"], st["idx"], state="skipped", note="execução desfeita")
        note = f"desfeita por {by}: {reason}" + (f" (irreversíveis, não desfeitos: {', '.join(irreversible)})" if irreversible else "")
        return self._finish(run, "rolled_back", note, "rollback_finished")

    # ---- consulta -------------------------------------------------------------------------------------------------------------------
    def describe(self, label: str) -> Dict[str, Any]:
        run = self.store.get_run(parse_label(label))
        if not run:
            raise SoarError(f"execução {label} não existe")
        pb = self.playbooks.get(run["playbook"])
        return {"label": run_label(run["id"]), "playbook": run["playbook"], "name": pb.name if pb else run["playbook"], "state": run["state"], "note": run["note"], "mode": run["mode"],
                "operator": run["operator"], "created": run["created"], "alert": json.loads(run["alert"]), "steps": self.store.get_steps(run["id"]), "approvals": self.store.approvals(run["id"])}


def _blast(blast: Dict[str, Any]) -> str:
    return ", ".join(f"{k}={'sim' if v is True else 'não' if v is False else v}" for k, v in blast.items())


def _person(name: str) -> str:
    n = str(name or "").strip()
    if not re.match(r"^[A-Za-zÀ-ÿ0-9_.\- ]{2,40}$", n):
        raise SoarError("informe quem está agindo (--by NOME, de 2 a 40 caracteres)")
    return n


# ---- testes de playbook ---------------------------------------------------------------------------------------------------------------
@dataclass
class TestResult:
    playbook: str
    name: str
    passed: bool
    message: str = ""


def run_playbook_tests(pb: Playbook, policy: Optional[Policy] = None, base_world: Optional[Dict[str, Any]] = None) -> List[TestResult]:
    """Cada teste simula o alerta (modo dry, nada é gravado) e confere o estado de cada passo."""
    results = []
    for t in pb.tests:
        name = str(t["name"])
        try:
            world = clone(base_world or default_world())
            for section, over in (t.get("world") or {}).items():
                if isinstance(over, dict) and isinstance(world.get(section), dict):
                    world[section].update(over)
            eng = Soar(mode="dry", policy=policy, playbooks=[pb], world=world)
            alert = clean_alert(t["alert"])
            want_match = t.get("expect_matches", True)
            if matches(pb, alert) != want_match:
                results.append(TestResult(pb.id, name, False, "o gatilho " + ("não casou, mas deveria" if want_match else "casou, mas não deveria")))
                eng.close()
                continue
            if not want_match:
                results.append(TestResult(pb.id, name, True))
                eng.close()
                continue
            res = eng.start(pb, alert)
            states = {s["step_id"]: s["state"] for s in eng.store.get_steps(res.run_id)}
            eng.close()
            if t.get("expect_run") and res.state != t["expect_run"]:
                results.append(TestResult(pb.id, name, False, f"a execução terminou em '{res.state}', esperado '{t['expect_run']}'"))
                continue
            wrong = [f"{sid}: {states.get(sid, 'inexistente')} (esperado {want})" for sid, want in (t.get("expect") or {}).items() if states.get(sid) != want]
            results.append(TestResult(pb.id, name, not wrong, "; ".join(wrong)))
        except Exception as exc:                                               # um teste malformado não pode derrubar os outros
            results.append(TestResult(pb.id, name, False, f"erro ao executar: {type(exc).__name__}: {exc}"))
    return results
