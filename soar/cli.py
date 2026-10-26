"""Linha de comando do Playbooker."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

from . import __version__, report
from .engine import Soar, SoarError, run_playbook_tests
from .playbook import PlaybookError, lint, load_dir
from .policy import Policy, PolicyError, defaults_dict, load_policy
from .store import Store, parse_label
from .world import WorldError, default_world, load_world, save_world

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PLAYBOOKS = os.path.join(ROOT, "playbooks")
SAMPLES = os.path.join(ROOT, "samples")
MAX_ALERTS = 100_000


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="playbooker", description="Resposta a incidentes (SOAR) em um mundo SIMULADO: playbooks com testes, aprovação humana, política de segurança e auditoria.",
                                 epilog="Nada aqui toca a rede nem o sistema operacional: as ações só alteram o arquivo do mundo simulado.")
    sub = ap.add_subparsers(dest="cmd")

    def common(p, run=True):
        p.add_argument("--playbooks", default=DEFAULT_PLAYBOOKS, help="pasta de playbooks (padrão: a pasta playbooks/ do projeto)")
        p.add_argument("--world", default="world.json", help="arquivo do mundo simulado (crie com: world init)")
        p.add_argument("--policy", metavar="ARQ.json", help="política de segurança (padrão: a embutida; veja: policy show)")
        p.add_argument("--db", default="soar.db", help="banco com as execuções e a auditoria")
        p.add_argument("--no-color", action="store_true")

    pb = sub.add_parser("playbooks", help="lista, valida, explica e testa os playbooks")
    pbs = pb.add_subparsers(dest="pbcmd")
    for name, text in (("list", "lista os playbooks"), ("validate", "valida os playbooks (o que um revisor conferiria)"), ("test", "roda os testes (x_tests) de cada playbook")):
        q = pbs.add_parser(name, help=text)
        common(q)
        if name == "validate":
            q.add_argument("--strict", action="store_true", help="avisos também fazem o comando falhar")
    ex = pbs.add_parser("explain", help="explica um playbook passo a passo")
    ex.add_argument("id")
    common(ex)

    rn = sub.add_parser("run", help="processa alertas (SIMULAÇÃO por padrão: nada é gravado; use --apply para aplicar no mundo simulado)")
    rn.add_argument("alerts", help="arquivo JSONL (um alerta por linha) ou JSON (um alerta ou uma lista)")
    rn.add_argument("--apply", action="store_true", help="aplica no mundo simulado e grava o banco e a auditoria")
    rn.add_argument("--operator", default="automacao", help="quem iniciou (quem inicia não aprova os próprios passos)")
    rn.add_argument("--only", metavar="ID", help="usa só este playbook")
    common(rn)
    ls = sub.add_parser("runs", help="lista as execuções gravadas")
    common(ls)
    sh = sub.add_parser("show", help="mostra uma execução")
    sh.add_argument("run")
    common(sh)
    ap_ = sub.add_parser("approve", help="aprova um passo que aguarda aprovação")
    ap_.add_argument("run")
    ap_.add_argument("step")
    ap_.add_argument("--by", required=True, metavar="NOME", help="quem aprova (identidade declarada: não é autenticada)")
    ap_.add_argument("--reason", default="")
    common(ap_)
    dn = sub.add_parser("deny", help="nega um passo (a execução é abortada)")
    dn.add_argument("run")
    dn.add_argument("step")
    dn.add_argument("--by", required=True, metavar="NOME")
    dn.add_argument("--reason", required=True)
    common(dn)
    rb = sub.add_parser("rollback", help="desfaz o que a execução aplicou (as ações irreversíveis são apontadas)")
    rb.add_argument("run")
    rb.add_argument("--by", required=True, metavar="NOME")
    rb.add_argument("--reason", required=True)
    common(rb)
    au = sub.add_parser("audit", help="mostra a trilha de auditoria")
    au.add_argument("--run")
    au.add_argument("--limit", type=int, default=40)
    common(au)
    vf = sub.add_parser("verify", help="confere a corrente de hashes da auditoria")
    vf.add_argument("--anchor", metavar="ARQ.json", help="âncora guardada FORA do banco: detecta também o apagamento dos últimos registros")
    common(vf)
    an = sub.add_parser("anchor", help="grava o último hash da auditoria num arquivo (guarde-o fora do banco)")
    an.add_argument("file")
    common(an)
    wd = sub.add_parser("world", help="cria ou mostra o mundo simulado")
    wd.add_argument("action", choices=["init", "show"])
    wd.add_argument("--force", action="store_true")
    common(wd)
    po = sub.add_parser("policy", help="cria ou mostra a política de segurança")
    po.add_argument("action", choices=["init", "show"])
    po.add_argument("file", nargs="?", default="policy.json")
    po.add_argument("--force", action="store_true")
    common(po)
    dm = sub.add_parser("demo", help="percorre tudo com dados FICTÍCIOS: simulação, aplicação, aprovações, recusas, desfazer e verificação")
    dm.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _color(a) -> bool:
    return not getattr(a, "no_color", False) and sys.stdout.isatty()


def _policy(a) -> Policy:
    return load_policy(a.policy) if getattr(a, "policy", None) else Policy()


def _playbooks(a):
    pbs, errors = load_dir(a.playbooks)
    for name, why in errors:
        print(f"Playbook inválido ({name}): {why}", file=sys.stderr)
    return pbs, errors


def load_alerts(path: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"não encontrei '{path}'")
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        return [x for x in data if isinstance(x, dict)][:MAX_ALERTS]
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            print(f"linha {n}: não é JSON válido (ignorada)", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            out.append(obj)
        if len(out) >= MAX_ALERTS:
            break
    return out


def _engine(a, mode: str, pbs) -> Soar:
    world = None if mode == "apply" else (load_world(a.world) if os.path.isfile(a.world) else default_world())
    return Soar(db_path=a.db, world_path=a.world if mode == "apply" else None, policy=_policy(a), playbooks=pbs, mode=mode, world=world)


def cmd_playbooks(a) -> int:
    if not a.pbcmd:
        print("Use: playbooks list | validate | explain ID | test")
        return 0
    pbs, errors = _playbooks(a)
    if a.pbcmd == "list":
        for pb in pbs:
            print(f"{pb.id:<30}{len(pb.steps)} passos · {len(pb.tests)} testes   {pb.name}")
        print(f"\n{len(pbs)} playbook(s)")
        return 1 if errors else 0
    if a.pbcmd == "validate":
        issues = [i for pb in pbs for i in lint(pb)]
        print(report.render_issues(issues, len(pbs), _color(a)))
        bad = bool(errors) or any(i.severity == "error" for i in issues) or (a.strict and any(i.severity == "warning" for i in issues))
        return 1 if bad else 0
    if a.pbcmd == "explain":
        pb = next((p for p in pbs if p.id == a.id), None)
        if not pb:
            print(f"Playbook '{a.id}' não encontrado.", file=sys.stderr)
            return 2
        from .actions import ACTIONS
        print(f"{pb.name}  ({pb.id})\n\n{pb.description}\n")
        print("QUANDO DISPARA: " + (" E ".join(x for x in (f"fonte em {pb.sources}" if pb.sources else "", f"gravidade >= {pb.min_severity}" if pb.min_severity else "",
                                                               f"mensagem contém {pb.contains}" if pb.contains else "") if x) or "qualquer alerta"))
        print("EXIGE NO ALERTA: " + (", ".join(f"{k} ({v})" for k, v in pb.inputs.items()) or "nada além do básico") + "\n\nPASSOS:")
        for i, s in enumerate(pb.steps, 1):
            spec = ACTIONS[s.action]
            print(f"  {i}. {s.id}: {s.action} (risco {report.RISK_PT[spec.risk]}{', irreversível' if not spec.reversible else ''})\n     {spec.about}")
            if s.when:
                print(f"     só se: {s.when}")
            print(f"     se falhar ou for recusado: {'continua' if s.on_failure == 'continue' else 'para'}")
        return 0
    results = [r for pb in pbs for r in run_playbook_tests(pb, _policy(a))]
    for r in results:
        print(f"{'ok    ' if r.passed else 'FALHOU'} {r.playbook}: {r.name}" + (f"  -> {r.message}" if not r.passed else ""))
    bad = [r for r in results if not r.passed]
    print(f"\n{len(results) - len(bad)} de {len(results)} teste(s) passaram em {len(pbs)} playbook(s)")
    return 1 if bad or errors else 0


def cmd_run(a) -> int:
    pbs, errors = _playbooks(a)
    if not pbs:
        print("Nenhum playbook válido.", file=sys.stderr)
        return 2
    alerts = load_alerts(a.alerts)
    eng = _engine(a, "apply" if a.apply else "dry", pbs)
    results, unmatched = [], 0
    for alert in alerts:
        found = eng.handle_alert(alert, a.operator, a.only)
        unmatched += 0 if found else 1
        results += found
    color = _color(a)
    if not a.apply:
        print("SIMULAÇÃO: nada foi gravado (nem o banco, nem o mundo). Use --apply para aplicar no mundo simulado.\n")
    for r in results:
        print(report.render_run(eng.describe(r.label), color), "\n")
    print(report.run_summary(results) + (f" · {unmatched} alerta(s) sem playbook" if unmatched else ""))
    eng.close()
    return 0


def cmd_runs(a) -> int:
    st = Store(a.db)
    print(report.render_runs(st.list_runs()))
    st.close()
    return 0


def _with_engine(a, fn) -> int:
    pbs, _ = _playbooks(a)
    eng = _engine(a, "apply", pbs)
    try:
        res = fn(eng)
        print(report.render_run(eng.describe(res.label), _color(a)))
    finally:
        eng.close()
    return 0


def cmd_approve(a) -> int:
    return _with_engine(a, lambda e: e.approve(a.run, a.step, a.by, a.reason))


def cmd_deny(a) -> int:
    return _with_engine(a, lambda e: e.deny(a.run, a.step, a.by, a.reason))


def cmd_rollback(a) -> int:
    return _with_engine(a, lambda e: e.rollback(a.run, a.by, a.reason))


def cmd_show(a) -> int:
    pbs, _ = _playbooks(a)
    eng = _engine(a, "apply", pbs)
    print(report.render_run(eng.describe(a.run), _color(a)))
    eng.close()
    return 0


def cmd_audit(a) -> int:
    st = Store(a.db)
    print(report.render_audit(st.audit_rows(parse_label(a.run) if a.run else None, a.limit)))
    st.close()
    return 0


def cmd_verify(a) -> int:
    st = Store(a.db)
    anchor = None
    if a.anchor:
        with open(a.anchor, encoding="utf-8") as f:
            anchor = json.load(f)
    ok, msg = st.verify(anchor)
    st.close()
    print(("ÍNTEGRA: " if ok else "ADULTERADA: ") + msg)
    return 0 if ok else 1


def cmd_anchor(a) -> int:
    st = Store(a.db)
    anchor = st.anchor()
    st.close()
    with open(a.file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(anchor, f)
    print(f"Âncora do registro {anchor['seq']} salva em {a.file}. Guarde-a FORA do banco (outra máquina, um cofre, um commit assinado).")
    return 0


def cmd_world(a) -> int:
    if a.action == "init":
        if os.path.exists(a.world) and not a.force:
            print(f"'{a.world}' já existe: use --force para sobrescrever.", file=sys.stderr)
            return 2
        save_world(a.world, default_world())
        print(f"Mundo simulado criado em {a.world} (dados fictícios).")
        return 0
    print(report.render_world(load_world(a.world)))
    return 0


def cmd_policy(a) -> int:
    if a.action == "init":
        if os.path.exists(a.file) and not a.force:
            print(f"'{a.file}' já existe: use --force para sobrescrever.", file=sys.stderr)
            return 2
        with open(a.file, "w", encoding="utf-8", newline="\n") as f:
            json.dump(defaults_dict(), f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"Política gravada em {a.file}.")
        return 0
    print(json.dumps(defaults_dict() if not a.policy else load_policy(a.policy).__dict__, ensure_ascii=False, indent=2, default=list))
    return 0


def cmd_demo(a) -> int:
    from .world import clone
    color = _color(a)
    p = lambda t, k="b": f"{report.ANSI[k]}{t}{report.ANSI['x']}" if color else t  # noqa: E731
    tmp = tempfile.mkdtemp(prefix="playbooker-")
    world_path, db = os.path.join(tmp, "world.json"), os.path.join(tmp, "soar.db")
    save_world(world_path, default_world())
    pbs, _ = load_dir(DEFAULT_PLAYBOOKS)
    alerts = load_alerts(os.path.join(SAMPLES, "alerts.jsonl"))
    print(p("DEMONSTRAÇÃO (dados FICTÍCIOS, mundo simulado em pasta temporária)") + f"\n{len(pbs)} playbooks · {len(alerts)} alertas\n")

    print(p("PASSO 1. Simulação: nada é gravado"))
    dry = Soar(mode="dry", playbooks=pbs, world=default_world())
    dry_results = [r for al in alerts for r in dry.handle_alert(al)]
    print(report.render_run(dry.describe(dry_results[0].label), color, hints=False))
    print("\n" + report.run_summary(dry_results) + "\n(o mundo e o banco continuam intocados)\n")
    dry.close()

    print(p("PASSO 2. Execução no mundo simulado: o que é de baixo risco roda sozinho; o resto espera um humano"))
    eng = Soar(db_path=db, world_path=world_path, playbooks=pbs, mode="apply")
    results = [r for al in alerts for r in eng.handle_alert(al, "automacao")]
    for r in results:
        d = eng.describe(r.label)
        print(f"  {r.label}  {r.playbook:<28}{report.RUN_PT[r.state]:<24}{_alert_hint(d['alert'])}" + (" (duplicada)" if r.duplicate else ""))
    print("\n  " + report.run_summary(results) + "\n")

    print(p("PASSO 3. Aprovações humanas (quem iniciou não aprova; ações de alto risco pedem duas pessoas)"))
    waiting = [r for r in results if r.state == "waiting_approval" and not r.duplicate]
    try:
        eng.approve(waiting[0].label, next(s["step_id"] for s in eng.describe(waiting[0].label)["steps"] if s["state"] == "waiting"), "automacao")
    except SoarError as exc:
        print(f"  tentativa de auto-aprovação: {exc}")
    for r in waiting:
        for _ in range(6):
            d = eng.describe(r.label)
            step = next((s for s in d["steps"] if s["state"] == "waiting"), None)
            if d["state"] != "waiting_approval" or not step:
                break
            have = {x["approver"] for x in d["approvals"] if x["step_id"] == step["step_id"]}
            who = next(n for n in ("bruno", "carla") if n not in have)
            res = eng.approve(r.label, step["step_id"], who, "demonstração")
            print(f"  {who} aprova '{step['step_id']}' em {r.label} -> {report.RUN_PT[res.state]}")
    print()

    print(p("PASSO 4. O que mudou no mundo simulado"))
    print(report.render_world(load_world(world_path)) + "\n")

    print(p("PASSO 5. Desfazer: a primeira execução de bloqueio é revertida"))
    block = next(r for r in results if r.playbook == "bloquear-origem-forca-bruta" and not r.duplicate)
    res = eng.rollback(block.label, "ana", "falso positivo: teste de segurança autorizado")
    print(report.render_run(eng.describe(res.label), color, hints=False) + "\n")

    print(p("PASSO 6. Auditoria"))
    ok, msg = eng.store.verify()
    print(f"  corrente de hashes: {'ÍNTEGRA' if ok else 'ADULTERADA'} ({msg})")
    print(report.render_audit(eng.store.audit_rows(limit=8)))
    print(f"\n  ... {eng.store.anchor()['seq']} registros no total. Para conferir depois: python app.py verify --db {db}")
    eng.close()
    return 0


def _alert_hint(alert: Dict[str, Any]) -> str:
    return " ".join(str(alert[k]) for k in ("ip", "user", "host") if alert.get(k)) or str(alert.get("message", ""))[:40]


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 0
    handlers = {"playbooks": cmd_playbooks, "run": cmd_run, "runs": cmd_runs, "show": cmd_show, "approve": cmd_approve, "deny": cmd_deny, "rollback": cmd_rollback, "audit": cmd_audit,
                "verify": cmd_verify, "anchor": cmd_anchor, "world": cmd_world, "policy": cmd_policy, "demo": cmd_demo}
    try:
        return handlers[a.cmd](a)
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except (SoarError, PlaybookError, PolicyError, WorldError, ValueError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
