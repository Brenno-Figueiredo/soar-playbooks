import contextlib
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar import actions, cli, engine, expr, playbook, policy as pol, report, store, world as wd, yamlite  # noqa: E402
from soar.engine import Soar, SoarError  # noqa: E402
from soar.playbook import PlaybookError, parse_playbook  # noqa: E402
from soar.policy import Policy, PolicyError  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
PLAYBOOKS = os.path.join(ROOT, "playbooks")
SAMPLES = os.path.join(ROOT, "samples")

BRUTE = {"ts": 1, "source": "logwatch", "severity": "high", "message": "Força bruta SSH de 203.0.113.50", "ip": "203.0.113.50"}
BRUTE_INTERNAL = {"source": "logwatch", "severity": "critical", "message": "Força bruta SSH de 10.0.4.12", "ip": "10.0.4.12"}
ACCOUNT = {"source": "loginguard", "severity": "critical", "message": "Login em 'deploy' após falhas", "user": "deploy"}
RANSOM = {"source": "ruleforge", "severity": "critical", "message": "Detecção: Remoção das cópias de sombra (T1490)", "host": "PC-FIN-01"}
PHISH = {"source": "phishguard", "severity": "medium", "message": "E-mail de phishing reportado: boleto falso"}
THREAT = {"source": "threatlens", "severity": "high", "message": "Reputação ruim: 198.51.100.23", "ip": "198.51.100.23"}


def shipped():
    pbs, errors = playbook.load_dir(PLAYBOOKS)
    assert not errors, errors
    return pbs


class Env:
    """Um Soar em modo apply, com mundo e banco em pasta temporária e relógio controlável."""

    def __init__(self, policy=None, world=None, pbs=None):
        self.dir = tempfile.mkdtemp()
        self.world_path = os.path.join(self.dir, "world.json")
        self.db = os.path.join(self.dir, "soar.db")
        wd.save_world(self.world_path, world or wd.default_world())
        self.t = [NOW]
        self.eng = Soar(self.db, self.world_path, policy, pbs or shipped(), "apply", clock=lambda: self.t[0])

    def world(self):
        return wd.load_world(self.world_path)

    def hours(self, n):
        self.t[0] = self.t[0] + timedelta(hours=n)

    def go(self, alert, operator="automacao", only=None):
        return self.eng.handle_alert(alert, operator, only)

    def steps(self, label):
        return {s["step_id"]: s["state"] for s in self.eng.describe(label)["steps"]}

    def close(self):
        self.eng.close()


def env(testcase, **kw):
    e = Env(**kw)
    testcase.addCleanup(e.close)
    return e


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write(directory, name, text):
    p = os.path.join(directory, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


MINI = """id: teste-minimo
name: Teste mínimo
description: Só para os testes.
trigger:
    source: [logwatch]
steps:
    - id: ver
      action: enrich_ip
      params: {ip: '{{ alert.ip }}'}
    - id: bloquear
      action: block_ip
      params: {ip: '{{ alert.ip }}'}
      when: steps.ver.score >= 70
%s
"""


# ---------------------------------------------------------------------------------------------------------------------------------------------
class ExprTests(unittest.TestCase):
    CTX = {"alert": {"severity": "critical", "ip": "203.0.113.50", "message": "Força bruta SSH", "n": 3, "flag": True, "zero": 0, "empty": ""},
           "steps": {"rep": {"score": 92, "known": True, "tags": ["a", "b"]}}, "run": {"id": "R0001"}}

    def test_comparisons_and_logic(self):
        cases = {"steps.rep.score >= 70 or alert.severity == 'critical'": True, "steps.rep.score >= 93": False, "steps.rep.score > 92": False, "steps.rep.score <= 92": True,
                 "steps.rep.score < 92": False, "alert.severity != 'low'": True, "alert.n == 3.0": True, "alert.n == 3": True, "not steps.rep.known": False, "alert.flag": True,
                 "alert.zero": False, "alert.empty": False, "alert.nada": False, "not alert.nada": True, "alert.nada == null": True, "steps.rep.known == true": True,
                 "1 == true": False, "0 == false": False, "'1' == 1": False, "(alert.n > 1 and alert.n < 5) and not alert.x": True, "alert.n > 5 or alert.n < 2": False}
        for text, want in cases.items():
            self.assertEqual(expr.evaluate(text, self.CTX), want, text)

    def test_precedence_and_parentheses(self):
        ctx = {"alert": {"a": True, "b": False, "c": False}}
        self.assertTrue(expr.evaluate("alert.a or alert.b and alert.c", ctx))                 # and vale mais que or
        self.assertFalse(expr.evaluate("(alert.a or alert.b) and alert.c", ctx))
        self.assertTrue(expr.evaluate("not alert.b and alert.a", ctx))
        self.assertFalse(expr.evaluate("not (alert.a or alert.b)", ctx))

    def test_in_operator(self):
        for text, want in {"alert.severity in ['high', 'critical']": True, "alert.severity in ['high']": False, "alert.severity not in ['low']": True, "'força' in alert.message": True,
                           "'FORÇA' in alert.message": True, "'xyz' in alert.message": False, "'xyz' not in alert.message": True, "alert.nada in ['a']": False, "3 in [1, 2, 3]": True,
                           "alert.n in [3.0]": True, "true in [1]": False, "'a' in steps.rep.tags": True, "alert.severity in []": False,
                           "'a' in alert.nada": False, "alert.nada in alert.nada2": False, "alert.nada in 'abc'": False, "'a' not in alert.nada": True, "alert.nada not in 'abc'": True}.items():
            self.assertEqual(expr.evaluate(text, self.CTX), want, text)

    def test_missing_data_never_satisfies_an_ordering(self):
        for text in ("alert.nada > 1", "alert.nada < 1", "alert.nada >= 0", "alert.nada <= 0", "1 < alert.nada"):
            self.assertFalse(expr.evaluate(text, self.CTX), text)

    def test_type_mismatches_are_errors_not_guesses(self):
        for text in ("alert.severity > 5", "alert.message < 'abc'", "alert.n > 'x'", "steps.rep.known > 0", "alert.n in 5", "alert.n in 'abc'", "steps.rep.tags in 5"):
            with self.assertRaises(expr.ExprError, msg=text):
                expr.evaluate(text, self.CTX)

    def test_injection_attempts_are_refused(self):
        bad = ["__import__('os').system('ls')", "alert.ip.__class__", "alert.__dict__", "alert._x == 1", "steps.a._b", "open('/etc/passwd')", "exec('1')", "eval('1')", "lambda: 1",
               "[x for x in alert]", "alert['ip']", "alert.ip()", "alert.ip(1)", "foo.bar == 1", "alert == 1", "run == 1", "alert.n === 3", "alert.n = 3", "alert.n > 1 > 0",
               "a" * 400, "alert.n >", "(alert.n == 3", "alert.n == 3)", "", "   ", "alert.a.b.c.d.e == 1", "alert.severity == 'a\\x41'", "alert.severity == 'a\\nb'", "$(id)", "`id`",
               "alert.n == 3; import os", "alert.n == 3 # x", "alert.n @ 3", "1 + 1", "alert.n * 2", "not", "and", "alert.n and", "alert.n in", "[1, 2", "[1, 2]]", "alert.n ==== 3", "{1: 2}", "alert.n if 1 else 2"]
        for text in bad:
            with self.assertRaises(expr.ExprError, msg=text):
                expr.evaluate(text, self.CTX)

    def test_attribute_looking_paths_are_only_dictionary_keys(self):
        ctx = {"alert": {"n": 3, "s": "texto", "d": {"x": 1}}}
        for path in ("alert.n.real", "alert.s.upper", "alert.s.__len__", "alert.d.keys", "alert.n.numerator"):
            self.assertIsNone(expr.lookup(ctx, path) if "__" not in path else None)              # números e textos não têm "atributos" aqui: o caminho só atravessa dicionários
        self.assertEqual(expr.lookup(ctx, "alert.d.x"), 1)
        with self.assertRaises(expr.ExprError):
            expr.evaluate("alert.s.__len__", ctx)

    def test_limits(self):
        with self.assertRaises(expr.ExprError):
            expr.parse("alert.n == 1 " + "or alert.n == 1 " * 40)                               # símbolos demais
        deep = "(" * 20 + "alert.n" + ")" * 20
        with self.assertRaises(expr.ExprError):
            expr.parse(deep)
        self.assertTrue(expr.evaluate("(" * 5 + "alert.n" + ")" * 5, self.CTX))

    def test_string_literals(self):
        ctx = {"alert": {"s": "a'b", "t": 'a"b', "u": "a\\b"}}
        self.assertTrue(expr.evaluate("alert.s == 'a\\'b'", ctx))
        self.assertTrue(expr.evaluate('alert.t == "a\\"b"', ctx))
        self.assertTrue(expr.evaluate("alert.u == 'a\\\\b'", ctx))

    def test_paths(self):
        self.assertEqual(expr.paths_in(expr.parse("steps.a.x >= 1 and (alert.y in ['a'] or not run.id)")), ["steps.a.x", "alert.y", "run.id"])
        for bad in ("foo.x", "alert", "alert._x", "a" ):
            with self.assertRaises(expr.ExprError):
                expr.check_path(bad)
        self.assertEqual(expr.check_path("steps.a.b"), ["steps", "a", "b"])
        self.assertTrue(expr.evaluate("alert.not == 1", {"alert": {"not": 1}}))                 # palavra reservada como parte de um caminho é só um nome

    def test_templates(self):
        ctx = {"alert": {"ip": "1.2.3.4", "n": 7, "ok": True}, "steps": {"r": {"score": 9}}, "run": {"id": "R0002"}}
        self.assertEqual(expr.render("{{ alert.n }}", ctx), 7)                                  # valor inteiro preserva o tipo
        self.assertEqual(expr.render(" {{alert.ok}} ", ctx), True)
        self.assertEqual(expr.render("IP {{ alert.ip }} nota {{ steps.r.score }} ({{ run.id }})", ctx), "IP 1.2.3.4 nota 9 (R0002)")
        self.assertEqual(expr.render({"a": ["{{ alert.ip }}", 5, None], "b": {"c": "{{ alert.n }}"}}, ctx), {"a": ["1.2.3.4", 5, None], "b": {"c": 7}})
        self.assertEqual(expr.render(42, ctx), 42)
        self.assertEqual(expr.template_paths({"a": "{{ alert.ip }} e {{ steps.r.score }}", "b": ["{{ run.id }}"]}), ["alert.ip", "steps.r.score", "run.id"])

    def test_templates_refuse_missing_and_forbidden(self):
        ctx = {"alert": {"ip": "1.2.3.4"}, "steps": {}, "run": {}}
        for bad in ("{{ alert.nao }}", "x {{ alert.nao }}", "{{ steps.a.b }}"):
            with self.assertRaises(expr.TemplateError, msg=bad):
                expr.render(bad, ctx)
        for bad in ("{{ foo.bar }}", "{{ alert._x }}", "{{ alert }}"):
            with self.assertRaises(expr.ExprError, msg=bad):
                expr.render(bad, ctx)
        with self.assertRaises(expr.TemplateError):
            expr.render("{{ alert.big }}" * 1, {"alert": {"big": "x" * 3000}, "steps": {}, "run": {}}) if False else expr.render("a {{ alert.big }}", {"alert": {"big": "x" * 3000}, "steps": {}, "run": {}})

    def test_template_injection_stays_literal(self):
        ctx = {"alert": {"message": "{{ steps.r.score }} e {{ run.id }}"}, "steps": {"r": {"score": 1}}, "run": {"id": "R1"}}
        self.assertEqual(expr.render("{{ alert.message }}", ctx), "{{ steps.r.score }} e {{ run.id }}")
        self.assertEqual(expr.render("x {{ alert.message }}", ctx), "x {{ steps.r.score }} e {{ run.id }}")


class YamlSmokeTests(unittest.TestCase):
    def test_what_playbooks_need(self):
        d = yamlite.load("a: >-\n  dobra\n  aqui\nb: {k: 'v, w', n: [1, 2]}\nc:\n  - x: 1\n    y: 2\nd: \"com 'aspas'\"\n")
        self.assertEqual(d, {"a": "dobra aqui", "b": {"k": "v, w", "n": [1, 2]}, "c": [{"x": 1, "y": 2}], "d": "com 'aspas'"})

    def test_refuses_unsafe_yaml(self):
        for bad in ("a: &x 1", "a: *x", "a: !!python/object:os.system x", "\ta: 1", "a: 'abc", "a:\n  b: 1\n  b: 2"):
            with self.assertRaises(yamlite.YamlError, msg=bad):
                yamlite.load(bad)


class PlaybookParseTests(unittest.TestCase):
    def test_shipped_playbooks(self):
        pbs = shipped()
        self.assertEqual([p.id for p in pbs], ["bloquear-origem-forca-bruta", "conta-comprometida", "host-com-ransomware", "ip-reputacao-ruim", "phishing-reportado"])
        self.assertEqual(sum(len(p.tests) for p in pbs), 19)
        self.assertEqual(len({p.fingerprint for p in pbs}), 5)

    def test_structure_errors(self):
        step = "steps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n"
        base = "id: pb-teste\n"
        bad = {"": "YAML inválido", base + "nome: x\n" + step: "chave desconhecida", "id: Maiúscula\n" + step: "'id'", "id: ab\n" + step: "'id'", base: "'steps'", base + "steps: []\n": "'steps'",
               base + "steps:\n  - {id: a, action: enrich_ip, foo: 1}\n": "aceita", base + "steps:\n  - {id: A, action: enrich_ip}\n": "'id' inválido", base + "steps:\n  - {id: a}\n": "falta 'action'",
               base + "steps:\n  - {id: a, action: enrich_ip, params: 5}\n": "'params'", base + "steps:\n  - {id: a, action: enrich_ip, when: 'alert.x >'}\n": "condição inválida",
               base + "steps:\n  - {id: a, action: enrich_ip, approval: talvez}\n": "approval", base + "steps:\n  - {id: a, action: enrich_ip, on_failure: ignorar}\n": "on_failure",
               base + "trigger: {foo: 1}\n" + step: "'trigger'", base + "trigger: {min_severity: enorme}\n" + step: "min_severity", base + "inputs: {ip: ipv9}\n" + step: "'inputs'",
               base + "inputs: {IP: ip}\n" + step: "'inputs'", base + "x_tests: [1]\n" + step: "x_tests", base + "x_tests: [{name: x}]\n" + step: "x_tests", base + "trigger: {source: [1, 2]}\n" + step: "gatilho",
               "[1, 2]": "YAML inválido", "a: &x 1": "YAML inválido"}
        for text, needle in bad.items():
            with self.assertRaises(PlaybookError, msg=text[:60]) as ctx:
                parse_playbook(text)
            self.assertIn(needle, str(ctx.exception), text[:60])

    def test_limits(self):
        many = "id: pb-teste\nsteps:\n" + "".join(f"  - {{id: s{i}, action: enrich_ip, params: {{ip: '1.1.1.1'}}}}\n" for i in range(21))
        with self.assertRaises(PlaybookError):
            parse_playbook(many)
        with self.assertRaises(PlaybookError):
            parse_playbook("id: pb-teste\ndescription: " + "x" * 210000 + "\nsteps: []\n")

    def test_defaults_and_fingerprint(self):
        pb = parse_playbook(MINI % "")
        self.assertEqual((pb.steps[0].approval, pb.steps[0].on_failure, pb.steps[1].when), ("auto", "stop", "steps.ver.score >= 70"))
        self.assertEqual(parse_playbook(MINI % "").fingerprint, pb.fingerprint)
        self.assertNotEqual(parse_playbook(MINI % "# mudou\n").fingerprint, pb.fingerprint)

    def test_load_dir_isolates_broken_files_and_duplicate_ids(self):
        d = tempfile.mkdtemp()
        write(d, "a.yml", MINI % "")
        write(d, "b.yml", MINI % "")                                                            # mesmo id
        write(d, "c.yml", "id: x\n\tsteps: 1\n")
        write(d, "d.txt", "não é playbook")
        pbs, errors = playbook.load_dir(d)
        self.assertEqual(len(pbs), 1)
        self.assertEqual(sorted(e[0] for e in errors), ["b.yml", "c.yml"])
        self.assertIn("id repetido", dict(errors)["b.yml"])
        with self.assertRaises(FileNotFoundError):
            playbook.load_dir("/nao/existe")

    def test_trigger_matching(self):
        pb = parse_playbook(MINI % "")
        self.assertTrue(playbook.matches(pb, {"source": "LogWatch"}))                           # sem diferenciar maiúsculas
        self.assertFalse(playbook.matches(pb, {"source": "outra"}))
        self.assertFalse(playbook.matches(pb, {}))
        full = shipped()[0]
        self.assertTrue(playbook.matches(full, BRUTE))
        self.assertFalse(playbook.matches(full, dict(BRUTE, severity="medium")))                # gravidade mínima
        self.assertTrue(playbook.matches(full, dict(BRUTE, severity="CRITICAL")))
        self.assertFalse(playbook.matches(full, dict(BRUTE, message="outra coisa")))             # a mensagem precisa conter um dos textos
        self.assertTrue(playbook.matches(full, dict(BRUTE, message="BRUTE FORCE detectado")))
        self.assertFalse(playbook.matches(full, dict(BRUTE, source="threatlens")))               # E entre as condições
        open_pb = parse_playbook("id: aberto\nsteps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n")
        self.assertTrue(playbook.matches(open_pb, {}))


class LintTests(unittest.TestCase):
    def codes(self, text):
        return {i.code for i in playbook.lint(parse_playbook(text))}

    def test_shipped_playbooks_have_no_errors_or_warnings(self):
        for pb in shipped():
            self.assertEqual([i for i in playbook.lint(pb) if i.severity != "info"], [], pb.id)

    def test_each_code(self):
        head = "id: pb-teste\ndescription: d\ntrigger: {source: [x]}\nx_tests: [{name: t, alert: {a: 1}}]\nsteps:\n"
        cases = {
            "E101": head + "  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n",
            "E102": head + "  - {id: a, action: apagar_tudo, params: {}}\n",
            "E103": head + "  - {id: a, action: enrich_ip, params: {}}\n",
            "E104": head + "  - {id: a, action: enrich_ip, params: {ip: '{{ foo.bar }}'}}\n",
            "E105": head + "  - {id: a, action: enrich_ip, params: {ip: '{{ steps.b.x }}'}}\n  - {id: b, action: enrich_ip, params: {ip: '1.1.1.1'}}\n",
            "W110": head + "  - {id: a, action: enrich_ip, params: {ip: '{{ alert.zzz }}'}}\n",
            "W101": head + "  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n  - {id: b, action: block_ip, params: {ip: '1.1.1.1'}}\n",
            "W102": head + "  - {id: b, action: block_ip, params: {ip: '1.1.1.1'}, when: 'alert.a == 1'}\n",
            "I101": head + "  - {id: a, action: lookup_user, params: {user: x}}\n  - {id: b, action: disable_account, params: {user: x}, when: 'alert.a == 1', on_failure: continue}\n",
            "I102": head + "  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}, approval: required}\n",
            "W103": "id: pb-teste\ndescription: d\nx_tests: [{name: t, alert: {a: 1}}]\nsteps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n",
            "W104": "id: pb-teste\ndescription: d\ntrigger: {source: [x]}\nsteps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n",
            "W105": "id: pb-teste\ntrigger: {source: [x]}\nx_tests: [{name: t, alert: {a: 1}}]\nsteps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n",
        }
        for code, text in cases.items():
            self.assertIn(code, self.codes(text), code)
        many = head + "  - {id: r, action: lookup_user, params: {user: x}}\n" + "".join(f"  - {{id: m{i}, action: revoke_sessions, params: {{user: x}}, when: 'alert.a == 1'}}\n" for i in range(4))
        self.assertIn("W106", self.codes(many))

    def test_declared_inputs_and_well_known_fields_do_not_warn(self):
        text = ("id: pb-teste\ndescription: d\ntrigger: {source: [x]}\ninputs: {ip: ip}\nx_tests: [{name: t, alert: {a: 1}}]\nsteps:\n"
                "  - {id: a, action: enrich_ip, params: {ip: '{{ alert.ip }}'}}\n  - {id: n, action: notify, params: {channel: soc, message: '{{ alert.message }} {{ alert.severity }}'}}\n")
        self.assertEqual(self.codes(text), set())


# ---------------------------------------------------------------------------------------------------------------------------------------------
class PolicyTests(unittest.TestCase):
    def test_defaults(self):
        p = Policy()
        p.validate()
        self.assertEqual(Policy.from_dict(pol.defaults_dict()), p)
        json.dumps(pol.defaults_dict())

    def test_overrides(self):
        p = Policy.from_dict({"automation_enabled": False, "max_block_prefix_v4": 28, "rate_limit_per_hour": {"block_ip": 2}, "protected_hosts": ["X"], "two_person_for": []})
        self.assertEqual((p.automation_enabled, p.max_block_prefix_v4, p.rate_limit_per_hour["block_ip"], p.rate_limit_per_hour["disable_account"], p.protected_hosts, p.two_person_for),
                         (False, 28, 2, 5, ("X",), ()))

    def test_invalid(self):
        bad = [({"nada": 1}, "desconhecida"), ({"automation_enabled": "sim"}, "true ou false"), ({"max_steps_per_run": 0}, "positivo"), ({"max_steps_per_run": True}, "positivo"),
               ({"protected_hosts": "DC"}, "lista"), ({"protected_hosts": [1]}, "lista"), ({"rate_limit_per_hour": {"foo": 1}}, "ações"), ({"rate_limit_per_hour": {"block_ip": 0}}, "ações"),
               ({"approval_required_for": ["read"]}, "só aceita"), ({"two_person_for": ["low"]}, "contido"), ({"protected_nets": ["lixo"]}, "inválida"), ({"protected_nets": ["10.0.0.1/8"]}, "inválida"),
               ({"max_block_prefix_v4": 4}, "prefixos"), ({"max_block_prefix_v6": 8}, "prefixos"), ({"block_hours_max": 10 ** 6}, "um ano"), ([], "objeto")]
        for data, needle in bad:
            with self.assertRaises(PolicyError, msg=str(data)) as ctx:
                Policy.from_dict(data)
            self.assertIn(needle, str(ctx.exception), str(data))

    def test_protected_networks(self):
        import ipaddress as ip
        p = Policy()
        for net in ("10.1.2.3/32", "10.0.0.0/8", "192.168.1.0/24", "172.20.0.0/16", "127.0.0.1/32", "169.254.1.1/32", "0.0.0.0/0", "8.0.0.0/5", "::1/128", "fe80::1/128", "fc00::/7", "224.0.0.1/32"):
            self.assertTrue(p.is_protected_net(ip.ip_network(net)), net)
        for net in ("203.0.113.50/32", "198.51.100.0/24", "192.0.2.99/32", "8.8.8.8/32", "2001:db8::1/128"):
            self.assertFalse(p.is_protected_net(ip.ip_network(net)), net)                        # os "atacantes" fictícios (RFC 5737) NÃO são protegidos

    def test_protected_names_ignore_case(self):
        p = Policy()
        self.assertTrue(p.is_protected_account("BREAK-GLASS"))
        self.assertTrue(p.is_protected_host("dc-01"))
        self.assertFalse(p.is_protected_account("ana"))

    def test_load_policy(self):
        d = tempfile.mkdtemp()
        with self.assertRaises(PolicyError):
            pol.load_policy(write(d, "x.json", "{quebrado"))
        self.assertFalse(pol.load_policy(write(d, "p.json", '{"automation_enabled": false}')).automation_enabled)
        with open(os.path.join(SAMPLES, "policy.example.json"), encoding="utf-8") as f:
            self.assertEqual(Policy.from_dict(json.load(f)), Policy())


class WorldTests(unittest.TestCase):
    def test_default_is_valid_and_has_the_demo_actors(self):
        w = wd.validate_world(wd.default_world())
        self.assertEqual(set(w), set(wd.SECTIONS))
        self.assertTrue({"deploy", "break-glass", "ana"} <= set(w["directory"]))
        self.assertEqual(w["hosts"]["DC-01"]["criticality"], "critical")

    def test_validation(self):
        for data, needle in (([], "objeto"), ({"nada": {}}, "desconhecida"), ({"blocklist": []}, "objeto"), ({"tickets": {}}, "lista"), ({"directory": {"a": 5}}, "mal formado"),
                             ({"directory": {"a": {"active": "sim"}}}, "mal formado"), ({"hosts": {"h": {"criticality": "enorme"}}}, "mal formado")):
            with self.assertRaises(wd.WorldError, msg=str(data)) as ctx:
                wd.validate_world(data)
            self.assertIn(needle, str(ctx.exception))
        self.assertEqual(wd.validate_world({}), wd.empty_world())

    def test_round_trip_and_errors(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "w.json")
        wd.save_world(path, wd.default_world())
        self.assertEqual(wd.load_world(path), wd.default_world())
        with self.assertRaises(wd.WorldError):
            wd.load_world(os.path.join(d, "nao.json"))
        with self.assertRaises(wd.WorldError):
            wd.load_world(write(d, "b.json", "{quebrado"))
        with mock.patch.object(wd, "MAX_WORLD", 10), self.assertRaises(wd.WorldError):
            wd.load_world(path)

    def test_save_is_atomic(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "w.json")
        wd.save_world(path, wd.default_world())
        before = sha(path)
        with mock.patch("os.replace", side_effect=OSError("queda no meio")), self.assertRaises(OSError):
            wd.save_world(path, wd.empty_world())
        self.assertEqual(sha(path), before)                                                      # o mundo antigo continua inteiro
        self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])                    # e não sobra arquivo temporário

    def test_clone_is_deep(self):
        w = wd.default_world()
        c = wd.clone(w)
        c["directory"]["ana"]["active"] = False
        self.assertTrue(w["directory"]["ana"]["active"])


# ---------------------------------------------------------------------------------------------------------------------------------------------
class ActionTests(unittest.TestCase):
    def setUp(self):
        self.w = wd.default_world()
        self.ctx = {"policy": Policy(), "now": NOW, "run": "R0001"}

    def plan(self, name, **p):
        return actions.ACTIONS[name].plan(p, self.w, self.ctx)

    def apply(self, name, **p):
        return actions.ACTIONS[name].apply(p, self.w, self.ctx)

    def undo(self, name, applied):
        return actions.ACTIONS[name].undo(applied.undo, self.w, self.ctx)

    def test_registry(self):
        risks = {n: s.risk for n, s in actions.ACTIONS.items()}
        self.assertEqual(risks, {"enrich_ip": "read", "lookup_user": "read", "lookup_host": "read", "open_ticket": "low", "notify": "low", "block_ip": "medium", "revoke_sessions": "medium",
                                 "disable_account": "high", "isolate_host": "high"})
        self.assertEqual({n for n, s in actions.ACTIONS.items() if not s.reversible}, {"notify", "revoke_sessions"})
        for s in actions.ACTIONS.values():
            self.assertGreater(len(s.about), 20)
        self.assertEqual({n for n, s in actions.ACTIONS.items() if s.risk in ("medium", "high")}, set(pol.MUTATING_ACTIONS))

    def test_enrich_ip(self):
        e = self.plan("enrich_ip", ip="203.0.113.50").effect
        self.assertEqual((e["score"], e["reputation"], e["known"], e["tags"]), (92, "ruim", True, ["ssh-bruteforce"]))
        self.assertEqual(self.plan("enrich_ip", ip="192.0.2.99").effect["reputation"], "suspeito")
        unknown = self.plan("enrich_ip", ip="1.2.3.4").effect
        self.assertEqual((unknown["score"], unknown["known"], unknown["reputation"]), (None, False, "desconhecido"))
        self.w["intel"]["9.9.9.9"] = {"score": 10}
        self.assertEqual(self.plan("enrich_ip", ip="9.9.9.9").effect["reputation"], "limpo")
        with self.assertRaises(actions.ActionError):
            self.plan("enrich_ip", ip="não é ip")
        before = json.dumps(self.w, sort_keys=True)
        self.apply("enrich_ip", ip="203.0.113.50")
        self.assertEqual(json.dumps(self.w, sort_keys=True), before)                             # consulta nunca altera

    def test_lookups(self):
        u = self.plan("lookup_user", user="DEPLOY").effect
        self.assertEqual((u["known"], u["privileged"], u["active"]), (True, True, True))
        self.assertFalse(self.plan("lookup_user", user="fantasma").effect["known"])
        h = self.plan("lookup_host", host="dc-01").effect
        self.assertEqual((h["known"], h["criticality"]), (True, "critical"))
        for bad in ("x; rm -rf /", "a b", "", "é" * 3, "a" * 80):
            with self.assertRaises(actions.ActionError, msg=bad):
                self.plan("lookup_user", user=bad)
        with self.assertRaises(actions.ActionError):
            self.plan("lookup_host", host="../etc")

    def test_block_ip_lifecycle(self):
        p = self.plan("block_ip", ip="203.0.113.50", hours=2)
        self.assertEqual((p.refusal, p.noop, p.blast, p.effect["horas"]), ("", False, {"enderecos": 1}, 2))
        a = self.apply("block_ip", ip="203.0.113.50", hours=2, reason="teste")
        self.assertEqual(self.w["blocklist"]["203.0.113.50/32"]["expires"], "2026-10-26T14:00:00Z")
        self.assertTrue(self.plan("block_ip", ip="203.0.113.50").noop)                          # já bloqueado: nada a fazer
        self.undo("block_ip", a)
        self.assertNotIn("203.0.113.50/32", self.w["blocklist"])

    def test_block_ip_expired_is_not_blocked(self):
        self.w["blocklist"]["203.0.113.50/32"] = {"expires": "2026-10-26T11:00:00Z", "reason": "velho", "run": "R0"}
        self.assertFalse(self.plan("block_ip", ip="203.0.113.50").noop)
        a = self.apply("block_ip", ip="203.0.113.50")
        self.undo("block_ip", a)
        self.assertEqual(self.w["blocklist"]["203.0.113.50/32"]["reason"], "velho")              # o desfazer restaura a entrada anterior

    def test_block_ip_refusals_and_validation(self):
        for ip in ("10.0.4.12", "192.168.1.1", "127.0.0.1", "0.0.0.0/0", "10.0.0.0/8", "::1", "fe80::1", "224.0.0.5"):
            self.assertIn("protegida", self.plan("block_ip", ip=ip).refusal, ip)
        for ip in ("203.0.0.0/16", "203.0.112.0/23", "2001:db8::/32"):
            self.assertIn("grande demais", self.plan("block_ip", ip=ip).refusal, ip)
        self.assertEqual(self.plan("block_ip", ip="203.0.113.0/24").refusal, "")
        self.assertEqual(self.plan("block_ip", ip="203.0.113.0/24").blast, {"enderecos": 256})
        self.assertEqual(self.plan("block_ip", ip="2001:db8::/64").refusal, "")
        for ip in ("203.0.113.0/16", "javascript:alert(1)", "", "1.2.3", "1.2.3.4/33", "203.0.113.5; id"):
            with self.assertRaises(actions.ActionError, msg=ip):
                self.plan("block_ip", ip=ip)
        for h in (0, -1, 721, "24", True, 1.5, None):
            with self.assertRaises(actions.ActionError, msg=repr(h)):
                self.plan("block_ip", ip="203.0.113.5", hours=h)
        self.assertEqual(self.plan("block_ip", ip="203.0.113.5", hours=720).refusal, "")

    def test_disable_account(self):
        p = self.plan("disable_account", user="deploy")
        self.assertEqual((p.refusal, p.noop, p.blast), ("", False, {"privilegiada": True}))
        a = self.apply("disable_account", user="DEPLOY")
        self.assertFalse(self.w["directory"]["deploy"]["active"])
        self.assertTrue(self.plan("disable_account", user="deploy").noop)
        self.undo("disable_account", a)
        self.assertTrue(self.w["directory"]["deploy"]["active"])
        for user in ("break-glass", "BREAK-GLASS", "svc-backup"):
            self.assertIn("protegida", self.plan("disable_account", user=user).refusal)
        self.assertIn("não existe", self.plan("disable_account", user="fantasma").refusal)
        self.assertFalse(self.plan("disable_account", user="ana").blast["privilegiada"])

    def test_revoke_sessions_is_irreversible(self):
        p = self.plan("revoke_sessions", user="deploy")
        self.assertEqual((p.effect, p.noop), ({"sessoes_encerradas": 3}, False))
        a = self.apply("revoke_sessions", user="deploy")
        self.assertIsNone(a.undo)
        self.assertEqual(self.w["directory"]["deploy"]["sessions"], 0)
        self.assertTrue(self.plan("revoke_sessions", user="deploy").noop)
        self.assertIn("protegida", self.plan("revoke_sessions", user="break-glass").refusal)

    def test_isolate_host(self):
        self.assertEqual(self.plan("isolate_host", host="PC-FIN-01").refusal, "")
        self.assertEqual(self.plan("isolate_host", host="SRV-APP-01").refusal, "")             # criticidade alta ainda é permitida
        self.assertIn("protegido", self.plan("isolate_host", host="DC-01").refusal)
        self.assertIn("não existe", self.plan("isolate_host", host="PC-X").refusal)
        self.w["hosts"]["DB-01"] = {"criticality": "critical", "isolated": False}
        self.assertIn("crítico", self.plan("isolate_host", host="DB-01").refusal)
        self.ctx["policy"] = Policy(isolate_critical=True)
        self.assertEqual(self.plan("isolate_host", host="DB-01").refusal, "")
        a = self.apply("isolate_host", host="pc-fin-01")
        self.assertTrue(self.w["hosts"]["PC-FIN-01"]["isolated"])
        self.assertTrue(self.plan("isolate_host", host="PC-FIN-01").noop)
        self.undo("isolate_host", a)
        self.assertFalse(self.w["hosts"]["PC-FIN-01"]["isolated"])

    def test_tickets_are_deterministic_and_never_deleted(self):
        p = dict(title="Força bruta", severity="high", body="detalhe")
        a, b = self.plan("open_ticket", **p), self.plan("open_ticket", **p)
        self.assertEqual(a.effect["chamado"], b.effect["chamado"])
        self.assertRegex(a.effect["chamado"], r"^TCK-[0-9A-F]{8}$")
        self.assertNotEqual(self.plan("open_ticket", **dict(p, body="outro")).effect["chamado"], a.effect["chamado"])
        applied = self.apply("open_ticket", **p)
        self.assertTrue(self.plan("open_ticket", **p).noop)
        self.undo("open_ticket", applied)
        self.assertEqual(self.w["tickets"][0]["status"], "cancelled")                           # fica o rastro
        self.assertFalse(self.plan("open_ticket", **p).noop)
        for bad in (dict(title="", severity="high"), dict(title="x", severity="enorme"), dict(title="  \n ", severity="low")):
            with self.assertRaises(actions.ActionError):
                self.plan("open_ticket", **bad)

    def test_notify(self):
        a = self.apply("notify", channel="soc", message="Olá")
        self.assertEqual(self.w["notifications"][0]["message"], "Olá")
        self.assertIsNone(a.undo)
        for bad in (dict(channel="todos", message="x"), dict(channel="soc", message=""), dict(channel="soc", message="\x00\x1f ")):
            with self.assertRaises(actions.ActionError):
                self.plan("notify", **bad)

    def test_text_from_alerts_is_sanitized(self):
        self.assertEqual(actions.clean_text("a\x00b\x1b[31m\n\tc   d\x7f", 50), "a b [31m c d")
        self.assertEqual(len(actions.clean_text("x" * 600, 100)), 100)
        self.assertTrue(actions.clean_text("x" * 600, 100).endswith("…"))
        self.apply("open_ticket", title="T\x00ítulo\n" + "x" * 300, severity="low", body="b" * 2000)
        t = self.w["tickets"][0]
        self.assertEqual((len(t["title"]), len(t["body"])), (120, 1000))
        self.assertNotIn("\x00", t["title"])

    def test_idempotency_key(self):
        k = actions.idempotency_key
        self.assertEqual(k("block_ip", {"ip": "1.1.1.1", "hours": 2}), k("block_ip", {"hours": 2, "ip": "1.1.1.1"}))
        self.assertNotEqual(k("block_ip", {"ip": "1.1.1.1"}), k("block_ip", {"ip": "1.1.1.2"}))
        self.assertNotEqual(k("block_ip", {"ip": "1.1.1.1"}), k("disable_account", {"ip": "1.1.1.1"}))


# ---------------------------------------------------------------------------------------------------------------------------------------------
class StoreTests(unittest.TestCase):
    def filled(self, n=5):
        s = store.Store(":memory:")
        for i in range(n):
            s.audit("ana", "evento", 1, "p", {"i": i}, f"2026-10-26T12:00:0{i}Z")
        return s

    def test_chain_is_valid_and_deterministic(self):
        s = self.filled()
        self.assertTrue(s.verify()[0])
        rows = s.audit_rows()
        self.assertEqual((rows[0]["prev"], rows[1]["prev"]), (store.GENESIS, rows[0]["hash"]))
        self.assertEqual(len({r["hash"] for r in rows}), 5)
        t = self.filled()
        self.assertEqual([r["hash"] for r in t.audit_rows()], [r["hash"] for r in rows])        # mesmo conteúdo, mesma corrente

    def test_empty_trail(self):
        s = store.Store(":memory:")
        self.assertTrue(s.verify()[0])
        self.assertEqual(s.anchor(), {"seq": 0, "hash": store.GENESIS})
        self.assertTrue(s.verify({"seq": 0, "hash": store.GENESIS})[0])

    def test_the_program_cannot_edit_or_delete(self):
        s = self.filled()
        for sql in ("UPDATE audit SET actor='x' WHERE seq=1", "DELETE FROM audit WHERE seq=1", "UPDATE audit SET data='{}'", "DELETE FROM audit"):
            with self.assertRaises(sqlite3.DatabaseError, msg=sql):
                s.db.execute(sql)

    def tamper(self, s, sql):
        s.db.execute("DROP TRIGGER audit_no_update")                                            # quem tem o arquivo pode derrubar os triggers: é a corrente que acusa
        s.db.execute("DROP TRIGGER audit_no_delete")
        s.db.execute(sql)
        s.db.commit()

    def test_tampering_is_detected(self):
        cases = {"conteúdo alterado": ("UPDATE audit SET data='{\"i\":99}' WHERE seq=3", "ALTERADO"), "autor trocado": ("UPDATE audit SET actor='mallory' WHERE seq=2", "ALTERADO"),
                 "evento trocado": ("UPDATE audit SET event='nada' WHERE seq=4", "ALTERADO"), "hora trocada": ("UPDATE audit SET ts='2020-01-01T00:00:00Z' WHERE seq=1", "ALTERADO"),
                 "registro apagado no meio": ("DELETE FROM audit WHERE seq=3", "ausente"), "primeiro apagado": ("DELETE FROM audit WHERE seq=1", "ausente"),
                 "elo trocado": ("UPDATE audit SET prev='" + "f" * 64 + "' WHERE seq=3", "quebrada")}
        for name, (sql, needle) in cases.items():
            s = self.filled()
            self.tamper(s, sql)
            ok, msg = s.verify()
            self.assertFalse(ok, name)
            self.assertIn(needle, msg, name)

    def test_truncation_needs_the_anchor(self):
        s = self.filled()
        anchor = s.anchor()
        self.tamper(s, "DELETE FROM audit WHERE seq>3")
        self.assertTrue(s.verify()[0])                                                           # sem âncora, o que sobrou parece íntegro: o limite que o README declara
        ok, msg = s.verify(anchor)
        self.assertFalse(ok)
        self.assertIn("APAGADOS", msg)

    def test_rewritten_trail_does_not_match_the_anchor(self):
        s = self.filled()
        anchor = s.anchor()
        t = store.Store(":memory:")
        for i in range(5):
            t.audit("ana", "evento", 1, "p", {"i": i + 100}, f"2026-10-26T12:00:0{i}Z")       # corrente refeita do zero, internamente consistente
        self.assertTrue(t.verify()[0])
        ok, msg = t.verify(anchor)
        self.assertFalse(ok)
        self.assertIn("reescrita", msg)

    def test_anchor_matches_when_untouched(self):
        s = self.filled()
        a = s.anchor()
        self.assertTrue(s.verify(a)[0])
        s.audit("ana", "mais um", 1, "p", {}, "2026-10-26T12:01:00Z")
        self.assertTrue(s.verify(a)[0])                                                          # crescer depois da âncora é normal

    def test_labels(self):
        self.assertEqual((store.run_label(3), store.parse_label("R0007"), store.parse_label(" r12 ")), ("R0003", 7, 12))
        for bad in ("7", "RX", "R", "", "R-1", "abc"):
            with self.assertRaises(ValueError, msg=bad):
                store.parse_label(bad)

    def test_count_events_and_find_recent(self):
        s = store.Store(":memory:")
        s.audit("a", "step_applied", 1, "x", {"action": "block_ip"}, "2026-10-26T11:30:00Z")
        s.audit("a", "step_applied", 1, "y", {"action": "notify"}, "2026-10-26T11:40:00Z")
        s.audit("a", "step_applied", 1, "x", {"action": "block_ip"}, "2026-10-26T09:00:00Z")
        self.assertEqual(s.count_events("step_applied", "2026-10-26T11:00:00Z"), 2)
        self.assertEqual(s.count_events("step_applied", "2026-10-26T11:00:00Z", "block_ip"), 1)
        self.assertEqual(s.count_events("step_applied", "2026-10-26T08:00:00Z", "block_ip"), 2)
        r1 = s.create_run("pb", "h", {"a": 1}, "ah", "apply", "op", "running", "", "2026-10-26T12:00:00Z")
        s.create_run("pb", "h", {"a": 1}, "ah", "apply", "op", "blocked", "x", "2026-10-26T12:05:00Z")
        self.assertEqual(s.find_recent("pb", "ah", "apply", "2026-10-26T00:00:00Z"), r1)         # blocked não conta como execução original
        self.assertIsNone(s.find_recent("pb", "ah", "dry", "2026-10-26T00:00:00Z"))
        self.assertIsNone(s.find_recent("pb", "ah", "apply", "2026-10-26T13:00:00Z"))


# ---------------------------------------------------------------------------------------------------------------------------------------------
class AlertTests(unittest.TestCase):
    def test_clean_alert(self):
        out = engine.clean_alert({"source": "x", "message": "a\x00b\nc" + "z" * 600, "n": 3, "f": 1.5, "b": True, "none": None, "nested": {"a": 1}, "lst": [1], "9bad": 1, "bad key": 2,
                                  "__dunder": 1, "k" * 50: 1, 5: "int key"})
        self.assertEqual(set(out), {"source", "message", "n", "f", "b", "none", "__dunder"})
        self.assertEqual(len(out["message"]), 500)
        self.assertNotIn("\x00", out["message"])
        with self.assertRaises(SoarError):
            engine.clean_alert([1])
        self.assertEqual(len(engine.clean_alert({f"k{i}": i for i in range(100)})), 40)

    def test_hash_ignores_the_timestamp_only(self):
        a = engine.alert_hash({"source": "x", "ip": "1.1.1.1", "ts": 1})
        self.assertEqual(a, engine.alert_hash({"ts": 999, "ip": "1.1.1.1", "source": "x"}))
        self.assertNotEqual(a, engine.alert_hash({"source": "x", "ip": "1.1.1.2", "ts": 1}))

    def test_input_validation(self):
        pb = parse_playbook("id: pb-teste\ninputs: {ip: ip, user: user, host: host, note: text}\nsteps:\n  - {id: a, action: enrich_ip, params: {ip: '1.1.1.1'}}\n")
        good = {"ip": "1.2.3.4", "user": "ana", "host": "PC-1", "note": "x"}
        self.assertEqual(engine.validate_inputs(pb, good), "")
        for key, bad in (("ip", "1.2.3"), ("ip", ""), ("user", "a b"), ("user", "x;y"), ("host", "../x"), ("note", ""), ("ip", None)):
            self.assertIn(f"'{key}'", engine.validate_inputs(pb, dict(good, **{key: bad})), (key, bad))
        self.assertIn("falta", engine.validate_inputs(pb, {k: v for k, v in good.items() if k != "user"}))


class DryRunTests(unittest.TestCase):
    def test_nothing_is_written_anywhere(self):
        d = tempfile.mkdtemp()
        wpath, db = os.path.join(d, "w.json"), os.path.join(d, "soar.db")
        wd.save_world(wpath, wd.default_world())
        before = sha(wpath)
        eng = Soar(db, wpath, mode="dry", playbooks=shipped(), clock=lambda: NOW)
        for alert in (BRUTE, ACCOUNT, RANSOM, PHISH, THREAT, BRUTE_INTERNAL):
            eng.handle_alert(alert)
        eng.close()
        self.assertEqual(sha(wpath), before)                                                     # o mundo não mudou
        self.assertFalse(os.path.exists(db))                                                     # e o banco nem foi criado
        self.assertEqual(sorted(os.listdir(d)), ["w.json"])

    def test_read_steps_run_and_mutating_steps_are_planned(self):
        eng = Soar(mode="dry", playbooks=shipped(), world=wd.default_world(), clock=lambda: NOW)
        (r,) = eng.handle_alert(BRUTE)
        states = {s["step_id"]: s["state"] for s in eng.describe(r.label)["steps"]}
        self.assertEqual(states, {"reputacao": "done", "bloquear": "planned", "chamado": "planned", "avisar": "planned"})
        self.assertEqual(r.state, "completed")
        notes = {s["step_id"]: s["note"] for s in eng.describe(r.label)["steps"]}
        self.assertIn("exigiria 1 aprovação", notes["bloquear"])
        self.assertIn("enderecos=1", notes["bloquear"])
        eng.close()

    def test_dry_run_announces_two_person_approvals(self):
        eng = Soar(mode="dry", playbooks=shipped(), world=wd.default_world(), clock=lambda: NOW)
        (r,) = eng.handle_alert(ACCOUNT)
        notes = {s["step_id"]: s["note"] for s in eng.describe(r.label)["steps"]}
        self.assertIn("exigiria 2 aprovação", notes["desativar"])
        self.assertIn("privilegiada=sim", notes["desativar"])
        eng.close()

    def test_dry_run_shows_refusals(self):
        eng = Soar(mode="dry", playbooks=shipped(), world=wd.default_world(), clock=lambda: NOW)
        (r,) = eng.handle_alert(BRUTE_INTERNAL)
        s = {x["step_id"]: x for x in eng.describe(r.label)["steps"]}
        self.assertEqual(s["bloquear"]["state"], "refused")
        self.assertIn("protegida", s["bloquear"]["note"])
        eng.close()

    def test_mode_validation(self):
        with self.assertRaises(SoarError):
            Soar(mode="talvez")
        with self.assertRaises(SoarError):
            Soar(mode="apply")


class ApplyTests(unittest.TestCase):
    def test_low_risk_playbook_runs_alone(self):
        e = env(self)
        (r,) = e.go(PHISH)
        self.assertEqual(r.state, "completed")
        w = e.world()
        self.assertEqual((len(w["tickets"]), w["tickets"][0]["severity"], len(w["notifications"])), (1, "medium", 1))
        events = [row["event"] for row in e.eng.store.audit_rows()]
        self.assertEqual(events, ["run_started", "step_applied", "step_applied", "run_finished"])
        self.assertTrue(e.eng.store.verify()[0])

    def test_medium_risk_waits_for_a_human(self):
        e = env(self)
        (r,) = e.go(BRUTE)
        self.assertEqual(r.state, "waiting_approval")
        self.assertEqual(e.steps(r.label), {"reputacao": "done", "bloquear": "waiting", "chamado": "pending", "avisar": "pending"})
        self.assertEqual((e.world()["blocklist"], e.world()["tickets"]), ({}, []))               # nada foi feito
        res = e.eng.approve(r.label, "bloquear", "bruno", "reputação confirmada")
        self.assertEqual(res.state, "completed")
        w = e.world()
        self.assertIn("203.0.113.50/32", w["blocklist"])
        self.assertEqual((len(w["tickets"]), len(w["notifications"])), (1, 1))
        self.assertEqual(e.steps(r.label)["bloquear"], "done")
        granted = [row for row in e.eng.store.audit_rows() if row["event"] == "step_applied" and json.loads(row["data"])["action"] == "block_ip"]
        self.assertEqual(json.loads(granted[0]["data"])["aprovadores"], ["bruno"])

    def test_high_risk_needs_two_different_people_and_not_the_operator(self):
        e = env(self)
        (r,) = e.go(ACCOUNT, operator="automacao")
        self.assertEqual(e.steps(r.label)["avisar_gestor"], "done")                              # o aviso (baixo risco) já foi
        self.assertEqual(e.steps(r.label)["desativar"], "waiting")
        with self.assertRaisesRegex(SoarError, "separação de funções"):
            e.eng.approve(r.label, "desativar", "automacao")
        self.assertEqual(e.eng.approve(r.label, "desativar", "bruno").state, "waiting_approval")
        with self.assertRaisesRegex(SoarError, "já aprovou"):
            e.eng.approve(r.label, "desativar", "BRUNO")                                         # a mesma pessoa duas vezes não vale
        self.assertTrue(e.world()["directory"]["deploy"]["active"])                              # uma aprovação só não basta
        res = e.eng.approve(r.label, "desativar", "carla")
        self.assertEqual(res.state, "waiting_approval")                                          # agora espera o passo seguinte (sessões, risco médio)
        self.assertFalse(e.world()["directory"]["deploy"]["active"])
        self.assertEqual(e.eng.approve(r.label, "sessoes", "dana").state, "completed")
        self.assertEqual(e.world()["directory"]["deploy"]["sessions"], 0)

    def test_the_operator_cannot_approve_even_under_another_case(self):
        e = env(self)
        (r,) = e.go(BRUTE, operator="Ana")
        with self.assertRaises(SoarError):
            e.eng.approve(r.label, "bloquear", "ana")

    def test_denial_aborts_and_skips_the_rest(self):
        e = env(self)
        (r,) = e.go(BRUTE)
        with self.assertRaisesRegex(SoarError, "motivo"):
            e.eng.deny(r.label, "bloquear", "bruno", "não")
        res = e.eng.deny(r.label, "bloquear", "bruno", "não confio nessa origem")
        self.assertEqual(res.state, "aborted")
        self.assertEqual(e.steps(r.label), {"reputacao": "done", "bloquear": "denied", "chamado": "skipped", "avisar": "skipped"})
        w = e.world()
        self.assertEqual((w["blocklist"], w["tickets"], w["notifications"]), ({}, [], []))
        with self.assertRaisesRegex(SoarError, "não está aguardando"):
            e.eng.approve(r.label, "bloquear", "carla")

    def test_approval_errors(self):
        e = env(self)
        with self.assertRaises(SoarError):
            e.eng.approve("R0099", "x", "bruno")
        with self.assertRaises(ValueError):
            e.eng.approve("lixo", "x", "bruno")
        (r,) = e.go(BRUTE)
        with self.assertRaisesRegex(SoarError, "não está aguardando"):
            e.eng.approve(r.label, "chamado", "bruno")                                           # esse passo ainda nem chegou
        with self.assertRaises(SoarError):
            e.eng.approve(r.label, "bloquear", "")
        with self.assertRaises(SoarError):
            e.eng.approve(r.label, "bloquear", "x")
        e.eng.approve(r.label, "bloquear", "bruno")
        with self.assertRaisesRegex(SoarError, "não está aguardando"):
            e.eng.approve(r.label, "bloquear", "carla")                                          # já concluída

    def test_policy_refusal_comes_before_asking_for_approval(self):
        e = env(self)
        (r,) = e.go(BRUTE_INTERNAL)
        self.assertEqual(r.state, "completed")                                                   # ninguém foi incomodado
        self.assertEqual(e.steps(r.label)["bloquear"], "refused")
        self.assertIn("1 passo(s) recusado(s)", r.note)
        self.assertEqual(e.world()["blocklist"], {})
        self.assertEqual(len(e.world()["tickets"]), 1)                                           # o chamado seguiu
        self.assertIn("step_refused", [row["event"] for row in e.eng.store.audit_rows()])
        self.assertNotIn("approval_requested", [row["event"] for row in e.eng.store.audit_rows()])

    def test_protected_resources_are_refused(self):
        e = env(self)
        (r1,) = e.go(dict(ACCOUNT, user="break-glass", message="Login em 'break-glass' após falhas"))
        self.assertEqual(e.steps(r1.label)["desativar"], "refused")
        (r2,) = e.go(dict(RANSOM, host="DC-01"))
        self.assertEqual(e.steps(r2.label)["isolar"], "refused")
        w = e.world()
        self.assertTrue(w["directory"]["break-glass"]["active"])
        self.assertFalse(w["hosts"]["DC-01"]["isolated"])

    def test_stop_versus_continue(self):
        stop = parse_playbook(MINI % "    - id: chamado\n      action: open_ticket\n      params: {title: 'x'}\n")
        world = wd.default_world()
        world["intel"]["10.0.4.12"] = {"score": 99}                                              # com reputação ruim, a condição passa e a política recusa o bloqueio
        e = env(self, pbs=[stop], world=world)
        (r,) = e.go(dict(BRUTE_INTERNAL, source="logwatch"))
        self.assertEqual(r.state, "stopped")
        self.assertEqual(e.steps(r.label), {"ver": "done", "bloquear": "refused", "chamado": "skipped"})
        self.assertIn("parado", r.note)
        self.assertEqual(e.world()["tickets"], [])

    def test_blocked_when_the_alert_lacks_the_input(self):
        e = env(self)
        (r,) = e.go({"source": "logwatch", "severity": "high", "message": "Força bruta SSH sem origem"})
        self.assertEqual(r.state, "blocked")
        self.assertIn("'ip'", r.note)
        self.assertEqual(set(e.steps(r.label).values()), {"skipped"})
        (r2,) = e.go(dict(BRUTE, ip="não-é-ip", message="Força bruta SSH com origem inválida"))
        self.assertEqual(r2.state, "blocked")
        self.assertIn("run_blocked", [row["event"] for row in e.eng.store.audit_rows()])

    def test_only_filter_and_unmatched(self):
        e = env(self)
        self.assertEqual(e.go({"source": "desconhecida", "severity": "low", "message": "x"}), [])
        self.assertEqual(e.go(BRUTE, only="phishing-reportado"), [])
        self.assertEqual(len(e.go(BRUTE, only="bloquear-origem-forca-bruta")), 1)

    def test_expression_failure_fails_the_run_visibly(self):
        pb = parse_playbook(MINI.replace("steps.ver.score >= 70", "alert.message > 5") % "")
        e = env(self, pbs=[pb])
        (r,) = e.go(BRUTE)
        self.assertEqual(r.state, "failed")
        self.assertEqual(e.steps(r.label)["bloquear"], "failed")
        self.assertIn("expressão", {s["step_id"]: s["note"] for s in e.eng.describe(r.label)["steps"]}["bloquear"])

    def test_missing_template_value_fails_the_step(self):
        pb = parse_playbook(MINI.replace("{ip: '{{ alert.ip }}'}\n      when", "{ip: '{{ alert.ip }}'}\n      when") % "    - id: aviso\n      action: notify\n      params: {channel: soc, message: '{{ steps.nao.existe }}'}\n")
        e = env(self, pbs=[pb])
        (r,) = e.go(dict(BRUTE, ip="192.0.2.99"))                                               # reputação média: o bloqueio é ignorado e o aviso é o próximo passo
        self.assertEqual(e.steps(r.label)["aviso"], "failed")
        self.assertEqual(r.state, "failed")

    def test_template_injection_from_an_alert_is_stored_literally(self):
        e = env(self)
        evil = dict(BRUTE_INTERNAL, message="Força bruta {{ steps.reputacao.score }} {{ run.id }} <script>x</script>")
        (r,) = e.go(evil)
        self.assertEqual(e.world()["tickets"][0]["body"], "Força bruta {{ steps.reputacao.score }} {{ run.id }} <script>x</script>")

    def test_max_steps_policy(self):
        e = env(self, policy=Policy(max_steps_per_run=2))
        (r,) = e.go(BRUTE)
        self.assertEqual(r.state, "blocked")
        self.assertIn("passos", r.note)

    def test_playbook_changed_between_pause_and_resume(self):
        e = env(self)
        (r,) = e.go(BRUTE)
        e.close()
        pbs = shipped()
        pbs[0] = parse_playbook(open(pbs[0].path, encoding="utf-8").read().replace("hours: 24", "hours: 720"), pbs[0].path)
        eng2 = Soar(e.db, e.world_path, None, pbs, "apply", clock=lambda: NOW)
        self.addCleanup(eng2.close)
        res = eng2.approve(r.label, "bloquear", "bruno")
        self.assertEqual(res.state, "aborted")
        self.assertIn("mudou", res.note)
        self.assertEqual(e.world()["blocklist"], {})                                             # nada foi aplicado com o playbook novo

    def test_world_changed_while_waiting_is_respected(self):
        e = env(self)
        (r,) = e.go(BRUTE)
        w = e.world()
        w["blocklist"]["203.0.113.50/32"] = {"expires": "2026-10-27T12:00:00Z", "reason": "outra execução", "run": "R0042"}
        wd.save_world(e.world_path, w)                                                           # outro processo bloqueou o IP nesse meio tempo
        res = e.eng.approve(r.label, "bloquear", "bruno")
        self.assertEqual(res.state, "completed")
        self.assertEqual(e.steps(r.label)["bloquear"], "noop")
        self.assertEqual(e.world()["blocklist"]["203.0.113.50/32"]["reason"], "outra execução")  # não sobrescreveu

    def test_unknown_run(self):
        e = env(self)
        with self.assertRaises(SoarError):
            e.eng.describe("R0001")


class DedupeAndIdempotencyTests(unittest.TestCase):
    def test_same_alert_twice_is_one_run(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        (b,) = e.go(dict(BRUTE, ts=99999))                                                       # só a hora mudou
        self.assertTrue(b.duplicate)
        self.assertEqual((b.label, a.label), (a.label, a.label))
        self.assertEqual(len(e.eng.store.list_runs()), 1)
        self.assertIn("run_deduplicated", [row["event"] for row in e.eng.store.audit_rows()])

    def test_a_different_alert_is_a_new_run(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        (b,) = e.go(dict(BRUTE, message="Força bruta SSH, de novo, de 203.0.113.50"))
        self.assertFalse(b.duplicate)
        self.assertNotEqual(a.label, b.label)

    def test_the_window_expires(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        e.hours(5)
        self.assertTrue(e.go(BRUTE)[0].duplicate)
        e.hours(2)                                                                               # 7 h depois: fora da janela de 6 h
        (c,) = e.go(BRUTE)
        self.assertFalse(c.duplicate)
        self.assertNotEqual(c.label, a.label)

    def test_blocked_and_aborted_runs_do_not_shield_a_retry(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        e.eng.deny(a.label, "bloquear", "bruno", "teste de negativa")
        self.assertFalse(e.go(BRUTE)[0].duplicate)                                               # depois de negada, um novo alerta idêntico abre outra execução

    def test_the_same_action_from_another_alert_is_a_noop_and_needs_no_approval(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        e.eng.approve(a.label, "bloquear", "bruno")
        (b,) = e.go(dict(BRUTE, source="loginguard", message="Força bruta contra o login vinda de 203.0.113.50"))
        self.assertEqual(b.state, "completed")                                                   # sem esperar ninguém: já estava bloqueado
        self.assertEqual(e.steps(b.label)["bloquear"], "noop")
        self.assertEqual(e.steps(b.label)["avisar"], "noop")                                     # o mesmo aviso, a mesma mensagem: não repete
        self.assertEqual(len(e.world()["notifications"]), 1)
        self.assertEqual(len([t for t in e.world()["tickets"]]), 2)                              # o chamado tem outro texto: é outro chamado
        self.assertEqual(len(e.world()["blocklist"]), 1)

    def test_applying_the_same_step_twice_changes_nothing_the_second_time(self):
        e = env(self)
        (a,) = e.go(PHISH)
        before = e.world()
        e.hours(7)
        (b,) = e.go(PHISH)
        self.assertEqual(e.steps(b.label), {"chamado": "noop", "avisar": "noop"})
        self.assertEqual(e.world(), before)


class SafetyRailsTests(unittest.TestCase):
    def test_kill_switch(self):
        e = env(self, policy=Policy(automation_enabled=False))
        (r,) = e.go(PHISH)
        self.assertEqual(r.state, "stopped")
        self.assertEqual(e.world()["tickets"], [])
        (r2,) = e.go(BRUTE)
        self.assertEqual(e.steps(r2.label)["reputacao"], "done")                                 # a leitura continua
        self.assertEqual(e.steps(r2.label)["bloquear"], "refused")
        self.assertIn("desligada", {s["step_id"]: s["note"] for s in e.eng.describe(r2.label)["steps"]}["bloquear"])

    def test_rate_limit_per_hour(self):
        e = env(self, policy=Policy.from_dict({"rate_limit_per_hour": {"block_ip": 1}}))
        (a,) = e.go(BRUTE)
        e.eng.approve(a.label, "bloquear", "bruno")
        (b,) = e.go(THREAT)
        res = e.eng.approve(b.label, "bloquear", "bruno")
        self.assertEqual(res.state, "stopped")                                                   # o segundo bloqueio passou do limite
        self.assertIn("limite de taxa", {s["step_id"]: s["note"] for s in e.eng.describe(b.label)["steps"]}["bloquear"])
        self.assertEqual(set(e.world()["blocklist"]), {"203.0.113.50/32"})
        e.hours(2)                                                                               # a janela de 1 hora passou
        (c,) = e.go(dict(THREAT, message="Reputação ruim: 198.51.100.23 (de novo)"))
        self.assertEqual(e.eng.approve(c.label, "bloquear", "bruno").state, "completed")
        self.assertEqual(len(e.world()["blocklist"]), 2)

    def test_block_expiry_uses_the_injected_clock(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        e.eng.approve(a.label, "bloquear", "bruno")
        self.assertEqual(e.world()["blocklist"]["203.0.113.50/32"]["expires"], "2026-10-27T12:00:00Z")


class RollbackTests(unittest.TestCase):
    def full_account_run(self, e):
        (r,) = e.go(ACCOUNT)
        e.eng.approve(r.label, "desativar", "bruno")
        e.eng.approve(r.label, "desativar", "carla")
        e.eng.approve(r.label, "sessoes", "dana")
        return r

    def test_undoes_in_reverse_and_reports_the_irreversible(self):
        e = env(self)
        r = self.full_account_run(e)
        self.assertFalse(e.world()["directory"]["deploy"]["active"])
        res = e.eng.rollback(r.label, "ana", "falso positivo confirmado")
        self.assertEqual(res.state, "rolled_back")
        self.assertTrue(e.world()["directory"]["deploy"]["active"])
        s = e.steps(r.label)
        self.assertEqual((s["desativar"], s["chamado"], s["sessoes"], s["avisar_gestor"]), ("rolled_back", "rolled_back", "irreversible", "irreversible"))
        self.assertIn("sessoes", res.note)
        self.assertEqual(e.world()["directory"]["deploy"]["sessions"], 0)                       # sessões encerradas não voltam
        self.assertEqual(e.world()["tickets"][0]["status"], "cancelled")
        order = [row["step_id"] for row in e.eng.store.audit_rows() if row["event"] in ("step_rolled_back", "step_irreversible")]
        self.assertEqual(order, ["chamado", "sessoes", "desativar", "avisar_gestor"])            # do último para o primeiro

    def test_rollback_requires_who_and_why_and_happens_once(self):
        e = env(self)
        r = self.full_account_run(e)
        with self.assertRaisesRegex(SoarError, "motivo"):
            e.eng.rollback(r.label, "ana", "x")
        with self.assertRaises(SoarError):
            e.eng.rollback(r.label, "", "motivo suficiente")
        e.eng.rollback(r.label, "ana", "motivo suficiente")
        with self.assertRaisesRegex(SoarError, "já foi desfeita"):
            e.eng.rollback(r.label, "ana", "motivo suficiente")
        with self.assertRaises(SoarError):
            e.eng.rollback("R0099", "ana", "motivo suficiente")

    def test_nothing_to_undo(self):
        e = env(self)
        (r,) = e.go(BRUTE)
        with self.assertRaisesRegex(SoarError, "não aplicou nada"):
            e.eng.rollback(r.label, "ana", "motivo suficiente")                                  # só leitura até agora

    def test_after_a_rollback_the_action_can_be_applied_again(self):
        e = env(self)
        (a,) = e.go(BRUTE)
        e.eng.approve(a.label, "bloquear", "bruno")
        e.eng.rollback(a.label, "ana", "falso positivo")
        self.assertEqual(e.world()["blocklist"], {})
        self.assertEqual(e.world()["applied_keys"], {k: v for k, v in e.world()["applied_keys"].items() if v["run"] != a.label or v["step"] == "avisar"})
        e.hours(7)
        (b,) = e.go(BRUTE)
        self.assertEqual(e.eng.approve(b.label, "bloquear", "bruno").state, "completed")
        self.assertIn("203.0.113.50/32", e.world()["blocklist"])

    def test_rollback_of_a_run_that_is_waiting(self):
        e = env(self)
        (r,) = e.go(ACCOUNT)
        e.eng.approve(r.label, "desativar", "bruno")
        e.eng.approve(r.label, "desativar", "carla")                                             # desativou; espera a aprovação das sessões
        res = e.eng.rollback(r.label, "ana", "interrompendo por precaução")
        self.assertEqual(res.state, "rolled_back")
        self.assertEqual(e.steps(r.label)["sessoes"], "skipped")
        self.assertTrue(e.world()["directory"]["deploy"]["active"])

    def test_the_trail_survives_everything(self):
        e = env(self)
        r = self.full_account_run(e)
        e.eng.rollback(r.label, "ana", "falso positivo confirmado")
        ok, msg = e.eng.store.verify()
        self.assertTrue(ok, msg)
        events = {row["event"] for row in e.eng.store.audit_rows()}
        self.assertTrue({"run_started", "approval_requested", "approval_granted", "step_applied", "rollback_started", "step_rolled_back", "step_irreversible", "rollback_finished"} <= events)


class PlaybookTestRunnerTests(unittest.TestCase):
    def test_shipped_tests_pass(self):
        for pb in shipped():
            results = engine.run_playbook_tests(pb)
            self.assertTrue(results and all(r.passed for r in results), [r.message for r in results if not r.passed])

    def test_failures_say_what_went_wrong(self):
        pb = parse_playbook(MINI % "x_tests:\n    - name: errado\n      alert: {source: logwatch, ip: 203.0.113.50}\n      expect: {ver: planned, bloquear: done}\n"
                            "    - name: gatilho\n      alert: {source: outra}\n      expect_matches: true\n"
                            "    - name: gatilho2\n      alert: {source: logwatch, ip: 1.1.1.1}\n      expect_matches: false\n"
                            "    - name: estado final\n      alert: {source: logwatch, ip: 203.0.113.50}\n      expect_run: blocked\n")
        r = engine.run_playbook_tests(pb)
        self.assertEqual([x.passed for x in r], [False, False, False, False])
        self.assertIn("ver: done (esperado planned)", r[0].message)
        self.assertIn("bloquear: planned (esperado done)", r[0].message)
        self.assertIn("não casou, mas deveria", r[1].message)
        self.assertIn("casou, mas não deveria", r[2].message)
        self.assertIn("esperado 'blocked'", r[3].message)

    def test_world_override_and_broken_tests(self):
        pb = parse_playbook(MINI % "x_tests:\n    - name: reputação injetada\n      alert: {source: logwatch, ip: 9.9.9.9}\n      world: {intel: {9.9.9.9: {score: 99}}}\n      expect: {bloquear: planned}\n"
                            "    - name: sem nada\n      alert: {source: logwatch, ip: 9.9.9.9}\n      expect: {bloquear: skipped}\n")
        self.assertTrue(all(r.passed for r in engine.run_playbook_tests(pb)))
        bad = parse_playbook(MINI.replace("steps.ver.score >= 70", "alert.message > 5") % "x_tests:\n    - name: expressão quebrada\n      alert: {source: logwatch, ip: 1.1.1.1}\n      expect: {bloquear: planned}\n")
        (r,) = engine.run_playbook_tests(bad)
        self.assertFalse(r.passed)


# ---------------------------------------------------------------------------------------------------------------------------------------------
class CLITests(unittest.TestCase):
    def paths(self):
        d = tempfile.mkdtemp()
        return d, ["--world", os.path.join(d, "w.json"), "--db", os.path.join(d, "s.db")]

    def test_demo(self):
        code, out, err = run_cli("demo", "--no-color")
        self.assertEqual((code, err), (0, ""))
        for needle in ("PASSO 1", "PASSO 6", "separação de funções", "RECUSADO" if False else "aguardando aprovação", "irreversíveis, não desfeitos", "ÍNTEGRA", "8 execução(ões)", "1 alerta(s) duplicado(s)"):
            self.assertIn(needle, out)

    def test_playbooks_commands(self):
        self.assertEqual(run_cli("playbooks", "validate", "--no-color")[0], 0)
        code, out, _ = run_cli("playbooks", "list")
        self.assertIn("5 playbook(s)", out)
        code, out, _ = run_cli("playbooks", "test")
        self.assertEqual(code, 0)
        self.assertIn("19 de 19", out)
        code, out, _ = run_cli("playbooks", "explain", "conta-comprometida")
        for needle in ("QUANDO DISPARA", "EXIGE NO ALERTA", "risco alto", "irreversível", "só se:"):
            self.assertIn(needle, out)
        self.assertEqual(run_cli("playbooks", "explain", "nao-existe")[0], 2)
        self.assertEqual(run_cli("playbooks")[0], 0)

    def test_validate_and_test_exit_codes(self):
        d = tempfile.mkdtemp()
        write(d, "ruim.yml", MINI.replace("block_ip", "apagar_tudo") % "")
        self.assertEqual(run_cli("playbooks", "validate", "--playbooks", d)[0], 1)
        write(d, "quebrado.yml", "id: x\n\tfoo")
        code, _, err = run_cli("playbooks", "list", "--playbooks", d)
        self.assertEqual(code, 1)
        self.assertIn("Playbook inválido", err)
        ok = tempfile.mkdtemp()
        write(ok, "a.yml", MINI % "")
        self.assertEqual(run_cli("playbooks", "validate", "--playbooks", ok)[0], 0)
        self.assertEqual(run_cli("playbooks", "validate", "--playbooks", ok, "--strict")[0], 1)         # só avisos: --strict falha
        failing = tempfile.mkdtemp()
        write(failing, "a.yml", MINI % "x_tests:\n    - name: errado\n      alert: {source: logwatch, ip: 203.0.113.50}\n      expect: {bloquear: done}\n")
        self.assertEqual(run_cli("playbooks", "test", "--playbooks", failing)[0], 1)

    def test_world_and_policy(self):
        d = tempfile.mkdtemp()
        w = os.path.join(d, "w.json")
        self.assertEqual(run_cli("world", "init", "--world", w)[0], 0)
        self.assertEqual(run_cli("world", "init", "--world", w)[0], 2)
        self.assertEqual(run_cli("world", "init", "--world", w, "--force")[0], 0)
        self.assertIn("IPs bloqueados (0)", run_cli("world", "show", "--world", w)[1])
        self.assertEqual(run_cli("world", "show", "--world", os.path.join(d, "x.json"))[0], 2)
        p = os.path.join(d, "p.json")
        self.assertEqual(run_cli("policy", "init", p)[0], 0)
        self.assertEqual(run_cli("policy", "init", p)[0], 2)
        self.assertEqual(Policy.from_dict(json.load(open(p, encoding="utf-8"))), Policy())
        self.assertIn("automation_enabled", run_cli("policy", "show")[1])

    def test_dry_run_leaves_no_trace(self):
        d, common = self.paths()
        run_cli("world", "init", *common[:2])
        before = sha(common[1])
        code, out, _ = run_cli("run", os.path.join(SAMPLES, "alerts.jsonl"), "--no-color", *common)
        self.assertEqual(code, 0)
        self.assertIn("SIMULAÇÃO: nada foi gravado", out)
        self.assertIn("8 execução(ões)", out)
        self.assertEqual(sha(common[1]), before)
        self.assertFalse(os.path.exists(common[3]))

    def test_full_flow_through_the_command_line(self):
        d, common = self.paths()
        run_cli("world", "init", *common[:2])
        alerts = write(d, "a.jsonl", json.dumps(BRUTE) + "\n" + json.dumps(ACCOUNT) + "\n")
        code, out, _ = run_cli("run", alerts, "--apply", "--no-color", *common)
        self.assertEqual(code, 0)
        self.assertIn("Para continuar: python app.py approve R0001 bloquear --by NOME", out)
        self.assertIn("R0002", run_cli("runs", *common)[1])
        self.assertEqual(run_cli("approve", "R0001", "bloquear", *common)[0], 2)                         # falta --by (argparse)
        code, out, err = run_cli("approve", "R0001", "bloquear", "--by", "automacao", *common)
        self.assertEqual(code, 2)
        self.assertIn("separação de funções", err)
        code, out, _ = run_cli("approve", "R0001", "bloquear", "--by", "bruno", "--reason", "ok", "--no-color", *common)
        self.assertEqual(code, 0)
        self.assertIn("[concluída]", out)
        self.assertIn("203.0.113.50/32", run_cli("world", "show", *common[:2])[1])
        self.assertEqual(run_cli("deny", "R0002", "desativar", "--by", "carla", "--reason", "preciso confirmar com o gestor", "--no-color", *common)[0], 0)
        self.assertIn("[abortada]", run_cli("show", "R0002", "--no-color", *common)[1])
        self.assertEqual(run_cli("rollback", "R0001", "--by", "ana", "--reason", "falso positivo", *common)[0], 0)
        self.assertIn("IPs bloqueados (0)", run_cli("world", "show", *common[:2])[1])
        code, out, _ = run_cli("audit", "--run", "R0001", *common)
        self.assertIn("rollback_started", out)
        self.assertEqual(run_cli("verify", *common)[0], 0)

    def test_verify_anchor_and_tampering(self):
        d, common = self.paths()
        run_cli("world", "init", *common[:2])
        run_cli("run", write(d, "a.jsonl", json.dumps(PHISH) + "\n"), "--apply", *common)
        anchor = os.path.join(d, "anchor.json")
        self.assertEqual(run_cli("anchor", anchor, *common)[0], 0)
        code, out, _ = run_cli("verify", "--anchor", anchor, *common)
        self.assertEqual(code, 0)
        self.assertIn("conferem com a âncora", out)
        con = sqlite3.connect(common[3])
        con.execute("DROP TRIGGER audit_no_update")
        con.execute("UPDATE audit SET actor='mallory' WHERE seq=2")
        con.commit()
        con.close()
        code, out, _ = run_cli("verify", *common)
        self.assertEqual(code, 1)
        self.assertIn("ADULTERADA", out)
        self.assertIn("ALTERADO", out)

    def test_alert_file_formats_and_errors(self):
        d = tempfile.mkdtemp()
        self.assertEqual(len(cli.load_alerts(write(d, "a.json", json.dumps([BRUTE, PHISH, 5])))), 2)
        self.assertEqual(len(cli.load_alerts(write(d, "b.jsonl", json.dumps(BRUTE) + "\nnão é json\n\n" + json.dumps(PHISH) + "\n[1]\n"))), 2)
        with self.assertRaises(FileNotFoundError):
            cli.load_alerts(os.path.join(d, "x"))
        self.assertEqual(run_cli("run", os.path.join(d, "x.jsonl"))[0], 2)
        self.assertEqual(run_cli("run", write(d, "c.jsonl", "{}\n"), "--playbooks", write(d, "vazio.yml", "x: 1") and d)[0], 2)

    def test_errors_are_reported_not_raised(self):
        d, common = self.paths()
        self.assertEqual(run_cli("run", os.path.join(SAMPLES, "alerts.jsonl"), "--apply", *common)[0], 2)      # o mundo não existe
        self.assertEqual(run_cli("show", "R0001", *common)[0], 2)
        self.assertEqual(run_cli("rollback", "R0001", "--by", "ana", "--reason", "motivo suficiente", *common)[0], 2)

    def test_no_command_and_broken_pipe(self):
        self.assertIn("usage", run_cli()[1].lower())

        class Closed(io.StringIO):
            def write(self, s):
                raise BrokenPipeError
        with contextlib.redirect_stdout(Closed()):
            self.assertEqual(cli.main(["playbooks", "list"]), 0)


class SampleContentTests(unittest.TestCase):
    def test_sample_files(self):
        with open(os.path.join(SAMPLES, "world.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f), wd.default_world())
        alerts = cli.load_alerts(os.path.join(SAMPLES, "alerts.jsonl"))
        self.assertEqual(len(alerts), 9)

    def test_the_demo_scenario_end_to_end(self):
        e = env(self)
        results = [r for a in cli.load_alerts(os.path.join(SAMPLES, "alerts.jsonl")) for r in e.go(a)]
        distinct = [r for r in results if not r.duplicate]
        self.assertEqual((len(results), len(distinct)), (9, 8))
        self.assertEqual({r.playbook: r.state for r in distinct if r.playbook in ("phishing-reportado", "conta-comprometida") and r.state != "waiting_approval"}, {"phishing-reportado": "completed", "conta-comprometida": "blocked"})
        states = sorted(r.state for r in distinct)
        self.assertEqual(states, ["blocked", "completed", "completed", "completed", "waiting_approval", "waiting_approval", "waiting_approval", "waiting_approval"])
        w = e.world()
        self.assertEqual((w["blocklist"], [h for h, x in w["hosts"].items() if x["isolated"]]), ({}, []))      # nada de alto/médio risco foi feito sem aprovação
        self.assertTrue(w["directory"]["deploy"]["active"])


class SafetyTests(unittest.TestCase):
    PKG = os.path.join(ROOT, "soar")

    def sources(self):
        for name in sorted(os.listdir(self.PKG)):
            if name.endswith(".py"):
                with open(os.path.join(self.PKG, name), encoding="utf-8") as f:
                    yield name, f.read()

    def test_no_network_no_programs_no_dynamic_code(self):
        net = re.compile(r"^\s*(import|from)\s+(socket|urllib|http|requests|ftplib|smtplib|ssl|asyncio|subprocess|multiprocessing|ctypes|webbrowser)\b", re.M)
        bad = re.compile(r"(?<![\w.])(eval|exec|compile)\(|\bpickle\b|\bmarshal\b|os\.system|os\.popen|shell\s*=\s*True|__import__|importlib")
        for name, text in self.sources():
            self.assertIsNone(net.search(text), name)
            code = re.sub(r'""".*?"""', "", text, flags=re.S)
            for n, line in enumerate(code.splitlines(), 1):
                if not line.lstrip().startswith("#"):
                    self.assertIsNone(bad.search(line), f"{name}:{n}: {line.strip()}")

    def test_the_expression_module_imports_nothing_dangerous(self):
        imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", dict(self.sources())["expr.py"], re.M)
        self.assertEqual(sorted(set(imports)), ["__future__", "re", "typing"])

    def test_only_the_world_module_and_the_cli_write_files(self):
        for name, text in self.sources():
            if name in ("cli.py", "world.py", "yamlite.py"):
                continue
            self.assertIsNone(re.search(r"open\([^)]*[\"'][wax+]", text), name)
            self.assertNotIn("os.replace", text.replace("world.py", "")) if name != "world.py" else None

    def test_actions_only_touch_the_world_dictionary(self):
        src = re.sub(r'""".*?"""', "", dict(self.sources())["actions.py"], flags=re.S)
        self.assertNotRegex(src, r"\bopen\(|\bos\.|pathlib|shutil|tempfile")


if __name__ == "__main__":
    unittest.main()
