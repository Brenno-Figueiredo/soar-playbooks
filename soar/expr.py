"""Condições e modelos SEM eval. Um playbook é escrito por pessoas e roda com o poder de agir: a linguagem de condições precisa ser pequena o bastante
para não conseguir fazer NADA além de comparar valores. Não há chamadas de função, acesso a atributos, índices nem execução de código.

Condição:  steps.reputacao.score >= 70 or alert.severity == 'critical'
Modelo:    '{{ alert.ip }}'   (valor inteiro do alerta) ou 'IP {{ alert.ip }} bloqueado' (texto)
Variáveis: alert.*, steps.<passo>.*, run.*"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

MAX_LEN = 300
MAX_TOKENS = 120
MAX_DEPTH = 12
MAX_RENDERED = 2000
ROOTS = ("alert", "steps", "run")
_PATH = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_TOK = re.compile(r"""\s*(?:(?P<num>\d+(?:\.\d+)?)|(?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")|(?P<op>==|!=|<=|>=|<|>)|(?P<id>""" + _PATH + r""")|(?P<p>[()\[\],]))""")
_TPL = re.compile(r"\{\{\s*(" + _PATH + r")\s*\}\}")
KEYWORDS = {"and", "or", "not", "in", "true", "false", "null"}


class ExprError(ValueError):
    pass


class TemplateError(ValueError):
    pass


def check_path(path: str) -> List[str]:
    parts = path.split(".")
    if parts[0] not in ROOTS:
        raise ExprError(f"variável desconhecida '{parts[0]}' (use alert., steps. ou run.)")
    if len(parts) < 2:
        raise ExprError(f"'{path}': diga qual campo (ex.: {path}.campo)")
    if len(parts) > 4:
        raise ExprError(f"'{path}': caminho profundo demais")
    if any(p.startswith("_") for p in parts):
        raise ExprError(f"'{path}': nomes que começam com '_' não são permitidos")
    return parts


def lookup(ctx: Dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


# ---- condições -----------------------------------------------------------------------------------------------------------------------
def _tokenize(text: str) -> List[Tuple[str, Any]]:
    if len(text) > MAX_LEN:
        raise ExprError(f"condição longa demais (limite de {MAX_LEN} caracteres)")
    out, pos = [], 0
    while pos < len(text):
        if not text[pos:].strip():
            break
        m = _TOK.match(text, pos)
        if not m:
            raise ExprError(f"caractere inesperado perto de {text[pos:pos + 12].strip()!r}")
        pos, kind = m.end(), m.lastgroup
        val = m.group(kind)
        if kind == "num":
            out.append(("lit", float(val) if "." in val else int(val)))
        elif kind == "str":
            out.append(("lit", _unescape(val[1:-1])))
        elif kind == "id" and val in KEYWORDS:
            out.append(("lit", {"true": True, "false": False, "null": None}[val]) if val in ("true", "false", "null") else ("kw", val))
        elif kind == "id":
            out.append(("path", val))
        else:
            out.append((kind, val))
        if len(out) > MAX_TOKENS:
            raise ExprError("condição com símbolos demais")
    if not out:
        raise ExprError("condição vazia")
    return out


def _unescape(body: str) -> str:
    """Só \\', \\\" e \\\\ são escapes válidos; lê em sequência, então o par \\\\ vale como UMA barra e a letra depois dele é comum."""
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\":
            if i + 1 >= len(body) or body[i + 1] not in "'\"\\":
                raise ExprError("escape não suportado em texto (só \\', \\\" e \\\\)")
            out.append(body[i + 1])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


class _Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, offset=0):
        return self.t[self.i + offset] if self.i + offset < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        if tok[0] is None:
            raise ExprError("a condição termina antes da hora")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_(0)
        if self.i != len(self.t):
            raise ExprError(f"sobrou texto na condição perto de {self.peek()[1]!r}")
        return node

    def or_(self, d):
        self._depth(d)
        parts = [self.and_(d)]
        while self.peek() == ("kw", "or"):
            self.take()
            parts.append(self.and_(d))
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_(self, d):
        parts = [self.not_(d)]
        while self.peek() == ("kw", "and"):
            self.take()
            parts.append(self.not_(d))
        return parts[0] if len(parts) == 1 else ("and", parts)

    def not_(self, d):
        if self.peek() == ("kw", "not") and self.peek(1) != ("kw", "in"):
            self.take()
            return ("not", self.not_(d + 1))
        return self.cmp(d)

    def cmp(self, d):
        left = self.atom(d)
        kind, val = self.peek()
        if kind == "op":
            self.take()
            node = ("cmp", val, left, self.atom(d))
        elif (kind, val) == ("kw", "in"):
            self.take()
            node = ("cmp", "in", left, self.atom(d))
        elif (kind, val) == ("kw", "not") and self.peek(1) == ("kw", "in"):
            self.take(), self.take()
            node = ("cmp", "not in", left, self.atom(d))
        else:
            return left
        if self.peek()[0] == "op" or self.peek() in (("kw", "in"), ("kw", "not")):
            raise ExprError("comparações encadeadas não são suportadas: use 'and'")
        return node

    def atom(self, d):
        self._depth(d)
        kind, val = self.take()
        if kind == "lit":
            return ("lit", val)
        if kind == "path":
            check_path(val)
            return ("path", val)
        if (kind, val) == ("p", "("):
            node = self.or_(d + 1)
            if self.take() != ("p", ")"):
                raise ExprError("faltou fechar um parêntese")
            return node
        if (kind, val) == ("p", "["):
            items = []
            if self.peek() != ("p", "]"):
                while True:
                    items.append(self.atom(d + 1))
                    if self.peek() == ("p", ","):
                        self.take()
                        continue
                    break
            if self.take() != ("p", "]"):
                raise ExprError("faltou fechar um colchete")
            return ("list", items)
        raise ExprError(f"não esperava '{val}' aqui")

    @staticmethod
    def _depth(d):
        if d > MAX_DEPTH:
            raise ExprError("condição aninhada demais")


def parse(text: str):
    return _Parser(_tokenize(str(text))).parse()


def paths_in(node) -> List[str]:
    k = node[0]
    if k == "path":
        return [node[1]]
    if k in ("and", "or", "list"):
        return [p for n in node[1] for p in paths_in(n)]
    if k == "not":
        return paths_in(node[1])
    if k == "cmp":
        return paths_in(node[2]) + paths_in(node[3])
    return []


def truthy(v: Any) -> bool:
    return bool(v) if not isinstance(v, (int, float)) or isinstance(v, bool) else v != 0


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def _cmp(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return _eq(a, b)
    if op == "!=":
        return not _eq(a, b)
    if op in ("in", "not in"):
        if isinstance(b, list):
            hit = any(_eq(a, x) for x in b)
        elif isinstance(b, str) and isinstance(a, str):
            hit = a.lower() in b.lower()                       # 'x' in alert.message: sem diferenciar maiúsculas
        elif b is None or a is None:
            hit = False
        else:
            raise ExprError("'in' compara com uma lista ou com um texto")
        return hit if op == "in" else not hit
    if a is None or b is None:
        return False                                           # dado ausente nunca satisfaz uma comparação de ordem
    if not (_num(a) and _num(b)):
        raise ExprError(f"'{op}' só compara números (recebeu {type(a).__name__} e {type(b).__name__})")
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def _val(node, ctx):
    k = node[0]
    if k == "lit":
        return node[1]
    if k == "path":
        return lookup(ctx, node[1])
    if k == "list":
        return [_val(n, ctx) for n in node[1]]
    if k == "not":
        return not truthy(_val(node[1], ctx))
    if k == "and":
        return all(truthy(_val(n, ctx)) for n in node[1])
    if k == "or":
        return any(truthy(_val(n, ctx)) for n in node[1])
    return _cmp(node[1], _val(node[2], ctx), _val(node[3], ctx))


def evaluate(text_or_ast, ctx: Dict[str, Any]) -> bool:
    node = parse(text_or_ast) if isinstance(text_or_ast, str) else text_or_ast
    return truthy(_val(node, ctx))


# ---- modelos -------------------------------------------------------------------------------------------------------------------------
def template_paths(value: Any) -> List[str]:
    if isinstance(value, str):
        return [m for m in _TPL.findall(value)]
    if isinstance(value, dict):
        return [p for v in value.values() for p in template_paths(v)]
    if isinstance(value, list):
        return [p for v in value for p in template_paths(v)]
    return []


def render(value: Any, ctx: Dict[str, Any]) -> Any:
    """Troca {{ caminho }} pelos valores. Uma passada só: o que vem de um alerta NUNCA é interpretado como modelo (injeção)."""
    if isinstance(value, str):
        whole = _TPL.fullmatch(value.strip())
        if whole:
            check_path(whole.group(1))
            v = lookup(ctx, whole.group(1))
            if v is None:
                raise TemplateError(f"'{whole.group(1)}' não existe neste alerta")
            return v

        def sub(m):
            check_path(m.group(1))
            v = lookup(ctx, m.group(1))
            if v is None:
                raise TemplateError(f"'{m.group(1)}' não existe neste alerta")
            return str(v)
        out = _TPL.sub(sub, value)
        if len(out) > MAX_RENDERED:
            raise TemplateError("texto gerado grande demais")
        return out
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value
