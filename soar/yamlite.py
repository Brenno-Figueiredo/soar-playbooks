"""Leitor de YAML SOMENTE do subconjunto usado nas regras Sigma, sem dependências e sem construir objetos a partir do arquivo.

Aceita: mapas e listas em bloco, listas e mapas em linha ([a, b] e {k: v}), textos simples e entre aspas (simples e duplas),
blocos literais (|) e dobrados (>), comentários, linhas de continuação e vários documentos separados por '---'.
RECUSA, com mensagem clara: âncoras e apelidos (&x, *x), etiquetas (!!tipo), chaves complexas (?), tabulações na indentação.
Recusar é de propósito: o arquivo de regras vem de fora, e interpretar errado uma regra de detecção é pior do que falhar."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Tuple

MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 40
_INT = re.compile(r"^[-+]?(0|[1-9][0-9]*)$")
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_FLOAT = re.compile(r"^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$")


class YamlError(ValueError):
    def __init__(self, message: str, line: int = 0):
        super().__init__(f"linha {line}: {message}" if line else message)
        self.line = line


@dataclass
class Line:
    no: int
    indent: int
    text: str          # sem comentário e sem espaços nas pontas
    raw: str


def strip_comment(s: str) -> str:
    quote = None
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


def scalar(token: str, line: int = 0) -> Any:
    t = token.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if t[0] in "&*!":
        raise YamlError(f"recurso de YAML não suportado em '{t[:20]}' (âncoras, apelidos e etiquetas). Use aspas se for texto literal", line)
    if t[0] == "'":
        return _single(t, line)
    if t[0] == '"':
        return _double(t, line)
    if _INT.match(t):
        return int(t)
    if _HEX.match(t):
        return int(t, 16)
    if _FLOAT.match(t):
        return float(t)
    return t


def _single(t: str, line: int) -> str:
    if len(t) < 2 or t[-1] != "'":
        raise YamlError("texto entre aspas simples não foi fechado", line)
    body = t[1:-1]
    if re.search(r"(?<!')'(?!')", body.replace("''", "")):
        raise YamlError("aspa simples solta dentro de um texto entre aspas simples (dobre-a: '')", line)
    return body.replace("''", "'")


_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "/": "/", " ": " ", "b": "\b", "f": "\f", "a": "\a", "e": "\x1b", "v": "\v"}


def _double(t: str, line: int) -> str:
    if len(t) < 2 or t[-1] != '"':
        raise YamlError("texto entre aspas duplas não foi fechado", line)
    out, i, body = [], 0, t[1:-1]
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 1
            if i >= len(body):
                raise YamlError("barra invertida no fim de um texto entre aspas duplas", line)
            c = body[i]
            if c in "xuU":
                n = {"x": 2, "u": 4, "U": 8}[c]
                hexa = body[i + 1:i + 1 + n]
                if len(hexa) != n or not re.fullmatch(r"[0-9a-fA-F]+", hexa):
                    raise YamlError(f"sequência \\{c} inválida", line)
                out.append(chr(int(hexa, 16)))
                i += n
            elif c in _ESC:
                out.append(_ESC[c])
            else:
                raise YamlError(f"escape desconhecido: \\{c}", line)
        elif ch == '"':
            raise YamlError('aspa dupla solta dentro de um texto entre aspas duplas (use \\")', line)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _flow(s: str, i: int, line: int, depth: int = 0) -> Tuple[Any, int]:
    """Lê [ ... ] ou { ... } a partir de s[i]; devolve (valor, posição seguinte)."""
    if depth > MAX_DEPTH:
        raise YamlError("estrutura aninhada demais", line)
    close = "]" if s[i] == "[" else "}"
    is_map = close == "}"
    i += 1
    items: List[Any] = []
    pairs = {}

    def skip(j):
        while j < len(s) and s[j] in " \t":
            j += 1
        return j

    def read_item(j, stop):
        j = skip(j)
        if j >= len(s):
            raise YamlError("lista ou mapa em linha não foi fechado", line)
        if s[j] in "[{":
            return _flow(s, j, line, depth + 1)
        if s[j] in "'\"":
            q, k = s[j], j + 1
            while k < len(s):
                if s[k] == q:
                    if q == "'" and k + 1 < len(s) and s[k + 1] == "'":
                        k += 2
                        continue
                    break
                if q == '"' and s[k] == "\\":
                    k += 1
                k += 1
            if k >= len(s):
                raise YamlError("texto entre aspas não foi fechado", line)
            return scalar(s[j:k + 1], line), k + 1
        k = j
        while k < len(s) and s[k] not in stop:
            k += 1
        return scalar(s[j:k], line), k

    i = skip(i)
    if i < len(s) and s[i] == close:
        return ({} if is_map else []), i + 1
    while True:
        if is_map:
            key, i = read_item(i, ",}:")
            i = skip(i)
            if i >= len(s) or s[i] != ":":
                raise YamlError("faltou ':' em um mapa em linha", line)
            val, i = read_item(i + 1, ",}")
            pairs[key] = val
        else:
            val, i = read_item(i, ",]")
            items.append(val)
        i = skip(i)
        if i >= len(s):
            raise YamlError("lista ou mapa em linha não foi fechado", line)
        if s[i] == ",":
            i = skip(i + 1)
            if i < len(s) and s[i] == close:
                break
            continue
        if s[i] == close:
            break
        raise YamlError(f"caractere inesperado '{s[i]}' em lista ou mapa em linha", line)
    return (pairs if is_map else items), i + 1


def inline(text: str, line: int = 0) -> Any:
    t = text.strip()
    if t and t[0] in "[{":
        value, end = _flow(t, 0, line)
        if t[end:].strip():
            raise YamlError(f"texto sobrando depois de '{t[:end][-10:]}'", line)
        return value
    return scalar(t, line)


def split_key(text: str, line: int) -> Tuple[Any, str]:
    if text[0] in "'\"":
        q, k = text[0], 1
        while k < len(text):
            if text[k] == q:
                if q == "'" and k + 1 < len(text) and text[k + 1] == "'":
                    k += 2
                    continue
                break
            if q == '"' and text[k] == "\\":
                k += 1
            k += 1
        if k >= len(text) or text[k + 1:k + 2] != ":":
            raise YamlError("esperava 'chave: valor'", line)
        return scalar(text[:k + 1], line), text[k + 2:].strip()
    if text[0] == "?":
        raise YamlError("chaves complexas ('? ') não são suportadas", line)
    depth, quote = 0, None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"" and i == 0:
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth <= 0 and (i + 1 == len(text) or text[i + 1] in " \t"):
            key = text[:i].strip()
            if not key:
                raise YamlError("chave vazia", line)
            return (scalar(key, line) if key[0] not in "&*!" else key), text[i + 1:].strip()
    raise YamlError(f"esperava 'chave: valor', encontrei '{text[:40]}'", line)


class _Parser:
    def __init__(self, lines: List[Line]):
        self.lines = lines

    def block(self, i: int, depth: int = 0) -> Tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise YamlError("estrutura aninhada demais", self.lines[i].no)
        ln = self.lines[i]
        if ln.text == "-" or ln.text.startswith("- "):
            return self.seq(i, ln.indent, depth)
        return self.mapping(i, ln.indent, depth)

    def _next_indent(self, i: int):
        return self.lines[i + 1].indent if i + 1 < len(self.lines) else -1

    def mapping(self, i: int, indent: int, depth: int) -> Tuple[Any, int]:
        out = {}
        while i < len(self.lines) and self.lines[i].indent == indent and not (self.lines[i].text == "-" or self.lines[i].text.startswith("- ")):
            ln = self.lines[i]
            key, rest = split_key(ln.text, ln.no)
            if key in out:
                raise YamlError(f"chave repetida: '{key}'", ln.no)
            if rest == "":
                nxt = self._next_indent(i)
                if nxt > indent:
                    out[key], i = self.block(i + 1, depth + 1)
                elif nxt == indent and i + 1 < len(self.lines) and (self.lines[i + 1].text == "-" or self.lines[i + 1].text.startswith("- ")):
                    out[key], i = self.seq(i + 1, indent, depth + 1)       # lista na mesma indentação da chave (permitido em YAML)
                else:
                    out[key], i = None, i + 1
            elif re.fullmatch(r"[|>][+-]?", rest):
                out[key], i = self.block_scalar(i, indent, rest)
            else:
                value_text, i = self.continuation(i, indent, rest)
                out[key] = inline(value_text, ln.no)
        return out, i

    def continuation(self, i: int, indent: int, rest: str) -> Tuple[str, int]:
        """Texto que continua nas linhas seguintes (mais indentadas): aspas abertas ou texto simples dobrado."""
        ln, i = self.lines[i], i + 1
        quote = rest[0] if rest[:1] in ("'", '"') else None
        if quote and not self._closed(rest, quote):
            parts = [rest]
            while i < len(self.lines) and self.lines[i].indent > indent:
                parts.append(self.lines[i].raw.strip())
                i += 1
                if self._closed(" ".join(parts), quote):
                    break
            joined = " ".join(parts)
            if not self._closed(joined, quote):
                raise YamlError("texto entre aspas não foi fechado", ln.no)
            return joined, i
        if rest[:1] not in ("[", "{", "'", '"'):
            parts = [rest]
            while i < len(self.lines) and self.lines[i].indent > indent:
                parts.append(self.lines[i].text)
                i += 1
            return " ".join(parts), i
        return rest, i

    @staticmethod
    def _closed(s: str, q: str) -> bool:
        if len(s) < 2:
            return False
        k = 1
        while k < len(s):
            if s[k] == q:
                if q == "'" and k + 1 < len(s) and s[k + 1] == "'":
                    k += 2
                    continue
                return not s[k + 1:].strip() or s[k + 1:].strip().startswith("#")
            if q == '"' and s[k] == "\\":
                k += 1
            k += 1
        return False

    def block_scalar(self, i: int, indent: int, header: str) -> Tuple[str, int]:
        style, chomp = header[0], (header[1] if len(header) > 1 else "")
        i += 1
        body: List[str] = []
        first = None
        while i < len(self.lines):
            ln = self.lines[i]
            if ln.indent <= indent and ln.text != "":
                break
            if ln.text == "" and ln.raw.strip() == "":
                body.append("")
            else:
                if first is None:
                    first = len(ln.raw) - len(ln.raw.lstrip(" "))
                body.append(ln.raw[first:] if len(ln.raw) - len(ln.raw.lstrip(" ")) >= first else ln.raw.strip())
            i += 1
        while body and body[-1] == "" and chomp != "+":
            body.pop()
        if style == "|":
            text = "\n".join(body)
        else:
            text, prev_blank = "", False
            for k, ln in enumerate(body):
                if ln == "":
                    text += "\n"
                    prev_blank = True
                else:
                    if k and not prev_blank:
                        text += " "
                    text += ln
                    prev_blank = False
        if chomp == "-":
            return text, i
        return (text + "\n") if body else "", i

    def seq(self, i: int, indent: int, depth: int) -> Tuple[Any, int]:
        out: List[Any] = []
        while i < len(self.lines) and self.lines[i].indent == indent and (self.lines[i].text == "-" or self.lines[i].text.startswith("- ")):
            ln = self.lines[i]
            rest = ln.text[1:].lstrip()
            spaces = len(ln.text) - 1 - len(ln.text[1:].lstrip())
            item_indent = indent + 1 + spaces
            if rest == "":
                nxt = self._next_indent(i)
                if nxt > indent:
                    value, i = self.block(i + 1, depth + 1)
                else:
                    value, i = None, i + 1
                out.append(value)
                continue
            is_map_start = rest[0] not in "'\"[{" and self._looks_like_key(rest, ln.no) or (rest[0] in "'\"" and self._quoted_key(rest))
            if rest.startswith("- ") or rest == "-" or is_map_start:
                self.lines[i] = Line(ln.no, item_indent, rest, ln.raw)
                value, i = self.block(i, depth + 1)
                out.append(value)
            else:
                value_text, i = self.continuation(i, indent, rest)
                out.append(inline(value_text, ln.no))
        return out, i

    @staticmethod
    def _looks_like_key(text: str, line: int) -> bool:
        try:
            split_key(text, line)
            return True
        except YamlError:
            return False

    @staticmethod
    def _quoted_key(text: str) -> bool:
        m = re.match(r"""^(?:'(?:[^']|'')*'|"(?:[^"\\]|\\.)*")\s*:(\s|$)""", text)
        return bool(m)


def _prepare(doc_lines: List[Tuple[int, str]]) -> List[Line]:
    out = []
    for no, raw in doc_lines:
        if "\t" in raw[:len(raw) - len(raw.lstrip(" \t"))]:
            raise YamlError("tabulação na indentação (use espaços)", no)
        out.append(Line(no, len(raw) - len(raw.lstrip(" ")), strip_comment(raw).strip(), raw.rstrip("\r\n")))
    return out


def _drop_blank_lines(lines: List[Line]) -> List[Line]:
    """Remove as linhas vazias (e de comentário), exceto as que estão dentro de blocos literais (| ou >), onde elas fazem parte do texto."""
    out: List[Line] = []
    block_indent = None
    for ln in lines:
        if block_indent is not None:
            if ln.text == "" or ln.indent > block_indent:
                out.append(ln)
                continue
            block_indent = None
        if ln.text == "":
            continue
        out.append(ln)
        if re.search(r":\s*[|>][+-]?\s*$", ln.text) or re.fullmatch(r"-\s*[|>][+-]?", ln.text):
            block_indent = ln.indent
    return out


def load_all(text: str) -> List[Any]:
    if len(text.encode("utf-8", "ignore")) > MAX_BYTES:
        raise YamlError("arquivo grande demais (limite de 2 MB)")
    docs: List[List[Tuple[int, str]]] = [[]]
    for no, raw in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        stripped = raw.strip()
        if stripped == "---" or stripped.startswith("--- "):
            if len(docs) > 1 or any(l[1].strip() and not l[1].strip().startswith("#") for l in docs[-1]):
                docs.append([])
            continue
        if stripped == "..." or raw.startswith("%"):
            continue                                        # fim de documento e diretivas YAML
        docs[-1].append((no, raw))
    result = []
    for d in docs:
        lines = _drop_blank_lines(_prepare(d))
        if not any(l.text for l in lines):
            continue
        parser = _Parser(lines)
        value, i = parser.block(0)
        if i < len(parser.lines):
            raise YamlError("indentação inconsistente: conteúdo sobrando", parser.lines[i].no)
        result.append(value)
    return result


def load(text: str) -> Any:
    docs = load_all(text)
    if not docs:
        raise YamlError("arquivo vazio")
    return docs[0]
