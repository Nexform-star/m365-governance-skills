"""Minimal YAML reader, standard library only.

Reads the subset of YAML that configuration files use: block mappings and sequences, plain and quoted scalars,
flow collections ([a, b] and {k: v}), literal (|) and folded (>) block scalars, comments, multi-document streams,
anchors, aliases and merge keys (<<). It follows YAML 1.2 scalar typing: true/false, null, integers and floats are
converted, while yes/no/on/off stay strings (which is what GitHub Actions and Kubernetes files need).

Not supported: complex keys, tags other than being ignored, multi-line quoted scalars that span more than a few
lines, and indentation tricks beyond those found in real-world config. On unsupported input it raises YAMLError
with the line number rather than guessing.

Usage:
    from _miniyaml import load, load_all, YAMLError
    data = load(text)            # first document
    docs = load_all(text)        # every document in the stream
"""
from __future__ import annotations

import re

__all__ = ["YAMLError", "load", "load_all"]


class YAMLError(ValueError):
    pass


_KEY_RE = re.compile(r'''^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#\[\{][^:]*?|-)\s*:(?=\s|$)''')
_INT_RE = re.compile(r"^[-+]?(?:0|[1-9][0-9_]*)$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F_]+$")
_OCT_RE = re.compile(r"^0o[0-7_]+$")
_FLOAT_RE = re.compile(r"^[-+]?(?:\.[0-9]+|[0-9][0-9_]*(?:\.[0-9_]*)?)(?:[eE][-+]?[0-9]+)?$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "/": "/", "0": "\0", "a": "\a", "b": "\b", "e": "\x1b", " ": " "}


class _Line:
    __slots__ = ("no", "indent", "text", "raw")

    def __init__(self, no: int, raw: str):
        self.no = no
        self.raw = raw
        stripped = raw.lstrip(" ")
        self.indent = len(raw) - len(stripped)
        self.text = _strip_comment(stripped).rstrip()


def _strip_comment(s: str) -> str:
    quote = None
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                if quote == "'" and i + 1 < len(s) and s[i + 1] == "'":
                    i += 2
                    continue
                quote = None
        elif c in "\"'" and (i == 0 or s[i - 1] in " \t[{,:"):
            quote = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
        i += 1
    return s


def _unquote_double(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u" and i + 5 < len(s):
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            if n == "x" and i + 3 < len(s):
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append(_ESCAPES.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _scalar(token: str):
    """Convert a plain or quoted scalar token to a Python value."""
    t = token.strip()
    if t == "":
        return None
    if t[0] == '"':
        if len(t) < 2 or t[-1] != '"':
            raise YAMLError(f"unterminated double-quoted string: {t}")
        return _unquote_double(t[1:-1])
    if t[0] == "'":
        if len(t) < 2 or t[-1] != "'":
            raise YAMLError(f"unterminated single-quoted string: {t}")
        return t[1:-1].replace("''", "'")
    if t in ("~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(t):
        return int(t.replace("_", ""))
    if _HEX_RE.match(t):
        return int(t.replace("_", ""), 16)
    if _OCT_RE.match(t):
        return int(t[2:].replace("_", ""), 8)
    if _FLOAT_RE.match(t) and t not in (".", "-", "+"):
        try:
            return float(t.replace("_", ""))
        except ValueError:
            return t
    if t in (".inf", ".Inf", ".INF", "+.inf"):
        return float("inf")
    if t in ("-.inf", "-.Inf", "-.INF"):
        return float("-inf")
    if t in (".nan", ".NaN", ".NAN"):
        return float("nan")
    return t


class _Parser:
    def __init__(self, text: str):
        self.lines = [_Line(n, raw.rstrip("\r")) for n, raw in enumerate(text.split("\n"), 1)]
        self.anchors: dict[str, object] = {}

    # ---- helpers --------------------------------------------------------------------------------------------
    def _is_blank(self, i: int) -> bool:
        return self.lines[i].text == ""

    def _next_content(self, i: int) -> int:
        while i < len(self.lines) and self._is_blank(i):
            i += 1
        return i

    def _strip_props(self, text: str):
        """Remove a leading anchor (&name) or tag (!x) from a value; return (anchor, rest)."""
        anchor = None
        rest = text.strip()
        changed = True
        while changed and rest:
            changed = False
            if rest.startswith("&"):
                m = re.match(r"&([^\s\[\]\{\},]+)\s*(.*)$", rest, re.S)
                if m:
                    anchor, rest, changed = m.group(1), m.group(2), True
            elif rest.startswith("!"):
                m = re.match(r"!\S*\s*(.*)$", rest, re.S)
                if m:
                    rest, changed = m.group(1), True
        return anchor, rest

    def _alias(self, text: str):
        name = text[1:].strip()
        if name not in self.anchors:
            raise YAMLError(f"unknown alias *{name}")
        return self.anchors[name]

    # ---- documents ------------------------------------------------------------------------------------------
    def documents(self) -> list:
        docs = []
        i = 0
        n = len(self.lines)
        saw_marker = False
        while i < n:
            i = self._next_content(i)
            if i >= n:
                break
            line = self.lines[i]
            if line.indent == 0 and line.text.startswith("%"):
                i += 1
                continue
            if line.indent == 0 and (line.text == "---" or line.text.startswith("--- ")):
                saw_marker = True
                rest = line.text[3:].strip()
                i += 1
                if rest:
                    docs.append(self._inline_document(rest, line.no))
                    continue
                j = self._next_content(i)
                if j >= n or self.lines[j].text in ("---", "...") or self.lines[j].text.startswith("--- "):
                    docs.append(None)
                continue
            if line.indent == 0 and line.text == "...":
                i += 1
                continue
            value, i = self._parse_node(i, line.indent)
            docs.append(value)
        if not docs and not saw_marker:
            return []
        return docs

    def _inline_document(self, rest: str, no: int):
        anchor, rest = self._strip_props(rest)
        value = self._parse_inline_value(rest, no)
        if anchor:
            self.anchors[anchor] = value
        return value

    # ---- block nodes ----------------------------------------------------------------------------------------
    def _parse_node(self, i: int, indent: int):
        i = self._next_content(i)
        if i >= len(self.lines):
            return None, i
        line = self.lines[i]
        if line.text == "-" or line.text.startswith("- "):
            return self._parse_sequence(i, line.indent)
        if _KEY_RE.match(line.text):
            return self._parse_mapping(i, line.indent)
        # a scalar (possibly multi-line) or flow collection at block level
        value, i = self._parse_value_lines(line.text, i, indent - 1 if indent > 0 else -1)
        return value, i

    def _at_doc_end(self, i: int) -> bool:
        line = self.lines[i]
        return line.indent == 0 and (line.text in ("---", "...") or line.text.startswith("--- "))

    def _parse_sequence(self, i: int, indent: int):
        items = []
        n = len(self.lines)
        while True:
            i = self._next_content(i)
            if i >= n:
                break
            line = self.lines[i]
            if self._at_doc_end(i) or line.indent < indent:
                break
            if line.indent > indent:
                raise YAMLError(f"line {line.no}: unexpected indentation")
            if not (line.text == "-" or line.text.startswith("- ")):
                break  # back to the parent mapping
            rest = line.text[1:].strip()
            if rest == "":
                value, i = self._parse_node(i + 1, indent + 1)
                items.append(value)
                continue
            anchor, rest = self._strip_props(rest)
            if rest == "":
                value, i = self._parse_node(i + 1, indent + 1)
                if anchor:
                    self.anchors[anchor] = value
                items.append(value)
                continue
            child_indent = line.indent + (len(line.text) - len(line.text[1:].lstrip()))
            if (rest == "-" or rest.startswith("- ")) and not rest.startswith("- -"):
                # nested sequence on the same line: "- - a"
                value, i = self._parse_nested_sequence_inline(i, child_indent, rest)
                items.append(value)
                continue
            if _KEY_RE.match(rest) and not rest.startswith(("[", "{", '"', "'")):
                value, i = self._parse_mapping(i, child_indent, first_text=rest)
                if anchor:
                    self.anchors[anchor] = value
                items.append(value)
                continue
            value, i = self._parse_value_lines(rest, i, indent)
            if anchor:
                self.anchors[anchor] = value
            items.append(value)
        return items, i

    def _parse_nested_sequence_inline(self, i: int, child_indent: int, rest: str):
        # Treat "- - a" by rewriting the current line as if the inner "- a" sat at child_indent.
        line = self.lines[i]
        self.lines[i] = _Line(line.no, " " * child_indent + rest)
        value, i = self._parse_sequence(i, child_indent)
        return value, i

    def _parse_mapping(self, i: int, indent: int, first_text: str | None = None):
        result: dict = {}
        n = len(self.lines)
        first = True
        while True:
            if not first or first_text is None:
                i = self._next_content(i)
                if i >= n:
                    break
                line = self.lines[i]
                if self._at_doc_end(i) or line.indent < indent:
                    break
                if line.indent > indent:
                    raise YAMLError(f"line {line.no}: unexpected indentation")
                text = line.text
            else:
                line = self.lines[i]
                text = first_text
            first = False
            if text == "-" or text.startswith("- "):
                break
            m = _KEY_RE.match(text)
            if not m:
                raise YAMLError(f"line {line.no}: expected 'key: value', got {text!r}")
            raw_key = m.group("key")
            key = _scalar(raw_key) if raw_key[0] in "\"'" else raw_key.strip()
            rest = text[m.end():].strip()
            anchor, rest = self._strip_props(rest)
            if rest == "":
                # nested block, or null
                j = self._next_content(i + 1)
                if j < n and not self._at_doc_end(j) and (
                    self.lines[j].indent > indent
                    or (self.lines[j].indent == indent and (self.lines[j].text == "-" or self.lines[j].text.startswith("- ")))
                ):
                    value, i = self._parse_node(j, self.lines[j].indent)
                else:
                    value, i = None, i + 1
            else:
                value, i = self._parse_value_lines(rest, i, indent)
            if anchor:
                self.anchors[anchor] = value
            if key == "<<":
                merged = value if isinstance(value, list) else [value]
                for src in merged:
                    if isinstance(src, dict):
                        for k, v in src.items():
                            result.setdefault(k, v)
                continue
            result[key] = value
        return result, i

    # ---- values ---------------------------------------------------------------------------------------------
    def _parse_value_lines(self, rest: str, i: int, parent_indent: int):
        """Parse a value that starts on line i (text `rest`); consume continuation lines. Returns (value, next_i)."""
        line = self.lines[i]
        n = len(self.lines)
        if rest[0] in "|>":
            return self._parse_block_scalar(rest, i, parent_indent)
        if rest[0] == "*":
            return self._alias(rest), i + 1
        if rest[0] in "[{":
            text = rest
            j = i + 1
            while not _flow_complete(text) and j < n:
                text += " " + self.lines[j].text
                j += 1
            value, end = _parse_flow(text, 0, self)
            if text[end:].strip():
                raise YAMLError(f"line {line.no}: trailing content after flow collection: {text[end:].strip()!r}")
            return value, j
        if rest[0] in "\"'":
            text = rest
            j = i + 1
            q = rest[0]
            while not _quoted_complete(text, q) and j < n:
                text += " " + self.lines[j].raw.strip()
                j += 1
            return _scalar(text), j
        # plain scalar with possible continuation lines (deeper indented, not structural)
        parts = [rest]
        j = i + 1
        while j < n:
            nxt = self.lines[j]
            if nxt.text == "":
                break
            if nxt.indent <= parent_indent or self._at_doc_end(j):
                break
            if nxt.indent <= line.indent and (nxt.text.startswith("- ") or nxt.text == "-" or _KEY_RE.match(nxt.text)):
                break
            if nxt.indent > line.indent or not (_KEY_RE.match(nxt.text) or nxt.text.startswith("- ")):
                parts.append(nxt.text.strip())
                j += 1
                continue
            break
        return _scalar(" ".join(parts)), j

    def _parse_block_scalar(self, header: str, i: int, parent_indent: int):
        m = re.match(r"^([|>])([+-]?)(\d?)([+-]?)\s*$", header)
        if not m:
            raise YAMLError(f"line {self.lines[i].no}: bad block scalar header {header!r}")
        style, chomp1, explicit, chomp2 = m.groups()
        chomp = chomp1 or chomp2
        n = len(self.lines)
        j = i + 1
        body: list[str] = []
        block_indent = None
        if explicit:
            block_indent = parent_indent + 1 + int(explicit) - 1 if parent_indent >= 0 else int(explicit)
        while j < n:
            raw = self.lines[j].raw
            if raw.strip() == "":
                body.append("")
                j += 1
                continue
            ind = len(raw) - len(raw.lstrip(" "))
            if block_indent is None:
                if ind <= parent_indent:
                    break
                block_indent = ind
            if ind < block_indent:
                break
            body.append(raw[block_indent:])
            j += 1
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        if style == ">":
            out_lines: list[str] = []
            para: list[str] = []
            for b in body:
                if b == "":
                    out_lines.append(" ".join(para))
                    out_lines.append("")
                    para = []
                elif b.startswith(" "):
                    if para:
                        out_lines.append(" ".join(para))
                        para = []
                    out_lines.append(b)
                else:
                    para.append(b)
            if para:
                out_lines.append(" ".join(para))
            text = "\n".join(out_lines)
        else:
            text = "\n".join(body)
        if chomp == "-":
            text = text.rstrip("\n")
        elif chomp == "+":
            text = text + "\n" * (1 + trailing)
        else:
            text = text.rstrip("\n") + "\n" if text else ""
        return text, j

    def _parse_inline_value(self, rest: str, no: int):
        if rest[0] in "[{":
            value, end = _parse_flow(rest, 0, self)
            return value
        if rest[0] == "*":
            return self._alias(rest)
        return _scalar(rest)


def _quoted_complete(text: str, q: str) -> bool:
    if q == '"':
        i = 1
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == '"':
                return True
            i += 1
        return False
    i = 1
    while i < len(text):
        if text[i] == "'":
            if i + 1 < len(text) and text[i + 1] == "'":
                i += 2
                continue
            return True
        i += 1
    return False


def _flow_complete(text: str) -> bool:
    depth = 0
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
            if depth == 0:
                return True
        i += 1
    return depth <= 0 and quote is None


def _parse_flow(s: str, i: int, parser: _Parser):
    """Parse a flow collection or scalar starting at s[i]. Returns (value, index after it)."""
    i = _skip_ws(s, i)
    if i >= len(s):
        raise YAMLError("unexpected end of flow collection")
    c = s[i]
    if c == "[":
        items = []
        i += 1
        while True:
            i = _skip_ws(s, i)
            if i >= len(s):
                raise YAMLError("unterminated flow sequence")
            if s[i] == "]":
                return items, i + 1
            value, i = _parse_flow(s, i, parser)
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ":":  # single-pair mapping inside a sequence: [a: 1]
                v2, i = _parse_flow(s, i + 1, parser)
                value = {value: v2}
                i = _skip_ws(s, i)
            items.append(value)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "]":
                return items, i + 1
            raise YAMLError(f"expected ',' or ']' in flow sequence near position {i}")
    if c == "{":
        result: dict = {}
        i += 1
        while True:
            i = _skip_ws(s, i)
            if i >= len(s):
                raise YAMLError("unterminated flow mapping")
            if s[i] == "}":
                return result, i + 1
            key, i = _flow_scalar(s, i, parser, in_map_key=True)
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ":":
                i += 1
                i = _skip_ws(s, i)
                if i < len(s) and s[i] in ",}":
                    value = None
                else:
                    value, i = _parse_flow(s, i, parser)
            else:
                value = None
            result[key] = value
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == "}":
                return result, i + 1
            raise YAMLError(f"expected ',' or '}}' in flow mapping near position {i}")
    return _flow_scalar(s, i, parser, in_map_key=False)


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\n":
        i += 1
    return i


def _flow_scalar(s: str, i: int, parser: _Parser, in_map_key: bool):
    if s[i] in "\"'":
        q = s[i]
        j = i + 1
        while j < len(s):
            if q == '"' and s[j] == "\\":
                j += 2
                continue
            if s[j] == q:
                if q == "'" and j + 1 < len(s) and s[j + 1] == "'":
                    j += 2
                    continue
                return _scalar(s[i:j + 1]), j + 1
            j += 1
        raise YAMLError("unterminated quoted string in flow collection")
    j = i
    while j < len(s):
        c = s[j]
        if c in ",]}":
            break
        if c == ":" and (j + 1 >= len(s) or s[j + 1] in " ,]}"):
            break
        j += 1
    token = s[i:j].strip()
    if token.startswith("*"):
        return parser._alias(token), j
    _, token = parser._strip_props(token)
    return _scalar(token), j


def load_all(text: str) -> list:
    """Parse every document in a YAML stream."""
    if "\t" in text:
        for no, raw in enumerate(text.split("\n"), 1):
            stripped = raw.lstrip(" ")
            if stripped.startswith("\t"):
                raise YAMLError(f"line {no}: tabs are not allowed for indentation")
    return _Parser(text).documents()


def load(text: str):
    """Parse the first document in a YAML stream (None for an empty stream)."""
    docs = load_all(text)
    return docs[0] if docs else None
