"""Shared tree-sitter helpers for the non-Python static analyzers."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from ..errors import DiscoveryError

_PARSERS: dict[str, Any] = {}


def get_parser(language: str) -> Any:
    """Load (and cache) a tree-sitter parser. Grammars may be downloaded on first use."""
    if language in _PARSERS:
        return _PARSERS[language]
    try:
        import tree_sitter_language_pack as tslp

        parser = tslp.get_parser(language)
    except Exception as exc:  # DownloadError / ImportError / LanguageError – all mean "unavailable"
        raise DiscoveryError(
            f"tree-sitter grammar for '{language}' is unavailable ({type(exc).__name__}: {exc}). "
            "It may need a one-time download; check network access or pre-install the grammar."
        ) from exc
    _PARSERS[language] = parser
    return parser


def parse(language: str, source: str) -> Any:
    return get_parser(language).parse(source.encode("utf-8"))


def text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def named_children(node: Any) -> list[Any]:
    return [c for c in node.children if c.is_named]


def children_of(node: Any, *types: str) -> list[Any]:
    return [c for c in node.children if c.type in types]


def first_of(node: Any, *types: str) -> Any | None:
    for c in node.children:
        if c.type in types:
            return c
    return None


def line_of(node: Any) -> int:
    return node.start_point[0] + 1


def ancestors(node: Any) -> Iterator[Any]:
    p = node.parent
    while p is not None:
        yield p
        p = p.parent


_STRING_TYPES = (
    "string", "string_literal", "interpreted_string_literal", "raw_string_literal", "encapsed_string",
    "template_string", "verbatim_string_literal", "string_value",
)


def is_string(node: Any) -> bool:
    return node is not None and node.type in _STRING_TYPES


def string_value(node: Any) -> str | None:
    """Static string content, or None when the string is dynamic / not a string."""
    if not is_string(node):
        return None
    raw = text(node)
    if raw.startswith("@"):  # C# verbatim
        raw = raw[1:]
    if raw.startswith("$"):  # C# interpolated
        return None
    if len(raw) >= 2 and raw[0] in "'\"`" and raw[-1] == raw[0]:
        inner = raw[1:-1]
    else:
        return None
    if node.type == "template_string" and "${" in inner:
        return None
    if node.type == "encapsed_string" and "$" in inner:
        return None
    return inner


_SINGULAR_IRREGULAR = {"people": "person", "children": "child", "men": "man", "women": "woman"}


def singular(word: str) -> str:
    w = word.lower()
    if w in _SINGULAR_IRREGULAR:
        return _SINGULAR_IRREGULAR[w]
    if w.endswith("ies") and len(w) > 3:
        return w[:-3] + "y"
    if w.endswith("ses") or w.endswith("xes"):
        return w[:-2]
    if w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


_NOPE = object()


def object_pairs(node: Any) -> dict[str, Any]:
    """{key: value node} of a JS/TS object literal (string or identifier keys)."""
    out: dict[str, Any] = {}
    if node is None or node.type != "object":
        return out
    for pair in children_of(node, "pair"):
        k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
        if k is not None and v is not None:
            out[text(k).strip("'\"`")] = v
    return out


def js_literal(node: Any) -> Any:
    """Plain Python value of a literal JS expression (objects, arrays, strings, numbers, booleans); _NOPE when it is not a literal."""
    if node is None:
        return _NOPE
    t = node.type
    if t in ("string", "template_string"):
        v = string_value(node)
        return v if v is not None else _NOPE
    if t == "number":
        s = text(node)
        try:
            return int(s) if re.fullmatch(r"-?\d+", s) else float(s)
        except ValueError:
            return _NOPE
    if t in ("true", "false"):
        return t == "true"
    if t == "null":
        return None
    if t == "array":
        vals = [js_literal(c) for c in named_children(node)]
        return [v for v in vals if v is not _NOPE]
    if t == "object":
        out = {}
        for k, v in object_pairs(node).items():
            val = js_literal(v)
            if val is not _NOPE:
                out[k] = val
        return out
    return _NOPE


def is_literal(value: Any) -> bool:
    return value is not _NOPE
