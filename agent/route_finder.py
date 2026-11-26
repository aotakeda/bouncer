from __future__ import annotations

import re

from .net import bare_path

IMPORT_PATTERN = re.compile(r"""import\s+(?:\{([^}]*)\}|\*\s+as\s+(\w+)|(\w+))\s+from\s+['"]\./routes/([\w/.-]+)['"]""")
ROUTE_PATTERN = re.compile(r"""app\.(get|post|put|patch|delete|all|use)\(\s*['"]([^'"]+)['"]""")
HANDLER_PATTERN = re.compile(r"\b(\w+)\s*(?:\.\s*\w+\s*)?\(")
WILDCARD_VERBS = ("all", "use")


def route_regex(path: str, prefix: bool) -> re.Pattern:
    path = path.rstrip("/") or "/"
    out = ""
    for part in re.split(r"(:\w+|\*)", path):
        if part == "*":
            out += ".*"
        elif part.startswith(":"):
            out += "[^/]+"
        else:
            out += re.escape(part)
    return re.compile("^" + out + ("(/.*)?$" if prefix else "/?$"), re.IGNORECASE)


def route_module(name: str) -> str:
    return "routes/" + name + ("" if name.endswith(".ts") else ".ts")


def parse_imports(source: str) -> dict:
    names = {}
    for m in IMPORT_PATTERN.finditer(source):
        named, namespace, default, module = m.groups()
        target = route_module(module)
        if not named:
            names[namespace or default] = target
            continue
        for item in named.split(","):
            item = item.strip()
            if item:
                names[item.split(" as ")[-1].strip()] = target
    return names


def handler_file(rest: str, names: dict) -> str:
    for ident in HANDLER_PATTERN.findall(rest):
        if ident in names:
            return names[ident]
    return ""


def call_tail(source: str, start: int) -> str:
    depth, quote_ch, escaped = 1, "", False
    for i in range(start, min(len(source), start + 1500)):
        ch = source[i]
        if escaped:
            escaped = False
        elif quote_ch:
            if ch == "\\":
                escaped = True
            elif ch == quote_ch:
                quote_ch = ""
        elif ch in ("'", '"', "`"):
            quote_ch = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[start:i]
    return source[start:start + 500]


def locate_route(server_source: str, method: str, path: str) -> str:
    names = parse_imports(server_source)
    bare = bare_path(path)
    method = method.lower()
    exact, loose = [], []
    for match in ROUTE_PATTERN.finditer(server_source):
        verb, route = match.groups()
        if verb != method and verb not in WILDCARD_VERBS:
            continue
        if not route_regex(route, prefix=verb == "use").match(bare):
            continue
        target = handler_file(call_tail(server_source, match.end()), names)
        if target:
            (exact if verb == method else loose).append(target)
    hits = exact or loose
    return hits[0] if hits else ""
