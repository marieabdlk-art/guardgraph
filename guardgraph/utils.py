from __future__ import annotations

import ast
from typing import Optional

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


def node_to_source(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ast.dump(node)


def get_call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return node_to_source(func)


def literal_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def walk_functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def has_fstring(node: ast.AST) -> bool:
    return any(isinstance(child, ast.JoinedStr) for child in ast.walk(node))


def contains_keywords(text: str, keywords: list[str]) -> bool:
    low = text.lower()
    return any(k.lower() in low for k in keywords)


def is_resource_id_name(name: str) -> bool:
    low = name.lower()
    return low.endswith("_id") or low in {"id", "user_id", "order_id", "transaction_id"}
