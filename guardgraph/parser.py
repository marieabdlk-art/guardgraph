from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional

from .models import Endpoint
from .utils import HTTP_METHODS, literal_string, node_to_source, walk_functions


class FastAPIEndpointExtractor:
    """Small FastAPI extractor for the GuardGraph MVP.

    Scope:
    - APIRouter(prefix=...)
    - router-level dependencies=[Depends(...)]
    - @router.get/post/put/delete/patch("/path")
    - route-level dependencies=[Depends(...)]
    - Annotated dependency aliases such as CurrentUser = Annotated[..., Depends(...)]
    - Pydantic / SQLModel schema classes
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.endpoint_counter = 0
        self.trees: list[tuple[Path, ast.AST]] = []
        self.func_index: dict[tuple[str, str], ast.AST] = {}
        self.router_prefix_by_file: dict[str, str] = {}
        self.router_dependencies_by_file: dict[str, list[str]] = {}
        self.route_dependencies_by_endpoint: dict[tuple[str, str], list[str]] = {}
        self.pydantic_models: set[str] = set()
        self.dependency_aliases: dict[str, set[str]] = {}

    def parse(self) -> "FastAPIEndpointExtractor":
        for py_file in self.root.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            self._normalize_keyword_only_endpoint_params(tree)
            self.trees.append((py_file, tree))
            self.router_prefix_by_file[str(py_file)] = self._extract_router_prefix(tree)
            self.router_dependencies_by_file[str(py_file)] = self._extract_router_dependencies(tree)
            self.pydantic_models |= self._extract_pydantic_models(tree)
            self.dependency_aliases.update(self._extract_dependency_aliases(tree))
            for fn in walk_functions(tree):
                self.func_index[(str(py_file), fn.name)] = fn
        return self

    def _normalize_keyword_only_endpoint_params(self, tree: ast.AST) -> None:
        for fn in walk_functions(tree):
            if not self._extract_route_from_function(fn):
                continue
            if not fn.args.kwonlyargs:
                continue
            for arg, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
                fn.args.args.append(arg)
                if default is not None:
                    fn.args.defaults.append(default)
            fn.args.kwonlyargs = []
            fn.args.kw_defaults = []

    def _extract_router_prefix(self, tree: ast.AST) -> str:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Name) and call.func.id == "APIRouter":
                    for kw in call.keywords:
                        if kw.arg == "prefix":
                            return literal_string(kw.value) or ""
        return ""

    def _extract_router_dependencies(self, tree: ast.AST) -> list[str]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Name) and call.func.id == "APIRouter":
                    return self._extract_dependencies_keyword(call)
        return []

    def _extract_dependencies_keyword(self, call: ast.Call) -> list[str]:
        dependencies: list[str] = []
        for kw in call.keywords:
            if kw.arg != "dependencies":
                continue
            value = kw.value
            if isinstance(value, (ast.List, ast.Tuple)):
                dependencies.extend(node_to_source(elt) for elt in value.elts)
            else:
                dependencies.append(node_to_source(value))
        return [dep for dep in dependencies if dep]

    def _extract_pydantic_models(self, tree: ast.AST) -> set[str]:
        models: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    base_src = node_to_source(base)
                    if base_src in {"BaseModel", "pydantic.BaseModel", "SQLModel", "sqlmodel.SQLModel"}:
                        models.add(node.name)
                    elif base_src.endswith(".BaseModel") or base_src.endswith(".SQLModel"):
                        models.add(node.name)
        return models

    def _extract_dependency_aliases(self, tree: ast.AST) -> dict[str, set[str]]:
        aliases: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
            else:
                continue
            if not targets:
                continue
            value_src = node_to_source(node.value)
            low = value_src.lower()
            if "depends" not in low:
                continue
            guard_types: set[str] = set()
            for target in targets:
                target_low = target.lower()
                if any(k in low or k in target_low for k in ["current_user", "get_current_user", "auth", "token", "user"]):
                    guard_types.add("AUTH_CHECK")
                if any(k in low or k in target_low for k in ["admin", "superuser", "permission", "role"]):
                    guard_types.add("AUTH_CHECK")
                    guard_types.add("ADMIN_GATE")
                if guard_types:
                    aliases[target] = set(guard_types)
        return aliases

    def extract_endpoints(self) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        self.endpoint_counter = 0
        for file_path, tree in self.trees:
            prefix = self.router_prefix_by_file.get(str(file_path), "")
            for fn in walk_functions(tree):
                route = self._extract_route_from_function(fn)
                if not route:
                    continue
                method, path, route_deps = route
                self.endpoint_counter += 1
                full_path = self._join_paths(prefix, path)
                self.route_dependencies_by_endpoint[(str(file_path), fn.name)] = route_deps
                endpoints.append(
                    Endpoint(
                        id=f"EP-{self.endpoint_counter:03d}",
                        method=method.upper(),
                        path=path,
                        full_path=full_path,
                        file=str(file_path),
                        line=getattr(fn, "lineno", 0),
                        handler=fn.name,
                        prefix=prefix,
                    )
                )
        return endpoints

    def _extract_route_from_function(self, fn: ast.AST) -> Optional[tuple[str, str, list[str]]]:
        for decorator in getattr(fn, "decorator_list", []):
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if not isinstance(func, ast.Attribute):
                continue
            method = func.attr.lower()
            if method not in HTTP_METHODS:
                continue
            path = "/"
            if decorator.args:
                path = literal_string(decorator.args[0]) or "/"
            for kw in decorator.keywords:
                if kw.arg == "path":
                    path = literal_string(kw.value) or path
            return method, path, self._extract_dependencies_keyword(decorator)
        return None

    @staticmethod
    def _join_paths(prefix: str, path: str) -> str:
        if not prefix:
            return path
        if path == "/":
            return prefix + "/"
        return prefix.rstrip("/") + "/" + path.lstrip("/")
