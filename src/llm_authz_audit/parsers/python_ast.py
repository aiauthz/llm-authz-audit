"""AST helpers for finding decorators, arguments, imports, and patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class DecoratorInfo:
    name: str
    lineno: int
    args: list[str]
    keyword_args: dict[str, str]


@dataclass
class ImportInfo:
    module: str
    names: list[str]
    lineno: int


@dataclass
class CallInfo:
    func_name: str
    lineno: int
    args: list[str]
    keyword_args: dict[str, str]


def get_decorators(tree: ast.Module) -> list[DecoratorInfo]:
    """Find all decorators in the module."""
    decorators: list[DecoratorInfo] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                info = _parse_decorator(dec)
                if info:
                    decorators.append(info)
    return decorators


def _parse_decorator(node: ast.expr) -> DecoratorInfo | None:
    if isinstance(node, ast.Name):
        return DecoratorInfo(name=node.id, lineno=node.lineno, args=[], keyword_args={})
    elif isinstance(node, ast.Attribute):
        name = _get_attr_name(node)
        return DecoratorInfo(name=name, lineno=node.lineno, args=[], keyword_args={})
    elif isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = _get_attr_name(func)
        else:
            return None
        args = [ast.dump(a) for a in node.args]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg:
                kwargs[kw.arg] = ast.dump(kw.value)
        return DecoratorInfo(name=name, lineno=node.lineno, args=args, keyword_args=kwargs)
    return None


def _get_attr_name(node: ast.Attribute) -> str:
    parts = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def get_imports(tree: ast.Module) -> list[ImportInfo]:
    """Find all import statements."""
    imports: list[ImportInfo] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportInfo(
                    module=alias.name,
                    names=[alias.asname or alias.name],
                    lineno=node.lineno,
                ))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [alias.name for alias in node.names]
            imports.append(ImportInfo(module=module, names=names, lineno=node.lineno))
    return imports


def has_import(tree: ast.Module, module_name: str) -> bool:
    """Check if a module is imported (partial match)."""
    for imp in get_imports(tree):
        if module_name in imp.module or module_name in imp.names:
            return True
    return False


def find_function_calls(tree: ast.Module, func_name: str) -> list[CallInfo]:
    """Find all calls to a function by name (supports dotted names)."""
    calls: list[CallInfo] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _get_call_name(node.func)
            if name and (name == func_name or name.endswith(f".{func_name}")):
                args = [ast.dump(a) for a in node.args]
                kwargs = {}
                for kw in node.keywords:
                    if kw.arg:
                        kwargs[kw.arg] = ast.dump(kw.value)
                calls.append(CallInfo(
                    func_name=name, lineno=node.lineno, args=args, keyword_args=kwargs,
                ))
    return calls


def _get_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return _get_attr_name(node)
    return None


def find_decorated_functions(
    tree: ast.Module, decorator_name: str
) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, int]]:
    """Find functions with a specific decorator. Returns (func_name, node, lineno)."""
    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                info = _parse_decorator(dec)
                if info and (info.name == decorator_name or info.name.endswith(f".{decorator_name}")):
                    results.append((node.name, node, node.lineno))
    return results


def find_class_instantiations(tree: ast.Module, class_name: str) -> list[CallInfo]:
    """Find all instantiations of a class."""
    return find_function_calls(tree, class_name)


def find_string_assignments(tree: ast.Module) -> list[tuple[str, str, int]]:
    """Find variable = "string" assignments. Returns (var_name, value, lineno)."""
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    results.append((target.id, node.value.value, node.lineno))
    return results


def find_fstring_variables(tree: ast.Module) -> list[tuple[str, int]]:
    """Find variable names used inside f-strings. Returns (var_name, lineno)."""
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name):
                        results.append((value.value.id, node.lineno))
                    elif isinstance(value.value, ast.Attribute):
                        results.append((_get_attr_name(value.value), node.lineno))
    return results


def get_function_defs(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Get all top-level and nested function definitions."""
    return [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
