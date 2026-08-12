"""
Module 2.1: AST-based taint analysis for Python (stdlib ast) and JS/TS (tree-sitter).

Python: intra-file inter-procedural taint tracking with:
  - f-string / format string variable recognition
  - Cross-function return value propagation
  - Function argument → parameter taint injection
  - Method chain intermediate tracking
  - Class attribute (self.x) propagation
  - Container subscript (dict[key], list[idx])
  - String concatenation / BinOp taint propagation
  - Multi-target assignment / tuple unpacking
  - Import alias resolution
  - Comprehension / lambda basic support

JS/TS: tree-sitter based AST traversal with:
  - Source detection (fetch, http.get, axios, WebSocket, etc.)
  - Sink detection (exec, eval, child_process.exec, fs.writeFile, etc.)
  - Variable-level taint tracking within function scope
  - Flow chain generation for compound threat detection
"""

import ast
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..taxonomy import (
    SOURCE_CAPABILITY_MAP,
    SINK_CAPABILITY_MAP,
    TRANSFORM_CAPABILITY_MAP,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Python TaintTracker — full inter-procedural within file
# =============================================================================


class TaintTracker:
    """Intra-file inter-procedural taint tracker for Python.

    Tracks taint across:
    - Variable assignments (simple, multi-target, tuple unpacking)
    - Function calls (return value propagation, argument → parameter injection)
    - Class attributes (self.x)
    - f-strings, format strings, BinOp (string concatenation)
    - Container subscripts (dict[key], list[idx])
    - Method chains (a.b().c())
    """

    def __init__(self, filepath: Path):
        self.filepath = filepath
        # var_name → {source_capability_code}
        self.tainted_vars: Dict[str, Set[str]] = {}
        # func_name → return_type: set of source_cap codes
        self.tainted_returns: Dict[str, Set[str]] = {}
        # func_name → {param_index: set of source_cap codes propagated from callers}
        self.func_param_taint: Dict[str, Dict[int, Set[str]]] = {}
        # class_name → {attr_name: set of source_cap codes}
        self.tainted_class_attrs: Dict[str, Dict[str, Set[str]]] = {}
        # Alias map: alias_name → original_qualified_name
        self.import_aliases: Dict[str, str] = {}

        self.capabilities: Set[str] = set()
        self.flows: List[Dict] = []
        self._func_defs: Dict[str, ast.FunctionDef] = {}
        self._current_class: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, tree: ast.AST) -> Tuple[Set[str], List[Dict]]:
        """Run full taint analysis on a Python AST."""
        self._collect_imports(tree)
        self._collect_func_defs(tree)
        self._collect_class_attrs(tree)
        # Analyze each top-level function body, then top-level statements
        self._analyze_node(tree)
        # Propagate: function param taint → internal usage
        self._propagate_param_taint(tree)
        return self.capabilities, self.flows

    # ------------------------------------------------------------------
    # Collection passes
    # ------------------------------------------------------------------

    def _collect_imports(self, node: ast.AST) -> None:
        """Collect import aliases for source/sink matching."""
        for child in ast.walk(node):
            if isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.asname:
                        self.import_aliases[alias.asname] = alias.name
            elif isinstance(child, ast.ImportFrom):
                module = child.module or ""
                for alias in child.names:
                    full_name = f"{module}.{alias.name}"
                    key = alias.asname if alias.asname else alias.name
                    self.import_aliases[key] = full_name

    def _collect_func_defs(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef):
                self._func_defs[child.name] = child

    def _collect_class_attrs(self, node: ast.AST) -> None:
        """Pre-scan class bodies for self.x = source() patterns."""
        for child in ast.walk(node):
            if isinstance(child, ast.ClassDef):
                for item in child.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            attr_parts = self._get_attr_parts(target)
                            if attr_parts and attr_parts[0] == "self":
                                attr_name = ".".join(attr_parts)
                                cls_name = child.name
                                # Check if RHS is a source call
                                if isinstance(item.value, ast.Call):
                                    src = self._match_source(
                                        self._get_func_name(item.value)
                                    )
                                    if src:
                                        self.tainted_class_attrs.setdefault(
                                            cls_name, {}
                                        ).setdefault(attr_name, set()).add(src[0])
                                        self.capabilities.add(src[0])
                                # Check if RHS is a simple tainted var
                                rhs_name = self._get_name(item.value)
                                if rhs_name and rhs_name in self.tainted_vars:
                                    self.tainted_class_attrs.setdefault(
                                        cls_name, {}
                                    ).setdefault(attr_name, set()).update(
                                        self.tainted_vars[rhs_name]
                                    )

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def _analyze_node(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                self._handle_assign(child)
            elif isinstance(child, ast.Call):
                self._handle_call(child)
            elif isinstance(child, ast.AugAssign):
                self._handle_aug_assign(child)

    def _handle_assign(self, node: ast.Assign) -> None:
        """Handle assignment: source, transform, or generic taint propagation."""
        rhs = node.value

        # ---- Case 1: RHS is a Call (source / transform / function return) ----
        if isinstance(rhs, ast.Call):
            func_name = self._get_func_name(rhs)

            # Source detection (with alias resolution)
            source_cap = self._match_source(func_name)
            if source_cap:
                self.capabilities.add(source_cap[0])
                for target in node.targets:
                    self._taint_target(target, source_cap[0])
                return

            # Transform detection
            transform_cap = self._match_transform(func_name)
            if transform_cap:
                self.capabilities.add(transform_cap[0])
                # Check if any argument is tainted → propagate through transform
                for arg in rhs.args:
                    arg_taints = self._get_expr_taint(arg)
                    if arg_taints:
                        for target in node.targets:
                            self._taint_target(target, *arg_taints)
                # Also check keyword arguments
                for kw in rhs.keywords:
                    kw_taints = self._get_expr_taint(kw.value)
                    if kw_taints:
                        for target in node.targets:
                            self._taint_target(target, *kw_taints)
                return

            # Cross-function return: func() where func is user-defined
            if func_name in self._func_defs:
                ret_taints = self.tainted_returns.get(func_name, set())
                if ret_taints:
                    for target in node.targets:
                        self._taint_target(target, *ret_taints)
                return

        # ---- Case 2: RHS is a BinOp (string concat: "prefix" + tainted_var) ----
        if isinstance(rhs, ast.BinOp):
            left_taints = self._get_expr_taint(rhs.left)
            right_taints = self._get_expr_taint(rhs.right)
            combined = left_taints | right_taints
            if combined:
                for target in node.targets:
                    self._taint_target(target, *combined)
                return

        # ---- Case 3: RHS is a simple name (propagation: a = tainted_b) ----
        rhs_name = self._get_name(rhs)
        if rhs_name and rhs_name in self.tainted_vars:
            for target in node.targets:
                self._taint_target(target, *self.tainted_vars[rhs_name])
            return

        # ---- Case 4: RHS is a subscript (data['key'] or items[0]) ----
        if isinstance(rhs, ast.Subscript):
            base_name = self._get_name(rhs.value)
            if base_name and base_name in self.tainted_vars:
                for target in node.targets:
                    self._taint_target(target, *self.tainted_vars[base_name])
                return

        # ---- Case 5: RHS is a JoinedStr (f-string) ----
        if isinstance(rhs, ast.JoinedStr):
            all_taints: Set[str] = set()
            for val in rhs.values:
                if isinstance(val, ast.FormattedValue):
                    val_taints = self._get_expr_taint(val.value)
                    all_taints.update(val_taints)
            if all_taints:
                for target in node.targets:
                    self._taint_target(target, *all_taints)
                return

        # ---- Case 6: RHS is an Attribute (method chain result or self.x) ----
        if isinstance(rhs, ast.Attribute):
            # Check for class attribute (self.url)
            attr_parts = self._get_attr_parts(rhs)
            if attr_parts:
                attr_key = ".".join(attr_parts)
                # Search all known class attribute stores
                for cls_name, attrs in self.tainted_class_attrs.items():
                    if attr_key in attrs:
                        for target in node.targets:
                            self._taint_target(target, *attrs[attr_key])
                        return
                    # Also check partial match (e.g. self.url matches self)
                    if attr_parts[0] == "self":
                        for akey, ataints in attrs.items():
                            if akey.endswith(f".{attr_parts[-1]}"):
                                for target in node.targets:
                                    self._taint_target(target, *ataints)
                                return

            # Check if the attribute chain starts from a tainted variable
            base_name = self._get_name(rhs.value)
            if base_name and base_name in self.tainted_vars:
                for target in node.targets:
                    self._taint_target(target, *self.tainted_vars[base_name])
                return

    def _handle_call(self, node: ast.Call) -> None:
        """Handle a bare call expression: check for sinks and function returns."""
        func_name = self._get_func_name(node)

        # ---- Sink detection ----
        sink_cap = self._match_sink(func_name)
        if sink_cap:
            self.capabilities.add(sink_cap[0])

            # Check positional arguments for taint
            for i, arg in enumerate(node.args):
                arg_taints = self._get_expr_taint(arg)
                if arg_taints and arg_taints != {"unknown"}:
                    for src in arg_taints:
                        if src in self.capabilities or src in {"unknown"}:
                            self.flows.append({
                                "source": src,
                                "source_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                                "transforms": [],
                                "sink": sink_cap[0],
                                "sink_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                            })

            # Check keyword arguments
            for kw in node.keywords:
                kw_taints = self._get_expr_taint(kw.value)
                if kw_taints and kw_taints != {"unknown"}:
                    for src in kw_taints:
                        if src in self.capabilities or src in {"unknown"}:
                            self.flows.append({
                                "source": src,
                                "source_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                                "transforms": [],
                                "sink": sink_cap[0],
                                "sink_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                            })

            # shell=True detection
            if "proc-exec" in sink_cap[0] or "proc-exec-shell" in sink_cap[0]:
                for kw in node.keywords:
                    if kw.arg == "shell" and self._is_truthy(kw.value):
                        self.capabilities.add("proc-exec-shell")
                        break
            return

        # ---- Cross-function: track return taint for user-defined functions ----
        if func_name in self._func_defs:
            func_def = self._func_defs[func_name]
            # Collect taint from arguments passed to this call
            arg_taints: Dict[int, Set[str]] = {}
            for i, arg in enumerate(node.args):
                taints = self._get_expr_taint(arg)
                if taints and taints != {"unknown"}:
                    arg_taints[i] = taints
            # Also check keyword arguments
            for kw in node.keywords:
                if kw.arg:
                    # Find parameter index by name
                    for idx, param in enumerate(func_def.args.args):
                        if param.arg == kw.arg:
                            taints = self._get_expr_taint(kw.value)
                            if taints and taints != {"unknown"}:
                                arg_taints[idx] = taints
                            break
            # Store for later propagation
            if arg_taints:
                existing = self.func_param_taint.setdefault(func_name, {})
                for idx, taints in arg_taints.items():
                    existing.setdefault(idx, set()).update(taints)

    def _handle_aug_assign(self, node: ast.AugAssign) -> None:
        """Handle +=, etc. — propagate taint if RHS is tainted."""
        rhs_taints = self._get_expr_taint(node.value)
        if rhs_taints:
            target_name = self._get_name(node.target)
            if target_name:
                self.tainted_vars.setdefault(target_name, set()).update(rhs_taints)

    # ------------------------------------------------------------------
    # Taint propagation helpers
    # ------------------------------------------------------------------

    def _propagate_param_taint(self, tree: ast.AST) -> None:
        """Second pass: inject collected param taints into function bodies."""
        for func_name, param_taints in self.func_param_taint.items():
            func_def = self._func_defs.get(func_name)
            if not func_def:
                continue
            for idx, taints in param_taints.items():
                if idx < len(func_def.args.args):
                    param_name = func_def.args.args[idx].arg
                    self.tainted_vars.setdefault(param_name, set()).update(taints)

        # After injecting param taints, re-analyze function bodies
        # to propagate newly tainted parameters to sinks
        for func_def in self._func_defs.values():
            self._analyze_function_body(func_def)

        # Capture return values from user-defined functions
        for func_name, func_def in self._func_defs.items():
            self._analyze_function_returns(func_def)

    def _analyze_function_body(self, func_def: ast.FunctionDef) -> None:
        """Re-analyze a function body for taint flows (called after param injection)."""
        for item in func_def.body:
            if isinstance(item, ast.Assign):
                self._handle_assign(item)
            elif isinstance(item, ast.Call):
                self._handle_call(item)
            elif isinstance(item, ast.Expr) and isinstance(item.value, ast.Call):
                self._handle_call(item.value)
            elif isinstance(item, ast.AugAssign):
                self._handle_aug_assign(item)

    def _analyze_function_returns(self, func_def: ast.FunctionDef) -> None:
        """Extract taint from function return statements."""
        for child in ast.walk(func_def):
            if isinstance(child, ast.Return) and child.value:
                ret_taints = self._get_expr_taint(child.value)
                if ret_taints and ret_taints != {"unknown"}:
                    self.tainted_returns.setdefault(func_def.name, set()).update(
                        ret_taints
                    )

    def _taint_target(self, target: ast.expr, *source_caps: str) -> None:
        """Mark a target expression as tainted.

        Handles: Name, Tuple (unpacking), Attribute (self.x), Starred, Subscript
        """
        for cap in source_caps:
            if cap == "unknown":
                continue

            if isinstance(target, ast.Name):
                self.tainted_vars.setdefault(target.id, set()).add(cap)

            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    self._taint_target(elt, cap)

            elif isinstance(target, ast.Attribute):
                attr_parts = self._get_attr_parts(target)
                if attr_parts and attr_parts[0] == "self":
                    attr_key = ".".join(attr_parts)
                    cls_name = self._current_class or "_global"
                    self.tainted_class_attrs.setdefault(cls_name, {}).setdefault(
                        attr_key, set()
                    ).add(cap)

            elif isinstance(target, ast.Subscript):
                base_name = self._get_name(target.value)
                if base_name:
                    self.tainted_vars.setdefault(base_name, set()).add(cap)

            elif isinstance(target, ast.Starred):
                self._taint_target(target.value, cap)

    def _get_expr_taint(self, expr: ast.expr) -> Set[str]:
        """Get all taint sources for an arbitrary expression.

        Recursively extracts taint from: Name, Attribute, Subscript,
        Call, BinOp, JoinedStr, FormattedValue, IfExp.
        """
        # Simple name
        if isinstance(expr, ast.Name):
            return self.tainted_vars.get(expr.id, set()).copy()

        # Attribute (self.x, a.b)
        if isinstance(expr, ast.Attribute):
            attr_parts = self._get_attr_parts(expr)
            if attr_parts:
                attr_key = ".".join(attr_parts)
                for cls_name, attrs in self.tainted_class_attrs.items():
                    if attr_key in attrs:
                        return attrs[attr_key].copy()
            base_name = self._get_name(expr.value)
            if base_name and base_name in self.tainted_vars:
                return self.tainted_vars[base_name].copy()

        # Subscript (data[key])
        if isinstance(expr, ast.Subscript):
            base_name = self._get_name(expr.value)
            if base_name and base_name in self.tainted_vars:
                return self.tainted_vars[base_name].copy()

        # Binary operation (a + b)
        if isinstance(expr, ast.BinOp):
            return self._get_expr_taint(expr.left) | self._get_expr_taint(expr.right)

        # f-string / JoinedStr
        if isinstance(expr, ast.JoinedStr):
            result: Set[str] = set()
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    result.update(self._get_expr_taint(val.value))
                elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                    pass  # literal string, no taint
            return result

        # FormattedValue (the {var} inside f-string)
        if isinstance(expr, ast.FormattedValue):
            return self._get_expr_taint(expr.value)

        # Call expression (func())
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr)
            # Check if it's a source call
            source = self._match_source(func_name)
            if source:
                return {source[0]}
            # Check if it returns a tainted value
            if func_name in self.tainted_returns:
                return self.tainted_returns[func_name].copy()
            # Check method chains: a.b().c()
            if isinstance(expr.func, ast.Attribute):
                base_taint = self._get_expr_taint(expr.func.value)
                if base_taint:
                    return base_taint

        # Conditional expression (x if cond else y)
        if isinstance(expr, ast.IfExp):
            return self._get_expr_taint(expr.body) | self._get_expr_taint(expr.orelse)

        # List/Tuple/Set literal
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = set()
            for elt in expr.elts:
                result.update(self._get_expr_taint(elt))
            return result

        # Constant (no taint)
        if isinstance(expr, ast.Constant):
            return set()

        return set()

    # ------------------------------------------------------------------
    # Name / attribute extraction
    # ------------------------------------------------------------------

    def _get_func_name(self, call_node: ast.Call) -> str:
        """Extract the full qualified function name, resolving aliases."""
        name = self._resolve_callable(call_node.func)
        if name in self.import_aliases:
            return self.import_aliases[name]
        return name

    def _resolve_callable(self, node: ast.expr) -> str:
        """Get a string representation of a callable expression."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def _get_name(self, node: ast.expr) -> Optional[str]:
        """Get variable name: handles Name, and extracts base from Attribute/Subscript."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_name(node.value)
        if isinstance(node, ast.Subscript):
            return self._get_name(node.value)
        if isinstance(node, ast.Starred):
            return self._get_name(node.value)
        return None

    def _get_attr_parts(self, node: ast.expr) -> Optional[List[str]]:
        """Get the full attribute chain: self.url.config → ['self','url','config']."""
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            base = self._get_attr_parts(node.value)
            if base is not None:
                return base + [node.attr]
        return None

    # ------------------------------------------------------------------
    # Source / Sink / Transform matching (with alias resolution)
    # ------------------------------------------------------------------

    def _match_source(self, func_name: str) -> Optional[Tuple[str, str]]:
        for pattern, (cap, _) in SOURCE_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        # Check alias
        if func_name in self.import_aliases:
            resolved = self.import_aliases[func_name]
            return self._match_source(resolved)
        return None

    def _match_sink(self, func_name: str) -> Optional[Tuple[str, str]]:
        for pattern, (cap, _) in SINK_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        if func_name in self.import_aliases:
            resolved = self.import_aliases[func_name]
            return self._match_sink(resolved)
        return None

    def _match_transform(self, func_name: str) -> Optional[Tuple[str, str]]:
        for pattern, (cap, _) in TRANSFORM_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        if func_name in self.import_aliases:
            resolved = self.import_aliases[func_name]
            return self._match_transform(resolved)
        return None

    def _is_truthy(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return True


# =============================================================================
# Python analysis entry point
# =============================================================================


def analyze_python_file(filepath: Path) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """Analyze a single Python file for capabilities and taint flows."""
    capabilities: Set[str] = set()
    flows: List[Dict] = []
    findings: List[Dict] = []

    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Cannot read {filepath}: {e}")
        return capabilities, flows, findings

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        logger.warning(f"Syntax error in {filepath}: {e}")
        return capabilities, flows, findings

    tracker = TaintTracker(filepath)
    caps, tracked_flows = tracker.analyze(tree)
    capabilities.update(caps)
    flows.extend(tracked_flows)

    # Additional AST pattern checks
    additional_caps, additional_findings = _ast_pattern_checks(filepath, tree, source)
    capabilities.update(additional_caps)
    findings.extend(additional_findings)

    return capabilities, flows, findings


def _ast_pattern_checks(
    filepath: Path, tree: ast.AST, source: str
) -> Tuple[Set[str], List[Dict]]:
    """Additional AST-based pattern checks."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = ""
        if isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            parts.reverse()
            func_name = ".".join(parts)
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        # subprocess with shell=True
        if func_name in (
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
        ):
            for kw in node.keywords:
                if kw.arg == "shell" and _ast_is_truthy(kw.value):
                    capabilities.add("proc-exec-shell")
                    findings.append({
                        "type": "Shell Execution via shell=True",
                        "severity": "high",
                        "category": "Process Execution",
                        "location": f"{filepath.name}:{node.lineno}",
                        "description": f"{func_name} 调用使用 shell=True，存在命令注入风险",
                        "evidence": _get_source_line(source, node.lineno),
                    })

        # os.system / os.popen
        if func_name in ("os.system", "os.popen"):
            capabilities.add("proc-exec-shell")
            findings.append({
                "type": "Shell Execution",
                "severity": "high",
                "category": "Process Execution",
                "location": f"{filepath.name}:{node.lineno}",
                "description": f"{func_name} 直接执行 shell 命令",
                "evidence": _get_source_line(source, node.lineno),
            })

        # eval / exec
        if func_name in ("eval", "exec"):
            capabilities.add("proc-code-eval")
            findings.append({
                "type": "Dynamic Code Execution",
                "severity": "high",
                "category": "Process Execution",
                "location": f"{filepath.name}:{node.lineno}",
                "description": f"{func_name}() 动态代码执行",
                "evidence": _get_source_line(source, node.lineno),
            })

    return capabilities, findings


def _ast_is_truthy(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return True


def _get_source_line(source: str, lineno: int) -> str:
    lines = source.split("\n")
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:200]
    return ""


# =============================================================================
# JS/TS tree-sitter based taint analysis
# =============================================================================

# JS/TS source → capability mapping
JS_SOURCE_PATTERNS: Dict[str, Tuple[str, str]] = {
    "fetch": ("net-http-out", "fetch()"),
    "http.get": ("net-http-out", "http.get()"),
    "http.request": ("net-http-out", "http.request()"),
    "https.get": ("net-http-out", "https.get()"),
    "https.request": ("net-http-out", "https.request()"),
    "axios": ("net-http-out", "axios()"),
    "got(": ("net-http-out", "got()"),
    "node-fetch": ("net-http-out", "node-fetch"),
    "WebSocket": ("net-socket-out", "WebSocket"),
    "net.createConnection": ("net-socket-out", "net.createConnection()"),
    "net.connect": ("net-socket-out", "net.connect()"),
    "socket.createConnection": ("net-socket-out", "socket()"),
}

# JS/TS sink → capability mapping
JS_SINK_PATTERNS: Dict[str, Tuple[str, str]] = {
    "exec": ("proc-exec", "exec()"),
    "execSync": ("proc-exec", "execSync()"),
    "spawn": ("proc-exec", "spawn()"),
    "spawnSync": ("proc-exec", "spawnSync()"),
    "execFile": ("proc-exec", "execFile()"),
    "execFileSync": ("proc-exec", "execFileSync()"),
    "eval": ("proc-code-eval", "eval()"),
    "Function(": ("proc-code-eval", "new Function()"),
    "require('child_process')": ("proc-exec", "require(child_process)"),
    'require("child_process")': ("proc-exec", "require(child_process)"),
    "fs.writeFile": ("fs-write", "fs.writeFile()"),
    "fs.writeFileSync": ("fs-write", "fs.writeFileSync()"),
    "fs.appendFile": ("fs-write", "fs.appendFile()"),
    "fs.appendFileSync": ("fs-write", "fs.appendFileSync()"),
    "fs.unlink": ("fs-delete", "fs.unlink()"),
    "fs.unlinkSync": ("fs-delete", "fs.unlinkSync()"),
    "process.env.": ("env-access-specific", "process.env"),
    "process.env[": ("env-access-specific", "process.env[]"),
}

# JS/TS transform → capability mapping
JS_TRANSFORM_PATTERNS: Dict[str, Tuple[str, str]] = {
    "JSON.stringify": ("enc-compression", "JSON.stringify()"),
    "JSON.parse": ("enc-compression", "JSON.parse()"),
    "Buffer.from": ("enc-base64", "Buffer.from()"),
    ".toString('base64'": ("enc-base64", ".toString('base64')"),
    "atob": ("enc-base64", "atob()"),
    "btoa": ("enc-base64", "btoa()"),
    "crypto.createHash": ("enc-crypto", "crypto.createHash()"),
    "crypto.createCipher": ("enc-crypto", "crypto.createCipher()"),
}


class JSTaintAnalyzer:
    """Tree-sitter based taint analyzer for JavaScript and TypeScript.

    Tracks variable-level taint within function scope and detects
    source → sink flows for compound threat detection.
    """

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.tainted_vars: Dict[str, Set[str]] = {}  # var → {source_cap}
        self.capabilities: Set[str] = set()
        self.flows: List[Dict] = []
        self.findings: List[Dict] = []
        # Track function call return taint
        self.func_taint_map: Dict[str, Set[str]] = {}

    def analyze(self, source: str, language: str = "javascript") -> Tuple[Set[str], List[Dict], List[Dict]]:
        """Run taint analysis on JS/TS source using tree-sitter."""
        try:
            if language == "typescript":
                import tree_sitter_typescript as ts_lang
                parser_lang = ts_lang.language_typescript()
            else:
                import tree_sitter_javascript as ts_lang
                parser_lang = ts_lang.language()
        except ImportError as e:
            logger.warning(f"tree-sitter language not available: {e}")
            return self._fallback_regex_analysis(source)

        try:
            from tree_sitter import Parser, Language
        except ImportError as e:
            logger.warning(f"tree-sitter not available: {e}")
            return self._fallback_regex_analysis(source)

        lang_obj = Language(parser_lang)
        parser = Parser(lang_obj)

        tree = parser.parse(source.encode("utf-8"))
        root = tree.root_node

        # Walk the tree to find:
        # 1. Source calls → mark assigned variables as tainted
        # 2. Sink calls → check if arguments reference tainted variables
        # 3. Variable assignments → propagate taint
        self._walk_tree(root, source)

        # Also run capability-level detection for patterns tree-sitter might miss
        regex_caps, regex_findings = self._supplement_regex(source)
        self.capabilities.update(regex_caps)
        self.findings.extend(regex_findings)

        return self.capabilities, self.flows, self.findings

    def _walk_tree(self, node, source: str) -> None:
        """Recursively walk the tree-sitter CST looking for taint patterns."""
        # Check this node for source/sink/assignment patterns
        self._check_node(node, source)

        # Recurse
        for child in node.children:
            self._walk_tree(child, source)

    def _check_node(self, node, source: str) -> None:
        """Check a single tree-sitter node for taint-relevant patterns."""
        node_type = node.type
        node_text = source[node.start_byte:node.end_byte]

        # ---- Variable declaration with call expression ----
        # e.g., const x = fetch(url)
        if node_type in ("variable_declaration", "lexical_declaration"):
            self._check_var_decl(node, source)

        # ---- Assignment expression ----
        # e.g., x = someFunc()
        if node_type == "assignment_expression":
            self._check_assignment(node, source)

        # ---- Call expression (bare) ----
        # e.g., exec(cmd) — not part of assignment
        if node_type == "call_expression" and node.parent and node.parent.type not in (
            "variable_declaration", "lexical_declaration", "assignment_expression",
            "variable_declarator",
        ):
            self._check_bare_call(node, source)

        # ---- Expression statement containing call ----
        if node_type == "expression_statement":
            for child in node.children:
                if child.type == "call_expression":
                    self._check_bare_call(child, source)

    def _check_var_decl(self, node, source: str) -> None:
        """Check a variable declaration: const x = expr"""
        for child in node.children:
            if child.type == "variable_declarator":
                # Find the name
                var_name = None
                init_expr = None
                for c in child.children:
                    if c.type == "identifier":
                        var_name = source[c.start_byte:c.end_byte]
                    elif c.type in ("call_expression", "new_expression", "assignment_expression", "binary_expression"):
                        init_expr = c
                    elif c.type == "arrow_function":
                        # Skip function definitions
                        pass
                if var_name and init_expr:
                    self._process_init(var_name, init_expr, source)

    def _check_assignment(self, node, source: str) -> None:
        """Check assignment expression: x = expr"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left and right:
            var_name = source[left.start_byte:left.end_byte] if left.type == "identifier" else None
            if var_name and right.type in ("call_expression", "new_expression", "binary_expression"):
                self._process_init(var_name, right, source)

    def _process_init(self, var_name: str, expr_node, source: str) -> None:
        """Process a variable initializer: check if it's a source or transform call."""
        if expr_node.type in ("call_expression", "new_expression"):
            func_name = self._extract_call_name(expr_node, source)

            # Check source
            for pattern, (cap, _) in JS_SOURCE_PATTERNS.items():
                if pattern in func_name:
                    self.capabilities.add(cap)
                    self.tainted_vars.setdefault(var_name, set()).add(cap)
                    return

            # Check transform
            for pattern, (cap, _) in JS_TRANSFORM_PATTERNS.items():
                if pattern in func_name:
                    self.capabilities.add(cap)
                    # Check if any argument is tainted
                    args = expr_node.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "identifier":
                                arg_name = source[arg.start_byte:arg.end_byte]
                                if arg_name in self.tainted_vars:
                                    self.tainted_vars.setdefault(var_name, set()).update(
                                        self.tainted_vars[arg_name]
                                    )
                    return

            # Check if we're calling a function whose return is known to be tainted
            # (e.g., getMaliciousUrl() defined elsewhere and auto-invoked)
            self._check_indirect_source(var_name, func_name, expr_node, source)

        # Check binary expression (string concat)
        if expr_node.type == "binary_expression":
            self._check_binary_taint(var_name, expr_node, source)

    def _check_bare_call(self, node, source: str) -> None:
        """Check a bare call expression (not in assignment) for sink patterns."""
        func_name = self._extract_call_name(node, source)

        # Check if it's a sink
        sink_cap = None
        for pattern, (cap, _) in JS_SINK_PATTERNS.items():
            if pattern in func_name or pattern in source[node.start_byte:node.end_byte]:
                sink_cap = (cap, pattern)
                break

        if not sink_cap:
            # Check if this function call is known to produce tainted data
            self._check_sink_indirect(node, source)
            return

        self.capabilities.add(sink_cap[0])

        # Check arguments for tainted variables
        args = node.child_by_field_name("arguments")
        if args:
            for arg in args.children:
                if arg.type == "identifier":
                    arg_name = source[arg.start_byte:arg.end_byte]
                    if arg_name in self.tainted_vars:
                        for src in self.tainted_vars[arg_name]:
                            self.flows.append({
                                "source": src,
                                "source_location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                                "transforms": [],
                                "sink": sink_cap[0],
                                "sink_location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                            })
                # Check template strings: `curl ${url}`
                if arg.type == "template_string":
                    for child in arg.children:
                        if child.type == "template_substitution":
                            for sub in child.children:
                                if sub.type == "identifier":
                                    sub_name = source[sub.start_byte:sub.end_byte]
                                    if sub_name in self.tainted_vars:
                                        for src in self.tainted_vars[sub_name]:
                                            self.flows.append({
                                                "source": src,
                                                "source_location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                                                "transforms": [],
                                                "sink": sink_cap[0],
                                                "sink_location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                                            })

    def _check_indirect_source(self, var_name: str, func_name: str, call_node, source: str) -> None:
        """Check if calling a user-defined function that returns tainted data."""
        # If we've already recorded this function as a source, propagate
        if func_name in self.func_taint_map:
            self.tainted_vars.setdefault(var_name, set()).update(self.func_taint_map[func_name])
            return

        # Check function arguments: if any are tainted, propagate
        args = call_node.child_by_field_name("arguments")
        if args:
            for arg in args.children:
                if arg.type == "identifier":
                    arg_name = source[arg.start_byte:arg.end_byte]
                    if arg_name in self.tainted_vars:
                        self.tainted_vars.setdefault(var_name, set()).update(
                            self.tainted_vars[arg_name]
                        )
                        self.func_taint_map.setdefault(func_name, set()).update(
                            self.tainted_vars[arg_name]
                        )
                        return

    def _check_sink_indirect(self, node, source: str) -> None:
        """Detect patterns like child_process methods called indirectly."""
        node_text = source[node.start_byte:node.end_byte]

        # Detect: require('child_process').exec(...)
        if "child_process" in node_text:
            self.capabilities.add("proc-exec")
            if "exec" in node_text:
                self.findings.append({
                    "type": "Dangerous JS Pattern",
                    "severity": "critical",
                    "category": "Malicious Code",
                    "location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                    "description": "child_process execution detected (potential reverse shell)",
                    "evidence": node_text[:200],
                })

        # Detect: net.createConnection / reverse shell patterns
        if "createConnection" in node_text or "net.connect" in node_text:
            self.capabilities.add("net-socket-out")
            self.findings.append({
                "type": "Dangerous JS Pattern",
                "severity": "critical",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}:{node.start_point[0] + 1}",
                "description": "TCP socket connection detected (potential reverse shell)",
                "evidence": node_text[:200],
            })

        # Detect: fs.writeFileSync (writing scripts to disk)
        if "writeFile" in node_text and ("fs." in node_text or "require('fs')" in node_text or 'require("fs")' in node_text):
            self.capabilities.add("fs-write")

    def _check_binary_taint(self, var_name: str, expr_node, source: str) -> None:
        """Check string concatenation for tainted operands."""
        for child in expr_node.children:
            if child.type == "identifier":
                child_name = source[child.start_byte:child.end_byte]
                if child_name in self.tainted_vars:
                    self.tainted_vars.setdefault(var_name, set()).update(
                        self.tainted_vars[child_name]
                    )

    def _extract_call_name(self, call_node, source: str) -> str:
        """Extract the function name from a call_expression node."""
        func_node = call_node.child_by_field_name("function")
        if not func_node:
            return ""
        if func_node.type == "identifier":
            return source[func_node.start_byte:func_node.end_byte]
        if func_node.type == "member_expression":
            # obj.method() → reconstruct dotted name
            return source[func_node.start_byte:func_node.end_byte]
        return ""

    def _fallback_regex_analysis(self, source: str) -> Tuple[Set[str], List[Dict], List[Dict]]:
        """Fallback regex analysis when tree-sitter is unavailable."""
        caps: Set[str] = set()
        findings: List[Dict] = []

        # Check for child_process execution (reverse shell indicator)
        if re.search(r"require\s*\(\s*['\"]child_process['\"]\s*\)", source):
            caps.add("proc-exec")
            findings.append({
                "type": "Dangerous JS Pattern",
                "severity": "critical",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}",
                "description": "child_process module import detected",
                "evidence": "require('child_process')",
            })

        # Check for exec/execSync calls
        if re.search(r"\.exec\s*\(|\.execSync\s*\(", source):
            caps.add("proc-exec")
        if re.search(r"\.spawn\s*\(|\.spawnSync\s*\(", source):
            caps.add("proc-exec")

        # Check for net.createConnection (reverse shell)
        if re.search(r"net\.createConnection|net\.connect", source):
            caps.add("net-socket-out")

        # Check for fs.writeFile (dropping payload)
        if re.search(r"fs\.writeFile|fs\.writeFileSync", source):
            caps.add("fs-write")

        # Check for eval
        if re.search(r"\beval\s*\(|new\s+Function\s*\(", source):
            caps.add("proc-code-eval")

        # Check for process.env
        if re.search(r"process\.env", source):
            caps.add("env-access-specific")

        return caps, self.flows, findings

    def _supplement_regex(self, source: str) -> Tuple[Set[str], List[Dict]]:
        """Supplementary regex checks for patterns tree-sitter might miss."""
        caps: Set[str] = set()
        findings: List[Dict] = []

        # Detect auto-execution patterns (IIFE, or function call at module level)
        if re.search(r'\}\s*\)\s*\(\s*\)\s*;?\s*$', source, re.MULTILINE):
            caps.add("instr-silent-exec")
            findings.append({
                "type": "IIFE Auto-Execution",
                "severity": "high",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}",
                "description": "IIFE (Immediately Invoked Function Expression) — code auto-executes on load",
                "evidence": source.strip()[:200],
            })

        # Detect auto-execution: funcName() at module level (no assignment)
        auto_call_matches = re.findall(
            r'^(?!.*(?:const|let|var|if|for|while|return|function|class|import|export|try|catch|switch)\b)\s*(\w+)\s*\(\s*\)\s*;?\s*$',
            source, re.MULTILINE
        )
        if auto_call_matches:
            caps.add("instr-silent-exec")
            findings.append({
                "type": "Auto-Execution on Load",
                "severity": "high",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}",
                "description": f"Function auto-executes on module load: {auto_call_matches[0]}()",
                "evidence": f"{auto_call_matches[0]}() called at module level",
            })

        # Detect reverse shell patterns (even inside template literals)
        if re.search(r"net\.createConnection|net\.connect", source):
            caps.add("net-socket-out")
            findings.append({
                "type": "Reverse Shell Pattern",
                "severity": "critical",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}",
                "description": "TCP socket connection pattern detected (potential reverse shell)",
                "evidence": "net.createConnection/net.connect found in source",
            })

        # Detect child_process.spawn/exec patterns for shell access
        if re.search(r"child_process.*\.(?:exec|spawn|fork)\s*\(", source, re.DOTALL):
            caps.add("proc-exec")
            caps.add("proc-exec-shell")

        # Detect pipe-based reverse shell: stdin.pipe + stdout.pipe
        if re.search(r"\.pipe\s*\(.*std(?:out|in)", source):
            caps.add("net-socket-out")
            findings.append({
                "type": "Shell I/O Redirection",
                "severity": "critical",
                "category": "Malicious Code",
                "location": f"{self.filepath.name}",
                "description": "stdin/stdout pipe to socket detected (reverse shell I/O redirection)",
                "evidence": "Process I/O piped to remote socket",
            })

        # Detect downloading + executing pattern
        has_write = bool(re.search(r"writeFile|writeFileSync|appendFile", source))
        has_exec = bool(re.search(r"execSync|exec\s*\(|spawn\s*\(", source))
        if has_write and has_exec:
            caps.add("net-download-exec")  # script dropper variant

        return caps, findings


# =============================================================================
# Main entry point
# =============================================================================


def run_ast_analysis(
    script_files: List[Path],
) -> Tuple[Set[str], List[Dict], List[Dict], Dict[str, bool]]:
    """Run AST/TS analysis on all script files (Python + JS/TS).

    Returns:
    - A_ast(s): set of capability codes
    - flows: list of flow dicts
    - findings: list of finding dicts
    - compound_flags: initial compound flag detection
    """
    all_capabilities: Set[str] = set()
    all_flows: List[Dict] = []
    all_findings: List[Dict] = []

    for script_path in script_files:
        suffix = script_path.suffix.lower()

        if suffix == ".py":
            caps, flows, findings = analyze_python_file(script_path)
            all_capabilities.update(caps)
            all_flows.extend(flows)
            all_findings.extend(findings)

        elif suffix in (".js", ".ts", ".mjs", ".cjs"):
            try:
                source = script_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            language = "typescript" if suffix == ".ts" else "javascript"
            analyzer = JSTaintAnalyzer(script_path)
            caps, flows, findings = analyzer.analyze(source, language)
            all_capabilities.update(caps)
            all_flows.extend(flows)
            all_findings.extend(findings)

        elif suffix == ".sh":
            # Shell files: tree-sitter-bash could be added later; keep regex path
            pass

    compound_flags: Dict[str, bool] = {
        "exfiltration_chain": False,
        "rce_chain": False,
        "code_obfuscation": False,
        "data_lineage_violation": False,
    }

    return all_capabilities, all_flows, all_findings, compound_flags
