"""
Module 2.1: Python AST-based taint analyzer.

Performs intra-file inter-procedural taint analysis:
- Identify sources (env vars, file reads, network responses)
- Track through transforms (base64, encoding, serialization)
- Detect sinks (subprocess, eval, network send, file write)

Output: A_ast(s), flow(s), partial compound flags.
"""

import ast
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..taxonomy import (
    CAPABILITIES,
    SOURCE_CAPABILITY_MAP,
    SINK_CAPABILITY_MAP,
    TRANSFORM_CAPABILITY_MAP,
    COMPOUND_FLAG_DEFS,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Taint Analysis Core
# =============================================================================


class TaintTracker:
    """Intra-file inter-procedural taint tracker.

    Tracks taint from sources → transforms → sinks within a single Python file.
    Cross-function tracking is supported within the file; cross-file is NOT.
    """

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.tainted_vars: Dict[str, Set[str]] = {}  # var_name → {source_cap}
        self.tainted_func_args: Dict[str, Dict[int, Set[str]]] = {}  # func_name → {arg_index: {source_cap}}
        self.flows: List[Dict] = []  # output flow triples
        self.capabilities: Set[str] = set()
        self._func_defs: Dict[str, ast.FunctionDef] = {}

    def analyze(self, tree: ast.AST) -> Tuple[Set[str], List[Dict]]:
        """Run taint analysis on an AST.

        Returns:
        - capabilities: set of capability codes detected
        - flows: list of source→transform→sink flow dicts
        """
        # First pass: collect all function definitions
        self._collect_func_defs(tree)

        # Second pass: analyze top-level code and function bodies
        self._analyze_node(tree)

        return self.capabilities, self.flows

    def _collect_func_defs(self, node: ast.AST) -> None:
        """Collect all function definitions in the file."""
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef):
                self._func_defs[child.name] = child

    def _analyze_node(self, node: ast.AST) -> None:
        """Recursively analyze an AST node for taint flows."""
        # Walk all nodes
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                self._handle_assign(child)
            elif isinstance(child, ast.Call):
                self._handle_call(child)
            elif isinstance(child, ast.AugAssign):
                self._handle_aug_assign(child)

    def _handle_assign(self, node: ast.Assign) -> None:
        """Handle assignment: check if RHS is a source or transform call."""
        if not isinstance(node.value, ast.Call):
            return

        call_node = node.value
        func_name = self._get_func_name(call_node)

        # Check if this is a source
        source_cap = self._match_source(func_name)
        if source_cap:
            # Taint the assigned variables
            for target in node.targets:
                var_name = self._get_name(target)
                if var_name:
                    self.tainted_vars.setdefault(var_name, set()).add(source_cap[0])
                    self.capabilities.add(source_cap[0])

        # Check if this is a transform
        transform_cap = self._match_transform(func_name)
        if transform_cap:
            # Check if any argument is tainted — if so, track the transform
            for arg in call_node.args:
                arg_name = self._get_name(arg)
                if arg_name and arg_name in self.tainted_vars:
                    self.capabilities.add(transform_cap[0])
                    # Taint propagates through transforms
                    for target in node.targets:
                        target_name = self._get_name(target)
                        if target_name:
                            for src in self.tainted_vars[arg_name]:
                                self.tainted_vars.setdefault(target_name, set()).add(src)

    def _handle_call(self, node: ast.Call) -> None:
        """Handle a bare call expression (not in assignment): check for sinks."""
        func_name = self._get_func_name(node)

        # Check if this is a sink
        sink_cap = self._match_sink(func_name)
        if not sink_cap:
            return

        self.capabilities.add(sink_cap[0])

        # Check if any argument is tainted → create a flow
        for i, arg in enumerate(node.args):
            arg_name = self._get_name(arg)
            if arg_name and arg_name in self.tainted_vars:
                for source_cap in self.tainted_vars[arg_name]:
                    flow = {
                        "source": source_cap,
                        "source_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                        "transforms": [],  # We track simple direct flows for now
                        "sink": sink_cap[0],
                        "sink_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                    }
                    self.flows.append(flow)

        # Also check keyword arguments
        for kw in node.keywords:
            kw_name = self._get_name(kw.value)
            if kw_name and kw_name in self.tainted_vars:
                for source_cap in self.tainted_vars[kw_name]:
                    flow = {
                        "source": source_cap,
                        "source_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                        "transforms": [],
                        "sink": sink_cap[0],
                        "sink_location": f"{self.filepath.name}:{getattr(node, 'lineno', '?')}",
                    }
                    self.flows.append(flow)

        # If this is a shell execution sink, also check for shell=True
        if "proc-exec" in sink_cap[0] or "proc-exec-shell" in sink_cap[0]:
            for kw in node.keywords:
                if kw.arg == "shell" and self._is_truthy(kw.value):
                    self.capabilities.add("proc-exec-shell")
                    break

    def _handle_aug_assign(self, node: ast.AugAssign) -> None:
        """Handle augmented assignment (+=, etc.)."""
        # Not typically a taint source, but could propagate taint
        pass

    def _get_func_name(self, call_node: ast.Call) -> str:
        """Extract the full dotted function name from a call node."""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            parts = []
            node = call_node.func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    def _get_name(self, node: ast.expr) -> Optional[str]:
        """Get the variable name from a node if it's a simple name."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _match_source(self, func_name: str) -> Optional[Tuple[str, str]]:
        """Match a function name against known sources."""
        for pattern, (cap, _) in SOURCE_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        return None

    def _match_sink(self, func_name: str) -> Optional[Tuple[str, str]]:
        """Match a function name against known sinks."""
        for pattern, (cap, _) in SINK_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        return None

    def _match_transform(self, func_name: str) -> Optional[Tuple[str, str]]:
        """Match a function name against known transforms."""
        for pattern, (cap, _) in TRANSFORM_CAPABILITY_MAP.items():
            if pattern in func_name:
                return (cap, func_name)
        return None

    def _is_truthy(self, node: ast.expr) -> bool:
        """Check if an AST expression evaluates to truthy."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name):
            return True  # Assume variables are truthy
        return True  # Default assumption


# =============================================================================
# AST Analysis Entry Point
# =============================================================================


def analyze_python_file(filepath: Path) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """Analyze a single Python file for capabilities and taint flows.

    Returns:
    - capabilities: set of capability codes
    - flows: list of flow dicts
    - raw_findings: list of finding dicts at AST-matched locations
    """
    capabilities: Set[str] = set()
    flows: List[Dict] = []
    raw_findings: List[Dict] = []

    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Cannot read {filepath}: {e}")
        return capabilities, flows, raw_findings

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        logger.warning(f"Syntax error in {filepath}: {e}")
        return capabilities, flows, raw_findings

    # Run taint tracker
    tracker = TaintTracker(filepath)
    caps, tracked_flows = tracker.analyze(tree)
    capabilities.update(caps)
    flows.extend(tracked_flows)

    # Additional pattern-based checks on AST (things regex can't catch well)
    additional_caps, additional_findings = _ast_pattern_checks(filepath, tree, source)
    capabilities.update(additional_caps)
    raw_findings.extend(additional_findings)

    return capabilities, flows, raw_findings


def _ast_pattern_checks(
    filepath: Path, tree: ast.AST, source: str
) -> Tuple[Set[str], List[Dict]]:
    """Additional AST-based pattern checks beyond taint tracking."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []

    for node in ast.walk(tree):
        # Check for shell=True in subprocess calls
        if isinstance(node, ast.Call):
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
                "subprocess.run",
                "subprocess.call",
                "subprocess.Popen",
                "subprocess.check_output",
                "subprocess.check_call",
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and _ast_is_truthy(kw.value):
                        capabilities.add("proc-exec-shell")
                        findings.append(
                            {
                                "type": "Shell Execution via shell=True",
                                "severity": "high",
                                "category": "Process Execution",
                                "location": f"{filepath.name}:{node.lineno}",
                                "description": f"{func_name} 调用使用 shell=True，存在命令注入风险",
                                "evidence": _get_source_line(source, node.lineno),
                            }
                        )

            # os.system / os.popen
            if func_name in ("os.system", "os.popen"):
                capabilities.add("proc-exec-shell")
                findings.append(
                    {
                        "type": "Shell Execution",
                        "severity": "high",
                        "category": "Process Execution",
                        "location": f"{filepath.name}:{node.lineno}",
                        "description": f"{func_name} 直接执行 shell 命令",
                        "evidence": _get_source_line(source, node.lineno),
                    }
                )

            # eval / exec
            if func_name in ("eval", "exec"):
                capabilities.add("proc-code-eval")
                findings.append(
                    {
                        "type": "Dynamic Code Execution",
                        "severity": "high",
                        "category": "Process Execution",
                        "location": f"{filepath.name}:{node.lineno}",
                        "description": f"{func_name}() 动态代码执行",
                        "evidence": _get_source_line(source, node.lineno),
                    }
                )

    return capabilities, findings


def _ast_is_truthy(node: ast.expr) -> bool:
    """Check if AST expression is truthy."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return True


def _get_source_line(source: str, lineno: int) -> str:
    """Get a specific line from source code."""
    lines = source.split("\n")
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:200]
    return ""


# =============================================================================
# Compound Flag Detection from Flows
# =============================================================================


def detect_compound_flags_from_flows(
    flows: List[Dict], actual_capabilities: Set[str], undeclared_capabilities: Set[str]
) -> Dict[str, bool]:
    """Detect the 4 compound threat flags from flow data and capability sets.

    Args:
        flows: list of flow triples
        actual_capabilities: A(s) set
        undeclared_capabilities: U(s) set

    Returns:
        dict of {flag_name: bool}
    """
    flags = {
        "exfiltration_chain": False,
        "rce_chain": False,
        "code_obfuscation": False,
        "data_lineage_violation": False,
    }

    # Exfiltration chain: fs-read → net-http-out in any flow
    for flow in flows:
        source = flow.get("source", "")
        sink = flow.get("sink", "")

        # fs-read → net-http-out
        if source.startswith("fs-read") and sink.startswith("net-http-out"):
            flags["exfiltration_chain"] = True

        # Also check net-socket-out as exfiltration sink
        if source.startswith("fs-read") and sink.startswith("net-socket-out"):
            flags["exfiltration_chain"] = True

        # RCE chain: net-http-out → fs-write → proc-exec
        # Check for net-http-out source with fs-write sink + separate proc-exec in capabilities
        if source.startswith("net-") and sink.startswith("fs-write"):
            if any(c.startswith("proc-exec") for c in actual_capabilities):
                flags["rce_chain"] = True

        if source.startswith("fs-") and sink.startswith("proc-exec"):
            # Check if there's also net-http-out capability present
            if any(c.startswith("net-") for c in actual_capabilities):
                flags["rce_chain"] = True

    # Code obfuscation: enc-base64 + proc-code-eval
    if "enc-base64" in actual_capabilities and (
        "proc-code-eval" in actual_capabilities
        or "proc-code-eval-dynamic" in actual_capabilities
    ):
        flags["code_obfuscation"] = True

    # Data lineage violation: undeclared fs-read + actual fs-write
    has_undeclared_fs_read = any(
        c.startswith("fs-read") for c in undeclared_capabilities
    )
    has_actual_fs_write = any(c.startswith("fs-write") for c in actual_capabilities)
    if has_undeclared_fs_read and has_actual_fs_write:
        flags["data_lineage_violation"] = True

    return flags


# =============================================================================
# Main Entry Point for Actual Track AST Module
# =============================================================================


def run_ast_analysis(script_files: List[Path]) -> Tuple[Set[str], List[Dict], List[Dict], Dict[str, bool]]:
    """Run AST taint analysis on all Python script files.

    Returns:
    - A_ast(s): set of capability codes
    - flows: list of flow dicts
    - findings: list of finding dicts
    - compound_flags: initial compound flag detection (will be merged later)
    """
    all_capabilities: Set[str] = set()
    all_flows: List[Dict] = []
    all_findings: List[Dict] = []
    compound_flags: Dict[str, bool] = {
        "exfiltration_chain": False,
        "rce_chain": False,
        "code_obfuscation": False,
        "data_lineage_violation": False,
    }

    for script_path in script_files:
        if script_path.suffix != ".py":
            continue

        caps, flows, findings = analyze_python_file(script_path)
        all_capabilities.update(caps)
        all_flows.extend(flows)
        all_findings.extend(findings)

    return all_capabilities, all_flows, all_findings, compound_flags
