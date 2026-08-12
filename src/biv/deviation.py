"""
Module 3: Deviation Detection — compute set differences and compound threat flags.

Core operations:
- U(s) = A(s) - D(s)  (undeclared/under-specification)
- O(s) = D(s) - A(s)  (overdeclared/over-specification)
- compound(s) ∈ {0,1}⁴  (compound threat flags)
- Risk assessment for relaxing veto

Output: Φ(s) = ⟨D(s), A(s), U(s), O(s), flow(s), compound(s)⟩
"""

import logging
from typing import Dict, List, Set, Tuple

from .taxonomy import (
    CAPABILITIES,
    CAPABILITY_RISK,
    COMPOUND_FLAG_DEFS,
    RELAXED_VETO_RISK_THRESHOLD,
    RiskTier,
)

logger = logging.getLogger(__name__)


def compute_deviation(
    D: Set[str], A: Set[str]
) -> Tuple[Set[str], Set[str]]:
    """Compute the typed symmetric difference.

    Args:
        D: declared capabilities D(s)
        A: actual capabilities A(s)

    Returns:
        U: undeclared capabilities (A - D) — skills that can do things they don't claim
        O: overdeclared capabilities (D - A) — skills that claim things they can't do
    """
    U = A - D  # Undeclared: actual but not declared
    O = D - A  # Overdeclared: declared but not actual
    return U, O


def detect_compound_flags(
    flows: List[Dict],
    A: Set[str],
    U: Set[str],
) -> Dict[str, bool]:
    """Detect the 4 compound threat flags.

    Args:
        flows: data flow triples from AST analysis
        A: actual capabilities
        U: undeclared capabilities

    Returns:
        dict of {flag_name: bool}
    """
    flags = {
        "exfiltration_chain": False,
        "rce_chain": False,
        "code_obfuscation": False,
        "data_lineage_violation": False,
    }

    # --- Exfiltration Chain ---
    # fs-read → net-http-out (or net-socket-out) in any flow
    fs_read_caps = {c for c in A if c.startswith("fs-read")}
    net_out_caps = {c for c in A if c.startswith("net-http-out") or c.startswith("net-socket-out")}

    # Check flows first
    for flow in flows:
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        if source.startswith("fs-read") and (
            sink.startswith("net-http-out") or sink.startswith("net-socket-out")
        ):
            flags["exfiltration_chain"] = True
            break

    # If no flow evidence, fall back to co-occurrence check
    if not flags["exfiltration_chain"]:
        if fs_read_caps and net_out_caps:
            flags["exfiltration_chain"] = True

    # --- RCE Chain ---
    # net-http-out → fs-write → proc-exec (download→write→execute)
    net_download = {c for c in A if c.startswith("net-download-exec") or c.startswith("net-http-out")}
    fs_write_caps = {c for c in A if c.startswith("fs-write")}
    proc_exec_caps = {c for c in A if c.startswith("proc-exec")}

    # Check for download→write→execute pattern in flows
    for flow in flows:
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        # net source → file write sink
        if (source.startswith("net-") and sink.startswith("fs-write")):
            if proc_exec_caps:
                flags["rce_chain"] = True
                break
        # file read → process exec with net capability present
        if source.startswith("fs-") and sink.startswith("proc-exec"):
            if net_download:
                flags["rce_chain"] = True
                break

    # Fallback: capability co-occurrence
    if not flags["rce_chain"]:
        if net_download and fs_write_caps and proc_exec_caps:
            flags["rce_chain"] = True

    # --- Code Obfuscation ---
    # enc-base64 + proc-code-eval co-occurrence
    if "enc-base64" in A and (
        "proc-code-eval" in A or "proc-code-eval-dynamic" in A
    ):
        flags["code_obfuscation"] = True

    # --- Data Lineage Violation ---
    # undeclared fs-read-project + actual fs-write
    has_undeclared_fs_read = any(
        c.startswith("fs-read") for c in U
    )
    has_actual_fs_write = any(
        c.startswith("fs-write") for c in A
    )
    if has_undeclared_fs_read and has_actual_fs_write:
        flags["data_lineage_violation"] = True

    return flags


def has_any_compound_flag(compound_flags: Dict[str, bool]) -> bool:
    """Check if any compound threat flag is set."""
    return any(compound_flags.values())


def check_relaxed_veto_condition(
    compound_flags: Dict[str, bool],
    U: Set[str],
) -> Tuple[bool, str, str]:
    """Check the Relaxed-Veto condition.

    V(Φ(s)) = 𝟙[compound(s) ≠ 0 ∧ ∃τ ∈ U(s): risk(τ) ≥ High]

    Returns:
        (fired, reason, compound_flag_name)
    """
    if not has_any_compound_flag(compound_flags):
        return False, "No compound threat flags triggered", ""

    # Find any undeclared capability with risk >= High
    high_risk_undeclared = []
    for cap in U:
        risk = CAPABILITY_RISK.get(cap, RiskTier.MEDIUM)
        if risk.value in ("critical", "high"):
            high_risk_undeclared.append((cap, risk.value))

    if not high_risk_undeclared:
        return False, "No undeclared capabilities at High/Critical risk level", ""

    # Find which compound flag triggered
    triggered_flags = [name for name, val in compound_flags.items() if val]
    primary_flag = triggered_flags[0] if triggered_flags else "unknown"

    reason_parts = []
    for cap, risk in high_risk_undeclared[:3]:  # Show up to 3
        reason_parts.append(f"'{cap}' (risk={risk})")

    reason = (
        f"compound_{primary_flag}=true AND undeclared capabilities: "
        + ", ".join(reason_parts)
    )

    return True, reason, primary_flag


def compute_risk_assessment(
    U: Set[str], O: Set[str], compound_flags: Dict[str, bool]
) -> Dict:
    """Compute a numerical risk assessment from deviation and compound flags.

    Returns a dict with risk scores that can inform the LLM Judge.
    """
    # Count undeclared capabilities by risk tier
    undeclared_critical = sum(
        1 for c in U if CAPABILITY_RISK.get(c, RiskTier.MEDIUM) == RiskTier.CRITICAL
    )
    undeclared_high = sum(
        1 for c in U if CAPABILITY_RISK.get(c, RiskTier.MEDIUM) == RiskTier.HIGH
    )
    undeclared_medium = sum(
        1 for c in U if CAPABILITY_RISK.get(c, RiskTier.MEDIUM) == RiskTier.MEDIUM
    )

    # Count compound flags
    compound_count = sum(1 for v in compound_flags.values() if v)

    # Simple risk score (not from paper, but useful for comparing skills)
    # Critical=10, High=5, Medium=1, compound_flag=20 each
    risk_score = (
        undeclared_critical * 10
        + undeclared_high * 5
        + undeclared_medium * 1
        + compound_count * 20
    )

    return {
        "risk_score": risk_score,
        "undeclared_by_risk": {
            "critical": undeclared_critical,
            "high": undeclared_high,
            "medium": undeclared_medium,
        },
        "overdeclared_count": len(O),
        "compound_flags_triggered": compound_count,
        "flagged_as_high_risk": risk_score >= 10,
    }


def assemble_evidence_tuple(
    D: Set[str],
    A: Set[str],
    U: Set[str],
    O: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    d_evidence: List[Dict],
    a_evidence: List[Dict],
) -> Dict:
    """Assemble the full Φ(s) evidence tuple.

    This is the structured evidence consumed by root cause analysis
    and the LLM Judge.
    """
    return {
        "declared_capabilities": sorted(D),
        "actual_capabilities": sorted(A),
        "undeclared_capabilities": sorted(U),
        "overdeclared_capabilities": sorted(O),
        "flows": flows,
        "compound_flags": compound_flags,
        "declared_sources": d_evidence,
        "actual_sources": a_evidence,
        "deviation_summary": {
            "total_declared": len(D),
            "total_actual": len(A),
            "undeclared_count": len(U),
            "overdeclared_count": len(O),
            "overlap_count": len(D & A),
        },
    }
