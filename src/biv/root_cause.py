"""
Module 4: Root Cause Classification — deterministic rule engine + LLM classifier.

- 15 prioritized deterministic rules (first-match-wins)
- LLM classifier for ambiguous cases (~1/3 of deviations)
- Matches against 10 predefined kill-chain patterns
- 8-branch × 36-leaf intent taxonomy (Appendix E, Table 4)
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from .taxonomy import (
    RULES,
    KILL_CHAINS,
    INTENT_LEAF_DESCRIPTIONS,
    INTENT_CATEGORY_NAMES,
    ADVERSARIAL_BRANCHES,
    NON_ADVERSARIAL_BRANCHES,
    AMBIGUOUS_BRANCHES,
    CAPABILITY_RISK,
    RuleDef,
    RiskTier,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Deterministic Rule Engine
# =============================================================================


def apply_rule_engine(
    U: Set[str],
    O: Set[str],
    A: Set[str],
    D: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    instruction_signals: int = 0,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Apply the 15 prioritized deterministic rules (first-match-wins).

    Args:
        U: undeclared capabilities
        O: overdeclared capabilities
        A: actual capabilities
        D: declared capabilities
        flows: data flow triples
        compound_flags: 4 compound threat flags
        instruction_signals: count of instruction-level signals detected
                             (from regex + LLM analysis)

    Returns:
        (intent_leaf, branch_code, rule_id, kill_chain)
        or (None, None, None, None) if no rule matches → pass to LLM classifier
    """
    # Build signal sets for efficient rule matching
    net_caps = {c for c in A if c.startswith("net-")}
    fs_caps = {c for c in A if c.startswith("fs-")}
    proc_caps = {c for c in A if c.startswith("proc-")}
    env_caps = {c for c in A if c.startswith("env-")}
    enc_caps = {c for c in A if c.startswith("enc-")}
    cred_caps = {c for c in A if c.startswith("cred-")}
    instr_caps = {c for c in A if c.startswith("instr-")}

    # Also check undeclared sets
    undeclared_net = {c for c in U if c.startswith("net-")}
    undeclared_fs = {c for c in U if c.startswith("fs-")}
    undeclared_proc = {c for c in U if c.startswith("proc-")}
    undeclared_env = {c for c in U if c.startswith("env-")}
    undeclared_cred = {c for c in U if c.startswith("cred-")}
    undeclared_instr = {c for c in U if c.startswith("instr-")}

    def _has_flow_pattern(sources: List[str], sinks: List[str]) -> bool:
        """Check if any flow matches source→sink pattern."""
        for flow in flows:
            src = flow.get("source", "")
            snk = flow.get("sink", "")
            if any(src.startswith(s) for s in sources) and any(
                snk.startswith(s) for s in sinks
            ):
                return True
        return False

    # Rule 1: Instruction hijacking (≥2 agent-specific signals)
    if instruction_signals >= 2:
        return "F1", "F", "rule_1", None

    # Rule 2: Dropper pattern (network + write + exec)
    # Includes: download remote (net-http-out), reverse shell (net-socket-out),
    # or script dropper (write embedded payload + execute)
    has_net = bool(net_caps)  # any network capability
    has_write = bool(fs_caps.intersection({"fs-write", "fs-write-sensitive"}))
    has_exec = bool(proc_caps)
    if has_net and has_write and has_exec:
        return "C1", "C", "rule_2", "download-write-execute"
    # Script dropper variant: write + execute without explicit network
    # (payload embedded in code — still C1 dropper pattern)
    if has_write and has_exec and ("instr-silent-exec" in A):
        return "C1", "C", "rule_2", "script-dropper"

    # Rule 3: Credential theft motif (direct credential file/env reading)
    if cred_caps:
        # Check for explicit credential reading (not just generic env access)
        if "cred-read" in cred_caps or "cred-transmit" in cred_caps:
            return "A1", "A", "rule_3", None

    # Rule 4: Evasion (encoding + code eval)
    if enc_caps and ("proc-code-eval" in proc_caps or "proc-code-eval-dynamic" in proc_caps):
        return "C4", "C", "rule_4", None

    # Rule 5: Ransomware keywords + crypto + write
    if "enc-crypto" in enc_caps and fs_caps.intersection({"fs-write", "fs-write-sensitive"}):
        # Check for ransomware keywords in flows or context (simplified heuristic)
        return "E1", "E", "rule_5", None

    # Rule 6: Bulk file deletion (high risk)
    if "fs-delete" in A:
        # Check if delete is undeclared (more suspicious)
        if "fs-delete" in U:
            return "E2", "E", "rule_6", None

    # Rule 7: Cryptominer motif or keywords
    # (simplified: crypto + compute-intensive operations)
    if "enc-crypto" in enc_caps and proc_caps:
        return "B3", "B", "rule_7", None

    # Rule 8: Credential + network outbound
    if cred_caps and net_caps:
        return "A1", "A", "rule_8", "steal_exfil"

    # Rule 9: Sensitive env + network outbound
    if "env-access-sensitive" in env_caps and net_caps:
        return "A1", "A", "rule_9", "steal_exfil"

    # Rule 10: Data exfiltration chain (high risk)
    if _has_flow_pattern(["fs-read"], ["net-http-out", "net-socket-out"]):
        return "A2", "A", "rule_10", "steal_exfil"

    # Rule 11: Bulk env access + network outbound
    if "env-access-bulk" in env_caps and net_caps:
        return "A2", "A", "rule_11", "steal_exfil"

    # Rule 12: Persistence motif or startup write
    if "fs-write-sensitive" in A:
        # Writing to config/startup paths → persistence
        return "C2", "C", "rule_12", None

    # Rule 13: Reconnaissance motif or enum + bulk
    if "fs-enumerate" in A and ("env-access-bulk" in A or len(A) >= 5):
        return "C5", "C", "rule_13", None

    # Rule 14: Over-specification (O(s) non-empty)
    if O:
        # Check risk level of overdeclared capabilities
        overdeclared_risk = max(
            (CAPABILITY_RISK.get(c, RiskTier.MEDIUM) for c in O),
            key=lambda r: {"critical": 3, "high": 2, "medium": 1}.get(r.value, 0),
            default=RiskTier.MEDIUM,
        )
        if overdeclared_risk in (RiskTier.MEDIUM,):
            return "G1", "G", "rule_14", None  # Low-risk over-spec → over-engineering
        else:
            return "G7", "G", "rule_14", None  # Higher risk → documentation error

    # Rule 15: Telemetry keywords (catch-all benign)
    # If we got here with only low-risk capabilities, classify as telemetry/benign
    all_risk_levels = [CAPABILITY_RISK.get(c, RiskTier.MEDIUM) for c in A]
    if all(r in (RiskTier.MEDIUM,) for r in all_risk_levels):
        return "G6", "G", "rule_15", None

    # No rule matched → ambiguous, pass to LLM classifier
    return None, None, None, None


# =============================================================================
# LLM Classifier (prompt builder)
# =============================================================================




def validate_classifier_output(llm_output: Dict) -> Tuple[Optional[str], Optional[str], str, Optional[str], float]:
    """Validate LLM classifier output.

    Returns:
        (intent_leaf, intent_category, classification, kill_chain, confidence)
    """
    leaf = llm_output.get("intent_leaf", "")
    branch = llm_output.get("intent_category", "")
    classification = llm_output.get("classification", "ambiguous")
    kill_chain = llm_output.get("kill_chain")
    confidence = float(llm_output.get("confidence", 0.5))

    # Validate leaf exists in taxonomy
    if leaf not in INTENT_LEAF_DESCRIPTIONS:
        logger.warning(f"Unknown intent leaf: {leaf}, defaulting to H2")
        return "H2", "H", "ambiguous", None, 0.1

    # Validate branch
    if branch not in INTENT_CATEGORY_NAMES:
        branch = leaf[:1]

    # Validate classification
    if classification not in ("adversarial", "non_adversarial", "ambiguous"):
        classification = "ambiguous"

    # Validate kill chain
    if kill_chain and kill_chain not in KILL_CHAINS:
        kill_chain = None

    return leaf, branch, classification, kill_chain, min(max(confidence, 0.0), 1.0)
