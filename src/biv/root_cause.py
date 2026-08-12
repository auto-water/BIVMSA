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
    INTENT_TAXONOMY,
    INTENT_LEAF_DESCRIPTIONS,
    INTENT_CATEGORY_NAMES,
    ADVERSARIAL_BRANCHES,
    NON_ADVERSARIAL_BRANCHES,
    AMBIGUOUS_BRANCHES,
    CAPABILITIES,
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

    # Rule 2: Dropper pattern (download + write + exec)
    has_download = bool(net_caps)  # net-http-out or net-download-exec
    has_write = bool(fs_caps.intersection({"fs-write", "fs-write-sensitive"}))
    has_exec = bool(proc_caps)
    if has_download and has_write and has_exec:
        return "C1", "C", "rule_2", "download-write-execute"

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


def build_classifier_prompt(
    U: Set[str],
    O: Set[str],
    A: Set[str],
    D: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    skill_name: str,
) -> str:
    """Build the structured prompt for the LLM root cause classifier.

    This handles the ~1/3 of deviations that don't match any deterministic rule.
    The LLM reasons jointly over the skill's full deviation list and matches
    against 10 predefined kill-chain patterns.
    """
    # Format capabilities for readability
    def _cap_names(cap_set: Set[str]) -> str:
        if not cap_set:
            return "(none)"
        items = []
        for c in sorted(cap_set):
            cap = CAPABILITIES.get(c)
            name = cap.name if cap else c
            items.append(f"  - `{c}`: {name}")
        return "\n".join(items)

    # Format flows
    flow_lines = []
    for i, flow in enumerate(flows[:10]):  # Limit to 10 flows
        flow_lines.append(
            f"  {i+1}. {flow.get('source','?')} → {flow.get('sink','?')}"
        )

    # Format compound flags
    triggered = [k for k, v in compound_flags.items() if v]
    flag_lines = "\n".join(f"  - {f}: TRIGGERED" for f in triggered) if triggered else "  (none)"

    # Kill chain patterns for reference
    kc_lines = "\n".join(
        f"  - `{name}`: {desc}" for name, desc in KILL_CHAINS.items()
    )

    # Intent taxonomy reference (abbreviated)
    intent_lines = []
    for branch in sorted(INTENT_TAXONOMY.keys()):
        data = INTENT_TAXONOMY[branch]
        intent_lines.append(f"**{branch} — {data['name']}**")
        for leaf, desc in sorted(data.items()):
            if leaf != "name":
                intent_lines.append(f"  - {leaf}: {desc}")

    prompt = f"""You are a root-cause classifier for AI agent skill behavioral deviations.

## Skill: {skill_name}

## Deviation Evidence

### Undeclared Capabilities U(s) — present in code but NOT in documentation:
{_cap_names(U)}

### Overdeclared Capabilities O(s) — claimed in documentation but NOT in code:
{_cap_names(O)}

### All Actual Capabilities A(s):
{_cap_names(A)}

### Data Flow Chains:
{chr(10).join(flow_lines) if flow_lines else '  (none detected)'}

### Compound Threat Flags:
{flag_lines}

## Your Task

1. Reason JOINTLY over the full deviation list — multi-deviation kill chains must be detected as units, not individual deviations.
2. Match against these 10 predefined kill-chain patterns:
{kc_lines}
3. Classify the root cause into one of these 36 intent leaves:

{chr(10).join(intent_lines)}

## Output Format

Return a structured JSON object:
- `intent_leaf`: the 36-leaf code (e.g., "C1", "F1", "G7", "H2")
- `intent_category`: the branch code (A-H)
- `classification`: "adversarial" | "non_adversarial" | "ambiguous"
- `kill_chain`: matching kill-chain pattern name, or null if none matches
- `reasoning`: 2-4 sentences explaining why this classification was chosen
- `confidence`: 0.0-1.0 indicating confidence in this classification

IMPORTANT:
- Non-adversarial branch is G (over-engineering, documentation error, telemetry, etc.)
- Adversarial branches are A-F
- Use H1/H2 only when truly ambiguous
- G1 vs G7 distinction: low-risk over-specification → G1 (over-engineering),
  higher-risk mismatch → G7 (documentation error)
- Joint reasoning matters: a single undeclared capability may be benign,
  but a pattern of multiple coordinated undeclared capabilities is suspicious."""

    return prompt


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
