"""
Module 5: Malicious Detection — final benign/malware classification.

Combines:
1. Relaxed-Veto Override V(Φ(s)) — deterministic, parameterless
2. LLM Judge gθ(Φ(s)) — structured evidence + raw skill content → verdict

Final: ŷ(s) = V(Φ(s)) ∨ 𝟙[LLM_judge(s) = malware]
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from .taxonomy import (
    CAPABILITY_RISK,
    INTENT_LEAF_DESCRIPTIONS,
    ADVERSARIAL_BRANCHES,
    RiskTier,
)

logger = logging.getLogger(__name__)


def relaxed_veto(
    compound_flags: Dict[str, bool],
    U: Set[str],
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Apply the Relaxed-Veto override.

    V(Φ(s)) = 𝟙[compound(s) ≠ 0 ∧ ∃τ ∈ U(s): risk(τ) ≥ High]

    This is a parameterless predicate that enables auditable decisions.
    In the paper, it fired alone on 3 of 906 benchmark skills.

    Returns:
        (fired, reason, compound_flag, high_risk_capability)
    """
    # Check if any compound flag is set
    triggered = [name for name, val in compound_flags.items() if val]
    if not triggered:
        return False, "", None, None

    # Check for undeclared capabilities at High/Critical risk
    high_risk_undeclared: List[Tuple[str, str]] = []
    for cap in U:
        risk = CAPABILITY_RISK.get(cap, RiskTier.MEDIUM)
        if risk.value in ("critical", "high"):
            high_risk_undeclared.append((cap, risk.value))

    if not high_risk_undeclared:
        return (
            False,
            "Compound flag triggered but no undeclared capability at High/Critical risk",
            triggered[0],
            None,
        )

    # Build reason
    flag = triggered[0]
    caps_str = ", ".join(f"'{c}' ({r})" for c, r in high_risk_undeclared[:5])

    reason = (
        f"Relaxed-Veto: compound_{flag}=true AND undeclared "
        f"high-risk capabilities: {caps_str}"
    )

    return True, reason, flag, high_risk_undeclared[0][0]


# =============================================================================
# LLM Judge Prompt Builder
# =============================================================================




def validate_judge_output(llm_output: Dict) -> Tuple[str, float, str, str, List[str]]:
    """Validate LLM Judge output.

    Returns:
        (verdict, confidence, reasoning, intent_category, key_evidence)
    """
    verdict = llm_output.get("verdict", "benign")
    if verdict not in ("benign", "malware"):
        verdict = "benign"

    confidence = float(llm_output.get("confidence", 0.5))
    confidence = min(max(confidence, 0.0), 1.0)

    reasoning = llm_output.get("reasoning", "No reasoning provided")
    intent_category = llm_output.get("intent_category", "H")
    key_evidence = llm_output.get("key_evidence", [])

    if not isinstance(key_evidence, list):
        key_evidence = []

    return verdict, confidence, reasoning, intent_category, key_evidence


def final_verdict(
    relaxed_veto_fired: bool,
    relaxed_veto_reason: str,
    llm_verdict: str,
    llm_confidence: float,
    llm_reasoning: str,
) -> Tuple[str, str, float]:
    """Compute the final verdict.

    ŷ(s) = V(Φ(s)) ∨ 𝟙[LLM_judge(s) = malware]

    Returns:
        (verdict, verdict_source, confidence)
    """
    if relaxed_veto_fired:
        if llm_verdict == "malware":
            return "malware", "both", max(0.95, llm_confidence)
        else:
            # Veto overrides LLM
            return "malware", "relaxed_veto", 0.90
    else:
        if llm_verdict == "malware":
            return "malware", "llm_judge", llm_confidence
        else:
            return "benign", "llm_judge", llm_confidence
