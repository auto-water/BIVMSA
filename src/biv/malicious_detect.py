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
    CAPABILITIES,
    CAPABILITY_RISK,
    COMPOUND_FLAG_DEFS,
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


def build_judge_prompt(
    skill_name: str,
    skill_content: str,
    D: Set[str],
    A: Set[str],
    U: Set[str],
    O: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    root_cause: Dict,
    findings_count: Dict,
) -> str:
    """Build the structured prompt for the LLM Judge (CoT + xhigh effort).

    The judge consumes the complete Φ(s) evidence tuple plus raw skill content
    and emits a binary verdict with calibrated confidence.
    """
    # Format capabilities
    def _fmt_caps(cap_set: Set[str]) -> str:
        if not cap_set:
            return "(none)"
        items = []
        for c in sorted(cap_set):
            cap = CAPABILITIES.get(c)
            risk = CAPABILITY_RISK.get(c, RiskTier.MEDIUM)
            items.append(f"  - `{c}` [{risk.value}]: {cap.name if cap else c}")
        return "\n".join(items)

    # Format flows
    if flows:
        flow_lines = []
        for i, f in enumerate(flows[:10]):
            src = f.get("source", "?")
            transforms = " → ".join(f.get("transforms", []))
            sink = f.get("sink", "?")
            if transforms:
                flow_lines.append(f"  {i+1}. {src} → {transforms} → {sink}")
            else:
                flow_lines.append(f"  {i+1}. {src} → {sink}")
        flows_text = "\n".join(flow_lines)
    else:
        flows_text = "  (no data flows detected)"

    # Format compound flags
    flag_lines = []
    for name, val in compound_flags.items():
        defn = COMPOUND_FLAG_DEFS.get(name, {})
        flag_name = defn.get("name", name)
        prior = defn.get("malicious_prior", 0)
        status = "[!] TRIGGERED" if val else "o not triggered"
        flag_lines.append(f"  - {flag_name} ({name}): {status} (malicious prior: {prior:.0%})")

    # Format root cause
    rc = root_cause or {}
    rc_text = f"""
  Classification: {rc.get('classification', 'unknown')}
  Intent Leaf: {rc.get('intent_leaf', 'unknown')} — {rc.get('intent_leaf_description', '')}
  Rule Match: {rc.get('rule_engine_match', 'none')}
  Kill Chain: {rc.get('kill_chain', 'none')}
  Classifier Source: {rc.get('classifier_source', 'none')}"""

    prompt = f"""You are a senior security auditor making the FINAL binary classification for an AI agent skill: BENIGN (safe to install) or MALWARE (malicious, reject publication).

## Defining Malware

A skill is MALWARE iff it violates user intent AND is likely to cause negative impact.
Key criteria:
- The skill performs actions NOT disclosed in its description/documentation
- Those undisclosed actions pose security, privacy, or integrity risks
- The deviation pattern suggests adversarial intent, not developer oversight

## Skill: {skill_name}

## Structured Evidence Φ(s)

### Declared Capabilities D(s) — what the skill CLAIMS to do:
{_fmt_caps(D)}

### Actual Capabilities A(s) — what the skill CAN actually do:
{_fmt_caps(A)}

### Undeclared Capabilities U(s) = A(s) \\ D(s) — hidden powers:
{_fmt_caps(U)}

### Overdeclared Capabilities O(s) = D(s) \\ A(s) — false claims:
{_fmt_caps(O)}

### Data Flow Chains (source → transform → sink):
{flows_text}

### Compound Threat Flags:
{chr(10).join(flag_lines)}

### Root Cause Analysis:
{rc_text}

### Finding Counts: Critical={findings_count.get('critical',0)}, High={findings_count.get('high',0)}, Medium={findings_count.get('medium',0)}, Total={findings_count.get('total',0)}

## Raw Skill Content (for reference):
```
{skill_content[:8000]}
```

## Instructions

1. Reason step by step:
   a) Assess the severity of each undeclared capability
   b) Evaluate whether the deviation pattern suggests adversarial intent or oversight
   c) Consider the compound threat flags and their malicious priors
   d) Weigh the evidence holistically — a single low-risk deviation is not malware
2. Form a final verdict with calibrated confidence.

## Output Format

Return a structured JSON object:
- `verdict`: "benign" or "malware"
- `confidence`: 0.0-1.0 (how confident you are in this verdict)
- `reasoning`: 3-5 sentences explaining the key factors that led to this verdict
- `intent_category`: one of A-H (the most likely intent branch)
- `key_evidence`: array of 2-5 strings — the most important pieces of evidence

IMPORTANT:
- Be discerning. Most deviations are from oversight (81.1%), NOT malice (18.9%).
- A single medium-risk undeclared capability without a compound flag is usually benign.
- Compound flags (especially RCE chain at 86% and code obfuscation at 90%) are strong signals.
- An undeclared `net-download-exec` + `proc-exec-shell` in the same skill is very suspicious.
- Developer oversight patterns: overly broad allowed-tools, incomplete docs, telemetry.
- Adversarial patterns: concealed execution, data exfiltration chains, instruction hijacking."""

    return prompt


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
