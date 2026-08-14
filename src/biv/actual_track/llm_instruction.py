"""
Module 2.3: LLM-based instruction-level capability extraction.

Reads SKILL.md body and references to detect instruction-level capabilities
(injection patterns, override motifs, concealment tactics) that deterministic
analyzers may miss.

The actual LLM call is orchestrated externally by the Workflow script.
"""

import logging
from typing import Dict, List, Set, Tuple

from ..taxonomy import (
    CAPABILITIES,
)

logger = logging.getLogger(__name__)




def validate_instruction_llm_output(
    llm_output: Dict, skill_content: str
) -> Tuple[Set[str], List[Dict], List[str]]:
    """Validate and filter LLM-extracted instruction capabilities.

    Same three hallucination controls as the Declared Track LLM.
    """
    valid_capabilities: Set[str] = set()
    evidence_list: List[Dict] = []
    rejected: List[str] = []

    declared = llm_output.get("instruction_capabilities", [])
    if not isinstance(declared, list):
        return valid_capabilities, evidence_list, ["LLM output missing instruction_capabilities array"]

    # Normalize content for evidence matching
    import re
    normalized_content = skill_content.strip()
    normalized_content = re.sub(r"\s+", " ", normalized_content).lower()

    for item in declared:
        if not isinstance(item, dict):
            continue

        cap = item.get("capability", "").strip()
        ev_text = item.get("evidence", "").strip()
        ev_location = item.get("evidence_location", "SKILL.md body")

        # Validate capability code (must be instruction category)
        if cap not in CAPABILITIES:
            rejected.append(f"Unknown capability: {cap}")
            continue
        if CAPABILITIES[cap].category != "instruction":
            rejected.append(f"Capability {cap} is not instruction-level")
            continue

        # Evidence grounding check
        if not ev_text:
            rejected.append(f"No evidence for capability '{cap}'")
            continue

        normalized_evidence = ev_text.strip()
        normalized_evidence = re.sub(r"\s+", " ", normalized_evidence).lower()

        # Require at least partial match
        evidence_words = set(normalized_evidence.split())
        content_words = set(normalized_content.split())
        if len(evidence_words) < 3:
            rejected.append(f"Evidence too short for '{cap}'")
            continue

        overlap = evidence_words & content_words
        if len(overlap) / max(len(evidence_words), 1) < 0.5:
            rejected.append(f"Evidence not grounded in source for '{cap}'")
            continue

        valid_capabilities.add(cap)
        evidence_list.append(
            {
                "capability": cap,
                "source_type": "llm_instruction",
                "evidence": ev_text[:500],
                "evidence_location": ev_location,
                "is_adversarial": item.get("is_adversarial", False),
            }
        )

    return valid_capabilities, evidence_list, rejected
