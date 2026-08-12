"""
Module 1: Declared Track — extract D(s) (declared capabilities) from SKILL.md.

D(s) = D_deterministic(s) ∪ D_llm(s)

- D_deterministic: parse YAML frontmatter, map allowed-tools → taxonomy
- D_llm: LLM semantic extraction from natural language body (orchestrated externally)
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .taxonomy import (
    ALL_CAPABILITY_CODES,
    CAPABILITIES,
    CAPABILITIES_BY_CATEGORY,
    TOOL_CAPABILITY_MAP,
    CapabilityDef,
)

logger = logging.getLogger(__name__)


def parse_frontmatter(content: str) -> Tuple[Optional[Dict], str]:
    """Parse YAML frontmatter from SKILL.md content.

    Returns (frontmatter_dict, body_content).
    frontmatter_dict is None if no frontmatter block found.
    """
    if not content.startswith("---"):
        return None, content

    # Find closing ---
    end_idx = content.find("---", 3)
    if end_idx == -1:
        return None, content

    frontmatter_text = content[3:end_idx].strip()
    body = content[end_idx + 3 :].strip()

    try:
        import yaml

        fm = yaml.safe_load(frontmatter_text)
        return fm if isinstance(fm, dict) else None, body
    except Exception:
        # Fallback: try to extract basic fields manually
        fm = _parse_frontmatter_fallback(frontmatter_text)
        return fm, body


def _parse_frontmatter_fallback(text: str) -> Dict:
    """Minimal frontmatter parser when yaml is unavailable/invalid."""
    fm: Dict = {}
    # Extract simple key: value pairs
    for line in text.split("\n"):
        match = re.match(r"^(\w[\w-]*)\s*:\s*(.*)", line)
        if match:
            key, value = match.groups()
            value = value.strip().strip('"').strip("'")
            fm[key] = value
    return fm


# =============================================================================
# Deterministic Parser
# =============================================================================


def extract_tools_from_frontmatter(frontmatter: Dict) -> List[str]:
    """Extract tool names from frontmatter allowed-tools field.

    Handles formats:
    - "Read, Write, Bash" → ["Read", "Write", "Bash"]
    - "Bash(diff:*), Bash(grep:*)" → ["Bash", "Bash"]
    - "*" (unrestricted) → all known tools
    """
    raw = frontmatter.get("allowed-tools", "")
    if not raw or not isinstance(raw, str):
        return []

    tools: List[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "*":
            # Unrestricted — return all known tool bases
            return list(TOOL_CAPABILITY_MAP.keys())
        # Extract base tool name (strip parenthetical args)
        base = part.split("(")[0].strip()
        if base in TOOL_CAPABILITY_MAP:
            tools.append(base)
    return tools


def map_tools_to_capabilities(tools: List[str]) -> Set[str]:
    """Map tool names to taxonomy capabilities using TOOL_CAPABILITY_MAP."""
    capabilities: Set[str] = set()
    for tool in tools:
        mapped = TOOL_CAPABILITY_MAP.get(tool, [])
        capabilities.update(mapped)
    return capabilities


def extract_declared_deterministic(
    skill_dir: Path, frontmatter: Dict, content: str
) -> Tuple[Set[str], List[Dict]]:
    """Run deterministic Declared Track extraction.

    Returns:
    - D_deterministic(s): set of capability codes
    - evidence: list of {capability, source_type, evidence, evidence_location}
    """
    capabilities: Set[str] = set()
    evidence: List[Dict] = []

    # 1. Map allowed-tools → capabilities
    tools = extract_tools_from_frontmatter(frontmatter)
    tool_caps = map_tools_to_capabilities(tools)
    for cap in tool_caps:
        capabilities.add(cap)
        evidence.append(
            {
                "capability": cap,
                "source_type": "deterministic",
                "evidence": f"allowed-tools: {', '.join(tools)}",
                "evidence_location": "frontmatter",
            }
        )

    # 2. Check for description field presence
    description = frontmatter.get("description", "")
    if description and isinstance(description, str) and len(description) > 20:
        # Description exists — this doesn't map to a specific capability,
        # but is noted for the LLM semantic extractor
        pass

    # 3. Detect structural declarations
    # Check for hook declarations in frontmatter
    hooks = frontmatter.get("hooks", None)
    if hooks and isinstance(hooks, dict):
        # Hooks imply process execution capability
        capabilities.add("proc-exec")
        capabilities.add("proc-exec-shell")
        evidence.append(
            {
                "capability": "proc-exec",
                "source_type": "deterministic",
                "evidence": f"frontmatter hooks: {', '.join(hooks.keys())}",
                "evidence_location": "frontmatter",
            }
        )

    return capabilities, evidence


# =============================================================================
# LLM Semantic Extractor (interface)
# =============================================================================

# The actual LLM call is orchestrated by the Workflow script.
# This module provides the prompt template and output processing.


def build_declared_llm_prompt(skill_body: str, skill_name: str) -> str:
    """Build the structured prompt for LLM semantic capability extraction.

    This produces the prompt that the Workflow script sends to the Agent tool
    with schema-based structured output.
    """
    # Build taxonomy reference
    taxonomy_lines = []
    for cat_key, cat_data in sorted(CAPABILITIES_BY_CATEGORY.items()):
        cat_info = CAPABILITIES[cat_data[0]]
        cat_name = {"network": "网络", "filesystem": "文件系统", "process": "进程执行",
                      "environment": "环境变量", "encoding": "编码/转换",
                      "credential": "凭证", "instruction": "指令级"}.get(cat_key, cat_key)
        taxonomy_lines.append(f"\n### {cat_name} (risk: {cat_info.risk.value})")
        for cap_code in cat_data:
            cap = CAPABILITIES[cap_code]
            taxonomy_lines.append(f"  - `{cap_code}`: {cap.description}")

    taxonomy_text = "\n".join(taxonomy_lines)

    prompt = f"""You are a behavioral capability auditor. Analyze the following agent skill description and extract ALL capabilities it DECLARES (claims to have).

## Taxonomy
The following capabilities exist in our taxonomy:
{taxonomy_text}

## Skill: {skill_name}

{skill_body}

## Instructions

1. Read the skill description carefully.
2. Extract ALL capabilities that the skill DECLARES (claims to perform or have access to).
3. For each declared capability, provide a QUOTED PASSAGE from the skill text as evidence.
4. Also describe the intended workflow and expected data lineages (this helps anchor your analysis but does not become part of the output).

## Output Format

Return a structured JSON object with:
- `declared_capabilities`: array of objects, each containing:
  - `capability`: the taxonomy code (e.g., "fs-read-project")
  - `evidence`: the EXACT quoted sentence/paragraph from the skill that supports this capability
  - `evidence_location`: approximate location ("frontmatter" or "body")
- `intended_workflow`: a 1-3 sentence description of what the skill intends to do (CoT anchor)
- `expected_data_lineages`: a 1-3 sentence description of expected data flows (CoT anchor)

IMPORTANT: Only claim a capability if there is clear textual evidence. Do NOT echo taxonomy categories verbatim — analyze the actual skill content."""
    return prompt


def validate_llm_output(
    llm_output: Dict, skill_content: str
) -> Tuple[Set[str], List[Dict], List[str]]:
    """Validate and filter LLM-extracted capabilities.

    Implements the three hallucination controls:
    1. Taxonomy-echo rejection
    2. Substring evidence grounding
    3. Keyword quality checks

    Returns:
    - valid_capabilities: set of capability codes that pass validation
    - evidence: list of evidence dicts
    - rejected: list of rejection reasons
    """
    valid_capabilities: Set[str] = set()
    evidence: List[Dict] = []
    rejected: List[str] = []

    declared = llm_output.get("declared_capabilities", [])
    if not isinstance(declared, list):
        return valid_capabilities, evidence, ["LLM output missing declared_capabilities array"]

    # Normalize skill content for evidence grounding
    normalized_content = _normalize_text(skill_content)

    for item in declared:
        if not isinstance(item, dict):
            continue

        cap = item.get("capability", "").strip()
        ev_text = item.get("evidence", "").strip()
        ev_location = item.get("evidence_location", "body")

        # Control 1: Taxonomy-echo rejection
        if _is_taxonomy_echo(cap, ev_text):
            rejected.append(f"Taxonomy echo: capability '{cap}' matches prompt template verbatim")
            continue

        # Validate capability code
        if cap not in ALL_CAPABILITY_CODES:
            rejected.append(f"Unknown capability code: {cap}")
            continue

        # Control 2: Substring evidence grounding
        if not _is_evidence_grounded(ev_text, normalized_content):
            rejected.append(
                f"Evidence not grounded in source text for capability '{cap}'"
            )
            continue

        # Control 3: Keyword quality check for high-risk capabilities
        cap_def = CAPABILITIES[cap]
        if cap_def.risk.value in ("critical", "high"):
            if not _passes_keyword_check(cap, ev_text):
                rejected.append(
                    f"High-risk capability '{cap}' lacks domain keywords in evidence"
                )
                continue

        valid_capabilities.add(cap)
        evidence.append(
            {
                "capability": cap,
                "source_type": "llm_semantic",
                "evidence": ev_text[:500],
                "evidence_location": ev_location,
            }
        )

    return valid_capabilities, evidence, rejected


def _normalize_text(text: str) -> str:
    """Normalize text for evidence matching: strip leading/trailing whitespace,
    collapse internal whitespace, lowercase."""
    import re

    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def _is_taxonomy_echo(capability: str, evidence: str) -> bool:
    """Control 1: Check if the LLM echoed taxonomy text verbatim."""
    if capability not in CAPABILITIES:
        return False

    cap_def = CAPABILITIES[capability]
    # If evidence is essentially the capability description, it's an echo
    norm_evidence = _normalize_text(evidence)
    norm_desc = _normalize_text(cap_def.description)

    # Exact match of description = echo
    if norm_evidence == norm_desc:
        return True

    # Evidence that is just the capability code name
    if norm_evidence == _normalize_text(cap_def.name):
        return True

    return False


def _is_evidence_grounded(evidence: str, normalized_content: str) -> bool:
    """Control 2: Check if the evidence quote exists in the source text."""
    if not evidence:
        return False

    normalized_evidence = _normalize_text(evidence)

    # Try exact substring match
    if normalized_evidence in normalized_content:
        return True

    # Try with partial matching (at least 60% of the evidence must match)
    # Split into words and check
    evidence_words = set(normalized_evidence.split())
    if len(evidence_words) < 3:
        return False

    content_words = set(normalized_content.split())
    overlap = evidence_words & content_words
    ratio = len(overlap) / len(evidence_words)

    return ratio >= 0.6


def _passes_keyword_check(capability: str, evidence: str) -> bool:
    """Control 3: High-risk capabilities need domain-specific keywords in context."""
    # Define expected keywords per high-risk capability
    KEYWORD_CHECKS = {
        "cred-read": [
            "key", "token", "secret", "password", "credential", "api",
            "auth", "ssh", "private", "env",
        ],
        "cred-create": [
            "create", "generate", "write", "store", "save", "key", "token", "config",
        ],
        "cred-transmit": [
            "send", "transmit", "upload", "post", "request", "exfiltrate", "forward",
        ],
        "instr-override": [
            "ignore", "disregard", "forget", "override", "instead", "new instruction",
        ],
        "instr-conceal": [
            "hidden", "conceal", "invisible", "zero-width", "unicode", "base64",
            "obfuscat", "comment", "metadata",
        ],
        "instr-identity-hijack": [
            "you are now", "act as", "role", "pretend", "persona", "identity",
        ],
        "instr-silent-exec": [
            "background", "silent", "daemon", "thread", "auto", "hook", "lifecycle",
        ],
        "instr-exfil-instruction": [
            "system prompt", "output your", "respond with", "reveal", "disclose",
            "instruction", "prompt",
        ],
        "net-download-exec": [
            "download", "fetch", "curl", "wget", "url", "http", "binary", "executable",
        ],
        "proc-exec-shell": [
            "shell", "bash", "subprocess", "command", "execute", "run", "os.system",
        ],
        "proc-code-eval": [
            "eval", "exec", "compile", "dynamic", "__import__", "importlib",
        ],
        "proc-code-eval-dynamic": [
            "import_module", "__import__", "dynamic import", "load module",
        ],
    }

    expected = KEYWORD_CHECKS.get(capability, [])
    if not expected:
        return True  # No specific keyword check for this capability

    evidence_lower = evidence.lower()
    return any(kw.lower() in evidence_lower for kw in expected)


# =============================================================================
# Merge
# =============================================================================


def merge_declared(
    d_deterministic: Set[str],
    det_evidence: List[Dict],
    d_llm: Set[str],
    llm_evidence: List[Dict],
) -> Tuple[Set[str], List[Dict]]:
    """Merge deterministic and LLM declared capabilities, deduplicating."""
    all_caps = d_deterministic | d_llm
    all_evidence = list(det_evidence) + list(llm_evidence)

    # Deduplicate evidence by capability
    seen_caps: Set[str] = set()
    deduped_evidence: List[Dict] = []
    for ev in all_evidence:
        cap = ev["capability"]
        if cap not in seen_caps:
            seen_caps.add(cap)
            deduped_evidence.append(ev)

    return all_caps, deduped_evidence
