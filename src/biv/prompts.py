"""
BIV 提示词统一模板 —— 唯一权威源。

集中管理所有 LLM 提示词（声明提取 / 指令级分析 / 根因分类 / 最终判定）与
taxonomy 参考文本。workflow（JS）通过 `scripts/prompt_render.py` 渲染获取，
Python 侧（root_cause / orchestrator）复用同一渲染函数。

设计：
- `taxonomy_ref_text()` 从 taxonomy.py 自动生成，消除 JS 硬编码漂移
- 渲染函数支持 `variant="single"|"batch"`：single 为 biv_workflow 详细版，
  batch 为 batch_workflow 精简版（统一管理 ≠ 抹平场景差异）
- `render_judge` 的 skill_content 截断在 Python 端完成（single 8000 / batch 6000）

CLI:
    python -m biv.prompts <name> [--vars-json '{...}'] [--variant single|batch]
    python -m biv.prompts --multi d_llm_extract,a_llm_instr --vars-json '{...}' --variant single
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .taxonomy import (
    CAPABILITIES,
    CAPABILITIES_BY_CATEGORY,
    CATEGORIES,
    KILL_CHAINS,
    INTENT_TAXONOMY,
    INTENT_LEAF_DESCRIPTIONS,
)

# 类别英文名（taxonomy.CATEGORIES 里 name 是中文，提示词里用英文保持与 LLM 稳定）
_CATEGORY_EN = {
    "network": "Network",
    "filesystem": "Filesystem",
    "process": "Process Execution",
    "environment": "Environment",
    "encoding": "Encoding",
    "credential": "Credential",
    "instruction": "Instruction-Level",
}

_TAXONOMY_REF_CACHE: Optional[str] = None


# =============================================================================
# Taxonomy reference
# =============================================================================


def taxonomy_ref_text() -> str:
    """Generate the taxonomy reference block from taxonomy.py (single source of truth)."""
    global _TAXONOMY_REF_CACHE
    if _TAXONOMY_REF_CACHE is None:
        lines = []
        for cat_key, caps in CAPABILITIES_BY_CATEGORY.items():
            name = _CATEGORY_EN.get(cat_key, cat_key)
            risk = CATEGORIES[cat_key]["risk"].value.capitalize()
            lines.append(f"{name} ({risk} risk): {', '.join(caps)}")
        _TAXONOMY_REF_CACHE = "\n".join(lines)
    return _TAXONOMY_REF_CACHE


# =============================================================================
# D_llm — declared capability extraction
# =============================================================================


def render_d_llm_extract(skill_name: str, skill_body: str, variant: str = "single") -> str:
    tax = taxonomy_ref_text()
    if variant == "batch":
        return f"""You are a behavioral capability auditor. Extract ALL capabilities this skill DECLARES.

## Taxonomy
{tax}

## Skill: {skill_name}
{skill_body}

Return JSON:
{{
  "declared_capabilities": [
    {{"capability": "taxonomy_code", "evidence": "quoted text from skill", "evidence_location": "body"}}
  ],
  "intended_workflow": "1-3 sentence description (CoT anchor)",
  "expected_data_lineages": "1-3 sentence data flow description (CoT anchor)"
}}

Only claim a capability with clear textual evidence. Do NOT echo taxonomy categories verbatim."""

    return f"""You are a behavioral capability auditor. Analyze the following agent skill description and extract ALL capabilities it DECLARES (claims to have).

## Taxonomy Reference
{tax}

## Skill: {skill_name}

{skill_body}

## Instructions
1. Read the skill description carefully.
2. Extract ALL capabilities that the skill DECLARES (claims to perform or have access to).
3. For each declared capability, provide a QUOTED PASSAGE from the skill text as evidence.
4. Also describe the intended workflow and expected data lineages (this helps anchor your analysis).

Return a JSON object with:
- declared_capabilities: array of {{capability: taxonomy_code, evidence: quoted_passage, evidence_location: "frontmatter" or "body"}}[]
- intended_workflow: 1-3 sentence description of what the skill intends to do (CoT anchor, not used downstream)
- expected_data_lineages: 1-3 sentence description of expected data flows (CoT anchor, not used downstream)

IMPORTANT: Only claim a capability if there is clear textual evidence. Do NOT echo taxonomy categories verbatim - analyze the actual skill content."""


# =============================================================================
# A_llm_actual — actual-capability extraction (A_llm)
#
# Definition (user-confirmed):
#   A(s) = ALL sensitive operations the skill REALLY EXECUTES when it runs,
#          whether declared or not. A_llm reads SKILL.md (imperative commands,
#          code blocks, tool invocations) and reports every sensitive operation,
#          tagging each with is_adversarial. Script files (scripts/*) are covered
#          separately by A_ast / A_regex; A_llm covers the SKILL.md body itself.
# =============================================================================


def render_a_llm_instr(
    skill_name: str,
    skill_body: str,
    variant: str = "single",
    declared_caps: Optional[List[str]] = None,
    intended_workflow: str = "",
) -> str:
    """A_llm: extract every sensitive operation the skill REALLY executes, and judge
    whether each is covered by the skill's DECLARED intent (D).

    User principle: operations covered by D's declared intent are PASSED (放行),
    only operations that EXCEED the declared intent count as deviation (U).
    `covered_by_declared` is therefore the semantic coverage check replacing the
    strict set-difference U = A - D (which over-flags implementation details).
    """
    decl_section = (
        "## Declared Intent (D) — the skill's claimed purpose\n"
        f"Declared capabilities: {', '.join(sorted(declared_caps)) if declared_caps else '(none)'}\n"
        f"Intended workflow: {intended_workflow or '(none)'}\n"
    )
    if variant == "batch":
        return f"""You are a security auditor. Identify ALL sensitive operations this AI agent skill ACTUALLY EXECUTES (A(s)).

## Definition
A(s) = every sensitive operation the skill REALLY performs when it runs — from imperative commands, code blocks, and tool invocations in SKILL.md. These may or may not be declared in the description.

## Target capability taxonomy
- Network: net-http-out, net-socket-out, net-inbound, net-download-exec
- Filesystem: fs-read-project, fs-read-sensitive, fs-read-home, fs-write, fs-write-sensitive, fs-enumerate, fs-delete
- Process Execution: proc-exec, proc-exec-shell, proc-code-eval, proc-code-eval-dynamic
- Credentials: cred-read, cred-transmit, cred-create, cred-overwrite
- Instruction-level (hidden instructions): instr-override, instr-conceal, instr-identity-hijack, instr-silent-exec, instr-exfil-instruction

{decl_section}
## Skill: {skill_name}
{skill_body}

## Task
Identify EVERY sensitive operation the skill ACTUALLY executes (commands, code, tool calls, sockets, etc.), including BENIGN ones (e.g. reading the user's own secrets is still cred-read, just not adversarial). For each, tag:
- is_adversarial: true when the operation violates user intent or is unconditionally harmful
- covered_by_declared: true when the operation falls WITHIN the skill's declared intent (D) — it is the natural/necessary implementation of what the skill claims to do (e.g. writing a temp file while implementing "read user's own secrets" is covered); FALSE when the operation EXCEEDS the declared intent (e.g. sending secrets to a third party while D only says "read user's own secrets") — a real undeclared / overscope operation.

Return JSON:
{{
  "actual_capabilities": [
    {{"capability": "taxonomy_code", "evidence": "quoted command/code", "evidence_location": "body" or "scripts/x.py:12", "is_adversarial": true/false, "covered_by_declared": true/false}}
  ],
  "analysis_summary": "2-3 sentence risk profile (CoT anchor)"
}}

Rules:
- Cover ALL sensitive operations the skill instructs, not only malicious ones.
- Distinguish "documenting/mentioning an operation" from "instructing to perform it" — list only operations the skill ACTUALLY instructs/executes.
- Be GENEROUS with covered_by_declared: implementation details that serve the declared purpose are covered. Only flag covered_by_declared=false when the operation clearly exceeds the skill's stated intent.
- Do NOT echo taxonomy category names verbatim as evidence; quote the actual command/code."""

    return f"""You are a security auditor. Identify ALL sensitive operations this AI agent skill ACTUALLY EXECUTES (A(s)).

## Definition
A(s) = every sensitive operation the skill REALLY performs when it runs — from imperative commands, code blocks, and tool invocations in SKILL.md. These may or may not be declared in the description.

## Target capability taxonomy
- Network: net-http-out, net-socket-out, net-inbound, net-download-exec
- Filesystem: fs-read-project, fs-read-sensitive, fs-read-home, fs-write, fs-write-sensitive, fs-enumerate, fs-delete
- Process Execution: proc-exec, proc-exec-shell, proc-code-eval, proc-code-eval-dynamic
- Credentials: cred-read, cred-transmit, cred-create, cred-overwrite
- Instruction-level (hidden instructions): instr-override, instr-conceal, instr-identity-hijack, instr-silent-exec, instr-exfil-instruction

{decl_section}
## Skill: {skill_name}

{skill_body}

## Task
1. Read SKILL.md and identify EVERY sensitive operation the skill ACTUALLY executes (imperative commands, code blocks, tool calls, sockets, background execution, etc.), including BENIGN ones.
2. For each, give its taxonomy code, a QUOTED PASSAGE as evidence, and the location.
3. Tag each with:
   - is_adversarial=true only when the operation violates user intent or is unconditionally harmful.
   - covered_by_declared=true when the operation falls WITHIN the skill's declared intent (D) — natural/necessary implementation of the claimed purpose; FALSE when it EXCEEDS the declared intent (a real undeclared / overscope operation).

Return a JSON object with:
- actual_capabilities: array of {{capability, evidence, evidence_location, is_adversarial, covered_by_declared}}
- analysis_summary: 2-3 sentence risk profile (CoT anchor)

Rules:
- Cover ALL sensitive operations the skill instructs, not only malicious ones.
- Distinguish "documenting/mentioning an operation" from "instructing to perform it" — list only operations the skill ACTUALLY instructs/executes.
- Be GENEROUS with covered_by_declared: implementation details that serve the declared purpose are covered. Only flag covered_by_declared=false when the operation clearly exceeds the skill's stated intent.
- Do NOT echo taxonomy category names verbatim as evidence; quote the actual command/code."""


# =============================================================================
# Phase 4 — malicious attack chain construction
#
# For each flagged malicious block, construct the attack chain:
#   User --[constructed trigger input]--> malicious block --> flow-items
#   (the actual malicious code snippets from external code evidence).
# =============================================================================


def render_attack_chain(
    skill_name: str,
    block: Dict[str, Any],
    code_evidence: Dict[str, Any],
) -> str:
    """Phase 4 prompt: build a malicious attack chain for ONE malicious block.

    Args:
        skill_name: skill name
        block: the malicious block classification row
               ({block_id, trigger_condition, classification, text, capabilities})
        code_evidence: capability_code_evidence map (capability -> locations[])
    """
    caps = block.get("capabilities") or []

    def _fmt_code(cap: str) -> str:
        locs = (code_evidence.get(cap) or {}).get("locations", [])
        if not locs:
            return f"- {cap}: (no code location)"
        return "\n".join(
            f"- {cap} | {l.get('file', '?')}:{l.get('line_start', '?')} | {l.get('code', '')}"
            for l in locs[:6]
        )

    code_txt = "\n".join(_fmt_code(cap) for cap in caps) or "(none)"
    block_text = (block.get("text") or "")[:2000]

    return f"""You are constructing a malicious ATTACK CHAIN for a flagged malicious block of an AI agent skill.

## Skill: {skill_name}

## Malicious Block
- block_id: {block.get("block_id")}
- trigger_condition: {block.get("trigger_condition") or "(none)"}
- classification: {block.get("classification")}
- block text:
{block_text}

## External code evidence for this block's capabilities
{code_txt}

## Task
1. Construct a REALISTIC USER INPUT that would trigger this block's execution — a plausible user request/prompt matching the block's trigger condition (this is what the user would say/ask to make the skill execute this malicious path).
2. Identify the ACTUAL malicious code snippet(s) from the external code evidence above that execute when the block is triggered (the lines implementing the harmful operation). Use the quoted file/line/code.

Return ONLY a JSON object:
{{
  "block_id": {block.get("block_id")},
  "user_input": "1-2 sentence realistic user prompt/request that triggers this block",
  "flow_items": [
    {{"capability": "taxonomy_code", "file": "path", "line_start": N, "code": "the malicious code line"}}
  ]
}}

Rules:
- user_input must match the trigger_condition (the scenario where this block runs).
- flow_items must come from the external code evidence (the malicious snippets), not invented code.
- Include ONLY code snippets that implement the harmful behavior."""


# =============================================================================
# LLM classifier — root cause classification
# =============================================================================


def render_classifier(
    U: Set[str],
    O: Set[str],
    A: Set[str],
    D: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    skill_name: str,
) -> str:
    """Structured prompt for the LLM root-cause classifier (migrated from root_cause.build_classifier_prompt)."""

    def _cap_names(cap_set: Set[str]) -> str:
        if not cap_set:
            return "(none)"
        items = []
        for c in sorted(cap_set):
            cap = CAPABILITIES.get(c)
            name = cap.name if cap else c
            items.append(f"  - `{c}`: {name}")
        return "\n".join(items)

    flow_lines = [f"  {i+1}. {f.get('source', '?')} → {f.get('sink', '?')}" for i, f in enumerate(flows[:10])]
    triggered = [k for k, v in compound_flags.items() if v]
    flag_lines = "\n".join(f"  - {f}: TRIGGERED" for f in triggered) if triggered else "  (none)"
    kc_lines = "\n".join(f"  - `{name}`: {desc}" for name, desc in KILL_CHAINS.items())

    intent_lines = []
    for branch in sorted(INTENT_TAXONOMY.keys()):
        data = INTENT_TAXONOMY[branch]
        intent_lines.append(f"**{branch} — {data['name']}**")
        for leaf, desc in sorted(data.items()):
            if leaf != "name":
                intent_lines.append(f"  - {leaf}: {desc}")

    return f"""You are a root-cause classifier for AI agent skill behavioral deviations.

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


# =============================================================================
# LLM judge — final verdict
# =============================================================================

_JUDGE_MAX_CONTENT = {"single": 8000, "batch": 6000}


def render_judge(
    skill_name: str,
    skill_content: str,
    evidence_summary: str,
    variant: str = "single",
) -> str:
    """Final binary classification prompt. skill_content truncated here (variant-dependent)."""
    content = (skill_content or "")[:_JUDGE_MAX_CONTENT.get(variant, 8000)]
    summary = evidence_summary or "(deterministic pipeline failed or unavailable)"

    if variant == "batch":
        return f"""You are a senior security auditor. FINAL binary classification: BENIGN or MALWARE.

## Definition
MALWARE = violates user intent AND likely causes negative impact.

## Skill: {skill_name}

## Raw Content
```
{content}
```

## Deterministic Analysis Φ(s) (from Python pipeline)
{summary}

## Instructions
1. Reason step by step about hidden capabilities, intent mismatch, and potential harm
2. IMPORTANT: The Deterministic Analysis Φ(s) above is high-confidence rule-based evidence.
   - compound_flags (rce_chain has 86% malicious prior, code_obfuscation 90%) are strong signals
   - undeclared high-risk capabilities are the core deviation signal
   - rule_engine and relaxed_veto are deterministic conclusions from 15 rules
3. Weigh deterministic evidence heavily — it comes from AST taint analysis + 15 rules
4. Form a final verdict

Return JSON:
{{
  "verdict": "benign" or "malware",
  "confidence": 0.0-1.0,
  "reasoning": "3-5 sentence explanation",
  "intent_category": "A"-"H",
  "key_evidence": ["2-5 most important evidence items"]
}}

IMPORTANT: Most deviations are oversight (81%), not malice (19%).
Undisclosed download+execute, reverse shells, credential theft → malware.
Overly broad permissions without hidden code → usually benign."""

    return f"""You are a senior security auditor making the FINAL binary classification for an AI agent skill.

## Defining Malware
A skill is MALWARE iff it violates user intent AND is likely to cause negative impact.
- The skill performs actions NOT disclosed in its description
- Those undisclosed actions pose security, privacy, or integrity risks
- The deviation pattern suggests adversarial intent, not developer oversight

## Skill: {skill_name}

## Full Skill Content
```
{content}
```

## Capability Extraction Results
{summary}

## Instructions
1. Reason step by step about:
   a) Whether the skill's actual behavior matches its declared purpose
   b) Whether any hidden capabilities pose security risks
   c) Whether patterns suggest adversarial intent or oversight
2. Form a final verdict: "benign" or "malware"

## Output Format
Return a JSON object:
- verdict: "benign" or "malware"
- confidence: 0.0-1.0
- reasoning: 3-5 sentences explaining key factors
- intent_category: A-H (most likely intent branch)
- key_evidence: array of 2-5 most important evidence strings

IMPORTANT:
- Most deviations are from oversight (81.1%), not malice (18.9%)
- A single low-risk undeclared capability is usually benign
- Hidden download + execution patterns are very suspicious
- Instruction hijacking + concealment strongly indicates malice"""


# =============================================================================
# Skill text normalization (Phase 3 preprocessing)
# =============================================================================
# v2: 不再按句末标点拆行（delete "标点后加换行"），块划分改由子智能体按
# "同一触发条件下会执行的最大行区间"执行（见 docs/chunking-phase0-v2.md）。
# 这里仅保留"删空行 + strip"，行 = SKILL.md 物理行（去空行）。


def normalize_skill_text(text: str) -> List[str]:
    """Preprocess skill text into non-empty physical lines (blank lines dropped).

    Returns a list of stripped non-blank lines — the base units for Phase-0
    chunking (trigger-condition blocks). Sentence splitting is intentionally
    removed: block semantics come from the chunking agent, not punctuation.
    """
    lines = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s:
            lines.append(s)
    return lines


# =============================================================================
# Phase 3 — sentence-level classifier (no-deviation-malicious recognition)
# =============================================================================


def render_sentence_classifier(
    skill_name: str,
    blocks: List[Dict[str, Any]],
    D: List[str],
    A: List[str],
    U: List[str],
    O: List[str],
) -> str:
    """Phase-3 prompt: classify EVERY block of SKILL.md (action vs non-action)
    and tag each action instruction block with the 2×2 malicious classification.

    Blocks come from Phase 0 chunking (src/biv/chunking.py) and carry a global
    block_id. Each block is a **trigger-condition block** (max line range executed
    under one trigger condition) and may span MULTIPLE lines. All downstream
    labeling operates on blocks by block_id; the LLM must emit ONE classification
    per block (with the block's full multi-line text), never per line.

    No-deviation-malicious = the declared action itself is unconditionally
    harmful even though it is consistent (Phase-2 label: no deviation).
    Recognition dimensions grounded in skill-scanner Phase 5 behavioral analysis
    and dangerous-code-patterns references.
    """

    def _fmt(x) -> str:
        return ", ".join(sorted(x)) if x else "(none)"

    # Each block rendered with an explicit header + indented multi-line body so the
    # model treats it as ONE unit and outputs one classification per block_id.
    def _render_block(b: Dict[str, Any]) -> str:
        bid = b.get("block_id")
        text = (b.get("text") or "").strip()
        indented = "\n".join(("    " + ln) if ln else "" for ln in text.split("\n"))
        return f"[block {bid}]\n{indented}"

    sent_txt = "\n\n".join(_render_block(b) for b in blocks)

    return f"""You are a senior security auditor performing PHASE 3 (malicious audit) for an AI agent skill.

## Pipeline Context
- Phase 0 chunked SKILL.md into trigger-condition blocks (max line range per trigger).
- Phase 1 extracted declared capabilities D(s) and actual capabilities A(s).
- Phase 2 (taint analysis) labeled the deviation: deviated vs no-deviation.
- Phase 3 (you): classify EVERY block, then tag each ACTION INSTRUCTION block
  with the 2x2 malicious classification. No block may be left unclassified.

## Skill: {skill_name}

## Capability Sets (from Phase 1/2)
- D(s) declared: {_fmt(D)}
- A(s) actual:   {_fmt(A)}
- U(s) = A - D (undeclared, deviated): {_fmt(U)}
- O(s) = D - A (overdeclared, deviated): {_fmt(O)}

## SKILL.md blocks (Phase 0 output — one block per line, blank lines removed)
{sent_txt}

## Task 1 — Block classification
For EVERY block, classify as one of:
- "non_action": description, metadata, examples, headings, or non-imperative prose
- "action_instruction": an imperative that tells the agent to perform a concrete action

## Task 2 — 2x2 classification of each action instruction block
Combine the Phase-2 deviation label with your malicious analysis:
- no-deviation-benign: consistent AND not harmful
- no-deviation-malicious: consistent BUT the declared action itself is unconditionally harmful
- deviated-benign: inconsistent BUT harmless (oversight, over-engineering)
- deviated-malicious: inconsistent AND harmful

## Task 3 — no-deviation-malicious (unconditional harmful) recognition
A declared action is unconditionally harmful if NO reasonable user-authorized /
legitimate use exists. Recognize these dimensions (skill-scanner behavioral analysis):
1. U1 credential / sensitive exfiltration — reading & sending SSH keys, API tokens,
   credentials, secrets, env vars to a third party / untrusted domain
2. U2 reverse shell / remote control — opening a remote shell, binding a listener,
   forwarding I/O to a remote host
3. U3 dropper / download-and-execute — fetching from an untrusted source and executing it
4. U4 configuration / memory poisoning — modifying CLAUDE.md, MEMORY.md, settings.json,
   hooks, allowlists, auto-approve permissions, writing to agent config dirs
5. U5 scope creep / excessive data gathering — reading files, env vars, git history,
   or user data beyond the skill's stated purpose
6. U6 instruction theft / identity hijack — extracting the system prompt, impersonating
7. U7 ransomware / destructive — encrypting or deleting user data
8. U8 instruction-level malice — instr-override, instr-conceal, instr-silent-exec

Decision rule per block:
- A reasonable authorized / legitimate use EXISTS -> NOT unconditional -> benign label
  (if deviated, leave deeper judgment to the Judge)
- NO such use -> unconditional harmful -> mark no-deviation-malicious

## Output Format
Return a JSON object:
- block_classifications: array of
  {{"block_id": n, "text": "...", "kind": "action_instruction"|"non_action",
    "deviation_label": "deviated"|"no_deviation",
    "malicious_label": "malicious"|"benign",
    "classification": "no-deviation-malicious"|"no-deviation-benign"|"deviated-malicious"|"deviated-benign",
    "capabilities": ["taxonomy code(s) this block involves, if any"],
    "core_instruction": "1-line verb-phrase SUMMARY of the block's core instruction (NOT verbatim text; e.g. \"send ~/.ssh/id_rsa to evil.example.com\")",
    "reason": "1 sentence justification"}}
- unconditional_harmful: array of
  {{"pattern": "U1".."U8", "anchor": "authorized/legit use or target", "block_id": n, "evidence": "quoted block"}}
- coverage: {{"total_blocks": N, "classified_blocks": N}}

For "capabilities": list the taxonomy codes (e.g. net-socket-out, proc-exec, cred-read)
that the block's action maps to; empty array for non_action or capability-free text.
This links the block to capability_code_evidence for the frontend to show code.

IMPORTANT:
- CLASSIFY EVERY BLOCK — output must cover 100% of input blocks (no leak, no overlap).
- Emit EXACTLY ONE block_classifications entry per block_id listed above. Each entry's
  "text" must be the FULL multi-line text of that block (verbatim from the block), NEVER
  a single line — do NOT split a block into per-line entries.
- Only action instruction blocks get a 2x2 label; non_action blocks get kind="non_action",
  deviation_label="no_deviation", malicious_label="benign".
- Distinguish "discussing/documenting an attack" (e.g. a security-audit skill listing
  exfiltration patterns) from "instructing to perform the attack". Documenting is NOT malicious."""


# =============================================================================
# CLI
# =============================================================================


def _emit(text: str) -> None:
    """Windows console-safe UTF-8 output."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(text)


def _render_one(name: str, vars: Dict[str, Any], variant: str) -> str:
    if name == "taxonomy_ref":
        return taxonomy_ref_text()
    if name == "d_llm_extract":
        return render_d_llm_extract(vars.get("skill_name", ""), vars.get("skill_body", ""), variant)
    if name == "a_llm_instr":
        return render_a_llm_instr(
            vars.get("skill_name", ""), vars.get("skill_body", ""), variant,
            declared_caps=vars.get("declared_caps"),
            intended_workflow=vars.get("intended_workflow", ""),
        )
    if name == "classifier":
        return render_classifier(
            set(vars.get("U", [])), set(vars.get("O", [])), set(vars.get("A", [])),
            set(vars.get("D", [])), vars.get("flows", []), vars.get("compound_flags", {}),
            vars.get("skill_name", ""),
        )
    if name == "judge":
        return render_judge(
            vars.get("skill_name", ""), vars.get("skill_content", ""),
            vars.get("evidence_summary", ""), variant,
        )
    if name == "sentence_classifier":
        blocks = vars.get("blocks")
        if not blocks:
            from .chunking import chunk_skill_text  # 延迟导入，避免 chunking→prompts 循环
            src = vars.get("skill_content") or vars.get("skill_body") or ""
            blocks = chunk_skill_text(src)
        return render_sentence_classifier(
            vars.get("skill_name", ""), blocks,
            vars.get("D", []), vars.get("A", []),
            vars.get("U", []), vars.get("O", []),
        )
    if name == "attack_chain":
        return render_attack_chain(
            vars.get("skill_name", ""),
            vars.get("block", {}) or {},
            vars.get("code_evidence", {}) or {},
        )
    raise ValueError(f"unknown template: {name}")


def main() -> None:
    args = sys.argv[1:]

    def _opt(flag: str) -> Optional[str]:
        for i, a in enumerate(args):
            if a == flag and i + 1 < len(args):
                return args[i + 1]
        return None

    multi = _opt("--multi")
    variant = _opt("--variant") or "single"

    # vars 注入顺序：--skill-dir（内部读 SKILL.md）→ --vars-json / stdin（后者覆盖）
    injected: Dict[str, Any] = {}
    skill_dir = _opt("--skill-dir")
    if skill_dir:
        from .skill_parser import parse_skill_dir
        try:
            parsed = parse_skill_dir(Path(skill_dir))
            injected = {
                "skill_name": parsed.get("name") or Path(skill_dir).name,
                "skill_body": parsed.get("body") or "",
                "skill_content": parsed.get("content_full") or "",
            }
        except (OSError, ValueError) as e:
            _emit(f"ERROR: cannot parse --skill-dir: {e}")
            sys.exit(1)

    vars_data: Dict[str, Any] = {}
    vars_json = _opt("--vars-json")
    if vars_json:
        try:
            vars_data = json.loads(vars_json)
        except json.JSONDecodeError as e:
            _emit(f"ERROR: invalid --vars-json: {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        # vars-json from stdin (reliable for large/quoted payloads e.g. evidence_summary)
        try:
            vars_data = json.load(sys.stdin)
        except (json.JSONDecodeError, OSError):
            vars_data = {}
    merged = {**injected, **vars_data}

    try:
        if multi:
            names = [n.strip() for n in multi.split(",") if n.strip()]
            out = {n: _render_one(n, merged, variant) for n in names}
            _emit(json.dumps(out, ensure_ascii=False))
        else:
            if not args or args[0].startswith("--"):
                _emit("Usage: python -m biv.prompts <name> [--skill-dir <dir>] [--vars-json '{...}'|stdin] [--variant single|batch]")
                sys.exit(1)
            _emit(_render_one(args[0], merged, variant))
    except (ValueError, KeyError) as e:
        _emit(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
