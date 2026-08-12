"""
Main pipeline orchestrator for BIV (Behavioral Integrity Verification).

Coordinates all 3 phases:
1. Capability Extraction (Declared + Actual Tracks)
2. Deviation Detection
3. Root Cause Classification + Malicious Detection

The LLM calls (D_llm, A_llm_instr, LLM classifier, LLM judge) are defined
as interfaces here — the Workflow script invokes them via Claude Code Agent tool.
"""

import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .taxonomy import (
    CAPABILITIES,
    CAPABILITY_RISK,
    COMPOUND_FLAG_DEFS,
    INTENT_LEAF_DESCRIPTIONS,
    INTENT_CATEGORY_NAMES,
    CATEGORIES,
    CAPABILITIES_BY_CATEGORY,
    ADVERSARIAL_BRANCHES,
    NON_ADVERSARIAL_BRANCHES,
    CapabilityDef,
    RiskTier,
)
from .declared_track import (
    parse_frontmatter,
    extract_tools_from_frontmatter,
    map_tools_to_capabilities,
    extract_declared_deterministic,
    build_declared_llm_prompt,
    validate_llm_output,
    merge_declared,
)
from .actual_track.ast_analyzer import run_ast_analysis
from .actual_track.regex_engine import run_regex_analysis
from .actual_track.llm_instruction import (
    build_instruction_llm_prompt,
    validate_instruction_llm_output,
)
from .deviation import (
    compute_deviation,
    detect_compound_flags,
    check_relaxed_veto_condition,
    compute_risk_assessment,
    assemble_evidence_tuple,
)
from .root_cause import (
    apply_rule_engine,
    build_classifier_prompt,
    validate_classifier_output,
)
from .malicious_detect import (
    relaxed_veto,
    build_judge_prompt,
    validate_judge_output,
    final_verdict,
)
from .trace import TraceContext

logger = logging.getLogger(__name__)


# =============================================================================
# Phase 1: Capability Extraction
# =============================================================================


def phase1_extract_capabilities(
    skill_dir: Path,
    trace: Optional[TraceContext] = None,
) -> Dict:
    """Run Phase 1: extract D(s), A(s), flow(s), compound(s).

    This runs ALL deterministic extraction. LLM extraction interfaces
    are prepared but not executed here — the Workflow script handles them.

    Returns a dict with:
    - skill info (name, dir, structure, frontmatter)
    - D_deterministic, A_regex, A_ast (deterministic results)
    - llm_prompts (prompts ready for Workflow Agent calls)
    - intermediate data for Phase 2
    """
    if trace:
        trace.phase("extract")

    from datetime import datetime

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        msg = f"No SKILL.md found in {skill_dir}"
        if trace:
            trace.error(msg)
        return {"error": msg}

    try:
        content = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        msg = f"Cannot read SKILL.md: {e}"
        if trace:
            trace.error(msg)
        return {"error": msg}

    # Parse frontmatter and body
    t0 = time.time()
    frontmatter, body = parse_frontmatter(content)
    if trace:
        trace.step("parse_frontmatter", message="Parsed SKILL.md frontmatter",
                   input_data={"path": str(skill_md)},
                   output_data={"has_frontmatter": frontmatter is not None, "body_len": len(body)},
                   duration_ms=(time.time() - t0) * 1000)

    # --- Declared Track: Deterministic ---
    t0 = time.time()
    if frontmatter:
        D_det, d_det_evidence = extract_declared_deterministic(
            skill_dir, frontmatter, content
        )
    else:
        D_det, d_det_evidence = set(), []
        if trace:
            trace.warn("No valid frontmatter found — D_det will be empty")
    if trace:
        trace.step("D_deterministic", message=f"Extracted {len(D_det)} declared capabilities",
                   output_data={"D_det": sorted(D_det), "evidence_count": len(d_det_evidence)},
                   duration_ms=(time.time() - t0) * 1000)
        trace.metric("D_det_count", len(D_det))

    # --- Declared Track: LLM prompt ---
    skill_name = frontmatter.get("name", skill_dir.name) if frontmatter else skill_dir.name
    llm_declared_prompt = build_declared_llm_prompt(body, skill_name)
    if trace:
        trace.step("build_llm_declared_prompt", message=f"Built LLM prompt for declared extraction ({len(llm_declared_prompt)} chars)")

    # --- Actual Track: AST Analysis ---
    t0 = time.time()
    scripts_dir = skill_dir / "scripts"
    script_files = []
    if scripts_dir.is_dir():
        script_files = sorted(
            [f for f in scripts_dir.iterdir() if f.suffix in (".py", ".sh", ".js", ".ts")]
        )

    A_ast, flows_ast, ast_findings, _ = run_ast_analysis(script_files)
    if trace:
        trace.step("A_ast", message=f"AST analysis: {len(A_ast)} capabilities, {len(flows_ast)} flows",
                   output_data={"A_ast": sorted(A_ast), "flows_count": len(flows_ast), "findings_count": len(ast_findings)},
                   duration_ms=(time.time() - t0) * 1000)
        trace.metric("A_ast_count", len(A_ast))
        trace.metric("flows_ast_count", len(flows_ast))

    # --- Actual Track: Regex Engine ---
    t0 = time.time()
    A_regex, regex_findings, all_urls, url_summary = run_regex_analysis(skill_dir)
    if trace:
        trace.step("A_regex", message=f"Regex engine: {len(A_regex)} capabilities, {len(regex_findings)} findings",
                   output_data={"A_regex": sorted(A_regex), "findings_count": len(regex_findings),
                               "urls_total": url_summary.get("total", 0),
                               "untrusted_urls": url_summary.get("untrusted_count", 0)},
                   duration_ms=(time.time() - t0) * 1000)
        trace.metric("A_regex_count", len(A_regex))
        trace.metric("regex_findings_count", len(regex_findings))
        if url_summary.get("untrusted_count", 0) > 0:
            trace.warn(f"Found {url_summary['untrusted_count']} untrusted URLs",
                       data={"untrusted_urls": [u.get("url", "") for u in url_summary.get("untrusted", [])[:5]]})

    # --- Actual Track: LLM Instruction prompt ---
    llm_instruction_prompt = build_instruction_llm_prompt(body, skill_name)
    if trace:
        trace.step("build_llm_instruction_prompt", message=f"Built LLM prompt for instruction analysis ({len(llm_instruction_prompt)} chars)")

    # --- Structure info ---
    refs_dir = skill_dir / "references"
    structure = {
        "has_skill_md": True,
        "has_references": refs_dir.is_dir(),
        "has_scripts": scripts_dir.is_dir(),
        "reference_files": (
            sorted(f.name for f in refs_dir.iterdir() if f.suffix == ".md")
            if refs_dir.is_dir()
            else []
        ),
        "script_files": (
            sorted(f.name for f in scripts_dir.iterdir()
                   if f.suffix in (".py", ".sh", ".js", ".ts"))
            if scripts_dir.is_dir()
            else []
        ),
    }

    # --- Tools info ---
    tools_info = None
    if frontmatter and "allowed-tools" in frontmatter:
        tools_str = frontmatter["allowed-tools"]
        if isinstance(tools_str, str):
            tools_list = [t.strip() for t in tools_str.replace(",", " ").split() if t.strip()]
            tools_info = {
                "tools": tools_list,
                "has_bash": any("Bash" in t for t in tools_list),
                "has_write": any("Write" in t or "Edit" in t for t in tools_list),
                "has_edit": any("Edit" in t for t in tools_list),
                "has_webfetch": any("WebFetch" in t for t in tools_list),
                "has_task": any("Task" in t for t in tools_list),
                "unrestricted": tools_str.strip() == "*",
            }

    # Sanitize frontmatter for JSON serialization
    sanitized_fm = _sanitize_frontmatter(frontmatter)

    return {
        "skill_name": skill_name,
        "skill_dir": str(skill_dir.resolve()),
        "structure": structure,
        "frontmatter": sanitized_fm,
        "tools": tools_info,
        # Deterministic extraction results
        "D_deterministic": sorted(D_det),
        "d_det_evidence": d_det_evidence,
        "A_ast": sorted(A_ast),
        "A_regex": sorted(A_regex),
        "flows_ast": flows_ast,
        "ast_findings": ast_findings,
        "regex_findings": regex_findings,
        # LLM prompts (for Workflow script)
        "llm_declared_prompt": llm_declared_prompt,
        "llm_instruction_prompt": llm_instruction_prompt,
        # URL data
        "urls": url_summary,
        # Raw skill body for LLM tasks
        "skill_body": body,
        "skill_content_full": content,
        # Reference data for LLM tasks
        "skill_md_path": str(skill_md),
    }


# =============================================================================
# Phase 2: Deviation Detection
# =============================================================================


def phase2_detect_deviations(
    D: Set[str],
    A: Set[str],
    flows: List[Dict],
    d_evidence: List[Dict],
    a_evidence: List[Dict],
    trace: Optional[TraceContext] = None,
) -> Dict:
    """Run Phase 2: compute deviations, compound flags, assemble Φ(s)."""
    if trace:
        trace.phase("detect")

    t0 = time.time()
    U, O = compute_deviation(D, A)
    if trace:
        trace.step("compute_deviation", message=f"U={len(U)} undeclared, O={len(O)} overdeclared",
                   output_data={"U": sorted(U), "O": sorted(O)},
                   duration_ms=(time.time() - t0) * 1000)
        trace.metric("undeclared_count", len(U))
        trace.metric("overdeclared_count", len(O))
        for cap in U:
            risk = CAPABILITY_RISK.get(cap, RiskTier.MEDIUM)
            if risk.value in ("critical", "high"):
                trace.warn(f"Undeclared high-risk capability: {cap} (risk={risk.value})")

    t0 = time.time()
    compound_flags = detect_compound_flags(flows, A, U)
    if trace:
        triggered = [k for k, v in compound_flags.items() if v]
        trace.step("detect_compound_flags", message=f"Compound flags: {len(triggered)} triggered",
                   output_data={"compound_flags": compound_flags, "triggered": triggered},
                   duration_ms=(time.time() - t0) * 1000)
        for flag in triggered:
            prior = COMPOUND_FLAG_DEFS.get(flag, {}).get("malicious_prior", 0)
            trace.warn(f"Compound threat flag triggered: {flag} (malicious prior: {prior:.0%})")

    phi = assemble_evidence_tuple(D, A, U, O, flows, compound_flags, d_evidence, a_evidence)
    risk_assessment = compute_risk_assessment(U, O, compound_flags)
    if trace:
        trace.metric("risk_score", risk_assessment["risk_score"])
        trace.metric("compound_flags_triggered", risk_assessment["compound_flags_triggered"])

    # Count instruction signals
    instr_count = sum(1 for c in A if c in CAPABILITIES and CAPABILITIES[c].category == "instruction")
    if trace:
        trace.metric("instruction_signals", instr_count)

    return {
        "U": sorted(U),
        "O": sorted(O),
        "compound_flags": compound_flags,
        "phi": phi,
        "risk_assessment": risk_assessment,
        "instruction_signals": instr_count,
    }


# =============================================================================
# Phase 3: Root Cause + Malicious Detection (deterministic parts)
# =============================================================================


def phase3_deterministic(
    U: Set[str],
    O: Set[str],
    A: Set[str],
    D: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    instruction_signals: int,
    trace: Optional[TraceContext] = None,
) -> Dict:
    """Run Phase 3 deterministic components: rule engine + relaxed veto."""
    if trace:
        trace.phase("classify")

    # Rule engine
    t0 = time.time()
    rule_leaf, rule_branch, rule_id, rule_kill_chain = apply_rule_engine(
        U, O, A, D, flows, compound_flags, instruction_signals
    )
    if trace:
        trace.step("apply_rule_engine",
                   message=f"Rule engine: {'matched=' + rule_id if rule_id else 'no match'}",
                   output_data={"matched": rule_leaf is not None, "intent_leaf": rule_leaf,
                               "rule_id": rule_id, "kill_chain": rule_kill_chain},
                   duration_ms=(time.time() - t0) * 1000)

    # Relaxed veto
    t0 = time.time()
    veto_fired, veto_reason, veto_flag, veto_cap = relaxed_veto(compound_flags, U)
    if trace:
        trace.step("relaxed_veto",
                   message=f"Relaxed veto: {'FIRED' if veto_fired else 'not triggered'}",
                   output_data={"fired": veto_fired, "reason": veto_reason},
                   duration_ms=(time.time() - t0) * 1000)
        if veto_fired:
            trace.warn(f"RELAXED_VETO FIRED: {veto_reason}")

    # Build LLM prompts if needed (rule engine didn't match, or for judge)
    needs_classifier = rule_leaf is None
    if trace:
        trace.metric("needs_llm_classifier", needs_classifier)

    return {
        "rule_engine": {
            "matched": rule_leaf is not None,
            "intent_leaf": rule_leaf,
            "intent_category": rule_branch,
            "rule_id": rule_id,
            "kill_chain": rule_kill_chain,
        },
        "relaxed_veto": {
            "fired": veto_fired,
            "reason": veto_reason,
            "compound_flag": veto_flag,
            "high_risk_capability": veto_cap,
        },
        "needs_classifier": needs_classifier,
    }


# =============================================================================
# Phase 3 LLM Prompts
# =============================================================================


def build_phase3_llm_prompts(
    skill_name: str,
    skill_content: str,
    U: Set[str],
    O: Set[str],
    A: Set[str],
    D: Set[str],
    flows: List[Dict],
    compound_flags: Dict[str, bool],
    findings_count: Dict,
    rule_engine_result: Dict,
) -> Dict:
    """Build LLM prompts for Phase 3 classifier and judge."""
    # Classifier prompt (only if rule engine didn't match)
    classifier_prompt = None
    if not rule_engine_result.get("matched"):
        classifier_prompt = build_classifier_prompt(
            U, O, A, D, flows, compound_flags, skill_name
        )

    # Judge prompt (always needed)
    root_cause_preview = {
        "classification": (
            "adversarial"
            if rule_engine_result.get("intent_category") in ADVERSARIAL_BRANCHES
            else "non_adversarial"
        )
        if rule_engine_result.get("matched")
        else "pending_classifier",
        "intent_leaf": rule_engine_result.get("intent_leaf", "pending"),
        "intent_leaf_description": INTENT_LEAF_DESCRIPTIONS.get(
            rule_engine_result.get("intent_leaf", ""), ""
        ),
        "rule_engine_match": rule_engine_result.get("rule_id"),
        "kill_chain": rule_engine_result.get("kill_chain"),
        "classifier_source": (
            "deterministic_rule"
            if rule_engine_result.get("matched")
            else "pending_llm_classifier"
        ),
    }

    judge_prompt = build_judge_prompt(
        skill_name, skill_content, D, A, U, O, flows, compound_flags,
        root_cause_preview, findings_count,
    )

    return {
        "classifier_prompt": classifier_prompt,
        "judge_prompt": judge_prompt,
        "root_cause_preview": root_cause_preview,
    }


# =============================================================================
# Final Assembly
# =============================================================================


def assemble_final_output(
    phase1: Dict,
    phase2: Dict,
    phase3_det: Dict,
    # LLM results
    D_llm: Set[str],
    d_llm_evidence: List[Dict],
    d_llm_rejected: List[str],
    A_llm_instr: Set[str],
    a_llm_instr_evidence: List[Dict],
    a_llm_instr_rejected: List[str],
    classifier_result: Optional[Dict],
    judge_verdict: str,
    judge_confidence: float,
    judge_reasoning: str,
    judge_intent_category: str,
    judge_key_evidence: List[str],
) -> Dict:
    """Assemble the final JSON output matching the agreed schema."""
    # Merge declared
    D_det = set(phase1.get("D_deterministic", []))
    D_all, d_all_evidence = merge_declared(D_det, phase1.get("d_det_evidence", []), D_llm, d_llm_evidence)

    # Merge actual
    A_ast = set(phase1.get("A_ast", []))
    A_regex = set(phase1.get("A_regex", []))
    A_all = A_ast | A_regex | A_llm_instr

    # Build actual sources
    a_all_evidence = []
    for cap in A_ast:
        a_all_evidence.append({
            "capability": cap,
            "source_type": "ast",
            "location": "(AST analysis)",
            "evidence": f"Detected via AST taint analysis",
        })
    for cap in A_regex:
        a_all_evidence.append({
            "capability": cap,
            "source_type": "regex",
            "location": "(regex rule engine)",
            "evidence": f"Detected via deterministic pattern matching",
        })
    a_all_evidence.extend(a_llm_instr_evidence)

    # Recompute deviations with merged sets
    U, O = compute_deviation(D_all, A_all)
    compound_flags = phase2.get("compound_flags", {})
    flows = phase1.get("flows_ast", [])

    # Root cause
    rule_eng = phase3_det.get("rule_engine", {})
    if classifier_result:
        rc_leaf = classifier_result.get("intent_leaf", "H2")
        rc_branch = classifier_result.get("intent_category", "H")
        rc_classification = classifier_result.get("classification", "ambiguous")
        rc_kill_chain = classifier_result.get("kill_chain")
        rc_rule = None
        rc_source = "llm_classifier"
    elif rule_eng.get("matched"):
        rc_leaf = rule_eng.get("intent_leaf")
        rc_branch = rule_eng.get("intent_category")
        rc_classification = (
            "adversarial" if rc_branch in ADVERSARIAL_BRANCHES
            else "non_adversarial" if rc_branch in NON_ADVERSARIAL_BRANCHES
            else "ambiguous"
        )
        rc_kill_chain = rule_eng.get("kill_chain")
        rc_rule = rule_eng.get("rule_id")
        rc_source = "deterministic_rule"
    else:
        rc_leaf = "H2"
        rc_branch = "H"
        rc_classification = "ambiguous"
        rc_kill_chain = None
        rc_rule = None
        rc_source = "none"

    # Final verdict
    veto = phase3_det.get("relaxed_veto", {})
    verdict, verdict_source, verdict_confidence = final_verdict(
        veto.get("fired", False),
        veto.get("reason", ""),
        judge_verdict,
        judge_confidence,
        judge_reasoning,
    )

    # Collect all findings
    all_findings = []
    all_findings.extend(phase1.get("regex_findings", []))
    all_findings.extend(phase1.get("ast_findings", []))
    # Assign IDs
    for i, f in enumerate(all_findings):
        f["id"] = f"FINDING-{i+1:03d}"

    # Finding counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0}
    for f in all_findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Build taxonomy section
    taxonomy_output = {}
    for cat_key, cat_data in CATEGORIES.items():
        cap_list = CAPABILITIES_BY_CATEGORY.get(cat_key, [])
        taxonomy_output[cat_key] = {
            "name": cat_data["name"],
            "risk": cat_data["risk"].value,
            "capabilities": cap_list,
        }

    # URL info
    urls_data = phase1.get("urls", {})
    untrusted = urls_data.get("untrusted", [])

    return {
        "skill_name": phase1.get("skill_name", "unknown"),
        "skill_dir": phase1.get("skill_dir", ""),
        "verdict": verdict,
        "confidence": round(verdict_confidence, 4),
        "verdict_source": verdict_source,
        "verdict_reasoning": judge_reasoning,
        "structure": phase1.get("structure", {}),
        "frontmatter": phase1.get("frontmatter", {}),
        "taxonomy": taxonomy_output,
        "capabilities": {
            "declared": sorted(D_all),
            "actual": sorted(A_all),
            "undeclared": sorted(U),
            "overdeclared": sorted(O),
            "declared_sources": d_all_evidence,
            "actual_sources": a_all_evidence,
        },
        "flows": [
            {
                "source": f.get("source", ""),
                "source_location": f.get("source_location", ""),
                "transforms": f.get("transforms", []),
                "sink": f.get("sink", ""),
                "sink_location": f.get("sink_location", ""),
            }
            for f in flows
        ],
        "compound_flags": compound_flags,
        "root_cause": {
            "classification": rc_classification,
            "intent_category": rc_branch,
            "intent_leaf": rc_leaf,
            "intent_leaf_description": INTENT_LEAF_DESCRIPTIONS.get(rc_leaf, ""),
            "kill_chain": rc_kill_chain,
            "rule_engine_match": rc_rule,
            "classifier_source": rc_source,
        },
        "findings": all_findings,
        "finding_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "total": len(all_findings),
        },
        "urls": {
            "total": urls_data.get("total", 0),
            "trusted_count": urls_data.get("trusted_count", 0),
            "untrusted_count": len(untrusted),
            "untrusted": untrusted,
        },
        "relaxed_veto": {
            "fired": veto.get("fired", False),
            "reason": veto.get("reason") if veto.get("fired") else None,
            "compound_flag": veto.get("compound_flag") if veto.get("fired") else None,
        },
        "_meta": {
            "d_llm_rejected": d_llm_rejected,
            "a_llm_instr_rejected": a_llm_instr_rejected,
            "timestamp": datetime.now().isoformat(),
        },
    }


def _sanitize_frontmatter(fm: Optional[Dict]) -> Optional[Dict]:
    """Sanitize frontmatter for JSON serialization."""
    if fm is None:
        return None
    sanitized = {}
    for key, value in fm.items():
        if isinstance(value, (str, int, float, bool, type(None))):
            sanitized[key] = value
        elif isinstance(value, (list, tuple)):
            sanitized[key] = [
                v if isinstance(v, (str, int, float, bool, type(None))) else str(v)
                for v in value
            ]
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_frontmatter(value)
        else:
            sanitized[key] = str(value)
    return sanitized


# =============================================================================
# Deterministic Evidence (compact output for LLM workflows)
# =============================================================================


def build_det_evidence(skill_dir: str) -> Dict:
    """Run the deterministic pipeline and return a COMPACT evidence object.

    This is the interface used by LLM workflows (biv_workflow.js / batch_workflow.js)
    to feed deterministic conclusions into the LLM Judge. It intentionally omits
    the bulky fields (full skill content, LLM prompts, trace records) and keeps
    only what the Judge needs to reason over Φ(s).

    Returns dict with:
    - skill_name, D_det, A_ast, A_regex, A_merged
    - U (undeclared), O (overdeclared)
    - flows (capped), flow_count
    - compound_flags, rule_engine, relaxed_veto, _det_verdict
    - finding_counts, untrusted_url_count
    """
    result = run_deterministic_pipeline(skill_dir)
    if "error" in result:
        return {"error": result["error"]}

    p1 = result.get("phase1", {})
    p2 = result.get("phase2", {})
    p3 = result.get("phase3_deterministic", {})
    det = result.get("_det_verdict", {})

    flows = p1.get("flows_ast", [])
    flows_capped = []
    for f in flows[:10]:
        flows_capped.append(
            {
                "source": f.get("source", ""),
                "source_location": f.get("source_location", ""),
                "sink": f.get("sink", ""),
                "sink_location": f.get("sink_location", ""),
            }
        )

    urls = p1.get("urls", {})

    return {
        "skill_name": p1.get("skill_name", "unknown"),
        "D_det": p1.get("D_deterministic", []),
        "A_ast": p1.get("A_ast", []),
        "A_regex": p1.get("A_regex", []),
        "A_merged": sorted(set(p1.get("A_ast", [])) | set(p1.get("A_regex", []))),
        "U": p2.get("U", []),
        "O": p2.get("O", []),
        "flows": flows_capped,
        "flow_count": len(flows),
        "compound_flags": p2.get("compound_flags", {}),
        "rule_engine": p3.get("rule_engine", {}),
        "relaxed_veto": p3.get("relaxed_veto", {}),
        "finding_counts": result.get("finding_counts", {}),
        "untrusted_url_count": urls.get("untrusted_count", 0),
        "untrusted_urls": [u.get("url", "") for u in urls.get("untrusted", [])[:5]],
        "_det_verdict": det,
    }


# =============================================================================
# CLI Entry Point
# =============================================================================


def run_deterministic_pipeline(skill_dir: str, trace: Optional[TraceContext] = None) -> Dict:
    """Run the full deterministic pipeline and return intermediate results.

    This is the main entry point called from the CLI or Workflow script.
    It runs phases 1+2+3(deterministic part) and returns everything needed
    for the Workflow script to make LLM calls.

    If trace is not provided, a new TraceContext is created automatically.
    """
    skill_path = Path(skill_dir).resolve()
    if not skill_path.is_dir():
        msg = f"Not a directory: {skill_path}"
        if trace:
            trace.error(msg)
        else:
            logger.error(msg)
        return {"error": msg}

    # Create trace if not provided
    if trace is None:
        trace = TraceContext(skill_name=skill_path.name, skill_dir=str(skill_path))

    t_pipeline_start = time.time()

    # Phase 1
    phase1 = phase1_extract_capabilities(skill_path, trace=trace)
    if "error" in phase1:
        return phase1

    # Phase 2: use only deterministic results for now (LLM results merged later)
    D_det = set(phase1["D_deterministic"])
    A_det = set(phase1["A_ast"]) | set(phase1["A_regex"])
    d_evidence = phase1.get("d_det_evidence", [])
    a_evidence = []

    if trace:
        trace.step("merge_deterministic_capabilities",
                   message=f"Merged capabilities: |D_det|={len(D_det)}, |A_det|={len(A_det)}",
                   output_data={"D_det": sorted(D_det), "A_det": sorted(A_det),
                               "overlap": sorted(D_det & A_det)})

    phase2 = phase2_detect_deviations(
        D_det, A_det, phase1.get("flows_ast", []), d_evidence, a_evidence, trace=trace
    )

    # Phase 3 deterministic
    phase3_det = phase3_deterministic(
        set(phase2["U"]),
        set(phase2["O"]),
        A_det,
        D_det,
        phase1.get("flows_ast", []),
        phase2["compound_flags"],
        phase2["instruction_signals"],
        trace=trace,
    )

    # Build finding counts for judge prompt
    all_findings = phase1.get("regex_findings", []) + phase1.get("ast_findings", [])
    severity_counts = {"critical": 0, "high": 0, "medium": 0}
    for f in all_findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    severity_counts["total"] = len(all_findings)

    if trace:
        trace.metric("total_findings", len(all_findings))
        trace.metric("findings_critical", severity_counts.get("critical", 0))
        trace.metric("findings_high", severity_counts.get("high", 0))

    # Build Phase 3 LLM prompts
    llm_prompts = build_phase3_llm_prompts(
        phase1["skill_name"],
        phase1["skill_content_full"],
        set(phase2["U"]),
        set(phase2["O"]),
        A_det,
        D_det,
        phase1.get("flows_ast", []),
        phase2["compound_flags"],
        severity_counts,
        phase3_det["rule_engine"],
    )

    if trace:
        trace.step("build_llm_prompts", message=f"Built LLM prompts for Phase 3 (judge: {len(llm_prompts.get('judge_prompt', ''))} chars)")

    # For deterministic-only output, simulate final verdict via rules
    if phase3_det["relaxed_veto"]["fired"]:
        det_verdict = "malware"
        det_confidence = 0.90
        det_source = "relaxed_veto"
    elif phase3_det["rule_engine"]["intent_category"] in ADVERSARIAL_BRANCHES:
        det_verdict = "malware"
        det_confidence = 0.80
        det_source = "deterministic_rule"
    else:
        det_verdict = "benign"
        det_confidence = 0.70
        det_source = "deterministic_rule"

    trace.finalize(det_verdict, det_confidence)
    trace.metric("pipeline_total_ms", (time.time() - t_pipeline_start) * 1000)

    return {
        "phase1": phase1,
        "phase2": phase2,
        "phase3_deterministic": phase3_det,
        "llm_prompts": llm_prompts,
        "finding_counts": severity_counts,
        "trace": trace.to_dict(),
        "trace_summary": trace.summary(),
        # Deterministic-only verdict (for debugging; final verdict requires LLM Judge)
        "_det_verdict": {
            "verdict": det_verdict,
            "confidence": det_confidence,
            "source": det_source,
        },
    }


def main():
    """CLI entry point for deterministic pipeline."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.biv.orchestrator <skill-directory>", file=sys.stderr)
        print("  Runs the deterministic BIV pipeline and outputs intermediate JSON.", file=sys.stderr)
        sys.exit(1)

    skill_dir = sys.argv[1]
    result = run_deterministic_pipeline(skill_dir)

    def _json_default(obj):
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    output = json.dumps(result, indent=2, default=_json_default, ensure_ascii=False)
    # Write to stdout, handling Windows console encoding
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    # Encode to UTF-8 bytes and write directly to avoid console encoding issues
    sys.stdout.buffer.write(output.encode('utf-8'))
    sys.stdout.buffer.write(b'\n')


if __name__ == "__main__":
    main()
