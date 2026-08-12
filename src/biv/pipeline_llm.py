"""
Full BIV audit pipeline with LLM — OpenAI-compatible business endpoint.

This replaces the Claude Code Workflow scripts (biv_workflow.js / batch_workflow.js).
The 4 LLM call points (D_llm, A_llm_instr, LLM Classifier, LLM Judge) are now
made via plain HTTP to the business endpoint (Qwen3-32B-V1 / MiniMax-M2.7 /
deepseek-v4-flash) through LLMClient, reusing ALL deterministic logic and the
existing prompt builders + validators (3 hallucination controls).

Flow:
1. run_deterministic_pipeline() -> Phi(s) evidence
2. D_llm: semantic declared-capability extraction (validate_llm_output)
3. A_llm_instr: instruction-level hidden capability detection (validate_instruction)
4. LLM Classifier: only when rule engine did NOT match (validate_classifier)
5. LLM Judge: merged D/A/U/O + flows + compound_flags + root_cause
   (validate_judge_output) — CoT reasoning in the prompt
6. final_verdict(veto, judge)
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from .llm_client import LLMClient, LLMConfigError, LLMError
from .llm_config import load_llm_config, config_missing_reason
from .orchestrator import run_deterministic_pipeline
from .declared_track import validate_llm_output
from .actual_track.llm_instruction import validate_instruction_llm_output
from .root_cause import validate_classifier_output
from .malicious_detect import (
    build_judge_prompt,
    final_verdict,
    validate_judge_output,
)
from .deviation import compute_deviation
from .taxonomy import (
    INTENT_LEAF_DESCRIPTIONS,
    INTENT_CATEGORY_NAMES,
    ADVERSARIAL_BRANCHES,
    NON_ADVERSARIAL_BRANCHES,
)

logger = logging.getLogger(__name__)


# =============================================================================
# LLM call validators (adapt existing validators to complete_structured contract)
# =============================================================================


def _d_llm_validator(skill_body: str):
    def _v(parsed: Dict) -> Optional[Dict]:
        if not isinstance(parsed.get("declared_capabilities"), list):
            return None  # wrong shape → retry
        caps, evidence, rejected = validate_llm_output(parsed, skill_body)
        return {
            "caps": sorted(caps),
            "evidence": evidence,
            "rejected": rejected,
        }

    return _v


def _a_llm_validator(skill_body: str):
    def _v(parsed: Dict) -> Optional[Dict]:
        if not isinstance(parsed.get("instruction_capabilities"), list):
            return None
        caps, evidence, rejected = validate_instruction_llm_output(parsed, skill_body)
        return {
            "caps": sorted(caps),
            "evidence": evidence,
            "rejected": rejected,
        }

    return _v


def _classifier_validator(parsed: Dict) -> Optional[Dict]:
    leaf, branch, classification, kill_chain, conf = validate_classifier_output(parsed)
    if leaf is None or leaf not in INTENT_LEAF_DESCRIPTIONS:
        return None
    return {
        "intent_leaf": leaf,
        "intent_category": branch,
        "classification": classification,
        "kill_chain": kill_chain,
        "confidence": conf,
    }


def _judge_validator(parsed: Dict) -> Optional[Dict]:
    verdict, conf, reasoning, category, key_evidence = validate_judge_output(parsed)
    if verdict not in ("benign", "malware"):
        return None
    return {
        "verdict": verdict,
        "confidence": conf,
        "reasoning": reasoning,
        "intent_category": category,
        "key_evidence": key_evidence,
    }


# =============================================================================
# Full pipeline
# =============================================================================


def run_full_audit(
    skill_dir: str,
    client: Optional[LLMClient] = None,
    verbose: bool = False,
) -> Dict:
    """Run the full BIV audit with LLM calls against the business endpoint.

    Returns the final verdict plus all intermediate evidence. On config error,
    returns {"error": ...}. On LLM total failure, falls back to deterministic
    verdict (_det_verdict) so the pipeline still produces a result.
    """
    skill_path = Path(skill_dir).resolve()
    if not skill_path.is_dir():
        return {"error": f"Not a directory: {skill_dir}"}

    # --- Config / client ---
    # If a client is passed in (mock or prebuilt), skip config validation.
    if client is None:
        cfg = load_llm_config()
        reason = config_missing_reason(cfg)
        if reason:
            return {"error": reason}
        try:
            client = LLMClient(cfg)
        except LLMConfigError as e:
            return {"error": str(e)}
    else:
        cfg = getattr(client, "cfg", None) or load_llm_config()

    model_name = cfg.model if cfg else "unknown"

    # --- Phase 1+2+3 deterministic ---
    if verbose:
        logger.info("Running deterministic pipeline...")
    result = run_deterministic_pipeline(str(skill_path))
    if "error" in result:
        return result

    phase1 = result["phase1"]
    phase2 = result["phase2"]
    phase3_det = result["phase3_deterministic"]
    finding_counts = result.get("finding_counts", {})

    D_det = set(phase1["D_deterministic"])
    A_ast = set(phase1["A_ast"])
    A_regex = set(phase1["A_regex"])
    flows = phase1.get("flows_ast", [])
    skill_body = phase1.get("skill_body", "")
    skill_content = phase1.get("skill_content_full", "")
    skill_name = phase1.get("skill_name", "unknown")

    # client already resolved above (prebuilt or freshly created)

    # --- D_llm: semantic declared capabilities ---
    d_llm_result = None
    if verbose:
        logger.info("D_llm: semantic declared-capability extraction...")
    try:
        d_llm_result = client.complete_structured(
            phase1["llm_declared_prompt"], _d_llm_validator(skill_body)
        )
    except LLMError as e:
        logger.warning(f"D_llm failed: {e}")

    D_llm = set(d_llm_result["caps"]) if d_llm_result else set()
    d_llm_evidence = d_llm_result["evidence"] if d_llm_result else []
    d_llm_rejected = d_llm_result["rejected"] if d_llm_result else []
    if verbose:
        logger.info(f"  D_llm extracted {len(D_llm)} caps (rejected {len(d_llm_rejected)})")

    # --- A_llm_instr: instruction-level hidden capabilities ---
    a_llm_result = None
    if verbose:
        logger.info("A_llm_instr: instruction-level analysis...")
    try:
        a_llm_result = client.complete_structured(
            phase1["llm_instruction_prompt"], _a_llm_validator(skill_body)
        )
    except LLMError as e:
        logger.warning(f"A_llm_instr failed: {e}")

    A_llm = set(a_llm_result["caps"]) if a_llm_result else set()
    a_llm_evidence = a_llm_result["evidence"] if a_llm_result else []
    a_llm_rejected = a_llm_result["rejected"] if a_llm_result else []
    if verbose:
        logger.info(f"  A_llm_instr extracted {len(A_llm)} caps (rejected {len(a_llm_rejected)})")

    # --- Merge D / A and recompute deviations ---
    D_all = D_det | D_llm
    A_all = A_ast | A_regex | A_llm
    U, O = compute_deviation(D_all, A_all)

    # --- LLM Classifier (only if rule engine did not match) ---
    classifier_result = None
    if phase3_det["needs_classifier"]:
        if verbose:
            logger.info("LLM Classifier: root-cause classification (rule engine no match)...")
        cp = result["llm_prompts"]["classifier_prompt"]
        if cp:
            try:
                classifier_result = client.complete_structured(cp, _classifier_validator)
            except LLMError as e:
                logger.warning(f"LLM Classifier failed: {e}")
        if verbose:
            logger.info(f"  Classifier -> {classifier_result}")

    # --- Build root-cause preview for Judge ---
    rule_eng = phase3_det["rule_engine"]
    if classifier_result:
        rc_leaf = classifier_result["intent_leaf"]
        rc_branch = classifier_result["intent_category"]
        rc_classification = classifier_result["classification"]
        rc_kill_chain = classifier_result["kill_chain"]
        rc_rule = None
        rc_source = "llm_classifier"
    elif rule_eng.get("matched"):
        rc_leaf = rule_eng["intent_leaf"]
        rc_branch = rule_eng["intent_category"]
        rc_classification = (
            "adversarial"
            if rc_branch in ADVERSARIAL_BRANCHES
            else "non_adversarial"
            if rc_branch in NON_ADVERSARIAL_BRANCHES
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

    root_cause = {
        "classification": rc_classification,
        "intent_leaf": rc_leaf,
        "intent_leaf_description": INTENT_LEAF_DESCRIPTIONS.get(rc_leaf, ""),
        "rule_engine_match": rc_rule,
        "kill_chain": rc_kill_chain,
        "classifier_source": rc_source,
    }

    # --- LLM Judge (merged evidence) ---
    if verbose:
        logger.info("LLM Judge: final verdict (CoT)...")
    judge_result = None
    judge_prompt = build_judge_prompt(
        skill_name,
        skill_content,
        D_all,
        A_all,
        U,
        O,
        flows,
        phase2["compound_flags"],
        root_cause,
        finding_counts,
    )
    try:
        judge_result = client.complete_structured(judge_prompt, _judge_validator)
    except LLMError as e:
        logger.warning(f"LLM Judge failed: {e}")
    if verbose:
        logger.info(f"  Judge -> {judge_result}")

    # --- Final verdict ---
    veto = phase3_det["relaxed_veto"]
    if judge_result:
        verdict, verdict_source, confidence = final_verdict(
            veto["fired"],
            veto.get("reason", ""),
            judge_result["verdict"],
            judge_result["confidence"],
            judge_result["reasoning"],
        )
    else:
        # LLM total failure → fall back to deterministic verdict
        det = result.get("_det_verdict", {})
        verdict = det.get("verdict", "benign")
        confidence = det.get("confidence", 0.5)
        verdict_source = "deterministic_fallback"
        judge_result = {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": "LLM 调用全部失败，回退到确定性判定",
            "intent_category": rc_branch,
            "key_evidence": [],
        }

    return {
        "skill_name": skill_name,
        "skill_dir": str(skill_path),
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "verdict_source": verdict_source,
        "verdict_reasoning": judge_result.get("reasoning", ""),
        "model": model_name,
        "deterministic": {
            "D_det": sorted(D_det),
            "A_ast": sorted(A_ast),
            "A_regex": sorted(A_regex),
            "U": sorted(U),
            "O": sorted(O),
            "flows": flows,
            "compound_flags": phase2["compound_flags"],
            "rule_engine": rule_eng,
            "relaxed_veto": veto,
            "_det_verdict": result.get("_det_verdict", {}),
        },
        "llm": {
            "D_llm": sorted(D_llm),
            "D_llm_evidence": d_llm_evidence,
            "D_llm_rejected": d_llm_rejected,
            "A_llm_instr": sorted(A_llm),
            "A_llm_instr_evidence": a_llm_evidence,
            "A_llm_instr_rejected": a_llm_rejected,
            "classifier": classifier_result,
            "judge": judge_result,
        },
        "root_cause": root_cause,
        "finding_counts": finding_counts,
        "trace_summary": result.get("trace_summary", ""),
    }
