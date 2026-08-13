#!/usr/bin/env python3
"""
BIV Audit CLI — end-to-end skill audit.

Usage:
    python scripts/biv_audit.py <skill-directory> [--output <json-path>]
    python scripts/biv_audit.py <skill-directory> --evidence   # compact Φ(s) evidence for LLM workflows

Two output modes:
- Default: full deterministic pipeline result (phases + trace + LLM prompts)
- --evidence: compact Φ(s) evidence object (for feeding LLM Judge in Workflow)

The LLM calls (D_llm, A_llm_instr, LLM classifier, LLM judge) are
invoked via Claude Code's Agent tool in the Workflow scripts.
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.orchestrator import (
    run_deterministic_pipeline,
    build_det_evidence,
    assemble_final_output,
)
from biv.declared_track import validate_llm_output, merge_declared
from biv.actual_track.llm_instruction import validate_instruction_llm_output
from biv.root_cause import validate_classifier_output, apply_rule_engine
from biv.malicious_detect import validate_judge_output, final_verdict


def _emit(output: str) -> None:
    """Write UTF-8 output handling Windows console encoding."""
    try:
        sys.stdout.buffer.write(output.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            print(output)
        except Exception:
            print(output)


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: biv_audit.py <skill-directory> [--output <json-path>] [--evidence] [--trace-dir <dir>]", file=sys.stderr)
        sys.exit(1)

    skill_dir = args[0]
    output_path = None
    evidence_only = False
    trace_dir = None

    i = 1
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif args[i] == "--evidence":
            evidence_only = True
            i += 1
        elif args[i] == "--trace-dir" and i + 1 < len(args):
            trace_dir = args[i + 1]
            i += 2
        else:
            i += 1

    if evidence_only:
        result = build_det_evidence(skill_dir)
    else:
        result = run_deterministic_pipeline(skill_dir, trace_dir=trace_dir)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        print(f"Results written to {output_path}")
    else:
        _emit(output)


if __name__ == "__main__":
    main()
