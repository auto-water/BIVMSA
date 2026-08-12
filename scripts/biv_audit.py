#!/usr/bin/env python3
"""
BIV Audit CLI — end-to-end skill audit with LLM calls.

Runs the deterministic pipeline first, then uses Claude Agent
for LLM-based extraction, classification, and final verdict.

Usage:
    python scripts/biv_audit.py <skill-directory> [--output <json-path>]

The LLM calls (D_llm, A_llm_instr, LLM classifier, LLM judge) are
invoked via Claude Code's Agent tool. This script runs the deterministic
parts and outputs prompts + intermediate data; the Workflow script
handles the LLM orchestration.

Alternative: When running inside Claude Code, use the Workflow script
at scripts/biv_workflow.js instead for full LLM integration.
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.orchestrator import (
    run_deterministic_pipeline,
    assemble_final_output,
)
from biv.declared_track import validate_llm_output, merge_declared
from biv.actual_track.llm_instruction import validate_instruction_llm_output
from biv.root_cause import validate_classifier_output, apply_rule_engine
from biv.malicious_detect import validate_judge_output, final_verdict


def main():
    if len(sys.argv) < 2:
        print("Usage: biv_audit.py <skill-directory> [--output <json-path>]", file=sys.stderr)
        sys.exit(1)

    skill_dir = sys.argv[1]
    output_path = None
    if len(sys.argv) >= 4 and sys.argv[2] == "--output":
        output_path = sys.argv[3]

    # Run deterministic pipeline
    result = run_deterministic_pipeline(skill_dir)
    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        print(f"Deterministic results written to {output_path}")
    else:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        try:
            sys.stdout.buffer.write(output.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
        except Exception:
            print(output)


if __name__ == "__main__":
    main()
