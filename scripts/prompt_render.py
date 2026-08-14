#!/usr/bin/env python3
"""
Render BIV prompt templates from the single authority src/biv/prompts.py.

CLI thin wrapper (same pattern as skill_parse.py) shared by the Workflow
scripts (via subagent) and by the Python pipeline.

Usage:
    python scripts/prompt_render.py <name> [--vars-json '{...}'] [--variant single|batch]
    python scripts/prompt_render.py --multi d_llm_extract,a_llm_instr --vars-json '{...}' --variant single

Names: taxonomy_ref | d_llm_extract | a_llm_instr | classifier | judge
Emits the rendered prompt text (or a JSON map for --multi) to stdout, UTF-8 safe.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.prompts import main  # noqa: E402

if __name__ == "__main__":
    main()
