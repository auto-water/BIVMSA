#!/usr/bin/env python3
"""
Stable single-skill directory parser — CLI entry point.

Shared by the Workflow scripts (single-case biv_workflow.js, batch
batch_workflow.js) via subagent calls, and by the deterministic pipeline.
The actual parsing logic lives in src/biv/skill_parser.py so every entry
point reuses the same stable implementation.

Usage:
    python scripts/skill_parse.py <skill-dir>

Emits a single JSON object to stdout:
    {skill_dir, name, frontmatter, body, content_full,
     scripts, non_executable, structure}
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.skill_parser import main

if __name__ == "__main__":
    main()
