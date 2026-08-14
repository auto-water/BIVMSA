#!/usr/bin/env python3
"""
Phase 0 预处理 CLI — 把 SKILL.md 划分成语义块（block）。

Workflow 脚本（batch_workflow.js / biv_workflow.js）通过 subagent 调用它，
在 P1/P2/P3 之前产出结构化块，作为后续所有阶段标注的基本单位。

Usage:
    python scripts/skill_chunk.py <skill-dir>

Emits a single JSON object to stdout:
    {"unit": "sentence", "count": N, "blocks": [{block_id, line_start, line_end, text, sentences}]}
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.chunking import build_phase0  # noqa: E402
from biv.skill_parser import parse_skill_dir  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/skill_chunk.py <skill-dir>", file=sys.stderr)
        sys.exit(1)

    parsed = parse_skill_dir(Path(sys.argv[1]))
    if "error" in parsed:
        print(json.dumps({"error": parsed["error"]}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)

    phase0 = build_phase0(parsed.get("content_full") or "")
    out = json.dumps(phase0, ensure_ascii=False, indent=2)
    try:
        sys.stdout.buffer.write(out.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(out)


if __name__ == "__main__":
    main()
