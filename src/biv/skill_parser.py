"""
Stable single-skill directory parser, shared by all audit entry points.

Parses one skill directory into structured fields so the deterministic pipeline
(orchestrator) and the Workflow scripts (single-case biv_workflow.js, batch
batch_workflow.js) all agree on the same parsing result:

    {skill_dir, name, frontmatter, body, content_full,
     scripts, non_executable, structure}

- frontmatter / body / name: from SKILL.md (robust YAML frontmatter split)
- scripts: executable script files ending in .py/.ts/.js/.sh, found anywhere
  under the skill directory (recursive walk, noise dirs excluded)
- non_executable: every other file (SKILL.md itself is not listed)

CLI:
    python -m src.biv.skill_parser <skill-dir>
    python scripts/skill_parse.py <skill-dir>   # thin wrapper (workflow entry)
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Script suffixes treated as "executable scripts" (case-insensitive).
SCRIPT_SUFFIXES = {".py", ".ts", ".js", ".sh"}

# Directory names never walked for files (VCS, caches, vendored deps).
IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    "__pycache__", "node_modules", ".venv", "venv", "env", ".tox",
}


def split_frontmatter(content: str) -> Tuple[Optional[Dict], str]:
    """Split SKILL.md raw content into (frontmatter, body).

    The opening marker is ``---`` at the very start of the file; the closing
    marker is the next line that is exactly ``---`` (whitespace tolerated).
    Matching whole lines avoids truncating the body on horizontal rules that
    appear mid-body. Returns (None, content) when there is no valid block.
    """
    if not content.startswith("---"):
        return None, content.strip()

    lines = content.split("\n")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            fm_text = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1:]).strip()
            try:
                import yaml

                fm = yaml.safe_load(fm_text)
                return (fm if isinstance(fm, dict) else None), body
            except Exception:
                return _parse_frontmatter_fallback(fm_text), body
    return None, content.strip()


def _parse_frontmatter_fallback(text: str) -> Dict:
    """Minimal ``key: value`` frontmatter parser when yaml is unavailable/invalid."""
    import re

    fm: Dict = {}
    for line in text.split("\n"):
        m = re.match(r"^(\w[\w-]*)\s*:\s*(.*)", line)
        if m:
            key, value = m.groups()
            fm[key] = value.strip().strip('"').strip("'")
    return fm


def walk_skill_files(root: Path) -> Tuple[List[str], List[str]]:
    """Recursively collect (scripts, non_executable) as POSIX relative paths.

    ``scripts`` = files ending in SCRIPT_SUFFIXES (case-insensitive);
    ``non_executable`` = every other file. SKILL.md is excluded (it is handled
    separately by parse_skill_dir). Directories in IGNORED_DIRS are pruned.
    """
    root = Path(root)
    scripts: List[str] = []
    others: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for fname in sorted(filenames):
            if fname == "SKILL.md":
                continue
            full = Path(dirpath) / fname
            rel = full.relative_to(root).as_posix()
            if full.suffix.lower() in SCRIPT_SUFFIXES:
                scripts.append(rel)
            else:
                others.append(rel)
    return scripts, others


def parse_skill_dir(skill_dir: Path) -> Dict:
    """Parse a skill directory into the structured fields (see module docstring)."""
    skill_dir = Path(skill_dir)
    resolved = str(skill_dir.resolve())
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return {"error": f"No SKILL.md found in {skill_dir}", "skill_dir": resolved}

    try:
        content = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"error": f"Cannot read SKILL.md: {e}", "skill_dir": resolved}

    frontmatter, body = split_frontmatter(content)
    name = (frontmatter or {}).get("name") or skill_dir.name

    scripts, non_exec = walk_skill_files(skill_dir)
    refs_dir = skill_dir / "references"

    return {
        "skill_dir": resolved,
        "name": str(name),
        "frontmatter": frontmatter,
        "body": body,
        "content_full": content,
        "scripts": scripts,
        "non_executable": non_exec,
        "structure": {
            "has_skill_md": True,
            "has_scripts": bool(scripts),
            "has_references": refs_dir.is_dir(),
            "reference_files": (
                sorted(f.name for f in refs_dir.iterdir() if f.is_file() and f.suffix == ".md")
                if refs_dir.is_dir()
                else []
            ),
        },
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m src.biv.skill_parser <skill-dir>", file=sys.stderr)
        sys.exit(1)
    result = parse_skill_dir(Path(sys.argv[1]))
    out = json.dumps(result, ensure_ascii=False, indent=2)
    try:
        sys.stdout.buffer.write(out.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(out)


if __name__ == "__main__":
    main()
