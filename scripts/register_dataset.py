#!/usr/bin/env python3
"""
Register a dataset into experiment/benchmark.yaml automatically.

Scans <dataset> under experiment/cases/, derives each case's expected label
from its path segment (benign/malware — same rule as batch_audit/benchmark),
and merges NEW entries into the benchmark manifest. Idempotent: running twice
does not duplicate entries; already-registered cases are left untouched unless
--overwrite reconciles a changed derived label.

Cases whose path has no benign/malware segment (flat dump) cannot be auto-
registered — they are skipped and reported for manual expected in the yaml.

Usage:
    python scripts/register_dataset.py --dataset my-newset [--dry-run] [--overwrite]
    npm run register:dataset -- --dataset my-newset

Note: rewriting the yaml drops its leading comments (pyyaml cannot preserve them).
"""

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CASES_ROOT = REPO / "experiment" / "cases"
DEFAULT_MANIFEST = REPO / "experiment" / "benchmark.yaml"
VALID = ("benign", "malware")


def _emit(text: str = "") -> None:
    """Windows console-safe UTF-8 output."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(text)


def derive_class(rel: Path) -> str:
    """Ground-truth label from the relative path (benign/malware segment)."""
    for seg in reversed(rel.parts):
        if seg in VALID:
            return seg
    return "unknown"


def load_manifest(path: Path) -> dict:
    if not path.is_file():
        return {"cases": []}
    import yaml
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("cases", [])
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True,
                        help="Path relative to experiment/cases/ (e.g. my-newset), or absolute inside it")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--overwrite", action="store_true",
                        help="Update 'expected' of already-registered cases when the derived label changed")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would change without writing the yaml")
    args = parser.parse_args()

    # Resolve dataset path — must live under CASES_ROOT so the relative name
    # matches what batch_audit writes into experiment/results/.
    root = CASES_ROOT.resolve()
    raw = Path(args.dataset)
    cand = (raw if raw.is_absolute() else CASES_ROOT / raw).resolve()
    try:
        rel = cand.relative_to(root)
    except ValueError:
        _emit(f"ERROR: dataset must be inside experiment/cases (got {cand})")
        sys.exit(1)
    if not cand.is_dir():
        _emit(f"ERROR: no such dataset directory: {cand}")
        sys.exit(1)

    # Scan cases under the dataset
    scanned = []
    for skill_md in sorted(cand.rglob("SKILL.md")):
        case_rel = skill_md.parent.relative_to(root)
        scanned.append((case_rel.as_posix(), derive_class(case_rel)))

    if not scanned:
        _emit(f"No SKILL.md cases found under {rel.as_posix()}")
        sys.exit(1)

    manifest = load_manifest(Path(args.manifest))
    by_name = {}
    order = []
    for entry in manifest.get("cases", []):
        nm = str(entry.get("name", "")).replace("\\", "/").strip("/")
        if nm:
            by_name[nm] = entry
            order.append(nm)

    added, updated, unchanged, skipped = [], [], [], []
    for rel_str, expected in scanned:
        if expected not in VALID:
            skipped.append(rel_str)
            continue
        if rel_str in by_name:
            cur = by_name[rel_str].get("expected")
            if cur != expected:
                if args.overwrite:
                    by_name[rel_str]["expected"] = expected
                    updated.append((rel_str, cur, expected))
                else:
                    unchanged.append((rel_str, cur, expected))
            else:
                unchanged.append((rel_str, expected, expected))
        else:
            by_name[rel_str] = {"name": rel_str, "expected": expected}
            added.append(rel_str)

    # Rebuild: existing entries keep original order, new ones appended (sorted)
    new_cases = [by_name[nm] for nm in order]
    for nm in sorted(added):
        new_cases.append(by_name[nm])
    manifest["cases"] = new_cases

    # Report
    _emit(f"Dataset: {rel.as_posix()}  ({len(scanned)} skills)")
    _emit(f"  added:      {len(added)}")
    for nm in sorted(added):
        _emit(f"    + {nm} -> {by_name[nm]['expected']}")
    _emit(f"  updated:    {len(updated)}")
    for nm, cur, exp in updated:
        _emit(f"    ~ {nm}: {cur} -> {exp}")
    _emit(f"  unchanged:  {len(unchanged)}")
    _emit(f"  skipped (no path label, needs manual expected): {len(skipped)}")
    for nm in skipped:
        _emit(f"    ? {nm}")

    if args.dry_run:
        _emit("Dry run — no file written.")
        sys.exit(0)

    import yaml
    with open(args.manifest, "w", encoding="utf-8") as f:
        yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    _emit(f"Wrote {args.manifest}")


if __name__ == "__main__":
    main()
