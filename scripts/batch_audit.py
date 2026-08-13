#!/usr/bin/env python3
"""
Batch audit runner — scans experiment/cases/ and runs BIV against all skills.

Usage:
    python scripts/batch_audit.py [--output batch-result.json] [--verbose]
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from biv.orchestrator import run_deterministic_pipeline


def discover_cases(cases_dir: Path) -> list[Path]:
    """Find all case directories (containing SKILL.md).

    Recursively finds SKILL.md at any depth, supporting both layouts:
    - Flat:   <cases>/<skill>/SKILL.md
    - Nested: <cases>/std-cases-4/benign/<skill>/SKILL.md  (std-cases-4)

    The class (benign/malware) is derived from the path segment — see
    _derive_class(); never from a .expected file (label leakage).
    """
    cases = []
    if not cases_dir.is_dir():
        return cases
    for skill_md in sorted(cases_dir.rglob("SKILL.md")):
        cases.append(skill_md.parent)
    return cases


def _derive_class(case_path: Path) -> str:
    """Derive ground-truth class from the path (benign/malware segment)."""
    parts = case_path.parts
    for seg in reversed(parts):
        if seg in ("benign", "malware"):
            return seg
    return "unknown"


def run_batch(
    cases_dir: str,
    verbose: bool = False,
    trace_dir: str | None = None,
    results_dir: str | None = None,
) -> dict:
    """Run BIV audit against all cases and return aggregated results.

    Trace separation: if trace_dir is given, each case's trace is written to
    <trace_dir>/<case>_trace.json; the aggregated results never embed trace.

    Results separation: if results_dir is given, each case's FULL pipeline
    result is written to <results_dir>/<rel>/result.json, mirroring the cases
    directory structure (e.g. results/std-cases-4/benign/<skill>/result.json).
    Error cases are written too, so no case is silently dropped.

    Trace separation: unless trace_dir is explicitly given, each case's trace
    is also written to its own mirrored directory
    (<results_dir>/<rel>/<skill>_trace.json), so result and trace never mix in
    the same file. result.json._meta.trace_file points to it.
    """
    cases = discover_cases(Path(cases_dir))

    if not cases:
        return {"error": f"No cases found in {cases_dir}"}

    results = []
    start_time = time.time()

    for case_path in cases:
        case_name = case_path.name
        t0 = time.time()

        # Trace separation: by default each case's trace goes into its own
        # mirrored result directory (<results_dir>/<rel>/), alongside result.json.
        # An explicitly passed --trace-dir overrides this and uses one directory.
        case_trace_dir = trace_dir
        if trace_dir is None and results_dir:
            rel = case_path.relative_to(Path(cases_dir))
            case_trace_dir = str(Path(results_dir) / rel)

        try:
            r = run_deterministic_pipeline(str(case_path), trace_dir=case_trace_dir)
        except Exception as e:
            # Error case: still record it and write a split result file.
            r = {"error": str(e)}

        p1 = r.get("phase1", {})
        p2 = r.get("phase2", {})
        p3 = r.get("phase3_deterministic", {})
        det = r.get("_det_verdict", {})

        # Ground truth comes from the path (std-cases-4: benign/ malware/).
        # Never read a .expected file — it leaks the label into the audit context.
        cls_name = _derive_class(case_path)
        expected = "unknown" if cls_name == "unknown" else cls_name

        result = {
            "case": case_name,
            "class": cls_name,
            "skill_name": p1.get("skill_name", "unknown"),
            "duration_ms": round((time.time() - t0) * 1000, 1),
            "verdict": det.get("verdict", "error"),
            "confidence": det.get("confidence", 0),
            "source": det.get("source", "error"),
            "expected": expected,
            "match": det.get("verdict") == expected if expected != "unknown" else None,
            "capabilities": {
                "D_det": len(p1.get("D_deterministic", [])),
                "A_ast": len(p1.get("A_ast", [])),
                "A_regex": len(p1.get("A_regex", [])),
                "U_count": len(p2.get("undeclared", [])),
                "O_count": len(p2.get("overdeclared", [])),
                "flows": len(p1.get("flows_ast", [])),
            },
            "compound_flags": {k: v for k, v in p2.get("compound_flags", {}).items() if v},
            "rule_engine": {
                "matched": p3.get("rule_engine", {}).get("matched", False),
                "rule_id": p3.get("rule_engine", {}).get("rule_id"),
                "intent_leaf": p3.get("rule_engine", {}).get("intent_leaf"),
                "kill_chain": p3.get("rule_engine", {}).get("kill_chain"),
            },
            "relaxed_veto": {
                "fired": p3.get("relaxed_veto", {}).get("fired", False),
            },
            "findings": r.get("finding_counts", {}),
            "error": r.get("error"),
        }

        if verbose:
            print(f"  {case_name:50s} {result['verdict']:8s} {result['duration_ms']:6.0f}ms")

        results.append(result)

        # --- Results separation: mirror the cases directory structure ---
        # rel keeps the full sub-path under cases/, e.g. std-cases-4/benign/<skill>.
        if results_dir:
            rel = case_path.relative_to(Path(cases_dir))
            out_path = Path(results_dir) / rel / "result.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            if verbose:
                print(f"  [write] {out_path}")

    total_ms = (time.time() - start_time) * 1000

    # Aggregate
    total = len(results)
    errors = sum(1 for r in results if r.get("error"))
    malware = sum(1 for r in results if r.get("verdict") == "malware")
    benign = sum(1 for r in results if r.get("verdict") == "benign")
    matched = sum(1 for r in results if r.get("match") is True)
    mismatched = sum(1 for r in results if r.get("match") is False)
    veto_count = sum(1 for r in results if r.get("relaxed_veto", {}).get("fired"))
    rule_count = sum(1 for r in results if r.get("rule_engine", {}).get("matched"))

    return {
        "summary": {
            "total_cases": total,
            "errors": errors,
            "malware": malware,
            "benign": benign,
            "expected_matched": matched,
            "expected_mismatched": mismatched,
            "veto_triggered": veto_count,
            "rule_engine_hits": rule_count,
        },
        "total_duration_ms": round(total_ms, 1),
        "results": results,
    }


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    output_path = None
    trace_dir = None
    results_dir = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--output" and i < len(sys.argv) - 1:
            output_path = sys.argv[i + 1]
        if arg == "--trace-dir" and i < len(sys.argv) - 1:
            trace_dir = sys.argv[i + 1]
        if arg == "--results-dir" and i < len(sys.argv) - 1:
            results_dir = sys.argv[i + 1]

    cases_dir = Path(__file__).resolve().parent.parent / "experiment" / "cases"

    # Results separation: default to experiment/results (mirrors cases structure)
    if results_dir is None:
        results_dir = str(Path(__file__).resolve().parent.parent / "experiment" / "results")

    if verbose:
        print(f"Scanning: {cases_dir}")
        print(f"Split results → {results_dir}")
        print()

    batch_result = run_batch(str(cases_dir), verbose=verbose, trace_dir=trace_dir, results_dir=results_dir)

    if verbose:
        print()
        s = batch_result["summary"]
        print(f"Total: {s['total_cases']} cases | {batch_result['total_duration_ms']:.0f}ms")
        print(f"Verdicts: {s['malware']} malware, {s['benign']} benign, {s['errors']} errors")
        if s['expected_matched'] + s['expected_mismatched'] > 0:
            print(f"Label match: {s['expected_matched']}/{s['expected_matched'] + s['expected_mismatched']}")
        print(f"Veto fired: {s['veto_triggered']} | Rule hits: {s['rule_engine_hits']}")

    output = json.dumps(batch_result, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        print(f"Results written to {output_path}")
    else:
        try:
            sys.stdout.buffer.write(output.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
        except Exception:
            print(output)


if __name__ == "__main__":
    main()
