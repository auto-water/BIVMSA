#!/usr/bin/env python3
"""
Batch BIV audit with LLM — OpenAI-compatible business endpoint.

Replaces batch_workflow.js for environments without Claude Code.
Scans experiment/cases/ and runs the full pipeline (deterministic + LLM)
against each skill using the business LLM endpoint.

Usage:
    python scripts/batch_llm.py [--output batch-llm-result.json] [--verbose]
    python scripts/batch_llm.py --single <skill-dir>   # single skill
"""

import json
import logging
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from biv.llm_config import load_llm_config, config_missing_reason
from biv.llm_client import LLMClient, LLMConfigError
from biv.pipeline_llm import run_full_audit


def discover_cases(cases_dir: Path) -> list[Path]:
    if not cases_dir.is_dir():
        return []
    return sorted(
        e for e in cases_dir.iterdir()
        if e.is_dir() and (e / "SKILL.md").exists()
    )


def _emit(output: str) -> None:
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
    verbose = "--verbose" in args or "-v" in args
    output_path = None
    single_dir = None

    i = 0
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif args[i] == "--single" and i + 1 < len(args):
            single_dir = args[i + 1]
            i += 2
        else:
            i += 1

    # Validate config early
    cfg = load_llm_config()
    reason = config_missing_reason(cfg)
    if reason:
        _emit(json.dumps({"error": reason}, ensure_ascii=False, indent=2))
        sys.exit(1)

    client = LLMClient(cfg)

    # Single-skill mode
    if single_dir:
        r = run_full_audit(single_dir, client=client, verbose=verbose)
        _emit(json.dumps(r, ensure_ascii=False, indent=2))
        if output_path:
            Path(output_path).write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        return

    # Batch mode
    cases_dir = Path(__file__).resolve().parent.parent / "experiment" / "cases"
    cases = discover_cases(cases_dir)
    if not cases:
        _emit(json.dumps({"error": f"No cases found in {cases_dir}"}, ensure_ascii=False))
        sys.exit(1)

    if verbose:
        print(f"Scanning: {cases_dir} | model: {cfg.model}")
        print()

    results = []
    t0_total = time.time()
    for case_path in cases:
        case_name = case_path.name
        if verbose:
            print(f"--- {case_name} ---", flush=True)
        r = run_full_audit(str(case_path), client=client, verbose=verbose)
        r["case"] = case_name

        # expected label
        exp = case_path / ".expected"
        expected = exp.read_text().strip().lower() if exp.exists() else "unknown"
        r["expected"] = expected
        r["match"] = (r.get("verdict") == expected) if expected != "unknown" else None

        if verbose:
            m = "OK" if r.get("match") else ("MISMATCH" if r.get("match") is False else "?")
            print(f"  [{m}] {case_name}: {r.get('verdict')} ({r.get('confidence')}) "
                  f"src={r.get('verdict_source')} | expected={expected}")
            print()
        results.append(r)

    total_ms = (time.time() - t0_total) * 1000
    valid = [r for r in results if "error" not in r]
    errors = [r for r in results if "error" in r]
    malware = sum(1 for r in valid if r["verdict"] == "malware")
    benign = sum(1 for r in valid if r["verdict"] == "benign")
    matched = sum(1 for r in valid if r.get("match") is True)
    mismatched = sum(1 for r in valid if r.get("match") is False)

    batch = {
        "summary": {
            "model": cfg.model,
            "total_cases": len(cases),
            "audited": len(valid),
            "errors": len(errors),
            "malware": malware,
            "benign": benign,
            "expected_matched": matched,
            "expected_mismatched": mismatched,
        },
        "total_duration_ms": round(total_ms, 1),
        "results": results,
    }

    if verbose:
        print()
        print("==== BATCH LLM AUDIT COMPLETE ====")
        print(f"Model: {cfg.model} | Total: {len(cases)} | Audited: {len(valid)} | Errors: {len(errors)}")
        print(f"Malware: {malware} | Benign: {benign}")
        print(f"Label match: {matched}/{matched + mismatched}")
        for r in results:
            if "error" in r:
                print(f"  ERR {r.get('case')}: {r['error'][:80]}")
                continue
            m = "OK" if r.get("match") else ("MISMATCH" if r.get("match") is False else "?")
            print(f"  [{m}] {r['case']}: {r['verdict']} conf={r['confidence']} src={r['verdict_source']}")

    _emit(json.dumps(batch, ensure_ascii=False, indent=2))
    if output_path:
        Path(output_path).write_text(json.dumps(batch, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
