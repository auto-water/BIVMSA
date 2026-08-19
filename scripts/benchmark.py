#!/usr/bin/env python3
"""
Benchmark scoring for BIV audit results.

Reads already-produced audit results and scores them against the ground-truth
label (benign/malware). It does NOT re-run the audit — run batch_audit.py (or
the workflow) first, then score.

Usage:
    python scripts/benchmark.py
    python scripts/benchmark.py --cases-dir <dir> --results-dir <dir> [--manifest <yaml>]

Ground truth:
  - default: derived from the path segment (benign/ malware/), same as batch_audit
  - benchmark.yaml can override/attach when the path has no label segment

Two verdict tracks (both reported, compared):
  - Det-only: verdict from result._det_verdict.verdict   (batch_audit, or workflow's det)
  - LLM:      verdict from result.verdict                 (workflow LLM judge), when present

Metrics (malware is the POSITIVE class):
    Accuracy, Precision, Recall, F1, FPR (误报率), FNR (漏报率)
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CASES = REPO / "experiment" / "cases"
DEFAULT_RESULTS = REPO / "experiment" / "results"
DEFAULT_MANIFEST = REPO / "experiment" / "benchmark.yaml"

VALID = ("benign", "malware")


def _emit(text: str = "") -> None:
    """Windows console-safe UTF-8 output."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(text)


def derive_class(case_path: Path) -> str:
    """Ground-truth label from the path (benign/malware segment)."""
    for seg in reversed(case_path.parts):
        if seg in VALID:
            return seg
    return "unknown"


def load_manifest(path: Path) -> dict:
    """Load benchmark.yaml -> {rel_posix_path: {expected, note}}."""
    if not path.is_file():
        return {}
    try:
        import yaml
    except ImportError:
        _emit(f"WARN: pyyaml not installed; ignoring manifest {path}")
        return {}
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    entries = {}
    for c in data.get("cases", []) or []:
        name = str(c.get("name", "")).replace("\\", "/").strip("/")
        if name:
            entries[name] = c
    return entries


def discover_cases(cases_dir: Path) -> list:
    return sorted(p.parent for p in cases_dir.rglob("SKILL.md"))


def extract_verdicts(data: dict) -> tuple:
    """Return (det_verdict, llm_verdict), tolerating both shapes:
    - batch_audit:  {"_det_verdict": {"verdict": ...}}
    - batch_workflow: {"verdict": <llm>, "det": {"_det_verdict": {"verdict": ...}}}
    """
    llm = data.get("verdict")
    if not isinstance(llm, str) or llm not in VALID:
        llm = None

    det = None
    dv = data.get("_det_verdict")
    if isinstance(dv, dict):
        det = dv.get("verdict")
    if not isinstance(det, str) or det not in VALID:
        det = None
    if not det:
        inner = data.get("det")
        if isinstance(inner, dict):
            dv2 = inner.get("_det_verdict") or {}
            det = dv2.get("verdict") if isinstance(dv2, dict) else None
            if not isinstance(det, str) or det not in VALID:
                det = None
    if not det:
        # biv_workflow shape: {"deterministic_evidence": {"_det_verdict": {"verdict": ...}}}
        de = data.get("deterministic_evidence")
        if isinstance(de, dict):
            dv3 = de.get("_det_verdict") or {}
            det = dv3.get("verdict") if isinstance(dv3, dict) else None
            if not isinstance(det, str) or det not in VALID:
                det = None
    return det, llm


def score(pairs: list) -> dict:
    """pairs: [(verdict, expected), ...] with expected in VALID. malware = positive."""
    tp = fp = tn = fn = 0
    for verdict, expected in pairs:
        if expected not in VALID:
            continue
        if verdict == "malware":
            if expected == "malware":
                tp += 1
            else:
                fp += 1
        elif verdict == "benign":
            if expected == "benign":
                tn += 1
            else:
                fn += 1
        # verdict missing -> counts as a miss against malware (fn), a safe error for benign
        else:
            if expected == "malware":
                fn += 1
            else:
                fp += 1

    n = tp + fp + tn + fn
    denom_prec = tp + fp
    denom_rec = tp + fn
    denom_fpr = fp + tn
    denom_fnr = fn + tp
    prec = tp / denom_prec if denom_prec else 0.0
    rec = tp / denom_rec if denom_rec else 0.0
    return {
        "n": n,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round((tp + tn) / n, 4) if n else 0.0,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(2 * prec * rec / (prec + rec), 4) if (prec + rec) else 0.0,
        "fpr": round(fp / denom_fpr, 4) if denom_fpr else 0.0,
        "fnr": round(fn / denom_fnr, 4) if denom_fnr else 0.0,
    }


def _fmt_metric_table(det: dict, llm: dict) -> list:
    head = f"{'metric':<11} {'det':>10} {'llm':>10}"
    lines = [head, "-" * len(head)]
    for key, label in (
        ("n", "n (scored)"), ("tp", "tp"), ("fp", "fp"), ("tn", "tn"), ("fn", "fn"),
        ("accuracy", "accuracy"), ("precision", "precision"), ("recall", "recall"),
        ("f1", "f1"), ("fpr", "fpr (误报)"), ("fnr", "fnr (漏报)"),
    ):
        lines.append(
            f"{label:<11} {str(det.get(key, '—')):>10} {str(llm.get(key, '—')):>10}"
        )
    return lines


def main() -> None:
    args = sys.argv[1:]

    def _arg(flag: str, default: Path) -> Path:
        for i, a in enumerate(args):
            if a == flag and i + 1 < len(args):
                return Path(args[i + 1])
        return default

    cases_dir = _arg("--cases-dir", DEFAULT_CASES)
    results_dir = _arg("--results-dir", DEFAULT_RESULTS)
    manifest_path = _arg("--manifest", DEFAULT_MANIFEST)

    manifest = load_manifest(manifest_path)
    cases = discover_cases(cases_dir)
    if not cases:
        _emit(f"No cases (SKILL.md) found under {cases_dir}")
        sys.exit(1)

    rows = []
    det_pairs, llm_pairs = [], []
    for case in cases:
        rel = case.relative_to(cases_dir)
        rel_str = rel.as_posix()

        expected = derive_class(case)
        entry = manifest.get(rel_str)
        if expected == "unknown" and entry and entry.get("expected") in VALID:
            expected = entry["expected"]

        det_v = llm_v = None
        result_file = results_dir / rel / "result.json"
        if result_file.is_file():
            try:
                with open(result_file, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    det_v, llm_v = extract_verdicts(data)
            except (OSError, json.JSONDecodeError) as e:
                det_v = llm_v = None

        if det_v:
            det_pairs.append((det_v, expected))
        if llm_v:
            llm_pairs.append((llm_v, expected))

        rows.append(
            {
                "case": rel_str,
                "note": (entry or {}).get("note", ""),
                "expected": expected,
                "det": det_v or "missing",
                "llm": llm_v or "missing",
                "match_det": (det_v == expected) if det_v else None,
                "match_llm": (llm_v == expected) if llm_v else None,
            }
        )

    # ---- per-case table ----
    case_w = min(max(max(len(r["case"]) for r in rows), 20), 88)
    head = f"{'case':<{case_w}} {'exp':<7} {'det':<8} {'llm':<8} note"
    _emit("Per-case (✓ match, ✗ mismatch, - no verdict):")
    _emit(head)
    _emit("-" * min(len(head), 110))
    for r in rows:
        md = "✓" if r["match_det"] else ("✗" if r["match_det"] is False else "-")
        ml = "✓" if r["match_llm"] else ("✗" if r["match_llm"] is False else "-")
        _emit(
            f"{r['case']:<{case_w}} {r['expected']:<7} {r['det']:<6}{md} {r['llm']:<6}{ml} {r['note']}"
        )

    _emit("")
    det_s = score(det_pairs)
    llm_s = score(llm_pairs)
    _emit("Metrics (malware = positive class):")
    for line in _fmt_metric_table(det_s, llm_s):
        _emit(line)

    n_cases = len(rows)
    n_scored_det = det_s["n"]
    n_scored_llm = llm_s["n"]
    _emit("")
    _emit(
        f"Cases: {n_cases} | det-track scored: {n_scored_det} | llm-track scored: {n_scored_llm}"
        + (" | LLM track unavailable (no workflow results)" if n_scored_llm == 0 else "")
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
