#!/usr/bin/env python3
"""
Self-contained HTML audit report for BIV results.

Reads experiment/results/**/result.json (batch_audit deterministic output),
reuses the benchmark scoring logic, and renders a single-page HTML report with
inlined CSS/JS — open in any browser, no server needed:
  - overview stats + metric table (det / LLM tracks)
  - per-case expandable details: verdict, capabilities D/A/U/O (risk-colored),
    data flows, rule engine / relaxed-veto, findings
  - client-side search box to filter cases

Usage:
    python scripts/report_html.py [--cases-dir experiment/cases] [--results-dir experiment/results] [--manifest experiment/benchmark.yaml] [--out experiment/results/report.html]
    npm run report
"""

import html
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "src"))
import benchmark as BM  # noqa: E402  (score / derive_class / extract_verdicts / load_manifest)
from biv.taxonomy import CAPABILITY_RISK  # noqa: E402

DEFAULT_CASES = REPO / "experiment" / "cases"
DEFAULT_RESULTS = REPO / "experiment" / "results"
DEFAULT_MANIFEST = REPO / "experiment" / "benchmark.yaml"
DEFAULT_OUT = REPO / "experiment" / "results" / "report.html"

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _emit(text: str = "") -> None:
    try:
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(text)


def _tier(cap: str) -> str:
    r = CAPABILITY_RISK.get(cap)
    return r.value if r else "low"


def collect(cases_dir: Path, results_dir: Path, manifest: dict) -> list:
    """Per-case row: {name, rel, expected, det, llm, match_*, data}."""
    rows = []
    for case in BM.discover_cases(cases_dir):
        rel = case.relative_to(cases_dir)
        rel_str = rel.as_posix()
        expected = BM.derive_class(case)
        entry = manifest.get(rel_str)
        if expected not in BM.VALID and entry and entry.get("expected") in BM.VALID:
            expected = entry["expected"]

        det = llm = None
        data = None
        result_file = results_dir / rel / "result.json"
        if result_file.is_file():
            try:
                data = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = None
            if isinstance(data, dict) and "error" not in data:
                det, llm = BM.extract_verdicts(data)
            else:
                data = None

        p1 = (data or {}).get("phase1", {}) or {}
        rows.append(
            {
                "name": p1.get("skill_name") or rel.name,
                "rel": rel_str,
                "expected": expected,
                "det": det,
                "llm": llm,
                "match_det": (det == expected) if det else None,
                "match_llm": (llm == expected) if llm else None,
                "note": (entry or {}).get("note", ""),
                "data": data,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# HTML building
# ---------------------------------------------------------------------------


def _badge(cls: str, text: str) -> str:
    return f'<span class="badge {cls}">{html.escape(text)}</span>'


def _cap_chips(caps, risk: bool = False) -> str:
    if not caps:
        return '<span class="none">(none)</span>'
    out = []
    for cap in sorted(caps):
        if risk:
            t = _tier(cap)
            out.append(f'<span class="cap {t}">{html.escape(cap)}</span>')
        else:
            out.append(f'<span class="cap">{html.escape(cap)}</span>')
    return "".join(out)


def _flow_items(flows) -> str:
    if not flows:
        return '<span class="none">no data flows</span>'
    items = []
    for f in flows[:10]:
        src = html.escape(f.get("source", ""))
        sloc = html.escape(f.get("source_location", ""))
        snk = html.escape(f.get("sink", ""))
        tloc = html.escape(f.get("sink_location", ""))
        items.append(f"<li>{src} ({sloc}) → {snk} ({tloc})</li>")
    return "<ul class='flows'>" + "".join(items) + "</ul>"


def _case_block(r: dict) -> str:
    data = r["data"]
    if data is None:
        verdict_txt = "missing result"
        return (
            f'<details class="case" data-q="{html.escape(r["name"].lower())}">'
            f"<summary>{_badge('missing', 'MISSING')} {html.escape(r['name'])} "
            f"<span class='exp'>(expected {r['expected']})</span></summary>"
            f"<p>No result.json produced for this case.</p></details>"
        )

    det = data.get("_det_verdict", {}) or {}
    cls = data.get("classification", {}) or {}
    cc = data.get("capability_counts", {}) or {}
    fc = data.get("finding_counts", {}) or {}
    p1 = data.get("phase1", {}) or {}
    p2 = data.get("phase2", {}) or {}
    p3 = data.get("phase3_deterministic", {}) or {}

    verdict = det.get("verdict", "?")
    badge_cls = "malware" if verdict == "malware" else ("benign" if verdict == "benign" else "missing")
    md = ("✓" if r["match_det"] else ("✗" if r["match_det"] is False else "—"))
    ml = ("✓" if r["match_llm"] else ("✗" if r["match_llm"] is False else "—"))
    note = f"<div class='note'>{html.escape(r['note'])}</div>" if r["note"] else ""

    rule = p3.get("rule_engine", {}) or {}
    veto = p3.get("relaxed_veto", {}) or {}
    rule_txt = (f"matched={rule.get('matched')} rule_id={rule.get('rule_id')} "
                f"intent={rule.get('intent_category')}/{rule.get('intent_leaf')} "
                f"kill_chain={rule.get('kill_chain')}") if rule.get("matched") else "none"
    veto_txt = f"fired — {html.escape(veto.get('reason', ''))}" if veto.get("fired") else "not fired"

    findings = p1.get("ast_findings", []) + p1.get("regex_findings", [])
    findings_prev = ""
    if findings:
        items = []
        for f in findings[:5]:
            sev = html.escape(f.get("severity", ""))
            loc = html.escape(f.get("location", ""))
            typ = html.escape(f.get("type", ""))
            items.append(f"<li>[{sev}] {typ} @ {loc}</li>")
        items.append(f"<li>… total {len(findings)}</li>" if len(findings) > 5 else "")
        findings_prev = "<ul>" + "".join(items) + "</ul>"
    else:
        findings_prev = '<span class="none">no findings</span>'

    meta = data.get("_meta", {}) or {}

    return (
        f'<details class="case" data-q="{html.escape(r["name"].lower())}" data-v="{verdict}">'
        f"<summary>{_badge(badge_cls, verdict.upper())} "
        f"<b>{html.escape(r['name'])}</b> "
        f"<span class='exp'>expected {r['expected']} · det {md} · llm {ml}</span></summary>"
        f"{note}"
        f'<div class="kv"><div class="verdict-line">'
        f"confidence={det.get('confidence', 0)} · source={html.escape(det.get('source', ''))} · "
        f"quadrant={html.escape(cls.get('quadrant', ''))} · "
        f"pipeline={html.escape(meta.get('pipeline_version', ''))} · "
        f"trace={html.escape(meta.get('trace_ref', '') or '')}"
        f"</div></div>"
        f'<table class="kv"><tr><td>declared</td><td>{_cap_chips(p1.get("D_deterministic", []))}</td></tr>'
        f'<tr><td>actual</td><td>{_cap_chips(sorted(set(p1.get("A_ast", [])) | set(p1.get("A_regex", []))))}</td></tr>'
        f'<tr><td>undeclared U</td><td>{_cap_chips(p2.get("undeclared", []), risk=True)}</td></tr>'
        f'<tr><td>overdeclared O</td><td>{_cap_chips(p2.get("overdeclared", []))}</td></tr>'
        f'<tr><td>flows</td><td>{_flow_items(p1.get("flows_ast", []))}</td></tr>'
        f'<tr><td>rule engine</td><td>{rule_txt}</td></tr>'
        f'<tr><td>relaxed veto</td><td>{veto_txt}</td></tr>'
        f'<tr><td>findings</td><td>crit={fc.get("critical", 0)} high={fc.get("high", 0)} med={fc.get("medium", 0)}{findings_prev}</td></tr>'
        f"</table>"
        f"</details>"
    )


def render(rows: list) -> str:
    det_pairs = [(r["det"], r["expected"]) for r in rows if r["det"] and r["expected"] in BM.VALID]
    llm_pairs = [(r["llm"], r["expected"]) for r in rows if r["llm"] and r["expected"] in BM.VALID]
    det_s, llm_s = BM.score(det_pairs), BM.score(llm_pairs)

    n = len(rows)
    have_data = sum(1 for r in rows if r["data"])
    mal = sum(1 for r in rows if (r["det"] or r["llm"]) == "malware")
    matched = sum(1 for r in rows if r["match_det"] is True)

    def _metric_rows(s: dict) -> str:
        cells = "".join(
            f"<td>{s.get(k, '—')}</td>"
            for k in ("n", "tp", "fp", "tn", "fn", "accuracy", "precision", "recall", "f1", "fpr", "fnr")
        )
        return cells

    metric_head = (
        "<tr><th></th><th>n</th><th>tp</th><th>fp</th><th>tn</th><th>fn</th>"
        "<th>acc</th><th>prec</th><th>rec</th><th>f1</th><th>fpr</th><th>fnr</th></tr>"
    )

    case_blocks = "\n".join(_case_block(r) for r in rows)

    return f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BIV 审计报告</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 22px; margin-bottom: 6px; }}
  .sub {{ color: #666; font-size: 13px; margin-bottom: 18px; }}
  .grid {{ display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 20px; }}
  .stat {{ border: 1px solid #ddd; border-radius: 8px; padding: 10px 18px; min-width: 96px; text-align: center; }}
  .stat .num {{ font-size: 26px; font-weight: 700; }}
  .stat .lab {{ color: #666; font-size: 12px; }}
  table.metrics {{ border-collapse: collapse; margin: 10px 0 20px; font-size: 13px; }}
  table.metrics th, table.metrics td {{ border: 1px solid #ddd; padding: 5px 12px; text-align: center; }}
  table.metrics th {{ background: #f6f8fa; }}
  .search {{ width: 100%; box-sizing: border-box; padding: 9px 12px; margin: 12px 0; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; }}
  details.case {{ border: 1px solid #ddd; border-radius: 8px; margin: 8px 0; padding: 6px 14px; }}
  details.case summary {{ cursor: pointer; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: 12px; margin-right: 6px; }}
  .badge.malware {{ background: #d62728; }}
  .badge.benign {{ background: #2ca02c; }}
  .badge.missing {{ background: #7f7f7f; }}
  .exp {{ color: #888; font-size: 12px; }}
  .note {{ color: #b3541e; font-size: 12px; margin: 4px 0; }}
  table.kv {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
  table.kv td {{ border-bottom: 1px solid #eee; padding: 5px 8px; vertical-align: top; }}
  table.kv td:first-child {{ width: 120px; color: #666; white-space: nowrap; }}
  .cap {{ display: inline-block; margin: 2px; padding: 1px 8px; border-radius: 10px; font-size: 12px; border: 1px solid #ccc; }}
  .cap.critical {{ background: #ffe9e9; border-color: #d62728; }}
  .cap.high {{ background: #fff3e0; border-color: #ff7f0e; }}
  .cap.medium {{ background: #fffde7; border-color: #e6c200; }}
  .cap.low {{ background: #f1f1f1; }}
  ul.flows {{ margin: 2px 0; padding-left: 18px; font-family: Consolas, "Courier New", monospace; font-size: 12px; }}
  .none {{ color: #aaa; font-size: 12px; }}
</style>
</head>
<body>
<h1>BIV 审计报告</h1>
<div class="sub">确定性管线输出 · 判分指标 malware 为正类 · 每 case 可展开查看详情</div>

<div class="grid">
  <div class="stat"><div class="num">{n}</div><div class="lab">cases</div></div>
  <div class="stat"><div class="num">{have_data}</div><div class="lab">with result</div></div>
  <div class="stat"><div class="num">{mal}</div><div class="lab">malware</div></div>
  <div class="stat"><div class="num">{det_s['n']}</div><div class="lab">det scored</div></div>
  <div class="stat"><div class="num">{llm_s['n']}</div><div class="lab">llm scored</div></div>
  <div class="stat"><div class="num">{matched}</div><div class="lab">det matched</div></div>
</div>

<table class="metrics">
  <tr><th colspan="12">指标（det 轨道）</th></tr>
  {metric_head}
  <tr><th>det</th>{_metric_rows(det_s)}</tr>
  <tr><th>llm</th>{_metric_rows(llm_s)}</tr>
</table>

<input class="search" id="q" placeholder="筛选 case（按名称 / verdict）...">
<div id="cases">
{case_blocks}
</div>

<script>
  var q = document.getElementById('q');
  q.addEventListener('input', function () {{
    var s = q.value.trim().toLowerCase();
    document.querySelectorAll('details.case').forEach(function (d) {{
      var show = !s || d.dataset.q.indexOf(s) !== -1 || d.dataset.v.indexOf(s) !== -1;
      d.style.display = show ? '' : 'none';
    }});
  }});
</script>
</body>
</html>
"""


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
    out = _arg("--out", DEFAULT_OUT)

    manifest = BM.load_manifest(manifest_path)
    rows = collect(cases_dir, results_dir, manifest)
    if not rows:
        _emit(f"No cases under {cases_dir}")
        sys.exit(1)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(rows), encoding="utf-8")
    _emit(f"[report] {out}  ({len(rows)} cases, {out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
