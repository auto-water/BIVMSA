#!/usr/bin/env python3
"""
Per-case annotated SKILL.md page generator (FRONTEND ONLY).

Renders one self-contained HTML page per case that displays the normalized
SKILL.md sentences with REAL Phase-3 annotations from a workflow result.json:
  - every sentence classified (action_instruction | non_action); action sentences bold
  - six-class color coding (malicious = warm, benign = cool):
      non-action·malicious / non-action·benign
      action·no-deviation-malicious / action·deviated-malicious
      action·no-deviation-benign     / action·deviated-benign
  - clicking an action sentence opens a modal card with deviation label,
    classification, capabilities, reason, and the capability→code evidence
    (code snippet + line number from phase1.capability_code_evidence)

Annotation data comes from the result.json produced by the LLM workflow
(vdecl.sentence_classifications). When no result.json is given (or it lacks
sentence-level classifications), a --mock demo palette is shown instead so the
colors/behavior remain visible.

Usage:
    python scripts/skill_page.py <skill-dir> [--result <result.json>] [--out-dir <dir>] [--mock]
  --result <result.json>   workflow/merged result (verdict + vdecl.sentence_classifications
                           + phase1.capability_code_evidence). HTML is written to the SAME
                           directory as the result file unless --out-dir is given.
  --mock                   ignore result classifications; cycle the demo palette
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "experiment" / "results" / "pages"

# ---------------------------------------------------------------------------
# Six-class color scheme (warm = malicious, cool = benign)
# ---------------------------------------------------------------------------
CLS = {
    "non-action-malicious":      {"bg": "#ffe5e0", "label": "非动作·恶意"},
    "non-action-benign":         {"bg": "#e6f2ff", "label": "非动作·非恶意"},
    "no-deviation-malicious":    {"bg": "#ffcccc", "label": "动作·无偏差恶意"},
    "deviated-malicious":        {"bg": "#ffd6c2", "label": "动作·有偏差恶意"},
    "no-deviation-benign":       {"bg": "#d9f7d9", "label": "动作·无偏差非恶意"},
    "deviated-benign":           {"bg": "#d6f0f7", "label": "动作·有偏差非恶意"},
}
UNCLS = "#f5f5f5"

DANGER = ["download", "execute", "curl", "socket", "secret", "credential", "shell",
          "exfil", "token", "password", "eval", "exec", "ssh key", "reverse"]
ACTION_VERBS = ["run ", "install ", "execute ", "create ", "send ", "read ", "delete ",
                "use ", "write ", "fetch ", "start ", "open ", "connect ", "copy ",
                "download ", "upload ", "compile ", "build ", "deploy ", "inject "]


def _emit(t: str = "") -> None:
    try:
        sys.stdout.buffer.write(t.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(t)


# ---------------------------------------------------------------------------
# Skill reading + normalization (mock fallback path)
# ---------------------------------------------------------------------------


def read_skill_lines(skill_dir: Path):
    """Return (name, frontmatter_block_lines, body_lines) — blank lines dropped."""
    content = (skill_dir / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    name = skill_dir.name
    if content.startswith("---"):
        end = content.find("\n---", 3)
        if end != -1:
            fm_raw = content[: end + 4]
            body_raw = content[end + 4 :]
            for ln in fm_raw.splitlines():
                if ln.strip().startswith("name:"):
                    name = ln.split(":", 1)[1].strip().strip("'\"") or name
        else:
            fm_raw, body_raw = "", content
    else:
        fm_raw, body_raw = "", content
    fm_lines = [l for l in fm_raw.splitlines() if l.strip()]
    body_lines = [l for l in body_raw.splitlines() if l.strip()]
    return name, fm_lines, body_lines


def _mock_classify(text: str, idx: int):
    """DEMO annotation — cycles the palette so all six colors are visible.
    NOT real classification; --result data replaces this."""
    t = text.lower().strip()
    is_heading = text.lstrip().startswith("#")
    danger = any(w in t for w in DANGER)
    action = (any(t.startswith(v) for v in ACTION_VERBS) or danger) and not is_heading
    if action:
        cls = ["no-deviation-malicious", "deviated-malicious",
               "no-deviation-benign", "deviated-benign"][idx % 4]
        return {"kind": "action_instruction", "cls": cls,
                "flow": {"deviation": "no_deviation" if "no-" in cls else "deviated",
                         "type": "U: cred-read / net-http-out" if "malicious" in cls else "none",
                         "flows": ["net-http-out → net-http-out"] if "malicious" in cls else [],
                         "core": text}}
    cls = "non-action-malicious" if (danger or idx % 5 == 0) else "non-action-benign"
    return {"kind": "non_action", "cls": cls, "flow": None}


# ---------------------------------------------------------------------------
# Real annotation loading (from workflow result.json)
# ---------------------------------------------------------------------------


def classify_cls(kind: str, classification: str, malicious_label: str) -> str:
    """Map a classification row to one of the six CLS palette keys."""
    if kind == "non_action":
        return "non-action-benign" if malicious_label != "malicious" else "non-action-malicious"
    # action_instruction: classification is already one of the four action classes
    if classification in CLS:
        return classification
    return "non-action-benign"


def _row_to_item(row: dict, cce_lookup: dict) -> dict:
    """Convert one classification row into a frontend item {text, kind, cls, flow}."""
    kind = row.get("kind", "non_action")
    classification = row.get("classification", "no-deviation-benign")
    malicious = row.get("malicious_label", "benign")
    caps = row.get("capabilities") or []
    cls = classify_cls(kind, classification, malicious)
    cls_info = CLS.get(cls, {})

    # gather code evidence for the block's capabilities
    code_evidence = []
    seen = set()
    for cap in caps:
        for loc in cce_lookup.get(cap, [])[:3]:
            key = (loc.get("file"), loc.get("line_start"), loc.get("code"))
            if key in seen:
                continue
            seen.add(key)
            code_evidence.append({"capability": cap, **loc})

    flow = {
        "block_id": row.get("block_id"),
        # 核心指令摘要（LLM 输出，见 vdecl prompt）；无则前端 fallback 截断块文本
        "core_instruction": row.get("core_instruction") or "",
        "deviation": row.get("deviation_label", "no_deviation"),
        "classification": classification,
        "cls_bg": cls_info.get("bg", UNCLS),
        "cls_label": cls_info.get("label", classification),
        "capabilities": caps,
        "reason": row.get("reason", ""),
        "code_evidence": code_evidence,
    }
    return {
        "text": row.get("text") or row.get("sentence") or "",
        "kind": kind,
        "cls": cls,
        "flow": flow,
    }


def load_real_annotations(result_file: Path) -> dict:
    """Load real block-level annotations from a workflow result.json.

    Renders by Phase-0 blocks (phase0.blocks) joined with vdecl.block_classifications
    by block_id. Falls back to flat classifications (old results without phase0).

    Returns {sentences:[{text,kind,cls,flow}], verdict, quadrant, unconditional, mode}.
    """
    d = json.loads(result_file.read_text(encoding="utf-8"))
    verdict = d.get("verdict", "unknown")
    quad = (d.get("classification", {}) or {}).get("quadrant", "—")

    vdecl = d.get("vdecl", {}) or {}
    # 新: block_classifications；旧: sentence_classifications（兼容历史 result）
    classifications = vdecl.get("block_classifications") or vdecl.get("sentence_classifications") or []
    unconditional = vdecl.get("unconditional_harmful") or []

    p1 = d.get("phase1", {}) or {}
    cce = p1.get("capability_code_evidence", {}) or {}
    cce_lookup = {}
    for cap, entry in cce.items():
        for loc in (entry.get("locations") or []):
            cce_lookup.setdefault(cap, []).append(loc)

    # Skill 描述能力空间：
    #   D = skill 描述包含的所有敏感操作（D_llm 语义 ∪ D_deterministic）
    #   A = skill 真实执行的所有敏感操作（A_ast ∪ A_regex ∪ A_llm 完整能力）
    d_caps = sorted(set((d.get("d_llm_caps") or []) + (p1.get("D_deterministic") or [])))
    a_caps = sorted(set((p1.get("A_ast") or []) + (p1.get("A_regex") or []) + (d.get("a_llm_instr_caps") or [])))
    intended = d.get("intended_workflow") or ""

    # Phase 4: 恶意调用链（每个恶意块 → 构造的用户输入 + 外部关联代码），可选
    attack_chains = d.get("attack_chains") or []
    attack_by_id = {
        ac.get("block_id"): ac
        for ac in attack_chains
        if ac and ac.get("block_id") is not None
    }

    blocks = (d.get("phase0", {}) or {}).get("blocks") or []

    sentences = []
    if blocks:
        # 以块为单位：标注按 block_id 关联；未标注块灰底展示
        ann_by_id = {}
        for row in classifications:
            bid = row.get("block_id")
            if bid is not None:
                ann_by_id[bid] = row
        for b in sorted(blocks, key=lambda x: x.get("block_id", 0)):
            bid = b.get("block_id")
            row = ann_by_id.get(bid)
            if row is None:
                sentences.append({
                    "text": b.get("text", ""),
                    "kind": "non_action",
                    "cls": "unclassified",
                    "flow": {"block_id": bid, "block_kind": b.get("kind", ""),
                             "trigger_condition": b.get("trigger_condition", ""),
                             "deviation": "no_deviation", "classification": "",
                             "capabilities": [], "reason": "未标注", "code_evidence": []},
                })
            else:
                item = _row_to_item(row, cce_lookup)
                if item["flow"]["block_id"] is None:
                    item["flow"]["block_id"] = bid
                item["flow"]["block_kind"] = b.get("kind", "")
                item["flow"]["trigger_condition"] = b.get("trigger_condition", "")
                item["flow"]["attack_chain"] = attack_by_id.get(bid)
                sentences.append(item)
        mode = "真实标注（按块）" if classifications else "待分类（无块级标注）"
    else:
        # 旧结果兼容：从 classifications 平铺
        for row in sorted(classifications, key=lambda x: x.get("block_id", x.get("line", 0))):
            sentences.append(_row_to_item(row, cce_lookup))
        mode = "真实标注" if classifications else "待分类（无句子级标注）"

    return {
        "sentences": sentences,
        "verdict": verdict,
        "quadrant": quad,
        "unconditional": unconditional,
        "mode": mode,
        "d_caps": d_caps,
        "a_caps": a_caps,
        "intended": intended,
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def _build_page(name: str, items: list, verdict: str, quadrant: str,
                mode: str, d_caps: list, a_caps: list, intended: str,
                skill_dir: str = "") -> str:
    # items: [{text, kind, cls, flow}]
    # Skill 描述能力空间：D/A 标签 + intended workflow
    _tags = lambda caps, extra: ("".join(
        f'<span class="cap-tag {extra}">{html_escape(c)}</span>' for c in caps)
        ) if caps else '<span class="muted">(none)</span>'
    d_tags = _tags(d_caps, "cap-D")
    a_tags = _tags(a_caps, "cap-A")
    intended_html = (html_escape(intended) if intended
                     else '<span class="muted">(无)</span>')
    capspace = (
        '<div class="capspace">'
        '<div class="capspace-title">Skill 描述能力空间</div>'
        f'<div class="caps-row"><span class="caps-label caps-D">D 声明能力</span><span class="caps-tags">{d_tags}</span></div>'
        f'<div class="caps-row"><span class="caps-label caps-A">A 实际能力</span><span class="caps-tags">{a_tags}</span></div>'
        f'<div class="caps-row"><span class="caps-label caps-I">Skill 意图</span><span class="caps-intended">{intended_html}</span></div>'
        '</div>'
    )

    def _rel_path(f):
        """flow-item 文件路径相对化到 skill 根目录（如 scripts/generateContent.js）。"""
        if not f:
            return '?'
        try:
            rel = Path(str(f)).resolve().relative_to(Path(skill_dir).resolve())
            return str(rel).replace("\\", "/")
        except (ValueError, OSError):
            return Path(str(f)).name

    def _chain_html(it):
        """恶意调用链 DAG 图：User → 触发输入 → 恶意块 → flow-items。

        借鉴 Cytoscape.js + Dagre 视觉：分层布局、节点卡片、贝塞尔曲线箭头。
        手写原生 JS/CSS（renderGraph），自包含单文件 HTML。
        """
        flow = it.get("flow") or {}
        ac = flow.get("attack_chain") or {}
        user_input = ac.get("user_input") or "（待 Phase 4 构造触发输入）"
        flow_items = ac.get("flow_items") or flow.get("code_evidence") or []
        bid = flow.get("block_id") or "?"
        trig = flow.get("trigger_condition") or ""

        nodes = [
            {"id": "n0", "type": "user", "title": "User", "text": ""},
            {"id": "n1", "type": "input", "title": "触发输入", "text": user_input},
            {"id": "n2", "type": "block", "title": f"恶意块 #{bid}", "text": trig},
        ]
        edges = [["n0", "n1"], ["n1", "n2"]]
        for i, fi in enumerate(flow_items):
            nid = f"n{3 + i}"
            nodes.append({
                "id": nid,
                "type": "code",
                "title": fi.get("capability") or "",
                "text": f'{_rel_path(fi.get("file"))}:{fi.get("line_start", "?")}',
                "code": str(fi.get("code") or ""),
            })
            edges.append(["n2", nid])

        gid = f"ag-{bid}"
        return (
            f'<div class="attack-graph" id="{gid}"><svg class="ag-edges"></svg></div>'
            f'<script>renderGraph("{gid}", {json.dumps(nodes, ensure_ascii=False)}, '
            f'{json.dumps(edges, ensure_ascii=False)})</' + 'script>'
        )

    rows_html = []
    for i, it in enumerate(items):
        kind = it["kind"]
        # 触发条件分组标题（非 frontmatter 块，且块携带 trigger_condition）
        trig = (it.get("flow") or {}).get("trigger_condition") or ""
        bkind = (it.get("flow") or {}).get("block_kind") or ""
        if trig and bkind != "frontmatter":
            bid = (it.get("flow") or {}).get("block_id")
            rows_html.append(
                f'<div class="trigger-head"><span class="th-icon">⚡</span>'
                f'{html_escape(trig)} <span class="th-id">block {bid}</span></div>'
            )
        if kind == "frontmatter":
            cls_style = UNCLS
            extra = "frontmatter-row"
        else:
            cls_style = CLS.get(it["cls"], {}).get("bg", UNCLS)
            extra = f"line {it['cls']}"
            if kind == "action_instruction":
                extra += " action-click"
        bold = ' font-weight:700;' if kind == "action_instruction" else ""
        rows_html.append(
            f'<div class="{extra}" data-idx="{i}" '
            f'style="background:{cls_style};{bold}">{html_escape(it["text"])}</div>'
        )
        # 恶意块下方渲染恶意调用链（Phase 4 数据；无则 flow_items 从 code_evidence fallback）
        if "malicious" in it["cls"]:
            rows_html.append(_chain_html(it))

    legend = "".join(
        f'<span class="lg" style="background:{v["bg"]}">{v["label"]}</span>'
        for v in CLS.values()
    )

    return f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_escape(name)} — BIV 审计页面</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0; color: #222; }}
  header {{ padding: 16px 24px; border-bottom: 1px solid #ddd; background: #fafafa; }}
  h1 {{ font-size: 20px; margin: 0 0 8px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 8px; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
  .lg {{ padding: 2px 10px; border-radius: 10px; font-size: 12px; border: 1px solid rgba(0,0,0,.12); }}
  #skill {{ margin: 0; padding: 20px 24px; }}
  .line {{ padding: 4px 10px; margin: 1px 0; border-radius: 4px; white-space: pre-wrap;
           font-family: Consolas, "Courier New", monospace; font-size: 14px; line-height: 1.5; }}
  .frontmatter-row {{ color: #999; font-size: 12px; }}
  .trigger-head {{ margin: 14px 10px 2px 10px; padding: 3px 10px; border-left: 4px solid #8a8a8a; background: #f2f2f2; border-radius: 3px; font-size: 12px; color: #555; font-weight: 600; }}
  .trigger-head .th-icon {{ margin-right: 4px; }}
  .trigger-head .th-id {{ color: #aaa; font-weight: 400; font-size: 11px; margin-left: 6px; }}
  .action-click {{ cursor: pointer; border: 1px dashed transparent; }}
  .action-click:hover {{ outline: 2px solid #888; border-radius: 4px; }}
  .action-click::after {{ content: " ▶"; font-size: 10px; color: #888; }}
  /* modal */
  #modal {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45); align-items: center; justify-content: center; z-index: 50; }}
  #modal.show {{ display: flex; }}
  .card {{ background: #fff; border-radius: 10px; max-width: 620px; width: 90%; padding: 20px 24px; box-shadow: 0 8px 30px rgba(0,0,0,.25); max-height: 85vh; overflow-y: auto; }}
  .card h2 {{ font-size: 16px; margin: 0 0 12px; }}
  .card .field {{ margin: 8px 0; }}
  .card .k {{ display: inline-block; width: 90px; color: #666; font-size: 13px; vertical-align: top; }}
  .card .v {{ font-size: 13px; }}
  .card .flow-item {{ font-family: Consolas, monospace; font-size: 12px; background: #f6f8fa; padding: 6px 8px; border-radius: 4px; margin: 3px 0; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: 12px; margin-right: 6px; }}
  .badge.malware {{ background: #d62728; }} .badge.benign {{ background: #2ca02c; }}
  .badge.deviated {{ background: #ff7f0e; }} .badge.no_deviation {{ background: #2ca02c; }}
  .cap-tag {{ display: inline-block; background: #eee; border-radius: 10px; padding: 1px 8px; font-size: 12px; margin: 2px 2px 0 0; }}
  .muted {{ color: #aaa; font-size: 12px; }}
  /* Skill 描述能力空间 */
  .capspace {{ margin: 12px 0 4px; padding: 10px 12px; background: #fff; border: 1px solid #e2e2e2; border-radius: 8px; }}
  .capspace-title {{ font-size: 13px; font-weight: 700; color: #444; margin-bottom: 6px; }}
  .caps-row {{ display: flex; align-items: flex-start; margin: 3px 0; }}
  .caps-label {{ flex: 0 0 76px; font-size: 12px; font-weight: 600; padding-top: 2px; }}
  .caps-D {{ color: #1f6feb; }} .caps-A {{ color: #d2691e; }} .caps-I {{ color: #555; }}
  .caps-tags {{ flex: 1; }}
  .cap-tag.cap-D {{ background: #e7f0ff; color: #1f6feb; border: 1px solid #c5d9f5; }}
  .cap-tag.cap-A {{ background: #fdeee2; color: #d2691e; border: 1px solid #f2d2b5; }}
  .caps-intended {{ flex: 1; font-size: 12px; color: #555; line-height: 1.6; }}
  /* modal 2x2 六色 badge */
  .cls-badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; color: #333; border: 1px solid rgba(0,0,0,.12); }}
  /* 恶意调用链 DAG 图（Cytoscape.js + Dagre 风格，手写原生） */
  .attack-graph {{ position: relative; margin: 8px 10px 12px 10px; background: #fbfbfd; border: 1px solid #e3e3ea; border-radius: 10px; overflow: hidden; }}
  .ag-edges {{ position: absolute; inset: 0; pointer-events: none; }}
  .ag-node {{ position: absolute; transform: translate(-50%, -50%); width: 170px; border-radius: 10px; padding: 6px 10px; font-size: 11px; box-shadow: 0 2px 6px rgba(0,0,0,.08); border: 1px solid; box-sizing: border-box; }}
  .ag-user {{ background: #2f3542; color: #fff; border-color: #2f3542; text-align: center; width: auto; padding: 8px 18px; font-weight: 700; border-radius: 20px; }}
  .ag-input {{ background: #fff8e1; border-color: #f0d97a; color: #6d5a00; max-width: 250px; }}
  .ag-block {{ background: #ffebe6; border-color: #f2b8a8; color: #c0392b; font-weight: 700; }}
  .ag-code {{ background: #fff; border-color: #d8d8e0; }}
  .ag-title {{ font-weight: 700; font-size: 11px; margin-bottom: 2px; }}
  .ag-text {{ font-size: 11px; line-height: 1.4; word-break: break-word; max-height: 52px; overflow: hidden; }}
  .ag-code .ag-text {{ font-family: Consolas, "Courier New", monospace; color: #777; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .ag-code .ag-code-text {{ font-family: Consolas, "Courier New", monospace; color: #555; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block; }}
  #close {{ float: right; cursor: pointer; border: none; background: none; font-size: 20px; color: #999; }}
</style>
<script>
  function escapeHtml(s) {{
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}
  // 恶意调用链 DAG 图（借鉴 Cytoscape.js + Dagre：分层布局 + 节点卡片 + 贝塞尔箭头，原生实现）
  // 定义在 <head> 顶部：<main> 内的调用 <script> 先于底部 script 执行，函数须先就绪。
  function renderGraph(gid, nodes, edges) {{
    const el = document.getElementById(gid);
    if (!el) return;
    const COL_W = 220, H = 150;
    const W = Math.max(300, nodes.length * COL_W + 40);
    el.style.width = W + 'px';
    el.style.height = H + 'px';
    const svg = el.querySelector('.ag-edges');
    svg.setAttribute('width', W);
    svg.setAttribute('height', H);
    const pos = {{}};
    nodes.forEach((n, i) => {{ pos[n.id] = {{ x: 20 + i * COL_W, y: H / 2 }}; }});
    let paths = '<defs><marker id="ag-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#9aa0a6"/></marker></defs>';
    edges.forEach(([a, b]) => {{
      const pa = pos[a], pb = pos[b];
      if (!pa || !pb) return;
      const x1 = pa.x + 85, y1 = pa.y;
      const x2 = pb.x - 85, y2 = pb.y;
      const mx = (x1 + x2) / 2;
      paths += '<path d="M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2 + '" fill="none" stroke="#9aa0a6" stroke-width="1.5" marker-end="url(#ag-arrow)"/>';
    }});
    svg.innerHTML = paths;
    let nodeHtml = '';
    nodes.forEach(n => {{
      const p = pos[n.id];
      if (!p) return;
      nodeHtml += '<div class="ag-node ag-' + n.type + '" style="left:' + p.x + 'px;top:' + p.y + 'px">' +
        '<div class="ag-title">' + escapeHtml(n.title || '') + '</div>' +
        (n.text ? '<div class="ag-text">' + escapeHtml(n.text) + '</div>' : '') +
        (n.code ? '<div class="ag-code-text">' + escapeHtml(n.code) + '</div>' : '') +
        '</div>';
    }});
    el.insertAdjacentHTML('beforeend', nodeHtml);
  }}
</script>
</head>
<body>
<header>
  <h1>{html_escape(name)}</h1>
  <div class="meta">
    <span class="badge {'malware' if verdict == 'malware' else 'benign'}">{html_escape(verdict)}</span>
    quadrant: {html_escape(quadrant)} · 动作指令加粗 + ▶ 可点击查看执行流 · <b>{mode}</b>
  </div>
  <div class="legend">{legend}</div>
  {capspace}
</header>
<main id="skill">
{''.join(rows_html)}
</main>

<div id="modal" onclick="if(event.target===this)hide()">
  <div class="card">
    <button id="close" onclick="hide()">×</button>
    <h2>块审计信息</h2>
    <div class="field"><span class="k">块 ID</span><span class="v" id="m-block"></span></div>
    <div class="field"><span class="k">触发条件</span><span class="v" id="m-trigger"></span></div>
    <div class="field"><span class="k">有无偏差</span><span class="v" id="m-dev"></span></div>
    <div class="field"><span class="k">2×2 分类</span><span class="v" id="m-cls"></span></div>
    <div class="field"><span class="k">关联能力</span><span class="v" id="m-caps"></span></div>
    <div class="field"><span class="k">外部关联代码片段</span><span class="v" id="m-code"></span></div>
    <div class="field"><span class="k">判定理由</span><span class="v" id="m-reason" style="background:#f6f8fa;padding:6px 8px;border-radius:6px;display:inline-block;"></span></div>
    <div class="field"><span class="k">核心指令(摘要)</span><span class="v" id="m-core" style="background:#f6f8fa;padding:6px 8px;border-radius:6px;display:inline-block;white-space:pre-wrap;"></span></div>
  </div>
</div>

<script>
  const items = {json.dumps(items, ensure_ascii=False)};
  const modal = document.getElementById('modal');
  function show(it) {{
    const dev = (it.flow && it.flow.deviation) || 'no_deviation';
    document.getElementById('m-block').textContent = (it.flow && it.flow.block_id != null) ? it.flow.block_id : '—';
    document.getElementById('m-trigger').textContent = (it.flow && it.flow.trigger_condition) || '—';
    document.getElementById('m-dev').innerHTML = '<span class="badge ' + (dev === 'deviated' ? 'deviated' : 'no_deviation') + '">' + dev + '</span>';
    // 2×2 分类：与 legend 六色一致的取值和 UI
    const _clsBg = (it.flow && it.flow.cls_bg) || '#f5f5f5';
    const _clsLabel = (it.flow && it.flow.cls_label) || '—';
    document.getElementById('m-cls').innerHTML = '<span class="cls-badge" style="background:' + _clsBg + '">' + _clsLabel + '</span>';
    const caps = (it.flow && it.flow.capabilities) || [];
    document.getElementById('m-caps').innerHTML = caps.length
      ? caps.map(c => '<span class="cap-tag">' + c + '</span>').join('')
      : '<span>—</span>';
    const code = (it.flow && it.flow.code_evidence) || [];
    document.getElementById('m-code').innerHTML = code.length
      ? code.map(c =>
          '<div class="flow-item"><b>' + (c.capability || '') + '</b> · ' +
          (c.file || '?') + (c.line_start ? ':' + c.line_start : '') +
          '<br><code>' + (c.code || '') + '</code></div>').join('')
      : '<span>no code location</span>';
    document.getElementById('m-reason').textContent = (it.flow && it.flow.reason) || '—';
    // 核心指令：优先 LLM 摘要（core_instruction），无则截断块文本
    const _core = (it.flow && it.flow.core_instruction) || '';
    document.getElementById('m-core').textContent = _core ||
      (it.text.length > 140 ? it.text.slice(0, 140) + '…' : it.text);
    modal.classList.add('show');
  }}
  function hide() {{ modal.classList.remove('show'); }}
  document.querySelectorAll('.action-click').forEach(el => {{
    el.addEventListener('click', () => show(items[+el.dataset.idx]));
  }});
</script>
</body>
</html>
"""


def html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0].startswith("--"):
        _emit("Usage: python scripts/skill_page.py <skill-dir> [--result <result.json>] [--out-dir <dir>] [--mock]")
        sys.exit(1)

    skill_dir = Path(args[0]).resolve()
    result_file, out_dir, mock = None, DEFAULT_OUT, False
    for i, a in enumerate(args):
        if a == "--result" and i + 1 < len(args):
            result_file = Path(args[i + 1])
        if a == "--out-dir" and i + 1 < len(args):
            out_dir = Path(args[i + 1])
        if a == "--mock":
            mock = True

    name, fm_lines, body_lines = read_skill_lines(skill_dir)
    verdict, quadrant, unconditional, mode = "unknown", "—", [], "演示标注(mock)"

    d_caps, a_caps, intended = [], [], ""
    # Real annotation mode: prefer workflow result's block_classifications.
    if not mock and result_file and result_file.is_file():
        try:
            real = load_real_annotations(result_file)
            items = [{"text": s["text"], "kind": s["kind"], "cls": s["cls"], "flow": s["flow"]}
                     for s in real["sentences"]]
            verdict, quadrant, unconditional, mode = (
                real["verdict"], real["quadrant"], real["unconditional"], real["mode"])
            d_caps = real.get("d_caps") or []
            a_caps = real.get("a_caps") or []
            intended = real.get("intended") or ""
        except (OSError, json.JSONDecodeError, KeyError) as e:
            _emit(f"[warn] result 解析失败，回退 mock：{e}")
            real = None
    else:
        real = None

    if real is None:
        # Fallback: frontmatter rows gray, body rows mock-classified.
        items = [{"text": l, "kind": "frontmatter", "cls": "", "flow": None} for l in fm_lines]
        for i, ln in enumerate(body_lines):
            a = _mock_classify(ln, i)
            items.append({"text": ln, "kind": a["kind"], "cls": a["cls"], "flow": a["flow"]})

    # Output directory: explicit --out-dir wins; otherwise write next to the
    # result.json (same directory); fall back to the default pages dir.
    if "--out-dir" in args:
        target_dir = out_dir
    elif result_file and result_file.is_file():
        target_dir = result_file.parent
    else:
        target_dir = DEFAULT_OUT

    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / f"{skill_dir.name}_page.html"
    out.write_text(_build_page(name, items, verdict, quadrant, mode,
                               d_caps, a_caps, intended,
                               skill_dir=str(skill_dir)), encoding="utf-8")
    _emit(f"[page] {out}  ({len(items)} rows)  verdict={verdict}  {mode}")


if __name__ == "__main__":
    main()
