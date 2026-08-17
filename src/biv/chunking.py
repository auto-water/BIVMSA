"""Phase 0 预处理 — 块划分 v2（触发条件块）。

块划分不再按"每句一块"，而是由**子智能体**按"同一触发条件下会执行的最大行
区间"划分（见 reference/chunking-phase0-v2.md）。本模块提供确定性的行级基础：
- `split_skill_units`: 拆 frontmatter 与 body（删空行，不拆句）
- `build_phase0`: 产出 v2 初始结构（frontmatter 元数据块 + body 行，正文块待 agent 填充）
- `chunk_skill_text`: 无 agent 时的兜底简化块（frontmatter + body 每行一块）

行号 = 去空行后的**全局行号**：frontmatter 块占 1..fm_n，body 行从 fm_n+1 连续编号。
"""

from typing import Any, Dict, List

from .prompts import normalize_skill_text  # 复用"删空行 + strip"（不拆句）


def split_skill_units(text: str) -> List[List[str]]:
    """拆 SKILL.md 为 (frontmatter_lines, body_lines)（各去空行）。

    frontmatter 判定：以 `---` 开头且存在闭合 `\n---`。frontmatter 作为
    **元数据块**（触发条件来源），不参与 agent 划分。
    """
    t = text or ""
    fm_raw, body_raw = "", t
    if t.startswith("---"):
        end = t.find("\n---", 3)
        if end != -1:
            fm_raw = t[: end + 4]
            body_raw = t[end + 4 :]
    fm_lines = [l.strip() for l in fm_raw.splitlines() if l.strip()]
    body_lines = [l.strip() for l in body_raw.splitlines() if l.strip()]
    return fm_lines, body_lines


def build_phase0(skill_content: str) -> Dict[str, Any]:
    """Phase 0 v2 初始结构：frontmatter 元数据块 + body 行（正文块待 agent 填充）。

    Returns:
        {
          "unit": "trigger-block",
          "frontmatter_block": {...},   # block_id=1，元数据块
          "body_offset": fm_n,          # body 第一行全局行号 = fm_n + 1
          "body_lines": [...],          # 去空行 body 行
          "body_text": "...",           # body 全文（agent 划分参考）
          "blocks": [frontmatter_block] # 初始仅 frontmatter 块
        }
    """
    fm_lines, body_lines = split_skill_units(skill_content)
    fm_n = len(fm_lines)
    fm_block = {
        "block_id": 1,
        "kind": "frontmatter",
        "line_start": 1,
        "line_end": fm_n,
        "trigger_condition": "frontmatter 元数据（触发条件来源，不参与划分）",
        "text": "\n".join(fm_lines),
        "sentences": fm_lines,
    }
    return {
        "unit": "trigger-block",
        "frontmatter_block": fm_block,
        "body_offset": fm_n,
        "body_lines": body_lines,
        "body_text": "\n".join(body_lines),
        "blocks": [fm_block],
        "count": 1,  # 初始仅 frontmatter 块；正文块由 workflow agent 增量划分后覆盖
    }


def chunk_skill_text(text: str) -> List[Dict[str, Any]]:
    """兜底简化块划分（无 agent 时）：frontmatter 块 + body 每行一块。

    真实触发条件块由 workflow 的 agent 增量划分产生；此函数仅供
    `prompts._render_one` 在无 blocks 注入时渲染 prompt 用。
    """
    fm_lines, body_lines = split_skill_units(text)
    fm_n = len(fm_lines)
    blocks: List[Dict[str, Any]] = [
        {
            "block_id": 1,
            "kind": "frontmatter",
            "line_start": 1,
            "line_end": fm_n,
            "trigger_condition": "frontmatter 元数据",
            "text": "\n".join(fm_lines),
            "sentences": fm_lines,
        }
    ]
    for i, ln in enumerate(body_lines, start=fm_n + 1):
        blocks.append(
            {
                "block_id": len(blocks) + 1,
                "kind": "fallback-line",
                "line_start": i,
                "line_end": i,
                "trigger_condition": "",
                "text": ln,
                "sentences": [ln],
            }
        )
    return blocks
