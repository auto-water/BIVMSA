# Phase 0 块划分 v2 — 触发条件块（agent 驱动）修改计划

> 日期：2026-08-14
> 状态：待执行
> 背景：v1（每句一块）的分批粒度太小，264 句 skill 仍要一次生成大量分类。v2 改为**触发条件块**：同一触发条件下会执行的最大行区间为一个块。

## 一、目标

1. **预处理逻辑**：删空行不变；**删除"标点后加换行"的句子拆分**，行 = SKILL.md 物理行（去空行）。
2. **块划分由子智能体执行**，划分原则：**同一触发条件下会执行的最大行区间为一个块**。
3. **frontmatter 作为元数据块**（触发条件来源），不再参与划分。
4. 正文初始为一块，由增量 agent（每次新开无历史 agent）逐步划分，直到覆盖全部正文。
5. 后续所有标注（P3 vdecl）以块为单位；前端按块展示。

## 二、块数据结构

```json
{
  "block_id": 1,              // frontmatter=1，正文块从 2 递增
  "kind": "frontmatter" | "trigger",
  "line_start": 1,            // 去空行后的物理行号（frontmatter 块=1..fm_end）
  "line_end": 5,
  "trigger_condition": "...", // 触发条件描述（frontmatter 块为 "metadata/触发条件来源"）
  "text": "...",              // 该区间全文（多行）
  "sentences": ["..."]        // 区间行数组
}
```

## 三、实现改动

| 文件 | 改动 |
|------|------|
| `src/biv/prompts.py` | `normalize_skill_text`：删除 `_insert_sentence_breaks` 调用，仅保留"删空行 + strip"。`_insert_sentence_breaks` 保留函数但不再被调用（或删除）。 |
| `src/biv/chunking.py` | 改为行级：`build_phase0` 输出 `{unit:"trigger-block", frontmatter_block, body_lines, blocks:[frontmatter块]}`（正文块待 agent 填充）。提供 `split_skill_units(text)` → {frontmatter_block, body_lines}。 |
| `scripts/skill_chunk.py` | 输出 v2 初始结构（frontmatter 块 + body_lines），供 workflow agent 增量划分。 |
| `scripts/batch_workflow.js` | Phase 0 改为：① 取初始结构；② agent 循环划分 body（IncrementalAgent：每次新开无历史 agent，提交 body 全文 + 当前起点，返回第一个块的 {line_start,line_end,trigger_condition}，收缩起点再开下一个）；③ 汇总 blocks。 |
| `scripts/biv_workflow.js` | 同上。 |
| `src/biv/prompts.py` `render_sentence_classifier` | 块文本可多行：prompt 中块显示为 `{block_id}. {block_text}`（多行缩进）。 |
| `scripts/skill_page.py` | 块文本多行渲染（white-space:pre-wrap 已支持）；显示 trigger_condition。 |
| `docs/schemas/result.schema.json` | block 加 `kind`/`trigger_condition`。 |

## 四、增量划分算法（IncrementalAgent）

```
seed = skill_chunk.py → {frontmatter_block, body_lines: L[1..N]}
blocks = [frontmatter_block]
start = 1
while start <= N:
    r = agent(                       # 无历史，每次新开
        提交 body 全文 + "从正文行 {start} 开始，划出同一触发条件下会执行的最大行区间的第一个块"
        → {line_start, line_end, trigger_condition}
    )
    校验: line_start <= start <= line_end <= N 且 line_end > start 或推进
    blocks.push({block_id: len(blocks)+1, kind:"trigger", ...r, text: L[start..line_end]})
    start = r.line_end + 1
    迭代上限保护（如 50）避免死循环
```

## 五、验证

- 冒烟：`experiment/cases/smoke/1password-1`（单样例）跑 workflow，Phase 0 产出 frontmatter 块 + 若干触发块（如 "安装" / "登录" / "读取 secrets" 等 section）
- `python scripts/skill_page.py <case> --result <result.json>` → 按块展示（块含多行文本）
- 4 case 全量 LLM-track 保持 4/4
- schema:check 通过

## 六、风险

| 风险 | 对策 |
|------|------|
| agent 划分不稳定（行号越界/不推进） | 校验 line_start/line_end 合法性；line_end 必须推进；迭代上限 |
| 块过大（agent 不细分） | prompt 强调"最大区间"但不含不同触发条件；若单块含多触发条件，前端仍可看 |
| 删标点拆分影响 sentence_classifier | block 文本多行，LLM 按块整体分类（触发条件块语义更自然） |
