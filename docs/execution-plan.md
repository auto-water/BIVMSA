# BIV 修改执行计划

> 依据：`docs/my-approach-modification-plan.md`（已废弃的 `docs/my-approach-design.md` **不**作为依据，凡涉及处以下文原则重定义）。
> 基线：当前 `master`（提交 `007af62`）。
> 现状：Phase 0 部分完成，Phase 1/2/3 全部未完成。

---

## 一、核对结果总览

| Phase | 任务 | 状态 |
|-------|------|------|
| 0.1 | `docs/schemas/{result,trace}.schema.json` | ✅ 已完成（3 文件：result / final-result / trace） |
| 0.2 | orchestrator 写两个独立文件 result.json + trace.json | ✅ 已完成（+ 增量补 classification / capability_counts / _meta） |
| 0.3 | trace.py 增加 `agent_calls` / `decisions` API | ✅ 已完成（AgentCall / DecisionRecord + to_dict 导出） |
| 0.4 | `build_det_evidence` 适配新 schema | ✅ schema 已定义，输出经 `schema_check.py` 校验 |
| 0.5 | batch_audit 输出镜像目录 | ✅ 已做（`--results-dir` 默认 `experiment/results`） |

> **进度 2026-08-13**：Phase 0/1/2 + 提示词统一模板 + Phase 3.1 V_decl（已接线实测）+ per-case 页面前端全部完成。**缺失字段三阶段获取已实施**：
> - ✅ `skill_body`（orchestrator 恢复）、`capability_code_evidence`（orchestrator 从 ast/regex findings 组装，含 file/line_start/code/snippet；schema 已同步）
> - ✅ ast_findings 补 `capabilities_mapped` + `file`/`line_start`（启发式）
> - ✅ sentence_classifier 每句 `capabilities[]`（提示词 + workflow schema）
> - 🟡 句子级 deviation_label / flows：LLM 模式由 sentence_classifier 输出；确定性反查待做
> - 🔴 JS/Shell supplement findings 行号待增强（无精确位置分支）
>
> **进度 2026-08-14：Phase 0 块划分 v2（触发条件块，agent 驱动）**：
> - ✅ `normalize_skill_text` 改为**删空行 + strip，不再按标点拆句**（v2，见 `docs/chunking-phase0-v2.md`）
> - ✅ `src/biv/chunking.py`：frontmatter 元数据块 + body 行（`build_phase0` v2）；`skill_chunk.py` 输出 seed
> - ✅ workflow Phase 0：**IncrementalAgent 增量划分**（每次新开无历史 agent 提交未覆盖区间，划出"同一触发条件最大行区间"块，收缩再开下一个）
> - ✅ P3 vdecl 以块为单位（`block_classifications`，block_id 替代 line）；`render_sentence_classifier` 多行块渲染（块头 + 缩进 + 每块一条约束）
> - ✅ 前端 skill_page 按块展示（触发条件分组标题 + modal 块 ID/触发条件）
> - ✅ 冒烟测试：`experiment/cases/smoke/1password-1`（单样例），实测 Phase 0 产出 4 触发块（sign-in/tmux/guardrails），vdecl 4/4 覆盖
> - ⚠️ resume 缓存对"执行外部命令"subagent（render-vdecl 等）不感知 prompts.py 变化 → 改提示词后需完整重跑（或改外层 prompt 使缓存失效）
>
> 下一步：Phase 3.2/3.3（A 兜底 / 流补全）+ 8000 样本批量。std-cases-4 4 case 已跑通 v1 句块格式，待用 v2 触发块全量重跑。链路：`batch_audit` → `benchmark` → `report` → `page`。
| 1.1 | `scripts/viz_audit.py`（V1-V4） | ❌ 未做 |
| 1.2 | `scripts/viz_case.py`（V5 仪表盘） | ❌ 未做 |
| 1.3 | package.json `viz` / `viz:case` | ❌ 未做 |
| 2.1 | 用例矩阵补齐（benign 已有 2，无偏差恶意/边界缺） | 🟡 部分（仅 std-cases-4 四例） |
| 2.2 | `experiment/benchmark.yaml` | ❌ 未做 |
| 2.3 | `scripts/benchmark.py` | ❌ 未做 |
| 2.4 | package.json `benchmark` | ❌ 未做 |
| 3.1 | V_decl 声明轨道恶意通道（U1-U8） | ❌ 全部未做 |
| 3.2 | Agent 兜底 A(s)（agent_gap） | ❌ 未做（`actual_track/` 三 analyzer 已就位） |
| 3.3 | Agent 执行流补全（跨文件链） | ❌ 未做（flows 仍仅 Python 同文件） |

---

## 二、当前 result schema 与计划 schema 的差距（Phase 0 对齐依据）

当前 `run_full_pipeline` 输出（orchestrator.py:518-580）字段：`skill_name / skill_dir / verdict / confidence / verdict_source / verdict_reasoning / structure / frontmatter / taxonomy / capabilities{declared,actual,undeclared,overdeclared,declared_sources,actual_sources} / flows / compound_flags / root_cause / findings / finding_counts / urls / relaxed_veto / _meta{timestamp, trace_file, trace_summary}`。

对照 modification-plan §2.2 目标 schema，**缺**：
1. `classification` 2×2 象限块（`deviation_axis` / `malicious_axis` / `quadrant`）——Phase 1 可视化的直接输入
2. `capability_counts`（基准判分用）
3. `_meta` 缺 `audit_time`（ISO）、`pipeline_version`、`trace_ref`（相对引用，非绝对路径）
4. trace 缺 `agent_calls` / `decisions`（Phase 0.3）

> 决策：**不做破坏性重构**，改为在现有 result 上**增量补齐**这 4 个缺口，保持 workflow 消费兼容（`build_det_evidence` 已是解耦层）。

---

## 三、执行计划（含优先级、落点、验收）

依赖主线：**Phase 0 → Phase 2 → Phase 1 → Phase 3**（原计划为 0→1→2→3；若 8000 样本批量测试优先，将 Phase 2 提前到 Phase 1 前，二者均只依赖 Phase 0）。

### Phase 0 — 输出规范补齐（增量，非重构）

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| 0.1 | 定义 `result.schema.json` / `trace.schema.json`（对齐现有实际字段 + 新增 4 缺口） | `docs/schemas/` | 现有 result.json 校验通过 |
| 0.2 | result 增量补：`classification` 象限（由 U/O/verdict 派生）、`capability_counts`、`_meta.audit_time`/`pipeline_version`/`trace_ref` | `src/biv/orchestrator.py` | batch 后各 case result 含四象限字段 |
| 0.3 | trace 增加 `agent_calls` / `decisions` 记录 API（对 workflow/管线调用埋点） | `src/biv/trace.py` | 单 case 跑通，trace.json 出现两数组 |

**验收**：`npm run batch-test` 后，对 4 个 case 的 result.json 跑 JSON Schema 校验全部通过；trace.json 结构含 phases/records/agent_calls/decisions。

### Phase 2 — 可测试基准（判分基础设施）✅ 已完成

> 判分只用二元标签（benign/malware）。**不做象限准确率**：数据只带恶意/非恶意标签，期望象限属于主观定义，无法作为客观 ground truth，对比无意义。`classification.quadrant` 仅作描述性输出保留，不参与判分。

| # | 任务 | 落点 | 状态 |
|---|------|------|------|
| 2.1 | ~~补齐用例~~ → 已取消（用户决定不加用例，直接复用 std-cases-4 + 8000 样本） | — | ✅ 已取消 |
| 2.2 | `experiment/benchmark.yaml`（case → expected/说明） | `experiment/benchmark.yaml` | ✅ 完成 |
| 2.3 | `scripts/benchmark.py`：跑全量 + 准确率/精确率/召回率/F1（malware 为正类）+ FPR/FNR + 确定性 vs LLM 对比 | `scripts/benchmark.py` | ✅ 完成 |
| 2.4 | package.json `benchmark` 脚本 | `package.json` | ✅ 完成 |

**验收通过**：`npm run benchmark` 输出指标表（Acc/Prec/Recall/F1/FPR/FNR），现有 4 case det-track 判分：TP=2 FP=1 TN=1 FN=0（acc=0.75, prec=0.667, rec=1.0, f1=0.8, fpr=0.5, fnr=0）；LLM-track 在无 workflow 结果时正确显示 unavailable。

**指标定义**（malware 为正类，P=positive/malware，N=negative/benign）：

| 指标 | 公式 | 含义 |
|------|------|------|
| 准确率 Accuracy | (TP+TN)/(P+N) | 整体判对比例 |
| 精确率 Precision | TP/(TP+FP) | 判为 malware 的样本中真恶意占比 |
| 召回率 Recall | TP/(TP+FN) | 真实恶意中被检出的比例 |
| F1 | 2·P·R/(P+R) | 精确率与召回率的调和均值 |
| **FPR 误报率** | FP/(FP+TN) | 良性被误判为恶意的比例 |
| **FNR 漏报率** | FN/(FN+TP) | 恶意被漏判为良性的比例 |

### Phase 1 — 结果可视化 ✅ 已完成（HTML 交互式报告）

> 用户选择的形态：**单页自包含 HTML 报告**（浏览器打开，内联 CSS/JS）。初版 matplotlib 图（V1-V5）已回退。

| # | 任务 | 落点 | 状态 |
|---|------|------|------|
| 1.1 | `scripts/report_html.py`：概览统计 + det/LLM 指标表 + 每 case 可展开详情（能力 D/A/U/O 风险着色、流、rule/veto、findings）+ 搜索框 | `scripts/report_html.py` | ✅ 完成 |
| 1.2 | package.json `report` 脚本 | `package.json` | ✅ 完成 |

**验收通过**：`npm run report` 生成 `experiment/results/report.html`（10 KB，4 case）。指标表与 benchmark 一致（det: n=4 acc=0.75 fpr=0.5 fnr=0；llm 无 workflow 结果时 n=0）。复用 benchmark 判分逻辑（score/derive_class/extract_verdicts）。

### Phase 3 — 修改（核心）

#### 3.1 声明轨道恶意通道 V_decl

> 判定原则以 modification-plan §1.3 为准：**是否存在任何合理的用户授权或合法使用场景？** 不存在 → 无条件有害 → 命中即恶意，不看上下文；存在 → 归语义层 Judge。模式目录 U1-U8 依此原则基于当前 taxonomy 重定义（不引用已废弃的 my-approach-design.md）。

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| 3.1.1 | `taxonomy.py` 增加 `UNCONDITIONAL_PATTERNS`（模式定义 + 锚规则） | `src/biv/taxonomy.py` | 模式清单含锚校验字段 |
| 3.1.2 | 新建 `src/biv/unconditional.py`（代码层匹配器 + 锚校验，复用 TRUSTED_DOMAINS/URL 分析） | `src/biv/unconditional.py` | `requests.post(不受信域, cred)` 命中 |
| 3.1.3 | `malicious_detect.py` 增加 `v_decl()` 硬否决；final_verdict 扩展为 `ŷ = V_actual ∨ V_decl ∨ Judge` | `src/biv/malicious_detect.py` | 无偏差恶意用例被检出 |
| 3.1.4 | workflow 增加文本层提取 agent（prompt + schema，输出 evidence + anchor） | `scripts/biv_workflow.js`、`scripts/batch_workflow.js` | agent 输出含证据与目标锚 |
| 3.1.5 | result 增加 `unconditional_patterns` 字段（与 0.1 schema 对齐） | `src/biv/orchestrator.py` | schema 校验通过 |

**验收**：无偏差恶意基准用例被 V_decl 检出；安全类 skill（如 1password-1 声明 cred-read）**不**误报（锚校验兜底）。

#### 3.2 Agent 兜底 A(s)（解决 P-AST 跨语言不同步）

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| 3.2.1 | 统一 `actual_track/` 三 analyzer 输出接口（A_ast/flows/findings 同构） | `src/biv/actual_track/` | 输出 schema 一致 |
| 3.2.2 | 定义"静态薄弱检测"规则（哪些模式静态必然漏 → 触发 agent） | `src/biv/actual_track/` | 规则清单 |
| 3.2.3 | workflow 增加 agent 兜底提取（仅静态弱处） | `scripts/*workflow.js` | 弱处触发 agent，非全量 |
| 3.2.4 | 兜底 merge 进 A(s)，来源标注 `source_type: agent_gap` | `src/biv/orchestrator.py` | A 集合含 agent_gap 来源 |

**验收**：JS/Shell skill 的 A(s) 完整度与 Python 对齐（benchmark 对比）。

#### 3.3 Agent 执行流补全（解决 P-FLOW 不完整）

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| 3.3.1 | 入口点提取：SKILL.md 中引用脚本的指令 → 追踪起点列表 | `scripts/*workflow.js` | 起点列表正确 |
| 3.3.2 | 每入口点一个 agent，追踪完整链（D₂ 头 → A₂ 序列） | `scripts/*workflow.js` | 输出跨文件 flow chain |
| 3.3.3 | 链 merge 进 flow(s)，`exfiltration_chain`/`rce_chain` 基于**证明的数据流**触发 | `src/biv/deviation.py` | 跨文件用例不再靠共现近似 |
| 3.3.4 | 追踪边界：仅 skill 目录内；标准库停在 sink 记录 capability | agent prompt | 链长度受控 |

**验收**：新增跨文件外泄用例的 `exfiltration_chain` 基于完整链触发。

---

## 四、里程碑与建议顺序

```
M1 (Phase 0 + 2)：schema 校验通过 + 基准判分可用   ← 8000 样本批量测试的前置
M2 (Phase 1)：    可视化可用，2×2 分布可见
M3 (Phase 3.1)：  V_decl 上线，无偏差恶意被检出
M4 (Phase 3.2/3)：agent 兜底 + 流补全上线，跨文件链触发
```

**若 8000 样本批量测试是近期目标**：先做 M1（Phase 0 + Phase 2），批量测试 → 再 Phase 1 可视化分析结果 → 最后 Phase 3 针对性改进。Phase 3 各子项相互独立，可单独排期。

---

## 五、风险

| 风险 | 对策 |
|------|------|
| V_decl 误报安全类 skill | 锚校验严格（第三方/不受信目标才命中）；基准含 1password 等安全负例 |
| result 增量改动破坏 workflow 兼容 | `build_det_evidence` 为解耦层先行；新字段只增不删 |
| Phase 2 用例人工构造耗时 | 先建无偏差恶意 1 + 边界 1 起跑，逐步补齐矩阵 |
| agent 兜底/流补全幻觉 | 复用 3 重幻觉控制；trace 记录原始输出 |
