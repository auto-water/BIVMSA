# BIV 系统说明书（System Specification）

> 版本：v0.3.0（pipeline_version）
> 日期：2026-08-14
> 依据：当前架构（Phase 0-4，触发条件块 + 意图覆盖偏差 + V_decl + 攻击链）。配套示意图见 `docs/system-diagrams.md`。
> 本文档回答：**为什么这么设计、要解决什么问题、假设是什么、每个模块怎么工作**。

---

## 目录

1. [系统设计思路](#一系统设计思路)
2. [想要解决的问题](#二想要解决的问题)
3. [核心假设](#三核心假设)
4. [术语对照表](#四术语对照表)
5. [技术栈](#五技术栈)
6. [运行环境（Harness）](#六运行环境harness)
7. [多智能体编排逻辑](#七多智能体编排逻辑)
8. [提示词管理](#八提示词管理)
9. [数据模型](#九数据模型)
10. [可视化](#十可视化)
11. [验证与基准](#十一验证与基准)
12. [目录结构](#十二目录结构)

---

## 一、系统设计思路

**BIV（Behavioral Integrity Verification，行为完整性验证）** 是一个对未知 AI Agent Skill 进行**上架前安全审计**的多智能体系统。它输入一个 Skill 目录，输出 `benign`（良性，可上架）或 `malware`（恶意，拒绝上架）的二元判定，以及支撑该判定的**完整证据链**。

设计严格复现论文 *Behavioral Integrity Verification for AI Agent Skills*（Yuhao Wu et al., 2025, arXiv:2605.11770）。

### 1.1 核心思想：声明与实际的双轨验证

Skill 是一种"会执行代码的文档"：`SKILL.md` 描述它能做什么（**声明轨道 D**），而配套的脚本 + 正文中的命令真正做了什么（**实际轨道 A**）。安全审计的本质是回答一个问题：

> **这个 Skill 声称的，和它实际做的，是否一致？这种不一致是否是恶意的？**

因此系统的核心骨架是一个**三阶段流水线**：

```
Phase 1 能力提取    →  D(s) 声明能力 + A(s) 实际能力
Phase 2 偏差检测    →  U = A − D, O = D − A, compound flags
Phase 3 恶意判定    →  ŷ = V_actual ∨ V_decl ∨ Judge
```

前后又扩展了两个阶段：

- **Phase 0（预处理）**：把 `SKILL.md` 划分成**触发条件块**——同一触发条件下会执行的最大行区间。这是后续所有标注操作的**公共语义单元**（解决"按句粒度太小、一次性生成上百条分类"的瓶颈）。
- **Phase 4（攻击链）**：对每个被判定恶意的块，构造一条**可执行的恶意攻击链**（用户输入 → 恶意块 → 具体恶意代码片段），让审计结论"可复现、可理解"。

### 1.2 用户确认的核心定义（权威，后续所有逻辑以此为准）

| 符号 | 定义 | 获取途径 |
|------|------|---------|
| **D(s)** | Skill 描述**包含的所有敏感操作**（frontmatter + body 声明） | `D_det`（确定性，frontmatter allowed-tools/hooks → taxonomy）∪ `D_llm`（LLM 语义提取，含 3 重幻觉控制） |
| **A(s)** | Skill **真实执行的所有敏感操作** | `A_ast`（AST 污点分析）∪ `A_regex`（正则能力映射）∪ `A_llm`（LLM 读取正文提取完整实际能力，非仅恶意指令） |
| **U(s)** | **超出声明意图**的操作（语义偏差） | 由 `A_llm` 输出的 `covered_by_declared=false` 操作决定，**不是**朴素的集合差 A − D |
| **O(s)** | 过度声明（D − A，声明了但代码没有） | 集合差 D − A |
| **Φ(s)** | 完整证据元组 `⟨D, A, U, O, flows, compound⟩` | Phase 1/2 组装，供 Phase 3 消费 |

### 1.3 意图覆盖原则（解决自然语言与代码的抽象差距）

设计上有一个重要张力：

> 自然语言的抽象程度天然比代码高，因此从自然语言分析出的 D **很难包含**从代码提取的 A。

如果 U = A − D（朴素集合差），那么一个 Skill 只要实现细节没被逐字声明，就会被记为"未声明"（假阳性）。这会让安全类 Skill（如实声明读凭证的密码管理器）大量误报。

**用户的解决方案**（意图覆盖原则）：

> **D 意图覆盖的 A 操作 → 放行（不是偏差）。** 实现细节只要是声明意图的自然/必要实现，就视为"被覆盖"；只有**明显超出声明意图**的操作才记为 U。

因此：
- `A_llm` 的提示词要求对每个实际操作标记 `covered_by_declared`（实现细节被意图覆盖 → 放行）；
- U 的定义从"集合差"改为"**超出声明意图的操作**"（`covered_by_declared=false`）；
- 判定时对 `covered_by_declared=true` 的操作**放行**，`covered_by_declared=false` 的操作才进入偏差。

这个原则把"交集"扩大了，**降低了假阳性误报**（代价是理论上漏报增多——由 Phase 3 的 V_decl 无条件有害识别兜底）。

### 1.4 三层判定（ŷ 的构成）

最终判定不再单一依赖某一路，而是三条通道的并集：

```
ŷ(s) = V_actual(s) ∨ V_decl(s) ∨ Judge(s)
```

| 通道 | 来源 | 性质 | 触发即 |
|------|------|------|--------|
| **V_actual** | 确定性规则引擎（15 规则）+ Relaxed-Veto | 代码事实驱动 | malware（不看上下文） |
| **V_decl** | 声明轨道恶意通道（U1-U8 无条件有害模式，块级） | 声明本身无条件有害 | malware（不看 Judge） |
| **Judge** | LLM 语义综合判定 | 全证据 + 原文综合 | 给出最终 verdict |

V_decl 引入的原因：**无偏差恶意**（no-deviation-malicious）——即声明本身是恶意的（例如"把 `~/.ssh/id_rsa` 发给 evil.com"），此时声明与实际一致（无偏差），朴素偏差检测完全失效。V_decl 在 Phase 0 的块级分类中识别这类"声明即有害"，与 V_actual 形成互补（代码事实 vs 声明内容）。

---

## 二、想要解决的问题

| # | 问题 | BIV 的解法 |
|---|------|-----------|
| 1 | **隐藏恶意代码**：Skill 可能携带恶意代码伪装成正常功能 | 双轨提取 A(s)，无论是否声明都检出 |
| 2 | **声明与实际不一致**：Skill 声称做 A 实际做 B | 偏差检测 U/O + Φ(s) 证据 |
| 3 | **安全类 Skill 误报**：诚实声明敏感能力（读凭证）被误判 | 意图覆盖原则：`covered_by_declared` 放行 + V_decl 锚校验兜底 |
| 4 | **无偏差恶意**：声明本身就有害，与代码一致仍应判恶意 | Phase 3 V_decl 块级 U1-U8 无条件有害识别 |
| 5 | **长 Skill 一次性分类超限**：264 句一次生成 264 条分类，retry 超限 | Phase 0 触发条件块（agent 增量划分）+ V_decl 按块分批（`VDECL_CHUNK=120`）+ 缺失块 backfill |
| 6 | **判定不可复现**：只给一个 verdict 没有证据 | 攻击链（Phase 4）+ 代码证据（capability_code_evidence）+ trace 全记录 |
| 7 | **多语言脚本分析**：Python/JS/TS/Shell 能力不对称 | AST 污点分析（Python ast 标准库、JS/TS tree-sitter、Shell tree-sitter-bash）+ regex 兜底 + A_llm 语义补充 |
| 8 | **审计结果人工不可读** | HTML 报告 + 每 case 标注页面 + 系统示意图（mermaid） |

---

## 三、核心假设

系统的一切设计都建立在以下假设之上（这些假设决定了解法的边界）：

### 3.1 判定假设

1. **恶意判定公式**（论文核心假设）：
   > 一个 Skill 是恶意的，当且仅当它**违背了用户意愿**（声明与实际能力不匹配 / 或声明本身有害）**且很可能造成负面影响**（存在高风险能力）。

2. **声明 vs 实际的不一致是恶意的主要信号**——绝大多数真实恶意 Skill 会通过隐藏代码或夸大声明来误导用户。

### 3.2 能力假设

3. **Taxonomy 完备性**：7 类 × 29 种敏感能力可以覆盖 Skill 的安全敏感操作空间（严格复现论文 Appendix E/G）。

4. **意图覆盖假设**：实现细节如果服务于声明意图，应被视为"被覆盖"而非"未声明"——这用 `covered_by_declared` 标记表达。

5. **代码即证据**：`SKILL.md` 正文 + 脚本中的**可执行指令/命令**是 A(s) 的可靠来源；"提及/描述攻击"与"指示执行攻击"可区分（A_llm 提示词明确要求区分）。

### 3.3 数据假设

6. **无偏差恶意的存在**：存在"声明本身无条件有害"的 Skill（U1-U8 模式），需要独立的 V_decl 通道识别。

7. **Ground truth 无泄漏**：真实标签只从目录路径段（`benign`/`malware`）推导，**不读取 `.expected` 文件**——防止标签泄漏进审计上下文。

8. **大多偏差是疏忽**（论文统计）：81% 的偏差来自开发者疏忽而非恶意——LLM Judge 提示词中显式给出该先验，避免过度判定。

### 3.4 工程假设

9. **Trace 与 result 分离**：调试追踪（`trace.json`）与审计结果（`result.json`）永不混在同一个文件——保持审计数据纯净，trace 通过 `_meta.trace_ref` 引用。

10. **schema 只增不删**：输出字段只增不删（`additionalProperties` 默认 true），保证下游兼容。

---

## 四、术语对照表

### 4.1 核心判定概念

| 术语 | 英文/符号 | 含义 |
|------|-----------|------|
| 行为完整性验证 | BIV (Behavioral Integrity Verification) | 系统名称 |
| 声明能力 | D(s) | Skill 描述包含的所有敏感操作 |
| 实际能力 | A(s) | Skill 真实执行的所有敏感操作 |
| 未声明能力 | U(s) = 超出声明意图的操作 | 语义偏差：`covered_by_declared=false` |
| 过度声明能力 | O(s) = D − A | 声明了但代码没有 |
| 证据元组 | Φ(s) | `⟨D, A, U, O, flows, compound⟩` |
| 判定 | ŷ | `V_actual ∨ V_decl ∨ Judge` |
| 意图覆盖 | covered_by_declared | 操作是否落在声明意图内（放行标记） |

### 4.2 阶段

| 术语 | 含义 |
|------|------|
| Phase 0 | 块划分：SKILL.md → 触发条件块（agent 增量划分） |
| Phase 1 | 能力提取：D/A 双轨 |
| Phase 2 | 偏差检测：U/O/compound flags |
| Phase 3 | 恶意审计：V_actual + V_decl + Judge 三层 |
| Phase 4 | 攻击链：每个恶意块 → 用户输入 + 恶意代码片段 |

### 4.3 块与标注

| 术语 | 含义 |
|------|------|
| 触发条件块 | 同一触发条件下会执行的最大行区间（`block_id` 全局编号） |
| frontmatter 块 | 元数据块（块 1），触发条件来源，不参与划分 |
| block_classifications | V_decl 对每个块的分类结果（kind/deviation/malicious/2×2） |
| 2×2 象限 | deviation × malicious：`no-deviation-benign` / `no-deviation-malicious` / `deviated-benign` / `deviated-malicious` |
| coverage | V_decl 覆盖校验（`classified_blocks/total_blocks`），缺失块 backfill |

### 4.4 检测通道

| 术语 | 含义 |
|------|------|
| V_actual | 代码事实驱动的恶意判定（规则引擎 + Relaxed-Veto） |
| V_decl | 声明轨道恶意通道（U1-U8 无条件有害模式，块级） |
| Judge | LLM 语义综合判定（CoT + xhigh） |
| U1-U8 | 无条件有害模式：凭证外泄 / 反向shell / dropper / 配置投毒 / 范围蔓延 / 指令窃取 / 勒索 / 指令级恶意 |
| Relaxed-Veto | `V(Φ) = 𝟙[compound ≠ 0 ∧ ∃τ∈U: risk(τ) ≥ High]`，无参确定性否决 |
| 规则引擎 | 15 条优先级规则（first-match-wins，附录 I Table 6） |
| compound flag | 4 个复合威胁标志：外泄链 / RCE 链 / 混淆 / 数据血缘违规 |
| kill-chain | 10 种攻击链模式（如 download-write-execute、steal_exfil） |
| 意图分类 | 8 分支 × 36 叶意图 Taxonomy（附录 E Table 4） |

### 4.5 数据与输出

| 术语 | 含义 |
|------|------|
| capability_code_evidence | 能力 → 代码片段 + 行号（`{capability: {source, locations[]}}`） |
| attack_chains | Phase 4 产物：`{block_id, user_input, flow_items[]}` |
| flow_items | 攻击链中的恶意代码片段（file/line_start/code） |
| trace | 调试追踪（phases/records/agent_calls/decisions），与 result 分离 |
| det-track / llm-track | 基准判分的两轨：确定性判定 vs LLM 判定 |

### 4.6 运行模式

| 术语 | 含义 |
|------|------|
| 模式 A | Python 确定性模式（无 LLM，任意主机） |
| 模式 B | Workflow 全流程（Claude Agent，Claude Code 运行时） |
| 模式 C | OpenAI 兼容 LLM 后端（**已移除**，commit a7918d3） |

---

## 五、技术栈

### 5.1 语言与运行时

| 层 | 技术 | 用途 |
|----|------|------|
| 确定性管线 | Python ≥ 3.9 | 解析、AST 污点、规则引擎、偏差计算、CLI |
| 编排 | Node.js ≥ 18 | npm scripts + Workflow 脚本（JS） |
| LLM 调用 | Claude Code CLI / Agent 工具 | 所有 LLM 子智能体（模式 B） |

### 5.2 Python 依赖

| 依赖 | 用途 |
|------|------|
| `pyyaml` | YAML frontmatter 解析 |
| `tree-sitter` + `tree-sitter-javascript` + `tree-sitter-typescript` + `tree-sitter-bash` | JS/TS/Shell 的 AST 解析 |
| Python 标准库 `ast` | Python 源码 AST 污点分析 |
| 标准库 `re` / `json` / `pathlib` | 正则、序列化、文件遍历 |

### 5.3 脚本语言覆盖（AST 污点分析）

| 语言 | 解析技术 | 追踪深度 |
|------|---------|---------|
| Python | `ast` 标准库 | **跨函数污点流**（inter-procedural）：f-string、返回值传播、参数→形参注入、方法链、类属性 `self.x`、下标、字符串拼接、多目标赋值、import 别名、推导式 |
| JavaScript / TS | `tree-sitter` | 变量级 + 模板字符串（fetch/http/axios/WebSocket/child_process/fs/net） |
| Shell | `tree-sitter-bash` | pipeline 流检测 + 反向 shell（`/dev/tcp`、`nc -e`、`bash -i`、`curl|bash`） |

三种语言都带**正则兜底**（tree-sitter 不可用或漏检时用 regex 补充）。

### 5.4 前端 / 可视化

| 技术 | 用途 |
|------|------|
| 原生 HTML/CSS/JS（单文件自包含） | 每 case 标注页面（`skill_page.py`） |
| 原生 JS/CSS SVG | 攻击链 DAG 图（`renderGraph`，Cytoscape.js + Dagre 风格，**手写原生**，无外部依赖） |
| 自包含 HTML 报告 | 批量审计报告（`report_html.py`，内联 CSS/JS） |
| Mermaid | 系统示意图（`docs/system-diagrams.md`，GitHub 原生渲染） |

---

## 六、运行环境（Harness）

### 6.1 两种模式（Harness 形态）

```
┌─────────────────────────────────────────────────────────────┐
│ 模式 A：Python 确定性模式（任意主机，无 LLM）                  │
│   python scripts/biv_audit.py <skill-dir> [--evidence]       │
│   python scripts/batch_audit.py [--results-dir ...]          │
│   → 纯本地进程，无网络，用于 CI / 快速预筛                     │
├─────────────────────────────────────────────────────────────┤
│ 模式 B：Workflow 全流程（Claude Code 运行时，最强推理）        │
│   Workflow({scriptPath: "scripts/biv_workflow.js", args})    │
│   Workflow({scriptPath: "scripts/batch_workflow.js", args})  │
│   → Workflow 编排器（JS）内用 Agent 工具调用 LLM 子智能体       │
└─────────────────────────────────────────────────────────────┘
```

- 两模式**共用同一套确定性核心**（taxonomy / AST 污点 / 规则引擎 / Relaxed-Veto），仅 LLM 调用层不同。
- LLM 调用**仅在模式 B**中通过 Claude Code 的 Agent 工具执行，无需 `.env` 配置。
- 模式 C（OpenAI 兼容 LLM 后端，供业务主机脱离 Claude Code）已移除（commit a7918d3）。

### 6.2 Workflow Harness 的边界

Workflow 脚本有几个**硬约束**，决定了它的交互方式：

| 约束 | 结果 |
|------|------|
| **无文件系统访问** | 落盘 JSON 必须由子智能体执行（`write-*` agent：`Write` 文件 + `mkdir -p`） |
| **无 shell 直接执行** | 调用 Python 管线必须通过子智能体执行 shell 命令（`det-*`、`chunk-seed`、`render-*`） |
| **Ground truth 不得泄漏** | `deriveClass()` 只从路径段推导 `benign`/`malware`，绝不读 `.expected` |
| **LLM 调用必须走 Agent 工具** | 提示词渲染（`prompt_render.py`）与执行分离：先渲染出 prompt 文本，再喂给 Agent |

### 6.3 Workflow 的通信协议

Workflow ↔ Python 管线的接口是**"子智能体跑命令，返回原始 stdout"**：

```
agent(`Run this shell command and return its EXACT raw stdout output
       with NO commentary, NO markdown code fences: python scripts/biv_audit.py <case> --evidence`)
```

- 返回是单个 JSON 对象 → `parseJsonOutput()` 解析。
- **fence-strip 只剥整段开头**：仅当输出整体以 ``` 开头时才剥 markdown fence；绝不任意位置剥——因为 SKILL.md 正文的 JSON 字符串值里可能合法包含 ```` ``` ```` 序列（曾导致 4 个 case 全部 "Cannot parse skill"）。
- Windows 控制台编码：所有 CLI 用 `sys.stdout.buffer.write(utf-8)` 绕过 GBK 问题。

### 6.4 缓存与可复现

- Workflow 支持 **resume**（对 `agent()` 长链做缓存）。
- **已知坑**：改 `prompts.py` 后，`render-*`（执行外部命令）的 subagent 可能命中旧缓存 → 需完整重跑或改外层 prompt 使缓存失效（见 memory `workflow-resume-cache-external-command`）。

---

## 七、多智能体编排逻辑

### 7.1 每个 case 的完整调用链

以 `batch_workflow.js` 为例（`biv_workflow.js` 结构相同，用 `variant=single` 更详细）：

```
Discover 阶段
  └─ discover-cases: find experiment/cases -name SKILL.md | sort

Audit 阶段（pipeline 模式：每个 case 独立，互不阻塞）
  每个 case:
  ├─ parse-<case>          → python scripts/skill_parse.py <case>（稳定解析）
  ├─ det-<case>            → python scripts/biv_audit.py <case> --evidence（紧凑 Φ(s)）
  ├─ det-full-<case>       → python scripts/biv_audit.py <case>（完整 phase1，含 code evidence）
  ├─ render-dllm-prompt    → python scripts/prompt_render.py d_llm_extract --variant batch
  ├─ d_llm                 → LLM：声明能力提取（schema 校验，先跑）
  ├─ render-allm-prompt    → python scripts/prompt_render.py a_llm_instr（vars 含 D 意图，stdin）
  ├─ a_llm_instr           → LLM：完整实际能力 + covered_by_declared（依赖 D_llm 意图，后跑）
  ├─ chunk-seed            → python scripts/skill_chunk.py <case>（Phase 0 初始结构）
  ├─ chunk-part-N          → LLM：增量划分触发条件块（IncrementalAgent 循环，≤60 次）
  ├─ render-vdecl-*        → python scripts/prompt_render.py sentence_classifier（块子集）
  ├─ vdecl_classifier-*    → LLM：块级恶意分类（按 120 块分批，block_id 合并）
  ├─ vdecl_backfill-*      → LLM：缺失块单块补测（coverage 校验）
  ├─ render-judge-prompt   → python scripts/prompt_render.py judge（evidence_summary via stdin）
  ├─ judge                 → LLM：最终判定（effort=xhigh，CoT）
  ├─ render-chain-N        → python scripts/prompt_render.py attack_chain（每个恶意块）
  ├─ attack_chain-N        → LLM：构造 user_input + flow_items（Phase 4）
  └─ write-*               → LLM：把结果 JSON 写入 experiment/results/<rel>/result.json

Report 阶段
  └─ 汇总 summary + write-batch-result
```

### 7.2 编排模式

| 模式 | 用法 | 说明 |
|------|------|------|
| **pipeline** | `pipeline(caseDirs, stage)` | 每个 case 独立跑完整审计，case 间无阻塞（默认） |
| **Promise.all** | 并行子任务 | det-evidence + det-full 并行；D_llm → A_llm 串行（意图依赖）；vdecl 分批并行；恶意块攻击链并行 |
| **IncrementalAgent** | Phase 0 循环 | 每次新开**无历史** agent，提交未覆盖区间 → 返回第一个块的 `{line_start,line_end,trigger_condition}` → 收缩起点 → 再开下一个，直到覆盖全部正文（上限 60 次防死循环） |
| **chunked StructuredOutput** | V_decl 分批 | 长 Skill 按块数分批（`VDECL_CHUNK=120`），每批一个 agent；结果按 `block_id` 合并去重排序。单次 StructuredOutput 在 ~250 行会 retry 超限 |
| **backfill** | coverage 校验 | 对 vdecl 漏标的 block_id 逐个单块补测并合并，确保 Phase 0 每块都有分类 |
| **effort 控制** | Judge | `effort: 'xhigh'` 最强推理，其余 agent 默认 |

### 7.3 Agent 角色的职责划分

| Agent 角色 | 输入 | 输出（schema 强制） |
|-----------|------|--------------------|
| `d_llm` | 渲染后的 D 提取提示词 | `declared_capabilities[] + intended_workflow + expected_data_lineages` |
| `a_llm_instr` | 渲染后的 A 提取提示词（含 D 意图） | `actual_capabilities[]（capability/evidence/evidence_location/is_adversarial/covered_by_declared）+ analysis_summary` |
| `chunk-part` | 未覆盖 body 区间 + 全局行号 | `{line_start, line_end, trigger_condition}` |
| `vdecl_classifier` | 块子集 + D/A/U/O | `block_classifications[] + unconditional_harmful[] + coverage` |
| `judge` | 全证据 + 原文 + V_decl 命中 | `verdict + confidence + reasoning + intent_category + key_evidence` |
| `attack_chain` | 恶意块 + 关联代码证据 | `{block_id, user_input, flow_items[]}` |

### 7.4 数据依赖（为什么 D→A 串行）

```
d_llm 必须先跑，因为：
  a_llm_instr 的 covered_by_declared 判断需要 "声明意图 (D)" 作为参照
  ├─ declared_caps 传入 a_llm 提示词
  └─ intended_workflow 作为 CoT 锚

vdeclVars 的组装：
  D = D_det ∪ D_llm（声明全集）
  A = A_ast ∪ A_regex ∪ A_llm_actual（真实全集，完整能力）
  U = aUncoveredCaps（covered_by_declared=false 的操作）
  O = detEvidence.overdeclared
```

### 7.5 汇总与落盘

- `batch_workflow.js` 落两个层次：
  1. `experiment/results/batch_workflow_result.json`（聚合 summary + 每 case 行）
  2. `experiment/results/<rel>/result.json`（**镜像 cases 目录结构**，每 case 一份，合并 `det_full.phase1` 使前端单文件可用）
- 错误 case **也写入报告**（含 `error` 字段），不静默丢弃。

---

## 八、提示词管理

### 8.1 单一权威源

所有 LLM 提示词集中在 **`src/biv/prompts.py`**（唯一权威源），消除 JS/Python 双份漂移：

```
src/biv/prompts.py
├── taxonomy_ref_text()           # 从 taxonomy.py 自动生成（单一数据源）
├── render_d_llm_extract()        # 声明能力语义提取
├── render_a_llm_instr()          # 实际能力完整提取 + covered_by_declared（意图覆盖）
├── render_attack_chain()         # Phase 4：恶意攻击链
├── render_classifier()           # 根因分类（36 叶意图 + 10 kill-chain）
├── render_judge()                # 最终二元判定（single 8000 / batch 6000 字符截断）
├── render_sentence_classifier()  # Phase 3：块级分类（kind + 2×2 + U1-U8）
├── normalize_skill_text()        # 预处理：删空行 + strip（v2 不拆句）
└── _render_one()                 # 模板注册表（name → 渲染函数）
```

### 8.2 渲染与调用流程

```
Workflow JS
  └─ agent(`python scripts/prompt_render.py <name> --skill-dir <case> --variant batch <<'VARS_JSON' {vars} VARS_JSON`)
       └─ prompt_render.py（薄封装）→ prompts.main()
            ├─ 注入：--skill-dir 自动读 SKILL.md（skill_name/skill_body/skill_content）
            ├─ 合并：--vars-json 或 stdin（大/含引号 payload 走 stdin，避免 shell 转义）
            └─ 输出：渲染后的 prompt 文本（或 --multi 输出 JSON map）
Workflow JS
  └─ agent(prompt_text, {schema: {...}})   # LLM 执行 + StructuredOutput 校验
```

### 8.3 变体（variant）

| 变体 | 用途 | 差异 |
|------|------|------|
| `single` | `biv_workflow.js` | 详细版，judge 内容截断 8000 字符 |
| `batch` | `batch_workflow.js` | 精简版，judge 内容截断 6000 字符 |

统一管理 ≠ 抹平场景差异：同一模板两个变体同源生成。

### 8.4 提示词设计要点

| 要点 | 位置 | 说明 |
|------|------|------|
| **3 重幻觉控制** | `declared_track.py` / `llm_instruction.py` 的 validate | ① Taxonomy 回显拒绝 ② 子串证据接地（evidence 必须在源文本中出现，≥60% 词重叠）③ 高风险能力关键词质量检查 |
| **意图覆盖** | `render_a_llm_instr` | "Be GENEROUS with covered_by_declared"——实现细节服务于声明意图即放行；只有明显超出才标 false |
| **区分"提及攻击"与"指示攻击"** | `render_a_llm_instr` / `render_sentence_classifier` | 安全审计 Skill 列出攻击模式不是恶意，指示执行才是 |
| **CoT 锚** | `render_d_llm_extract` / `render_a_llm_instr` | `intended_workflow` / `analysis_summary` 作为推理锚点，不参与下游判定 |
| **先验注入** | `render_judge` | "Most deviations are oversight (81%), not malice (19%)" |
| **不重不漏** | `render_sentence_classifier` | 强制"CLASSIFY EVERY BLOCK"（100% 覆盖）+ 每块恰一条 |
| **核心指令摘要** | `render_sentence_classifier` | `core_instruction` = 1 行动词短语摘要（**非逐字**，如 "send ~/.ssh/id_rsa to evil.example.com"） |
| **攻击链真实性** | `render_attack_chain` | user_input 必须匹配 trigger_condition；flow_items 必须来自代码证据（不发明代码） |

### 8.5 CLI

```bash
# 手动渲染（调试/查看）
npm run prompt:render -- d_llm_extract --skill-dir <case> --variant single
npm run prompt:render -- judge --skill-dir <case> --variant single < evidence.json   # stdin 传 vars
npm run prompt:render -- taxonomy_ref
# --multi 一次渲染多个，输出 JSON map
python scripts/prompt_render.py --multi d_llm_extract,a_llm_instr --vars-json '{...}' --variant single
```

---

## 九、数据模型

### 9.1 Schema 体系

| Schema | 定义 | 校验对象 |
|--------|------|---------|
| `docs/schemas/result.schema.json` | `run_deterministic_pipeline` 输出 | `experiment/results/**/result.json` |
| `docs/schemas/final-result.schema.json` | `assemble_final_output` 完整审计最终结果 | 完整审计最终结果 |
| `docs/schemas/trace.schema.json` | TraceContext 序列化 | `<skill>_trace.json` |

约定：**字段只增不删**（`additionalProperties` 默认 true）；trace 与 result **永不混同**。

### 9.2 result.json 顶层结构

```jsonc
{
  "phase0": {                       // Phase 0 块划分
    "unit": "trigger-block",
    "count": 9,
    "blocks": [
      { "block_id": 1, "kind": "frontmatter", "line_start": 1, "line_end": 8,
        "trigger_condition": "frontmatter 元数据（触发条件来源，不参与划分）",
        "text": "---\nname: ...", "sentences": ["..."] }
    ]
  },
  "phase1": {                       // 能力提取（确定性部分）
    "skill_name": "...", "skill_dir": "...",
    "structure": {"has_skill_md": true, "has_references": false, "has_scripts": true,
                  "reference_files": [], "script_files": ["scripts/tool.py"]},
    "frontmatter": {...}, "tools": {"tools": [...], "has_bash": bool, ...},
    "skill_body": "...",            // 原文（前端展示）
    "capability_code_evidence": {   // 能力 → 代码片段 + 行号（前端恶意句点击查看）
      "net-socket-out": {"source": "ast", "locations": [
        {"file": "scripts/generateContent.js", "line_start": 32, "line_end": 56,
         "col_start": 4, "col_end": 8, "code": "...", "snippet": "..."}]}},
    "D_deterministic": [...], "d_det_evidence": [...],
    "A_ast": [...], "A_regex": [...],
    "flows_ast": [{"source", "source_location", "transforms", "sink", "sink_location"}],
    "ast_findings": [...], "regex_findings": [...],
    "urls": {"total": N, "untrusted": [...], "untrusted_count": N, "trusted_count": N}
  },
  "phase2": {
    "undeclared": [...], "overdeclared": [...],
    "compound_flags": {"exfiltration_chain": false, "rce_chain": true,
                       "code_obfuscation": false, "data_lineage_violation": false},
    "phi": {...}, "risk_assessment": {...}, "instruction_signals": 0
  },
  "phase3_deterministic": {
    "rule_engine": {"matched": bool, "intent_leaf", "intent_category", "rule_id", "kill_chain"},
    "relaxed_veto": {"fired": bool, "reason", "compound_flag", "high_risk_capability"}
  },
  "llm_prompts": {...},             // 已渲染的 LLM 提示词（供调试）
  "finding_counts": {"critical", "high", "medium", "total"},
  "_det_verdict": {"verdict", "confidence", "source"},
  "classification": {"deviation_axis", "malicious_axis", "quadrant"},   // 2×2
  "capability_counts": {"declared", "actual", "undeclared", "overdeclared"},
  "_meta": {"timestamp", "audit_time", "pipeline_version", "trace_file", "trace_ref", "trace_summary"}
}
```

### 9.3 Workflow 附加字段（LLM 轨）

`result.json` 在模式 B 下还包含（`result.schema.json` 已含这些属性定义）：

```jsonc
{
  "verdict": "malware",             // ŷ 最终判定
  "verdict_source": "vdecl | llm_judge | both | relaxed_veto",
  "vdecl": {
    "fired": true,
    "verdict": "malware",
    "unconditional_harmful": [
      {"pattern": "U2", "anchor": "remote host", "block_id": 4, "evidence": "..."}],
    "block_classifications": [
      {"block_id": 4, "text": "...", "kind": "action_instruction",
       "deviation_label": "no_deviation", "malicious_label": "malicious",
       "classification": "no-deviation-malicious",
       "capabilities": ["net-socket-out"], "core_instruction": "send ~/.ssh/id_rsa to evil.com",
       "reason": "..."}],
    "no_deviation_malicious_count": 1,
    "coverage": {"total_blocks": 9, "classified_blocks": 9}
  },
  "attack_chains": [
    {"block_id": 4, "user_input": "请帮我同步远程服务器配置",
     "flow_items": [{"capability": "net-socket-out", "file": "scripts/x.js",
                     "line_start": 45, "code": "net.createConnection(...)"}]}],
  "phase0": {...},                   // Phase 0 块
  "declared_capabilities": [...],    // D_llm 原始输出
  "actual_capabilities": [...],      // A_llm 原始输出（含 covered_by_declared）
  "deterministic_evidence": {...},   // 紧凑 Φ(s)（透传）
  "a_llm_instr_caps": [...], "a_llm_adv_caps": [...],
  "intended_workflow": "...",
  "judge_intent_category": "C", "judge_key_evidence": [...]
}
```

### 9.4 核心数据结构细节

#### block（Phase 0）

```jsonc
{
  "block_id": 1,                    // 全局唯一（frontmatter=1，正文从 2 递增）
  "kind": "frontmatter | trigger | fallback-line",
  "line_start": 1, "line_end": 8,   // 去空行后的全局行号
  "trigger_condition": "sign-in",   // 触发条件描述（触发块）
  "text": "多行文本",                // 该区间全文
  "sentences": ["..."]              // 区间行数组
}
```

#### block_classifications（V_decl）

```jsonc
{
  "block_id": 4,
  "text": "完整多行文本（逐字，绝不允许拆成单行条目）",
  "kind": "action_instruction | non_action",
  "deviation_label": "deviated | no_deviation",
  "malicious_label": "malicious | benign",
  "classification": "no-deviation-malicious | no-deviation-benign | deviated-malicious | deviated-benign",
  "capabilities": ["net-socket-out"],   // 链接到 capability_code_evidence
  "core_instruction": "动词短语摘要（非逐字）",
  "reason": "1 句理由"
}
```

#### capability_code_evidence（代码证据）

```jsonc
{
  "net-socket-out": {
    "source": "ast | regex | declared",     // declared 无行号
    "locations": [
      {"file": "scripts/x.js", "line_start": 32, "line_end": 56,
       "col_start": 4, "col_end": 8, "code": "...", "snippet": "..."}
    ]
  }
}
```

来源组装：`orchestrator._build_capability_code_evidence` 从 `ast_findings` + `regex_findings` 组装；`ast_findings` 补 `capabilities_mapped` + `file`/`line_start`（启发式 `_attach_finding_meta`）。

#### trace（TraceContext）

```jsonc
{
  "skill_name", "skill_dir", "start_time", "total_duration_ms",
  "phases": {"extract": {"name", "start_time", "step_count", "error_count", "warn_count", "record_count"}},
  "total_records": N,
  "records": [{"timestamp", "phase", "step", "level": "INFO|WARN|ERROR|PHASE|METRIC", "message", "data", "duration_ms"}],
  "agent_calls": [{"call_id", "role", "agent_id", "prompt_len", "duration_ms", "tokens_in", "tokens_out", "retries", "raw_output_hash"}],
  "decisions": [{"record_id", "decision", "reason"}]
}
```

---

## 十、可视化

### 10.1 每 case 标注页面（`skill_page.py` → `<skill>_page.html`）

**数据源**：`phase0.blocks` + `vdecl.block_classifications` + `attack_chains` + `capability_code_evidence`，按 `block_id` join。

| 元素 | 说明 |
|------|------|
| **块级渲染** | 每个 Phase 0 块一行/一区，显示 `trigger_condition` |
| **六色分类** | 每块按 2×2 × kind 着色（恶意=暖色 / 非恶意=冷色）：非动作·恶意 / 非动作·非恶意 / 动作·无偏差恶意 / 动作·有偏差恶意 / 动作·无偏差非恶意 / 动作·有偏差非恶意 |
| **frontmatter 块** | 单独渲染（元数据头），正文格式与其他块一致但**强制灰色**（phase0 kind 覆盖 vdecl 的 non_action 着色） |
| **能力空间** | D/A 标签：声明能力（declared）与真实能力（actual）并列，`intended_workflow` 展示 |
| **meta 块** | 仅保留 `verdict` badge（去掉 quadrant 等冗余文本） |
| **Modal（块审计信息）** | 点击恶意/动作块弹出：block_id、触发条件、`core_instruction`、2×2 六色 badge、外部关联代码片段（`capability_code_evidence` file:line + 代码） |
| **攻击链 DAG 图** | Modal 内的 `m-graph`：`User` → 构造的用户输入 → 恶意块 → `flow_items`（具体恶意代码节点），**原生 JS/CSS/SVG**（Cytoscape.js + Dagre 风格，手写 `renderGraph`，无外部依赖） |

### 10.2 攻击链 DAG 图设计（积累的经验）

- **节点布局**：统一节点宽度（如 170px）+ 首列中心偏移 `COL_W/2`——避免 User 节点右侧空白 + 左侧被裁剪。
- **文本完整**：节点全文本渲染；超出边界出现滚动条。
- **宽度约束**：`m-graph` 限宽 + 内部横向滚动（**不给外层 card 加横向滚动**）。
- **flow-item 路径**：显示**相对 skill 根目录**的路径，不显示完整路径。
- **定义顺序**：`renderGraph` 定义移到 `<head>`（在调用前），避免 ReferenceError。

### 10.3 批量报告（`report_html.py` → `report.html`）

- 自包含单页（内联 CSS/JS，无外部依赖，浏览器直接打开）。
- 概览统计：case 数 / 有结果数 / malware 数 / det 与 llm 判分数 / 匹配数。
- 指标表：det 与 llm 轨道并排（Acc/Prec/Recall/F1/FPR/FNR，malware 为正类）。
- 每 case 可展开：verdict + 象限 + 声明/实际/未声明（风险着色）/过度声明能力、数据流链、rule_engine、relaxed_veto、findings。
- 搜索框：按 case 名称 / verdict 实时过滤。

### 10.4 系统示意图（`docs/system-diagrams.md`）

8 张 mermaid 图：系统架构图、完整审计时序图、恶意判定流程图、Phase 0 块划分、Phase 1 A/D 提取、Phase 2 偏差检测、Phase 3 恶意审计、Phase 4 恶意调用链。GitHub 网页端直接渲染。

---

## 十一、验证与基准

### 11.1 冒烟测试

```bash
npm run test:smoke
# PASS: jeremy    （Python dropper 必须判 malware）
# PASS: ai-wrapper（JS 反向 shell 必须判 malware）
```

### 11.2 基准判分（`benchmark.py`）

- malware 为正类，判分只用二元标签（**不做象限准确率**——象限是主观定义，无法作为客观 ground truth）。
- 指标：Acc / Prec / Recall / F1 / FPR（误报率）/ FNR（漏报率）。
- 两轨对比：**det-track**（`_det_verdict.verdict`，确定性）vs **llm-track**（`verdict`，LLM judge）。
- Ground truth 从路径段推导，`experiment/benchmark.yaml` 可覆盖。

### 11.3 已知误报（设计动因）

> 1password-1 是良性密码管理器，诚实声明读凭证能力，被确定性规则 `rule_3`（凭证窃取）误判为 malware。

这正是**意图覆盖原则 + V_decl + LLM Judge** 设计要解决的假阳性问题：声明敏感能力 ≠ 恶意，需要语义层放行。

### 11.4 schema 校验

```bash
npm run schema:check   # result.json / <skill>_trace.json 全量校验
python scripts/schema_check.py --file <path> --schema final-result
```

---

## 十二、目录结构

```
MAS4MalSkill/
├── package.json                # npm scripts（audit/batch/benchmark/report/page/prompt:render/schema:check/test:smoke）
├── requirements.txt            # Python 依赖（pyyaml + tree-sitter 系列）
├── README.md                   # 使用手册（两模式 + 输入输出约定）
├── docs/
│   ├── system-spec.md          # 本文档（系统说明书）
│   ├── system-diagrams.md      # 系统示意图（8 张 mermaid）
│   ├── execution-plan.md       # 修改执行计划（Phase 0-4 进度）
│   ├── my-approach-modification-plan.md  # 修改计划依据（Phase 0-3）
│   ├── chunking-phase0-v2.md   # 块划分 v2 设计（触发条件块）
│   ├── p-flow-investigation.md # P-flow 调研（Phase 3.3）
│   ├── skill-scanner/          # 旧版 scanner 参考
│   └── schemas/                # result / final-result / trace 三个 JSON Schema
├── src/biv/                    # BIV 核心实现（Python）
│   ├── taxonomy.py             # 7×29 能力 + 8×36 意图 + 15 规则 + 10 kill-chain + 4 compound + tool 映射
│   ├── trace.py                # TraceContext（线程安全追踪，与 result 分离）
│   ├── skill_parser.py         # 稳定单 skill 目录解析（各入口共用）
│   ├── chunking.py             # Phase 0：块划分 v2（frontmatter 块 + body 行）
│   ├── declared_track.py       # Module 1：D(s) 声明能力提取（D_det + 3 重幻觉控制）
│   ├── actual_track/           # Module 2：A(s) 实际能力提取
│   │   ├── ast_analyzer.py     #   AST 污点分析（Python/JS/TS/Shell）
│   │   ├── regex_engine.py     #   Regex 能力映射
│   │   └── llm_instruction.py  #   LLM 指令分析（validate）
│   ├── deviation.py            # Module 3：偏差检测（U/O/compound/relaxed-veto 条件）
│   ├── root_cause.py           # Module 4：15 规则引擎 + LLM 分类器 validate
│   ├── malicious_detect.py     # Module 5：Relaxed-Veto + LLM Judge + final_verdict
│   ├── prompts.py              # 提示词唯一权威源（渲染 + taxonomy_ref）
│   └── orchestrator.py         # 三阶段编排器 + CLI + build_det_evidence + capability_code_evidence 组装
├── scripts/                    # 入口与薄封装
│   ├── biv_audit.py            # [模式A] 单 skill 审计（--evidence 精简模式）
│   ├── batch_audit.py          # [模式A] 批量确定性审计（递归发现 + 镜像结果目录）
│   ├── skill_parse.py          # skill_parser 的 CLI（workflow 复用）
│   ├── skill_chunk.py          # Phase 0 CLI（workflow 复用）
│   ├── prompt_render.py        # 提示词渲染 CLI（workflow 复用）
│   ├── biv_workflow.js         # [模式B] LLM 单 case 审计（Workflow + Agent）
│   ├── batch_workflow.js       # [模式B] LLM 批量审计（pipeline 模式）
│   ├── skill_page.py           # 每 case 标注页面（六色块 + modal + 攻击链 DAG）
│   ├── report_html.py          # 批量 HTML 报告
│   ├── benchmark.py            # 基准判分（det vs llm）
│   ├── schema_check.py         # JSON Schema 校验
│   └── register_dataset.py     # 数据集自动注册到 benchmark.yaml
└── experiment/
    ├── cases/                  # 测试用例（路径段 = ground truth：benign/ malware/）
    └── results/                # 批量输出（.gitignore 排除，镜像 cases 目录 + report.html + pages/）
```
