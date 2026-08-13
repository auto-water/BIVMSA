# My Approach — 两轮 D-A 校对设计文档

> 本分支（`my-approach`）的替代实现方案设计。三阶段（能力提取、偏差检测、判定）不变，
> 但采用"信任链传递 + 执行流追踪"的思路替代 BIV 的"双轨独立提取"。
>
> 状态：**设计中**。待协商协议（D/A 字段、时序）后再进入实现。

---

## 一、核心思路

BIV 的做法：D（声明能力）和 A（实际能力）各自独立提取（AST + regex + LLM），事后做集合差。

本方案：**先找出所有 D，再用 agent 跟踪每个 D 的执行流，沿途找到 A。**

- D → agent 追踪 → A：单向因果链，非双轨独立
- 执行模型依据：所有行为都从 SKILL.md 出发。攻击者注入的隐藏行为若要执行，
  一定存在于某条由 SKILL.md 发出的执行流中（或封闭于 skill 内）。
  因此从 D 出发追踪，即可覆盖完整 A。反证法：若某操作既不在 SKILL.md 中，
  也不在 SKILL.md 发出的任何执行流中，则它根本不会被执行。

---

## 二、两轮 D-A 校对架构

### Round 1：信任锚 = 全量 frontmatter → D₁

```
D₁ = {name, description, allowed-tools}    ← 全量使用，不做摘要
```

- LLM 分解 body 为完整操作 A₁ = {op₁, ..., opₙ}
  - A₁_close：闭环于 SKILL.md 内（纯文本指令，无外部引用）
  - A₁_open：引用外部执行（脚本调用、文件引用）
- 粒度规则：以**条件状语**判断操作边界 —— 同一条件状语 = 同一触发条件 = 一条操作
- LLM 比对 D₁ ↔ A₁ → 每个 A₁_i 打偏差标签
- A₁ 之间构造链关系 → 提前识别跨操作交互
- 恶意性判断：对 D₁ 自身 + A₁_close 设置恶意检测，识别言行一致的恶意意图

### Round 2：信任锚 = A₁_open → 重新标定为 D₂

```
D₂ = {D₂_1, ..., D₂_k}     ← 每个 A₁_open 变为一个 D₂
```

- 每个 D₂_i → 1 个子 agent
- 追踪执行流，每个完整操作记为 A₂_j，按执行顺序串联成 chain_i（D₂_i 为头节点）
- 判定：是否完成声明任务？做了哪些未声明动作？
- 追踪边界：目录限定在当前 skill 内，仅追踪 skill 自身声明的函数和变量
- 每轮恶意性判断

### Round 3：最终 D₁-A₁ 校对

- 综合 D₁ + 补充后的 A₁ + 全部 chain_i
- 识别失配且恶意的 chain → 根因分类 → 最终 verdict

---

## 三、已解决的问题

| 问题 | 解决 |
|------|------|
| D₁-A₁ 粒度不匹配 | D₁ 全量使用（frontmatter 很简略）；粒度用条件状语界定 |
| A₁_close 盲区 | 每轮 D 都设恶意性判断，识别言行一致的恶意意图 |
| A₁ 分解粒度 | 条件状语 = 触发条件一致 = 一条操作 |
| 跨链协同作恶 | A₁ 之间构造链关系，第一轮审计即识别 |
| 追踪深度 | 限定 skill 目录内，仅追踪 skill 声明的函数/变量 |

---

## 四、搁置的边界问题（待后续协商）

| # | 边界问题 | 具体内容 |
|---|---------|---------|
| B1 | A₁ 链的链接依据 | SOP 顺序链（显式步骤编号）还是数据依赖链（隐式数据流）？Round 1 阶段做到什么深度？ |
| B2 | D₂ 的形态 | 自由自然语言 → agent 需自行定位入口函数，有歧义。是否需要结构化追踪起点（target_file / entry_point / declared_purpose / expected_capabilities）？ |
| B3 | 信任衰减 | D₂ 源自 LLM 分解（非 ground truth）。若 A₁_open 被漏分解 → 错误标记为 A₁_close → 永远不进 Round 2。是否需要 A₁ 分解的交叉验证？ |
| B4 | 追踪边界实操 | 标准库/第三方库调用如何处理？"停在第三方库但记录 capability"的规则 |
| B5 | 每轮恶意检查的输出 | 串联模式（任一轮命中即终止）还是并联模式（全跑完由 Round 3 综合）？ |

---

## 五、系统流程协议

### 5.1 已确认决策

| # | 决策 | 内容 |
|---|------|------|
| P1 | D/A 统一格式 | D 和 A 共用同一 schema，便于对齐与转化 |
| P2 | type 二值 | `type = [description, action]`。区分标准：有无"发出动作指令"——description 无指令（纯声明），action 有指令 |
| P3 | description 必备字段 | 背景、目的 |
| P4 | action 必备字段 | 背景、目的、发出动作指令、full_chain（下一级动作链表）、关键布尔值（下一级验证完成后填充） |
| P5 | trace/result 分离 | result（审计结论+证据）与 trace（审计过程日志）为两个独立层 |
| P6 | evidence 归属 | 归 **result** 层（审计证据链组成部分） |
| P7 | 物理形态 | result 与 trace 为**两个独立 JSON 文件**（result.json + trace.json），trace 按 record id / phase 索引 |

### 5.2 分层标准

> 字段归哪一层：**它是结论/证据（消费方要读），还是推导过程（排查时用）？**

| 层 | 内容 | 示例 |
|----|------|------|
| **Result** | 结论 + 支撑结论的证据 | D/A 记录（声明层+校验层布尔值）、链结构、偏差标签、各轮恶意判断、最终判定、evidence 原文引用、verified_by |
| **Trace** | 推导过程 + 调试信息 | agent 调用日志（prompt/response/耗时/token/重试）、确定性步骤 I/O、记录推导路径、决策记录、轮次统计 |

### 5.3 建议的统一 D/A schema（含补充字段，待逐字段校对）

```json
{
  "id": "A1-003",
  "type": "action",
  "round": 1,
  "level": 0,
  "parent_id": "D1-001",
  "source": "SKILL.md L47-52",
  "evidence": "引用原文片段",

  "semantics": {
    "背景": {
      "condition": "when user asks for product data",
      "input_from": "A1-002",
      "context": "用户请求产品信息"
    },
    "目的": "获取产品数据并保存到本地",
    "capability_tags": ["net-http-out", "fs-write"]
  },

  "action": {
    "command": "python scripts/calc.py 1 2",
    "trace_target": { "file": "scripts/calc.py", "entry": "main()", "args": ["1", "2"] }
  },

  "full_chain": ["A1-004", "A1-005"],

  "verification": {
    "status": "pending | verified",
    "verified_by": "agent-D2-001",
    "purpose_completed": true,
    "sensitive_side_effects": ["写入 ~/.bashrc"],
    "exceeds_boundary": false
  }
}
```

### 5.4 待协商剩余项

- 逐字段校对统一 schema（id/type/round/level/source/evidence/semantics/action/full_chain/verification）
- 时序设计（各轮之间、轮内并行/串行、检查点）
- 各轮恶意判断的中间 verdict 归属（result 还是独立层）
