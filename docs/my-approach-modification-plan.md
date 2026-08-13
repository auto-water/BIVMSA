# My Approach — 修改计划

> 分支：`my-approach`（基于 `BIV`）。
> 设计依据：`docs/my-approach-design.md`（两轮 D-A 校对架构 + 协议决策 P1-P7）。
>
> **核心结论**：协议模型不变（D/A 集合、U=A−D、O=D−A、compound flags、15 规则、Relaxed-Veto、LLM Judge），
> 通过两个 agent 补丁解决已识别问题，新增声明轨道恶意通道覆盖无偏差恶意盲区。
>
> **执行顺序**：Phase 0 规范输出 → Phase 1 可视化 → Phase 2 测试基准 → Phase 3 修改。

---

## 一、背景与已确认问题

### 1.1 两个技术问题（原架构）

| 问题 | 现状 | 根因 |
|------|------|------|
| **P-AST 跨语言不同步** | Python（标准库 ast，过程间污点分析）完整；JS/TS（tree-sitter + regex 补充）弱；Shell（tree-sitter-bash）弱 | 逐语言实现深度不一致，同一行为在不同语言产出不同 A(s) 完整度 |
| **P-FLOW 执行流不完整** | flow(s) 全部来自 `ast_analyzer.py` 的 `flows_ast`（Python 单文件过程间）；JS/Shell 无 flow；SKILL.md 编排链缺失 | 静态跨文件调用图构建脆弱（动态导入、环境变量驱动路径）；无入口点追踪 |

结果：`exfiltration_chain`（58% 先验）、`rce_chain`（86% 先验）退化为**同文件能力共现**的近似判断（见 `deviation.py:82-112`）。

### 1.2 2×2 分类模型与盲区

两个正交维度：
- **偏差轴**：代码行为 vs 语义（声明）行为是否一致（U/O 是否非空）
- **恶意轴**：行为本身是否违背用户意图且可能造成负面影响

| | 无偏差 (D≈A) | 有偏差 (U/O 非空) |
|---|---|---|
| **恶意** | 无偏差恶意 ❌ 盲区 | 有偏差恶意 ✅ 覆盖到位 |
| **非恶意** | 无偏差非恶意 ✅ 平凡覆盖 | 有偏差非恶意 ✅ 覆盖到位 |

**盲区根因**：整个判定管线（compound flags / 15 规则 / Relaxed-Veto）都以 U、flow 为信号源。
若 D≈A，全部不触发，Judge 读到空的 Φ(s) 判良性。**系统从不问"声明本身是否恶意"。**

### 1.3 无偏差恶意的判定原则（已确认）

> **是否存在任何合理的用户授权或合法使用场景？**
> - 不存在 → **无条件有害模式** → 只要出现即恶意，不看上下文
> - 存在 → 条件依赖 → 归语义层（Judge）判断

示例：*"外发用户密钥到第三方站点"* = 无条件恶意；*"用户明确要求时删除本地密钥"* = 非恶意（用户授权锚）。

### 1.4 方案定位

**混合架构**：静态分析（成熟、确定性、可复现）为主干 + agent 补薄弱点（语义均衡、执行流补全）+ 声明轨道恶意通道（V_decl）。**非完全 agent 驱动。**

---

## 二、Phase 0：规范输出格式

> 前置目标：让审计结果可被机器稳定消费、可被可视化、可作为基准判分。当前问题：trace 与 result 混在一个 JSON（`orchestrator.py:815`）。

### 2.1 目标形态：两个独立 JSON 文件（决策 P7）

```
实验输出目录/result.json     ← 结论 + 证据（消费方读取）
实验输出目录/trace.json      ← 过程日志（排查时读取）
```

trace 按 record id / phase 索引，不内嵌于 result（决策 P5）。

### 2.2 Result JSON Schema（标准化）

```jsonc
{
  "meta": {
    "skill_name": "string",
    "skill_dir": "string",
    "audit_time": "ISO8601",
    "pipeline_version": "string",
    "trace_ref": "trace.json"            // 指向过程日志
  },

  "classification": {                    // 2×2 象限（Phase 1 可视化输入）
    "deviation_axis": "none | deviated",
    "malicious_axis": "malicious | benign",
    "quadrant": "no-deviation-benign | no-deviation-malicious | deviated-benign | deviated-malicious"
  },

  "verdict": {
    "verdict": "benign | malware",
    "confidence": 0.0-1.0,
    "source": "relaxed_veto | rule_engine | llm_judge | v_decl | llm_judge+veto | ...",
    "reasoning": "string"
  },

  "evidence": {                          // 证据链（全在 result 层，含原文引用）
    "declared":          [{"capability": "...", "source": "...", "evidence": "原文引用"}],
    "actual":            [{"capability": "...", "source": "...", "evidence": "原文引用"}],
    "undeclared":        ["capability", ...],
    "overdeclared":      ["capability", ...],
    "flows":             [{"source": "...", "source_location": "...", "transforms": [], "sink": "...", "sink_location": "..."}],
    "compound_flags":    {"exfiltration_chain": bool, "rce_chain": bool, "code_obfuscation": bool, "data_lineage_violation": bool},
    "unconditional_patterns": [           // V_decl 命中（Phase 3.1 新增）
      {"pattern": "U1", "anchor": "untrusted_domain", "evidence": "..."}
    ]
  },

  "root_cause": {
    "classification": "adversarial | non_adversarial | ambiguous",
    "intent_category": "A-H",
    "intent_leaf": "A1...H2",
    "kill_chain": "string | null",
    "rule_engine_match": "rule_id | null",
    "classifier_source": "deterministic_rule | llm_classifier | none"
  },

  "capability_counts": {                 // 基准判分用
    "declared": n, "actual": n, "undeclared": n, "overdeclared": n
  }
}
```

### 2.3 Trace JSON Schema（标准化）

```jsonc
{
  "meta": { "skill_name": "...", "start_time": "...", "total_duration_ms": 0 },
  "phases": { "extract": {"step_count": 0, "warn_count": 0, "error_count": 0, ...} },
  "records": [                          // 现有 TraceRecord 结构保留
    {"timestamp": "...", "phase": "...", "step": "...", "level": "...", "message": "...", "data": {...}}
  ],
  "agent_calls": [                      // 新增：LLM 调用日志
    {"call_id": "...", "role": "d_llm | a_llm_instr | classifier | judge | trace", "agent_id": "...", "prompt_len": 0, "duration_ms": 0, "tokens_in": 0, "tokens_out": 0, "retries": 0, "raw_output_hash": "..."}
  ],
  "decisions": [                        // 新增：决策记录（为何如此判定）
    {"record_id": "...", "decision": "classified_open", "reason": "..."}
  ]
}
```

### 2.4 实现任务

| # | 任务 | 落点 |
|---|------|------|
| 0.1 | 定义 result.schema.json / trace.schema.json（JSON Schema 文件） | `docs/schemas/` |
| 0.2 | `orchestrator.py` 输出改为写两个文件（result.json + trace.json），删除内嵌 trace | `src/biv/orchestrator.py` |
| 0.3 | `trace.py` 增加 `agent_calls` 与 `decisions` 记录 API | `src/biv/trace.py` |
| 0.4 | `build_det_evidence` 适配新 schema（workflow 消费兼容） | `src/biv/orchestrator.py` |
| 0.5 | `batch_audit.py` 输出到 `experiment/results/{result,trace}.json` | `scripts/batch_audit.py` |

**验收**：对 2 个现有 case 跑通，result.json 与 trace.json 均生成且 schema 校验通过。

---

## 三、Phase 1：基本可视化

> 目标：把审计结果变成可读的图形，暴露 2×2 象限、能力集合关系、偏差结构与执行流。
> 技术选型：`matplotlib`（离线 PNG）+ 可选 HTML 报告。新脚本，不侵入核心。

### 3.1 可视化清单

| # | 图 | 输入 | 说明 |
|---|----|------|------|
| V1 | **2×2 象限散点图** | result.json 的 classification | 每个 skill 一个点，x=偏差信号强度，y=恶意信号强度，四象限着色 |
| V2 | **能力集合 Venn 图** | evidence.declared / actual | D(s) 与 A(s) 的交集、U、O 直观呈现 |
| V3 | **偏差风险条** | evidence.undeclared | 按 Critical/High/Medium 分色的 U 条形图 |
| V4 | **执行流链图** | evidence.flows | source → transform → sink 有向图（networkx / graphviz） |
| V5 | **单 case 仪表盘** | 单个 result.json | verdict + 象限 + 各信号汇总，一图看懂 |

### 3.2 实现任务

| # | 任务 | 落点 |
|---|------|------|
| 1.1 | 新建 `scripts/viz_audit.py`（读 result.json，出 V1-V4） | `scripts/viz_audit.py` |
| 1.2 | 新建 `scripts/viz_case.py`（单 case 仪表盘 V5） | `scripts/viz_case.py` |
| 1.3 | `package.json` 增加 `viz` / `viz:case` 脚本 | `package.json` |

**验收**：对现有 2 个 case 跑出 PNG；2×2 图上两个 case 落在"有偏差恶意"象限。

---

## 四、Phase 2：可测试基准

> 目标：产出**一般可测试基准**（benchmark）——覆盖 2×2 四个象限 + 边界 case 的用例集 + 判分脚本。
> 现状：仅 2 个 case（都是 malware）。需要补齐良性、无偏差恶意、边界。

### 4.1 用例矩阵（目标）

| 象限 | 目标数量 | 特征 | 示例 |
|------|---------|------|------|
| 无偏差非恶意 | 3 | 纯文档只读 skill；正常工具 skill；描述与代码一致 | 格式化工具、翻译工具 |
| 无偏差恶意 | 2 | 诚实声明的恶意 skill（V_decl 应命中） | "导出 SSH 密钥到服务器"；挖矿 skill |
| 有偏差非恶意 | 2 | 过度工程、模板残留、文档错误（G 类） | 声明了未用的 Bash 权限 |
| 有偏差恶意 | 2（现有）+ 1 | dropper、reverse shell（现有）；再加一个跨文件链 | ai-wrapper / jeremy + 新增跨文件外泄 |
| 边界 | 2 | 模糊声明、上下文依赖删除 | "用户要求时清理密钥" |

### 4.2 基准结构

```
experiment/cases/<case-name>/        # 现有结构不变
├── SKILL.md
├── scripts/...
└── .expected                        # "malware" | "benign"

experiment/benchmark.yaml            # 基准清单：case → {象限, 期望, 说明}
```

### 4.3 判分指标

| 指标 | 公式 |
|------|------|
| 准确率 | (TP+TN)/(P+N) |
| 精确率 / 召回率 / F1 | 标准定义（malware 为正类） |
| **象限准确率** | 每象限正确率单独统计（暴露 2×2 分布） |
| V_decl 命中率（Phase 3 后） | 无偏差恶意象限的检出率 |
| 确定性 vs LLM 对比 | `run_deterministic_pipeline` vs workflow 判分差异 |

### 4.4 实现任务

| # | 任务 | 落点 |
|---|------|------|
| 2.1 | 新建用例（按 4.1 矩阵，先建 benign 与无偏差恶意各 1-2 个） | `experiment/cases/` |
| 2.2 | 新建 `experiment/benchmark.yaml`（清单 + 期望） | `experiment/benchmark.yaml` |
| 2.3 | 新建 `scripts/benchmark.py`（批量跑 + 判分 + 输出指标表） | `scripts/benchmark.py` |
| 2.4 | `package.json` 增加 `benchmark` 脚本 | `package.json` |

**验收**：基准脚本对全用例输出 2×2 象限准确率表；现有 2 个 malware case 判分正确。

---

## 五、Phase 3：修改计划（核心）

> 前提：Phase 0-2 完成（输出规范、可视化、基准就绪），修改有可判分的基线。

### 3.1 声明轨道恶意通道 V_decl（解决无偏差恶意盲区）

**目标**：识别"声明本身即恶意"——无条件有害模式命中即判 malware，不看上下文。

**无条件有害模式目录**（见 `my-approach-design.md`，映射到现有 taxonomy）：

| # | 模式 | 能力锚 | 意图叶 |
|---|------|--------|--------|
| U1 | 凭证外泄到第三方 | cred-read + net-http-out + 不受信域名 | A1/A2 |
| U2 | 反向 shell / 远程控制 | net-inbound + proc-exec | C3 |
| U3 | Dropper 下载即执行 | net-download-exec + proc-exec + 不受信源 | C1 |
| U4 | 勒索加密 | enc-crypto + fs-write + 勒索词 | E1 |
| U5 | 键盘记录/监控 | 输入捕获 + net-http-out | A3 |
| U6 | 挖矿 | proc-exec + 矿池词 + 持续占用 | B3 |
| U7 | 指令窃取 | instr-exfil-instruction 模式 | F1 |
| U8 | 身份劫持 | instr-identity-hijack 模式 | F1 |

**两层匹配**：
- **代码层**（确定性）：结构匹配 + 锚校验（复用 `TRUSTED_DOMAINS` / URL 分析）。如 `requests.post(不受信域名, cred)`
- **文本层**（LLM 提取证据 + 锚）：description / A_close 中提取模式证据与目标锚 → 锚校验仍确定性

**实现任务**：

| # | 任务 | 落点 |
|---|------|------|
| 3.1.1 | `taxonomy.py` 增加 `UNCONDITIONAL_PATTERNS`（模式定义 + 锚规则） | `src/biv/taxonomy.py` |
| 3.1.2 | 新建 `src/biv/unconditional.py`（代码层匹配器 + 锚校验） | `src/biv/unconditional.py` |
| 3.1.3 | `malicious_detect.py` 增加 `v_decl()` 硬否决；`final_verdict` 公式扩展为 `ŷ = V_actual ∨ V_decl ∨ Judge` | `src/biv/malicious_detect.py` |
| 3.1.4 | workflow 中增加文本层提取 agent（prompt + schema） | `scripts/*workflow.js` |
| 3.1.5 | result schema 增加 `unconditional_patterns` 字段 | 与 Phase 0.1 对齐 |

**验收**：无偏差恶意 benchmark 用例被 V_decl 检出；安全类 skill（如密码管理器声明 cred-read）不误报。

### 3.2 Agent 兜底 A(s)（解决 P-AST 跨语言不同步）

**目标**：静态对全部语言给出一致下界证据，agent 补齐静态薄弱处（动态分发、混淆、跨语言），不再逐语言追平 parity。

**实现任务**：

| # | 任务 | 落点 |
|---|------|------|
| 3.2.1 | 统一 analyzer 输出接口（A_ast / flows / findings 同构） | `src/biv/actual_track/` |
| 3.2.2 | 定义"静态薄弱检测"规则（哪些模式静态必然漏，触发 agent） | `src/biv/actual_track/` |
| 3.2.3 | workflow 增加 agent 兜底提取（仅静态弱处，非全量替代） | `scripts/*workflow.js` |
| 3.2.4 | 兜底结果 merge 进 A(s)，来源标注 `source_type: agent_gap` | `orchestrator.py` |

### 3.3 Agent 执行流补全（解决 P-FLOW 不完整）

**目标**：从 SKILL.md 入口点出发，agent 追踪完整执行链（SKILL.md → 脚本 → 函数 → sink），产出跨文件 flow chain，喂给现有 compound flag 检测。

**实现任务**：

| # | 任务 | 落点 |
|---|------|------|
| 3.3.1 | 入口点提取：SKILL.md 中引用脚本的指令 → 追踪起点列表 | `scripts/*workflow.js` |
| 3.3.2 | 每个入口点一个 agent，追踪并输出完整链（D₂ 头节点 → A₂ 序列） | `scripts/*workflow.js` |
| 3.3.3 | 链结果 merge 进 flow(s)，使 exfiltration_chain / rce_chain 基于**证明的数据流**触发 | `deviation.py` |
| 3.3.4 | 追踪边界：skill 目录内，仅 skill 声明的函数/变量；标准库/三方库停在 sink 并记录 capability | agent prompt 约束 |

**验收**：跨文件外泄 benchmark 用例的 `exfiltration_chain` 基于完整链触发（不再是共现近似）。

---

## 六、依赖关系与里程碑

```
Phase 0 输出规范 ──→ Phase 1 可视化 ──→ Phase 2 基准 ──→ Phase 3 修改
   (2个case可跑)      (图可看)           (象限判分)      (V_decl→A兜底→流补全)

里程碑 M1：Phase 0-2 完成，基准判分脚本可用（基线建立）
里程碑 M2：V_decl 上线，无偏差恶意被检出（3.1）
里程碑 M3：agent 兜底 + 流补全上线，跨文件链触发（3.2 + 3.3）
```

## 七、风险与对策

| 风险 | 对策 |
|------|------|
| V_decl 误报安全类 skill | 锚校验严格（第三方/不受信目标才命中）；benchmark 含安全类负例 |
| agent 兜底引入幻觉 | 复用 3 重幻觉控制（taxonomy-echo / 证据锚定 / 关键词）；trace 记录原始输出 |
| 流补全链过长 | 追踪边界约束 + 深度上限；链只补到 taxonomy sink |
| 输出格式改动破坏 workflow 兼容 | `build_det_evidence` 适配层先行；result schema 后向兼容 |
