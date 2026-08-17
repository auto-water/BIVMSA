# P-FLOW 执行流补全 — 调研报告

> 日期：2026-08-13
> 状态：调研完成，方案待评审
> 关联：`my-approach-modification-plan.md §3.3`（已有蓝图）、`src/biv/actual_track/ast_analyzer.py`（现状）、`src/biv/deviation.py`（消费方）、`scripts/skill_page.py`（前端）

---

## 一、问题定义

**P-FLOW** = `flows_ast` 数据流链不完整。当前 flow(s) 全部来自 `ast_analyzer.py` 的 `run_ast_analysis`，表现为**能力级三元组**（source/sink 是 taxonomy 能力码，不是变量级数据流），且存在四个缺口（见 §3）。直接后果是 `deviation.py` 的 `exfiltration_chain` / `rce_chain` 复合标志**退化为能力共现近似判断**（无 flow 证据时 fallback），误报率偏高（先验 exfil 58% / rce 86%，见 modification-plan §1.1）。

---

## 二、现状梳理（代码实证）

### 2.1 生成：`run_ast_analysis`（ast_analyzer.py:1408）

按脚本后缀分派三种语言分析器：

| 语言 | 分析器 | taint 能力 | flow 产出 |
|------|--------|-----------|----------|
| `.py` | `analyze_python_file`（标准库 `ast`） | **强**：`_propagate_param_taint` 参数注入 + `_analyze_function_body` 函数间传播 + `_analyze_function_returns` 返回 taint + class 属性追踪 | 能生成 |
| `.js/.ts` | `JSTaintAnalyzer`（tree-sitter） | **弱**：`_check_var_decl`/`_check_bare_call`/`_check_indirect_source`，无参数注入、无函数间传播、无返回 taint | 几乎不生成 |
| `.sh` | `ShellTaintAnalyzer`（tree-sitter-bash） | **弱**：`_check_pipeline` 管道匹配 | 仅管道场景 |

flow 三元组结构：`{source: capability_code, source_location: "file:line", sink: capability_code, sink_location: "file:line"}`。**source/sink 是能力码而非变量**，无法回答"哪个数据从哪到哪"。

### 2.2 消费：`detect_compound_flags`（deviation.py:45-112）

- `exfiltration_chain`：flow 中 `fs-read* → net-*`；**无 flow 则 fallback 到 `fs_read_caps && net_out_caps` 能力共现**（:82-85）
- `rce_chain`：flow 中 `net* → fs-write`（+proc-exec）或 `fs* → proc-exec`（+net）；**无 flow 则 fallback 到 `net && fs-write && proc-exec` 共现**（:109-112）

关键：**flow 证据只是"加分项"，没有证据时能力共现照样触发** → compound flag 对能力集合高度敏感，容易误报（良性 skill 同时声明读文件+网络即可能被标记）。

### 2.3 前端消费：`skill_page.py`

- 句子 → `sentence_classifications[].capabilities[]` → `capability_code_evidence`（file:line + snippet）✅ 已实现（恶意句点击可看代码片段）
- 句子 → **flow 链**（SKILL.md 指令 → 脚本 → 数据流）❌ 未接通——modal 卡片 "Flow" 区域目前无真实数据

---

## 三、四个缺口

| 缺口 | 描述 | 影响 |
|------|------|------|
| **G1 能力级而非数据级** | flow 的 source/sink 是能力码，不含变量名/中间变换 | 无法展示真实数据路径，无法证明"具体哪个数据流到 sink" |
| **G2 JS/Shell taint 弱** | JS/Shell 无参数注入、无函数间传播、无返回 taint（与 Python 不对齐） | JS/Shell skill 的 flows_ast 基本为空 |
| **G3 SKILL.md 编排链缺失** | SKILL.md 中"运行 script X"的指令与脚本内数据流无关联 | 前端点击 SKILL.md 指令句看不到"指令→脚本→sink"链；无入口点追踪 |
| **G4 句子→flow 关联缺失** | `sentence_classifications`（SKILL.md 句子）与 `flows_ast`（脚本 file:line）两套数据无桥接 | 即使有 flow，前端也无法从句子定位 |

---

## 四、实证（std-cases-4 全量审计结果）

2026-08-13 全量跑通 4 个 case 后的 `flows_ast` 实际数据：

| case | 语言/脚本 | flows_ast | compound flags | 真值 |
|------|-----------|-----------|----------------|------|
| 1password-1 | 无脚本 | 0 | 全 false | benign ✅ 正确 |
| 2captcha | 无脚本 | 0 | 全 false | benign ✅ 正确 |
| 000-jeremy | Python `content_validator.py` | **1（自环）** | `rce_chain=true` | malware ✅ 命中 |
| ai-wrapper | JS `generateContent.js` | **0** | `rce_chain=true` | malware ✅ 命中 |

### 案例 A：000-jeremy（Python dropper）

- 真实链：`urlopen(CONFIG_URL)` → 下载写盘（fs-write）→ `chmod +x` → `subprocess.run(shell=True)`（proc-exec-shell）→ 后台线程执行
- 实测 flows_ast 仅 1 条：`net-http-out (content_validator.py:20) -> net-http-out (content_validator.py:20)` —— **自环**（urlopen 同时被识别为 source 和 sink），**未捕捉到 fs-write → proc-exec 的 dropper 链**
- `rce_chain=true` 靠**能力共现**（A_ast 含 net-http-out/proc-exec/proc-exec-shell + U 含 fs-write）触发，而非证明的数据流

### 案例 B：ai-wrapper（JS reverse shell + dropper）

- 真实链：`net.createConnection(C2:4444)` → `exec(data)`（远程命令）→ `writeFileSync(initScript)` → `execSync(node initScript)`
- 实测 flows_ast = **0**（JS taint 传播未跟踪 socket data 变量到 sink）
- `rce_chain=true` 同样靠能力共现（net-socket-out + proc-exec + fs-write 在 A）触发

**结论**：即使 Python case，跨方法的 dropper 链也未被 flow 检测捕获；JS case 完全无 flow。compound flag 的"证明链"能力实际上**从未被用到**，当前全靠共现近似。

---

## 五、候选方案

### 方案 A — 确定性桥接（零成本，立即见效）

复用已有三件套：`sentence_classifications[].capabilities[]`、`capability_code_evidence`（cap → file:line）、`flows_ast`（file:line 级）。

桥接规则：flow 的 `source_location`/`sink_location`（`file:line`）与某 capability 的 code evidence 位置匹配 → 该 flow 归到该 capability → 归到引用该 capability 的句子 → 前端句子的 modal 显示 flow。

- 优点：纯确定性、零 LLM 成本、改动小（新增 result 字段 `sentence_flows`）
- 局限：**flows_ast 本身不完整**（实证 0-1 条），能桥接展示的 flow 很少——治标不治本，但先让前端"有东西可看"

### 方案 B — 入口点驱动的 Agent 流追踪（modification-plan §3.3 落地）

三步：
1. **B1 入口点提取**（确定性）：从 SKILL.md 提取引用脚本的指令（如 jeremy SKILL.md:99 `python scripts/content_validator.py ...`）→ 追踪起点列表。可用 `skill_parse.py` 的 `scripts` 列表 + 正则/LLM 匹配 SKILL.md 中引用它们的句子
2. **B2 每入口点一个 agent 追踪完整链**：prompt 给出 SKILL.md 指令句 + 脚本全文，agent 输出 `[D₂ 头节点 → A₂ 序列 → sink]` 链（跨函数/跨文件），复用 3 重幻觉控制（要求引用证据、区分"讨论攻击"与"执行攻击"、trace 记录原始输出）
3. **B3 merge 进 flows**：agent 链转成统一 flow 结构 merge 进 `flows_ast`，`source_type: agent_traced`；`deviation.py` 的 exfil/rce chain 改为**优先消费 agent 链**，无链才 fallback 共现

- 优点：跨语言统一（agent 不看语言）、补动态路径/环境变量、补 G3 编排链、G2 弱项
- 缺点：agent 成本（每入口点一次调用）、幻觉风险（需严格证据约束）、长脚本链可能超 token（需边界控制）

### 方案 C — JS/Shell taint 对齐 Python（补 G2）

给 `JSTaintAnalyzer`/`ShellTaintAnalyzer` 补参数注入、函数间传播、返回 taint，对齐 Python 能力。

- 优点：纯静态、确定性、可复现
- 缺点：工作量大，tree-sitter 手工实现脆弱（与 Python 标准库 ast 相比要手写大量 CST 遍历）；只解决 G2，不解决 G3/G4

### 方案 D — 数据级污点增强（flow 记录变量链）

重构 flow 结构，记录 `[source_var → transform → sink_var]` 的变量链。

- 优点：flow 从"能力级"升级为"数据级"，可展示真实路径
- 缺点：大工程、需重构 analyzer + deviation + schema + 前端，周期长

---

## 六、推荐方案与实施路径

**推荐 A + B 组合**（分层递进，非互斥）：

```
P0（本周可做） 方案 A：新增 result 字段 sentence_flows（确定性桥接）
               → 前端恶意句 modal 显示已关联 flow（可能少但真实）
P1（下一迭代） 方案 B：入口点提取（B1）→ agent 追踪链（B2）→ merge（B3）
               → exfil/rce chain 基于"证明链"触发，benchmark 对比共现版
P2（视需求）   方案 C 对齐 JS/Shell taint；方案 D 数据级重构（长期）
```

**优先级判断依据**：
- A 改动最小、风险最低，立即让前端具备 flow 展示能力，是 P-FLOW 的"可见性"补全
- B 是唯一能补 G3（SKILL.md 编排链）的方案，也是让判定脱离共现近似的正解；agent 成本可控（每 skill 通常 1-3 个入口点）
- C/D 工程量大，且 C 只补 G2、D 周期长，放后续；先看 B 上线后 benchmark 是否消除误报

---

## 七、实施步骤（详细）

### P0 — 方案 A：确定性桥接

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| A1 | 桥接逻辑：flow 位置 ∩ cce 位置 → capability → 句子 | `orchestrator.py`（组装 `sentence_flows`）或 `skill_page.py`（渲染时桥接） | 恶意句 modal 出现 Flow 数据（哪怕 1 条） |
| A2 | result schema 声明 `sentence_flows`（每句关联的 flow 链） | `docs/schemas/result.schema.json` | schema:check 通过 |
| A3 | 前端 modal "Flow" 区域渲染关联链 | `scripts/skill_page.py` | 点击恶意句显示 source→sink 链 + 行号 |

### P1 — 方案 B：Agent 流追踪

| # | 任务 | 落点 | 验收 |
|---|------|------|------|
| B1 | 入口点提取：SKILL.md 引用脚本的指令句列表 | `scripts/*workflow.js`（或独立脚本 `skill_parse.py` 增强） | jeremy 提取到 `content_validator.py` 入口 |
| B2 | 每入口点一个 agent，prompt（复用 prompts.py 模板管理）输出跨函数链 | `scripts/*workflow.js` + `src/biv/prompts.py` | 输出含 D₂ 头节点 → A₂ 序列 → sink 与证据 |
| B3 | agent 链 merge 进 flows，`source_type: agent_traced`；deviation 优先消费链 | `orchestrator.py` / `deviation.py` | 跨文件/JS 用例的 chain 基于证明链触发 |
| B4 | 追踪边界：仅 skill 目录内；标准库停在 sink 记录 capability | agent prompt | 链长度受控 |

### P2 — 可选

- 方案 C：`JSTaintAnalyzer` 补参数注入/函数间传播（对齐 Python）
- 方案 D：flow 结构升级为变量级

---

## 八、风险与对策

| 风险 | 对策 |
|------|------|
| agent 链幻觉（编造不存在的调用） | 复用 3 重幻觉控制：要求逐跳证据引用、区分"讨论攻击"与"执行攻击"、trace 记录原始输出；merge 前校验链节点都存在于脚本 |
| agent 成本（每入口点一次调用） | 只对"静态薄弱"触发（先跑确定性，flows 为空或不足才调 agent）；边界限制链长度 |
| A 桥接产出极少（flows_ast 空） | 接受为过渡：A 的价值是让前端先有展示；判定正确性由 B 解决 |
| SKILL.md 入口点提取误判 | 提取后让 agent 确认该指令确实执行脚本（二次校验） |

---

## 九、验收基准

- **可见性**：点击 ai-wrapper 恶意句（如 reverse shell 代码句）modal 显示至少一条 flow（A 提供）
- **正确性**：新增/改造跨文件或 JS/Shell 恶意用例的 `exfiltration_chain`/`rce_chain` 基于**证明链**触发，且 benchmark 误报（FPR）相比共现版下降（B 提供）
- **无回归**：std-cases-4 4 case LLM-track 保持 4/4（benchmark acc=1.0），det-track FPR 不劣化

---

## 十、结论

P-FLOW 问题现状：flows_ast 能力级且基本为空（4 case 实测 0-1 条），compound flag 全程依赖能力共现近似，误报率高；前端句子与 flow 无关联。

建议 **A + B 组合**：A 用零成本确定性桥接让前端先"看到" flow（P0）；B 用入口点驱动的 agent 追踪补全 SKILL.md 编排链与 JS/Shell 弱项，让 exfil/rce 判定基于证明链（P1）。C/D（语言对齐 / 数据级重构）作为长期优化。验收以"证明链触发 + FPR 下降"为准。
