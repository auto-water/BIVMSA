# BIV (Behavioral Integrity Verification) 系统文档

> 基于论文 *Behavioral Integrity Verification for AI Agent Skills* (Yuhao Wu et al., 2025, arXiv:2605.11770) 的严格复现。
>
> 输入一个 AI Agent Skill 目录，经过三阶段流水线分析，输出 `benign`（良性，可上架）或 `malware`（恶意，拒绝上架）的审计结论及完整证据链。

---

## 一、系统架构

```mermaid
flowchart TB
    subgraph input["输入"]
        SKILL["Skill 目录<br/>SKILL.md + scripts/ + references/"]
    end

    subgraph phase1["Phase 1: 能力提取 Capability Extraction"]
        direction TB
        D_DET["D_deterministic<br/>确定性解析器<br/>frontmatter to taxonomy"]
        D_LLM["D_llm<br/>LLM 语义提取器<br/>CoT structured output"]
        A_AST["A_ast<br/>AST 污点分析器<br/>Python/JS/TS/Shell"]
        A_REGEX["A_regex<br/>确定性规则引擎<br/>regex to capability"]
        A_LLM["A_llm_instr<br/>LLM 指令分析器<br/>隐藏指令检测"]

        D_DET --> D_MERGE["D(s) = D_det U D_llm"]
        D_LLM --> D_MERGE
        A_AST --> A_MERGE["A(s) = A_ast U A_regex U A_llm_instr<br/>+ flow(s) 数据流链"]
        A_REGEX --> A_MERGE
        A_LLM --> A_MERGE
    end

    subgraph phase2["Phase 2: 偏差检测 Deviation Detection"]
        direction TB
        SETOPS["集合运算<br/>U = A - D 未声明能力<br/>O = D - A 过度声明"]
        COMPOUND["复合威胁标志位<br/>exfiltration_chain<br/>rce_chain<br/>code_obfuscation<br/>data_lineage_violation"]
        PHI["Phi(s) 证据元组组装"]

        SETOPS --> COMPOUND --> PHI
    end

    subgraph phase3["Phase 3: 根因分类 & 恶意判定"]
        direction TB
        RULES["15条确定性规则引擎<br/>first-match-wins"]
        CLASSIFIER["LLM 分类器<br/>10 kill-chain 联合推理"]
        VETO["Relaxed-Veto<br/>V = compound != 0 AND exists U >= High"]
        JUDGE["LLM Judge<br/>CoT + xhigh<br/>Phi(s) 完整证据裁决"]
        VERDICT["最终判定<br/>y_hat = veto OR judge"]

        RULES --> CLASSIFIER
        CLASSIFIER --> JUDGE
        VETO --> VERDICT
        JUDGE --> VERDICT
    end

    subgraph output["输出"]
        JSON["审计结果 JSON<br/>verdict + confidence<br/>evidence chain<br/>trace debug log"]
    end

    SKILL --> phase1
    phase1 --> phase2
    phase2 --> phase3
    phase3 --> JSON

    style phase1 fill:#e1f5fe
    style phase2 fill:#fff3e0
    style phase3 fill:#fce4ec
    style input fill:#e8f5e9
    style output fill:#e8f5e9
```

---

## 一-b、双层运行架构

系统分为两个运行层，通过 `--evidence` 精简证据接口打通：

```mermaid
flowchart TB
    subgraph L1["运行层 1: Python 确定性管线<br/>(biv_audit.py / batch_audit.py)"]
        direction TB
        D1["Phase 1: 确定性能力提取<br/>D_det + A_ast + A_regex"]
        D2["Phase 2: 偏差检测<br/>U/O + compound_flags"]
        D3["Phase 3: 15条规则 + Relaxed-Veto"]
        D1 --> D2 --> D3
        D3 --> E["build_det_evidence()<br/>精简 Phi(s) 证据 JSON"]
    end

    subgraph L2["运行层 2: Claude Code Workflow<br/>(workflow JS, 子代理调度)"]
        direction TB
        W1["子代理: python --evidence<br/>获取确定性 Phi(s)"]
        W2["子代理: D_llm<br/>LLM 语义声明提取"]
        W3["子代理: A_llm_instr<br/>LLM 指令分析"]
        W4["子代理: LLM Judge<br/>CoT + xhigh 裁决"]
        W5["最终判定 verdict + confidence"]

        W1 --> W4
        W2 --> W4
        W3 --> W4
        W4 --> W5
    end

    E --> W1
    E --> W4

    style L1 fill:#e1f5fe
    style L2 fill:#fce4ec
    style E fill:#c8e6c9
```

**两层分工**：

| 层 | 职责 | 产出 |
|----|------|------|
| Python 确定性层 | 静态分析、AST 污点、规则引擎、Relaxed-Veto | `Phi(s)` 精简证据 (纯确定性，无 LLM) |
| Workflow LLM 层 | D_llm / A_llm_instr / LLM Judge | 最终 verdict (综合 Phi(s) + LLM 提取) |

---

## 二、时序图 - 完整审计流程 (Workflow 含 LLM)

```mermaid
sequenceDiagram
    actor User as 用户/Auditor
    participant WF as workflow JS<br/>(编排器 batch_workflow.js)
    participant DET as 子代理: python<br/>biv_audit.py --evidence
    participant LLM as 子代理: D_llm + A_llm_instr<br/>(LLM 并行提取)
    participant JUDGE as 子代理: LLM Judge<br/>(CoT + xhigh)
    participant OUT as 审计结果输出

    User->>WF: Workflow({scriptPath: "batch_workflow.js"})
    WF->>WF: 扫描 experiment/cases/ 发现所有 Skill

    loop 每个 Skill Case
        rect rgb(225, 245, 254)
            Note over WF,DET: 确定性管线 (Python 子代理)
            WF->>DET: 运行 python biv_audit.py <case> --evidence
            DET->>DET: Phase 1: 确定性能力提取<br/>D_det / A_ast / A_regex
            DET->>DET: Phase 2: 偏差检测<br/>U / O / compound_flags
            DET->>DET: Phase 3: 15条规则引擎 + Relaxed-Veto
            DET-->>WF: 返回 Phi(s) 精简证据 JSON
        end

        rect rgb(225, 245, 254)
            Note over WF,LLM: LLM 能力提取 (并行)
            par D_llm: 语义声明能力提取
                WF->>LLM: 声明能力提取 (taxonomy + body)
                LLM-->>WF: declared_capabilities + evidence
            and A_llm_instr: 指令隐藏能力检测
                WF->>LLM: 指令级能力检测 (instr-*)
                LLM-->>WF: instruction_capabilities + is_adversarial
            end
        end

        rect rgb(252, 228, 236)
            Note over WF,JUDGE: 恶意判定
            WF->>JUDGE: LLM Judge<br/>(Phi(s) 证据 + LLM 提取 + 原始内容)
            JUDGE->>JUDGE: CoT + xhigh 综合推理<br/>权衡确定性证据权重
            JUDGE-->>WF: verdict + confidence + reasoning
        end
    end

    WF->>OUT: 汇总所有 case 审计结果
    OUT-->>User: verdict + evidence chain + match summary
```

---

## 二-b、确定性流水线时序 (无 LLM, Python CLI)

```mermaid
sequenceDiagram
    actor User as 用户/Auditor
    participant CLI as biv_audit.py / batch_audit.py
    participant P1 as Phase 1 能力提取
    participant P2 as Phase 2 偏差检测
    participant P3 as Phase 3 规则+判定
    participant OUT as result.json

    User->>CLI: npm run batch (或 python batch_audit.py)
    CLI->>CLI: 扫描 experiment/cases/

    loop 每个 Skill Case
        CLI->>P1: 读取 SKILL.md + scripts/
        P1->>P1: D_det (frontmatter to taxonomy)
        P1->>P1: A_ast (AST 污点分析)
        P1->>P1: A_regex (规则引擎)
        P1-->>P2: D(s) + A(s) + flow(s)

        P2->>P2: U = A - D (未声明能力)
        P2->>P2: O = D - A (过度声明)
        P2->>P2: 4 个 compound flags
        P2-->>P3: Phi(s) 证据元组

        P3->>P3: 15条规则引擎 (first-match-wins)
        P3->>P3: Relaxed-Veto 检查
        P3-->>CLI: _det_verdict (确定性判定)
    end

    CLI->>OUT: 汇总 JSON + trace
    OUT-->>User: verdict + evidence + trace summary
```

---

## 三、数据流图 - 模块间数据传递

```mermaid
flowchart LR
    subgraph Input["输入层"]
        SKILL_MD["SKILL.md<br/>YAML frontmatter + body"]
        SCRIPTS["scripts 目录<br/>.py .js .ts .sh"]
        REFS["references 目录<br/>.md 文档"]
    end

    subgraph Track1["Declared Track"]
        direction TB
        D1["确定性解析<br/>allowed-tools to taxonomy"]
        D2["LLM 语义提取<br/>3重幻觉控制"]
        D3["D(s) 能力集合<br/>+ 来源证据"]
        D1 --> D3
        D2 --> D3
    end

    subgraph Track2["Actual Track"]
        direction TB
        A1["Python AST<br/>污点追踪 source to sink"]
        A2["JS/TS tree-sitter<br/>变量追踪 + regex"]
        A3["Shell tree-sitter<br/>pipeline 流检测"]
        A4["Regex 引擎<br/>模式 to capability"]
        A5["LLM 指令分析<br/>隐藏指令检测"]
        A1 --> A6["A(s) + flow(s) + findings"]
        A2 --> A6
        A3 --> A6
        A4 --> A6
        A5 --> A6
    end

    subgraph Deviation["偏差检测"]
        direction TB
        B1["集合差 U/O"]
        B2["compound flags x4"]
        B3["Phi(s) 证据元组"]
        A6 --> B1
        D3 --> B1
        B1 --> B2 --> B3
    end

    subgraph Verdict["判定层"]
        direction TB
        C1["15条规则<br/>first-match-wins"]
        C2["Relaxed-Veto<br/>V formula"]
        C3["LLM Judge<br/>CoT + xhigh"]
        C4["最终判定<br/>y_hat = veto OR judge"]
        B3 --> C1 --> C3
        B3 --> C2 --> C4
        C3 --> C4
    end

    SKILL_MD --> Track1
    SKILL_MD --> Track2
    SCRIPTS --> Track2
    REFS --> Track2
    Track1 --> Deviation
    Track2 --> Deviation
    Deviation --> Verdict

    style Input fill:#e8f5e9
    style Track1 fill:#e1f5fe
    style Track2 fill:#e1f5fe
    style Deviation fill:#fff3e0
    style Verdict fill:#fce4ec
```

---

## 四、判定决策树 - 从偏差到最终结论

```mermaid
flowchart TD
    START(["Phi(s) 证据元组"]) --> COMPOUND{"compound flags<br/>是否触发?"}

    COMPOUND -->|"否"| RULE_CHECK["15条规则引擎<br/>遍历优先级队列"]
    COMPOUND -->|"是"| VETO_CHECK{"exists t in U(s):<br/>risk(t) >= High?"}

    VETO_CHECK -->|"否"| RULE_CHECK
    VETO_CHECK -->|"是"| VETO_FIRE["Relaxed-Veto 触发<br/>直接判定 MALWARE<br/>confidence >= 0.90"]

    RULE_CHECK --> RULE_MATCH{"规则匹配?"}
    RULE_MATCH -->|"是"| CLASSIFY_ADV{"意图分类<br/>是否为 A-F 对抗性?"}
    RULE_MATCH -->|"否"| LLM_CLASS["LLM Classifier<br/>10 kill-chain 联合推理"]

    CLASSIFY_ADV -->|"是"| JUDGE_ADV["LLM Judge<br/>CoT + xhigh<br/>综合 Phi(s) + 原始内容"]
    CLASSIFY_ADV -->|"否 (G/H)"| JUDGE_BEN["LLM Judge<br/>CoT + xhigh<br/>评估是否为疏忽"]

    LLM_CLASS --> JUDGE_ADV

    JUDGE_ADV --> FINAL{"MALWARE?"}
    JUDGE_BEN --> FINAL

    VETO_FIRE --> FINAL_OUT["输出 JSON<br/>verdict + confidence<br/>+ evidence chain<br/>+ trace debug log"]
    FINAL -->|"是"| MAL_OUT["MALWARE<br/>intent: A-F"]
    FINAL -->|"否"| BEN_OUT["BENIGN<br/>intent: G/H"]

    MAL_OUT --> FINAL_OUT
    BEN_OUT --> FINAL_OUT

    style VETO_FIRE fill:#ffcdd2
    style MAL_OUT fill:#ffcdd2
    style BEN_OUT fill:#c8e6c9
    style FINAL_OUT fill:#e3f2fd
```

---

## 五、能力分类体系 (Taxonomy)

```mermaid
flowchart TB
    TAX["Taxonomy T<br/>7类 x 29项能力"]

    TAX --> NET["Network 网络<br/>risk: HIGH (4项)"]
    TAX --> FS["Filesystem 文件系统<br/>risk: MEDIUM (7项)"]
    TAX --> PROC["Process 进程执行<br/>risk: HIGH (4项)"]
    TAX --> ENV["Environment 环境变量<br/>risk: HIGH (3项)"]
    TAX --> ENC["Encoding 编码<br/>risk: MEDIUM (3项)"]
    TAX --> CRED["Credential 凭证<br/>risk: CRITICAL (3项)"]
    TAX --> INSTR["Instruction 指令级<br/>risk: CRITICAL (5项)"]

    NET --> NET1["net-http-out: HTTP 外发请求"]
    NET --> NET2["net-socket-out: Socket 外连"]
    NET --> NET3["net-inbound: 入站网络监听"]
    NET --> NET4["net-download-exec: 下载并执行"]

    FS --> FS1["fs-read-project"]
    FS --> FS2["fs-read-sensitive"]
    FS --> FS3["fs-read-home"]
    FS --> FS4["fs-write"]
    FS --> FS5["fs-write-sensitive"]
    FS --> FS6["fs-enumerate"]
    FS --> FS7["fs-delete"]

    PROC --> P1["proc-exec"]
    PROC --> P2["proc-exec-shell"]
    PROC --> P3["proc-code-eval"]
    PROC --> P4["proc-code-eval-dynamic"]

    INSTR --> I1["instr-override: 指令覆盖"]
    INSTR --> I2["instr-conceal: 指令隐藏"]
    INSTR --> I3["instr-identity-hijack: 身份劫持"]
    INSTR --> I4["instr-silent-exec: 静默执行"]
    INSTR --> I5["instr-exfil-instruction: 指令窃取"]

    style NET fill:#ffcdd2
    style PROC fill:#ffcdd2
    style ENV fill:#ffcdd2
    style INSTR fill:#ffcdd2
    style CRED fill:#ffcdd2
    style FS fill:#fff9c4
    style ENC fill:#fff9c4
```

---

## 六、意图分类体系 (Intent Taxonomy)

```mermaid
flowchart LR
    subgraph Adversarial["对抗性 Adversarial (18.9%)"]
        direction TB
        A["A: 数据窃取与间谍<br/>A1 凭证窃取 A2 数据外泄<br/>A3 监控 A4 商业间谍 A5 内部侦察"]
        B["B: 财务与变现<br/>B1 广告注入 B3 加密挖矿<br/>B4 加密货币窃取 B5 资源劫持"]
        C["C: 载荷与基础设施<br/>C1 载荷投递 C2 持久化 C3 C2通信<br/>C4 规避 C5 侦察 C6 预置"]
        D["D: 内容与社会工程<br/>D1 钓鱼 D2 虚假信息<br/>D3 社会操纵 D4 身份冒充"]
        E["E: 破坏性<br/>E1 勒索软件 E2 数据擦除 E3 系统破坏"]
        F["F: AI Agent 特定<br/>F1 指令劫持 F2 记忆投毒 F3 会话走私<br/>F4 输出操纵 F5 权限提升"]
    end

    subgraph NonAdv["非对抗性 Non-Adversarial (81.1%)"]
        direction TB
        G["G: 非对抗性<br/>G1 过度工程 G2 防御性过度工程<br/>G3 未完成实现 G4 合法辅助<br/>G5 模板残留 G6 遥测 G7 文档错误"]
    end

    subgraph Amb["模糊 Ambiguous"]
        direction TB
        H["H: 模糊<br/>H1 上下文依赖 H2 证据不足"]
    end

    style Adversarial fill:#ffcdd2
    style NonAdv fill:#c8e6c9
    style Amb fill:#e0e0e0
```

---

## 七、污点分析流程

```mermaid
flowchart TB
    SOURCE_CODE["脚本源码<br/>Python / JS / TS / Shell"] --> PARSE

    subgraph Parse["解析层"]
        direction LR
        AST_PY["Python: ast 模块<br/>标准库 AST 解析"]
        AST_JS["JS/TS: tree-sitter<br/>JavaScript / TypeScript"]
        AST_SH["Shell: tree-sitter-bash<br/>Pipeline 感知解析"]
    end

    PARSE --> Parse
    Parse --> WALK["AST/CST 遍历"]

    subgraph Taint["污点追踪"]
        direction TB
        S1["(1) 识别 Source<br/>urlopen / fetch / curl<br/>os.environ / process.env"]
        S2["(2) 识别 Transform<br/>base64.decode / JSON.parse<br/>codecs.decode"]
        S3["(3) 传播 Taint 标签<br/>跨函数 / 类属性 / f-string<br/>容器下标 / 方法链 / 元组"]
        S4["(4) 检测 Sink<br/>subprocess.run / execSync<br/>eval / bash / fs.writeFile"]
    end

    WALK --> Taint

    S1 --> S2 --> S3 --> S4

    subgraph Output["输出"]
        direction LR
        O1["A(s) 能力集合"]
        O2["flow(s) 数据流三元组<br/>source to transform to sink"]
        O3["findings 发现项<br/>file:line:evidence"]
    end

    S4 --> Output

    style Parse fill:#e1f5fe
    style Taint fill:#fff3e0
    style Output fill:#c8e6c9
```

---

## 八、项目结构

```
MAS4MalSkill/
├── package.json                    # npm scripts (batch/test)
├── docs/
│   ├── skill-scanner/              # 原有 skill scanner 文档
│   │   ├── SKILL.md
│   │   ├── references/             # 威胁模式参考文档
│   │   └── scripts/scan_skill.py   # 旧版 regex scanner
│   └── BIV-SYSTEM-DOCS.md          # 本文档
│
├── src/biv/                        # BIV 核心实现
│   ├── taxonomy.py                 # 7类x29能力 + 意图分类 + 规则 + kill-chain
│   ├── trace.py                    # 结构化调试追踪
│   ├── declared_track.py           # Module 1: D(s) 声明能力提取
│   ├── actual_track/
│   │   ├── ast_analyzer.py         # Module 2: AST 污点分析 (Python/JS/TS/Shell)
│   │   ├── regex_engine.py         # Module 2: Regex 模式 to capability 映射
│   │   └── llm_instruction.py      # Module 2: LLM 指令级能力提取
│   ├── deviation.py                # Module 3: 偏差检测 + compound flags
│   ├── root_cause.py               # Module 4: 15条规则引擎 + LLM 分类器
│   ├── malicious_detect.py         # Module 5: Relaxed-Veto + LLM Judge
│   └── orchestrator.py             # 3-Phase 编排器 + JSON 输出 + CLI
│                                    #   + build_det_evidence() (精简 Phi(s))
│
├── scripts/
│   ├── biv_audit.py                # 单 skill 审计 CLI
│   ├── batch_audit.py              # 批量审计 (确定性)
│   ├── biv_workflow.js             # Claude Code Workflow: LLM 编排
│   └── batch_workflow.js           # Claude Code Workflow: LLM 批量审计
│
└── experiment/cases/               # 测试用例
    ├── 000-jeremy...__CI_B4/       # Python dropper (恶意)
    │   ├── SKILL.md
    │   ├── scripts/content_validator.py
    │   └── .expected -> malware
    └── ai-wrapper-product__CI_B6/  # JS reverse shell (恶意)
        ├── SKILL.md
        ├── scripts/generateContent.js
        └── .expected -> malware
```

---

## 九、运行命令速查

| 命令 | 环境 | 说明 |
|------|------|------|
| `npm run test:smoke` | 终端 / CI | 确定性冒烟测试 (断言 2 case = malware) |
| `npm run batch` | 终端 / CI | 批量确定性审计 (汇总表) |
| `npm run batch:json` | 终端 / CI | 批量审计 to JSON 文件 |
| `npm run audit:jeremy` | 终端 | 单 case 审计 to result.json |
| `Workflow({scriptPath: "scripts/biv_workflow.js", args: {skill_dir: "..."}})` | Claude Code | 单 case 完整含 LLM |
| `Workflow({scriptPath: "scripts/batch_workflow.js"})` | Claude Code | 批量完整含 LLM |
| `python scripts/batch_audit.py --verbose` | 终端 | 批量审计 (详细输出) |

---

## 十、关键指标

| 指标 | 值 |
|------|-----|
| 能力分类 | 7 类 x 29 项 |
| 风险等级 | Critical / High / Medium |
| 意图分类 | 8 分支 x 36 叶子 |
| 确定性规则 | 15 条 (优先级队列) |
| Kill-Chain 模式 | 10 种 |
| Compound 威胁标志 | 4 个 |
| 支持脚本语言 | Python (ast) + JS/TS (tree-sitter) + Shell (tree-sitter-bash) |
| LLM 调用点 | 4 个 (D_llm, A_llm_instr, LLM Classifier, LLM Judge) |
| 幻觉控制 | 3 重 (taxonomy-echo, evidence grounding, keyword quality) |
| 确定性延迟 | ~20ms/case |
| 含 LLM 延迟 | 取决于模型响应 (~5-30s/case) |
