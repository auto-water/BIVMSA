# BIV 系统示意图（Mermaid）

> 日期：2026-08-14
> 依据当前架构（Phase 0-4，意图覆盖偏差 + 触发条件块）。替代过时的 `BIV-SYSTEM-DOCS.md`。

## 1. 系统架构图

```mermaid
flowchart LR
    SKILL["SKILL.md"] --> PH0["Phase 0 · 块划分<br/>触发条件块 + frontmatter"]
    PH0 --> D
    D --> A
    A --> U
    U --> CF
    CF --> VA
    VA --> J
    J --> AC
    AC --> R["result.json + trace.json"]

    subgraph SG1["Phase 1 · A/D 提取"]
      direction TB
      D["D = 声明能力<br/>D_det ∪ D_llm"]
      A["A = 实际能力<br/>A_ast ∪ A_regex ∪ A_llm"]
    end

    subgraph SG2["Phase 2 · 偏差检测"]
      direction TB
      U["U = 超出声明意图<br/>covered_by_declared = false"]
      O["O = D − A 过度声明"]
      CF["compound_flags + flows"]
    end

    subgraph SG3["Phase 3 · 恶意审计"]
      direction TB
      VA["V_actual<br/>rule_engine + relaxed_veto"]
      VD["V_decl<br/>U1-U8 无条件有害"]
      J["LLM Judge<br/>语义综合判定"]
    end

    subgraph SG4["Phase 4 · 调用链"]
      direction TB
      AC["恶意块 → 子智能体<br/>user_input + flow_items"]
    end
```

## 2. 完整审计时序图

```mermaid
sequenceDiagram
    participant WF as Workflow 编排器
    participant PY as Python 确定性管道
    participant SK as skill_parse / skill_chunk
    participant D as D_llm agent
    participant A as A_llm agent
    participant C as 块划分 agent(增量)
    participant V as V_decl agent
    participant J as LLM Judge
    participant P4 as Phase 4 agent

    WF->>SK: parse_skill + chunk_seed
    SK-->>WF: frontmatter 元数据块 + body 行
    loop 每块
      C-->>WF: 划出触发条件块 (line_start/end/trigger)
    end
    WF->>D: render_d_llm_extract → 声明能力
    D-->>WF: declared_capabilities + intended_workflow
    WF->>A: render_a_llm_instr (含 D 意图)
    A-->>WF: actual_capabilities + covered_by_declared
    WF->>PY: biv_audit --evidence
    PY-->>WF: D_det/A_ast/A_regex/flows/compound
    WF->>V: 块级恶意分类 (blocks + D/A/U/O)
    V-->>WF: block_classifications + unconditional_harmful
    WF->>J: render_judge (Φ + V_decl + 原文)
    J-->>WF: verdict/confidence/intent
    WF->>P4: 恶意块 → render_attack_chain
    P4-->>WF: attack_chains (user_input + flow_items)
    WF-->>WF: ŷ = V_actual ∨ V_decl ∨ Judge
```

## 3. 恶意判定流程图

```mermaid
flowchart TD
    PHI["Φ(s): D/A/U/O + flows + compound"] --> VA{V_actual relaxed_veto?}
    VA -->|触发| M1[malware · verdict_source=relaxed_veto]
    VA -->|否| VD{V_decl 无条件有害命中?<br/>U1-U8}
    VD -->|命中| M2[malware · verdict_source=vdecl<br/>不看 Judge]
    VD -->|否| J{LLM Judge 语义综合}
    J -->|malware| M3[malware · verdict_source=llm_judge]
    J -->|benign| B[benign]
```

## 4. Phase 0 — 块划分

```mermaid
flowchart LR
    SK[SKILL.md] --> SPLIT[frontmatter / body 拆分<br/>删空行 · 不拆句]
    SPLIT --> FM[frontmatter 元数据块<br/>触发条件来源 · 不参与划分]
    SPLIT --> BODY[body 行列表]
    BODY --> AGENT{增量 agent}
    AGENT -->|提交未覆盖区间| PART[划出同一触发条件<br/>最大行区间块]
    PART --> NEXT[收缩范围]
    NEXT --> AGENT
    PART --> BLOCKS[触发条件块列表<br/>block_id/line_start/line_end/trigger]
```

## 5. Phase 1 — A/D 能力提取

```mermaid
flowchart TD
    SK[SKILL.md + scripts] --> P1

    subgraph P1[Phase 1]
      subgraph D_TRACK[声明轨道 D]
        DD[D_deterministic<br/>frontmatter allowed-tools/hooks]
        DL[D_llm<br/>语义提取声明能力]
      end
      subgraph A_TRACK[实际轨道 A]
        AA[A_ast<br/>AST 静态分析脚本]
        AR[A_regex<br/>正则危险模式]
        AL[A_llm<br/>语义提取真实执行操作<br/>+ covered_by_declared]
      end
    end

    D_TRACK --> D_OUT[D = D_det ∪ D_llm]
    A_TRACK --> A_OUT[A = A_ast ∪ A_regex ∪ A_llm]
    D_OUT --> U[U = 超出声明意图操作]
    A_OUT --> U
```

## 6. Phase 2 — 偏差检测

```mermaid
flowchart TD
    A[A 完整能力] --> COV{covered_by_declared?}
    COV -->|true| PASS[放行 · 非偏差<br/>实现细节被意图覆盖]
    COV -->|false| U[U 语义偏差<br/>超出声明意图]
    D[D 声明能力] --> O[O = D − A 过度声明]
    FLOW[数据流] --> CF[compound_flags<br/>exfiltration / rce 链]
    U --> CF
    O --> CF
```

## 7. Phase 3 — 恶意审计（三层判定）

```mermaid
flowchart TD
    B[触发条件块] --> V{Phase 3}
    subgraph P3BOX[恶意审计]
      V1[V_decl 块级分类<br/>kind + 2×2 + capabilities<br/>+ core_instruction]
      U1[U1-U8 无条件有害模式<br/>凭证外泄/反向shell/dropper/<br/>配置投毒/范围蔓延/指令窃取/勒索/指令级]
      V2[V_actual<br/>rule_engine 15规则 A-H + relaxed_veto]
      V3["LLM Judge<br/>Φ(s) + V_decl 命中 + 原文"]
    end
    V1 --> U1
    U1 -->|命中| HIT[无条件有害]
    V2 -->|触发| HIT
    V3 --> JV[verdict]
    HIT --> JV
```

## 8. Phase 4 — 恶意调用链

```mermaid
flowchart LR
    MB[恶意块<br/>trigger_condition + capabilities] --> P4[子智能体]
    CCE[capability_code_evidence<br/>外部关联代码] --> P4
    P4 --> UI[构造触发用户输入 user_input]
    P4 --> FI[恶意代码片段 flow_items<br/>file/line/code]
    UI --> CHAIN[attack_chains]
    FI --> CHAIN
    CHAIN --> FE[前端 DAG 图渲染<br/>User → 输入 → 恶意块 → flow-items]
```

## 9. 单 case 审计：静态管线 × 动态管线（数据传递）

> 两条管线共享 `skill_parser` 解析产物；静态管线的确定性证据（Φ(s)、代码证据、det 判定）是动态管线 LLM Judge 与 V_decl 的输入；D/A 能力集双轨合并后进入最终判定 `ŷ = V_actual ∨ V_decl ∨ Judge`。

```mermaid
flowchart TD
    IN["SKILL.md + scripts/ + references/"] --> PARSE["skill_parser 稳定解析<br/>frontmatter / body / scripts"]

    subgraph STATIC["静态管线 · 确定性静态分析（模式 A · Python）"]
        direction TB
        FM["frontmatter 解析<br/>allowed-tools / hooks"] --> DET["D_det 声明能力"]
        AST["AST 污点分析 + Regex 模式<br/>+ 结构攻击检测"] --> AET["A_ast ∪ A_regex<br/>+ flows_ast"]
        DET --> DEV["偏差检测 U/O + compound"]
        AET --> DEV
        DEV --> PHI["Φ(s) 证据元组"]
        PHI --> RULE["规则引擎 + Relaxed-Veto"]
        RULE --> DETV["_det_verdict"]
        AST --> CCE["capability_code_evidence<br/>代码片段 + 行号"]
    end

    subgraph DYN["动态管线 · LLM 语义增强（模式 B · Workflow）"]
        direction TB
        BODY["body 语义提取"] --> DLLM["D_llm 声明能力"]
        INS["A_llm_instr 指令分析<br/>covered_by_declared → 语义 U"] --> ALLM["A_llm 实际能力"]
        P0["Phase 0 触发条件块"] --> VD["V_decl 块级分类<br/>U1-U8 无条件有害"]
        VD --> JDG["LLM Judge"]
        JDG --> FINAL["最终判定 ŷ"]
    end

    PARSE --> FM
    PARSE --> AST
    PARSE --> BODY
    PARSE --> INS

    DET -- "D = D_det ∪ D_llm" --> DLLM
    AET -- "A = A_ast ∪ A_regex ∪ A_llm" --> ALLM
    PHI -- "Φ(s) 证据 evidence_summary" --> JDG
    CCE -- "代码证据（恶意块引用）" --> VD
    RULE -- "V_actual ∨" --> FINAL
    VD -- "V_decl ∨" --> FINAL

    FINAL --> OUT["result.json + trace.json"]
    OUT --> VIZ["前端标注页 / report / benchmark"]
```

## 10. LLM 三重幻觉控制

> 对 LLM 提取的声明/指令能力做落库前校验，三道关卡逐项过滤。声明轨（`declared_track.validate_llm_output`）完整三道；指令轨（`llm_instruction.validate_instruction_llm_output`）为变体（能力类别限制 + 扎根阈值 50%）。详见 `docs/system-spec.md` §13.5。

```mermaid
flowchart TD
    IN["LLM 输出<br/>capability + evidence"] --> VALID{"能力码合法?<br/>∈ ALL_CAPABILITY_CODES"}
    VALID -->|非法| R0["拒绝 unknown capability"]
    VALID -->|合法| C1{"关卡 1 · Taxonomy-echo<br/>回显检测"}
    C1 -->|"evidence 归一化后<br/>== 能力描述 或 == 能力名"| R1["拒绝 taxonomy echo<br/>（模板回显）"]
    C1 -->|通过| C2{"关卡 2 · Evidence grounding<br/>证据扎根"}
    C2 -->|"归一化子串命中源文本<br/>或词集重合度 ≥ 60%<br/>（词数少于 3 直接拒绝）"| C3{"关卡 3 · Keyword quality<br/>领域关键词"}
    C2 -->|不扎根| R2["拒绝 evidence 未在原文"]
    C3 -->|"critical / high 能力<br/>缺领域关键词"| R3["拒绝 缺关键词"]
    C3 -->|通过| OK["valid_capabilities<br/>+ evidence 入证据集"]
    R0 --> REJ["rejected 列表（带原因）<br/>供 trace / 审计回溯"]
    R1 --> REJ
    R2 --> REJ
    R3 --> REJ
```
