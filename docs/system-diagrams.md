# BIV 系统示意图（Mermaid）

> 日期：2026-08-14
> 依据当前架构（Phase 0-4，意图覆盖偏差 + 触发条件块）。替代过时的 `BIV-SYSTEM-DOCS.md`。

## 1. 系统架构图

```mermaid
flowchart TD
    SKILL[SKILL.md] --> P0[Phase 0 · 块划分<br/>frontmatter 元数据块 + 触发条件块<br/>agent 增量划分]
    P0 --> P1[Phase 1 · A/D 提取]
    P1 --> P2[Phase 2 · 偏差检测]
    P2 --> P3[Phase 3 · 恶意审计]
    P3 --> P4[Phase 4 · 恶意调用链]
    P4 --> R[result.json]

    subgraph P1[A/D 提取]
      D[D = 描述包含的所有敏感操作<br/>D_det ∪ D_llm]
      A[A = 真实执行的所有敏感操作<br/>A_ast ∪ A_regex ∪ A_llm]
    end

    subgraph P2[偏差检测]
      U[U = 超出声明意图的操作<br/>covered_by_declared=false]
      O[O = D − A 过度声明]
      CF[compound_flags + flows]
    end

    subgraph P3[恶意审计]
      VA[V_actual<br/>rule_engine + relaxed_veto]
      VD[V_decl<br/>块级分类 + U1-U8 无条件有害]
      J[LLM Judge<br/>语义综合判定]
    end

    subgraph P4[调用链]
      AC[每个恶意块 → 子智能体<br/>user_input + flow_items]
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
