// BIV Workflow Script — Claude Code Workflow orchestration
//
// This script orchestrates the full Behavioral Integrity Verification pipeline:
// Phase 1: Capability Extraction (Python deterministic + LLM parallel)
// Phase 2: Deviation Detection (Python computation)
// Phase 3: Root Cause & Malicious Detection (LLM classifier + LLM judge)
//
// Usage (inside Claude Code):
//   Workflow({scriptPath: "scripts/biv_workflow.js", args: {skill_dir: "..."}})

export const meta = {
  name: 'biv-audit',
  description: 'BIVMSA (Behavior Integrity Verification for Malicious Skill Audit) — full pipeline with LLM calls',
  phases: [
    { title: 'Extract', detail: 'Capability extraction: deterministic + LLM declared/instruction analysis' },
    { title: 'Detect', detail: 'Deviation detection and compound flag analysis' },
    { title: 'Classify', detail: 'Root cause classification and malicious detection' },
  ],
};

// =============================================================================
// Main Workflow
// =============================================================================

const skillDir = args?.skill_dir;
if (!skillDir) {
  throw new Error("Missing required argument: skill_dir. Usage: Workflow({scriptPath: 'scripts/biv_workflow.js', args: {skill_dir: '...'}})");
}

log(`Starting BIV audit for: ${skillDir}`);

// ---------------------------------------------------------------------------
// Phase 1: Capability Extraction
// ---------------------------------------------------------------------------
phase('Extract');

// Step 1a: Run deterministic Python pipeline (Φ(s) evidence via subagent)
log('Running deterministic extraction...');
const detEvidence = await (async () => {
  try {
    const raw = await agent(
      `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences:

python scripts/biv_audit.py ${skillDir} --evidence

The output is a single JSON object. Output ONLY that JSON object.`,
      { label: 'det-evidence' }
    );
    return parseJsonOutput(raw);
  } catch (e) {
    log(`Warning: deterministic pipeline failed: ${e}`);
    return null;
  }
})();

if (detEvidence) {
  log(`Deterministic: U=${(detEvidence.undeclared || []).length}, compound=${JSON.stringify(detEvidence.compound_flags)}, rule=${detEvidence.rule_engine?.rule_id || 'none'}`);
} else {
  log('Warning: could not obtain deterministic evidence');
}

function parseJsonOutput(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let text = raw.trim();
  // Strip a markdown code fence ONLY when the whole output is fenced (starts
  // with ```). Never strip fences at arbitrary positions: JSON string VALUES
  // can legitimately contain ``` sequences (e.g. SKILL.md embeds ```bash
  // blocks), and a blind .match() would corrupt the JSON before parsing.
  if (text.startsWith('```')) {
    const fenceMatch = text.match(/^```(?:json)?\s*([\s\S]*?)```\s*$/);
    if (fenceMatch) text = fenceMatch[1].trim();
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(text.slice(start, end + 1));
      } catch (e2) {
        return null;
      }
    }
    return null;
  }
}

function fmtCapList(arr) {
  return arr && arr.length ? arr.map(x => `  - ${x}`).join('\n') : '  (none)';
}

function fmtFlows(flows) {
  if (!flows || !flows.length) return '  (no data flows detected)';
  return flows.map(f => `  ${f.source} (${f.source_location}) -> ${f.sink} (${f.sink_location})`).join('\n');
}

function buildDetEvidenceText(det) {
  if (!det) return '(deterministic pipeline failed or unavailable)';
  const flagged = det.compound_flags
    ? Object.entries(det.compound_flags).filter(([, v]) => v).map(([k]) => k)
    : [];
  return `### Declared Capabilities D(s) (deterministic):
${fmtCapList(det.D_det)}
### Actual Capabilities A(s) (AST + regex):
${fmtCapList(det.A_merged)}
### Undeclared Capabilities U(s) = A - D (HIDDEN POWERS):
${fmtCapList(det.undeclared)}
### Overdeclared Capabilities O(s) = D - A (false claims):
${fmtCapList(det.overdeclared)}
### Data Flow Chains:
${fmtFlows(det.flows)}
### Compound Threat Flags (${flagged.length} triggered):
  ${flagged.length ? flagged.map(f => `[!] ${f}`).join(' | ') : 'none triggered'}
### Rule Engine:
  ${det.rule_engine?.matched
      ? `matched=${det.rule_engine.rule_id} -> intent=${det.rule_engine.intent_leaf} (kill_chain: ${det.rule_engine.kill_chain || 'none'})`
      : 'no rule matched'}
### Relaxed-Veto: ${det.relaxed_veto?.fired ? '[!] FIRED — ' + (det.relaxed_veto.reason || '') : 'not triggered'}
### Finding Counts: ${JSON.stringify(det.finding_counts || {})}
### Untrusted URLs: ${det.untrusted_url_count || 0}
### Deterministic Verdict: ${JSON.stringify(det._det_verdict || {})}`;
}

// Parse the skill via the stable Python parser (frontmatter / body / name /
// scripts / non_executable) so this workflow shares the same parsing logic as
// the deterministic pipeline and batch workflow. See scripts/skill_parse.py.
const parsedSkill = parseJsonOutput(await agent(
  `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences:

python scripts/skill_parse.py ${skillDir}

The output is a single JSON object. Output ONLY that JSON object.`,
  { label: 'parse-skill' }
));
const skillContent = (parsedSkill && parsedSkill.content_full) || '';
const skillName = (parsedSkill && parsedSkill.name) || skillDir.split('/').pop();
const bodyContent = (parsedSkill && parsedSkill.body) || '';

// Step 1b: Parallel LLM extraction
log('Running LLM capability extraction (declared track + instruction analysis)...');

// Render D_llm prompt (single template → plain rendered prompt text).
const dLlmPrompt = await agent(
  `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py d_llm_extract --skill-dir ${skillDir} --variant single

Return ONLY the rendered prompt text.`,
  { label: 'render-dllm-prompt' }
);

// D_llm: Extract declared capabilities from natural language
const dLlmResult = await agent(
  dLlmPrompt,
  {
    label: 'd_llm_extract',
    phase: 'Extract',
    schema: {
      type: 'object',
      properties: {
        declared_capabilities: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              capability: { type: 'string' },
              evidence: { type: 'string' },
              evidence_location: { type: 'string' },
            },
            required: ['capability', 'evidence', 'evidence_location'],
          },
        },
        intended_workflow: { type: 'string' },
        expected_data_lineages: { type: 'string' },
      },
      required: ['declared_capabilities', 'intended_workflow', 'expected_data_lineages'],
    },
  }
);

// A_llm: Extract actual capabilities AND judge coverage by declared intent (D).
// Runs after D_llm because covered_by_declared needs the declared intent.
const aLlmInstrPrompt = await agent(
  `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py a_llm_instr --skill-dir ${skillDir} --variant single <<'VARS_JSON'
${JSON.stringify({ declared_caps: (dLlmResult?.declared_capabilities || []).map(c => c.capability), intended_workflow: dLlmResult?.intended_workflow || '' })}
VARS_JSON

Return ONLY the rendered prompt text.`,
  { label: 'render-allm-prompt' }
);
const aLlmInstrResult = await agent(
  aLlmInstrPrompt,
  {
    label: 'a_llm_instr_analysis',
    phase: 'Extract',
    schema: {
      type: 'object',
      properties: {
        actual_capabilities: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              capability: { type: 'string' },
              evidence: { type: 'string' },
              evidence_location: { type: 'string' },
              is_adversarial: { type: 'boolean' },
              covered_by_declared: { type: 'boolean' },
            },
            required: ['capability', 'evidence', 'evidence_location', 'is_adversarial', 'covered_by_declared'],
          },
        },
        analysis_summary: { type: 'string' },
      },
      required: ['actual_capabilities', 'analysis_summary'],
    },
  }
);

log(`D_llm extracted: ${dLlmResult?.declared_capabilities?.length || 0} declared capabilities`);
log(`A_llm extracted: ${aLlmInstrResult?.actual_capabilities?.length || 0} actual capabilities`);

// ---------------------------------------------------------------------------
// Phase 2: Deviation Detection (computed by Python pipeline, already in detEvidence)
// ---------------------------------------------------------------------------
phase('Detect');

log('Deviation detection computed by Python pipeline (see Deterministic Analysis Φ(s)).');

// ---------------------------------------------------------------------------
// Phase 3: Root Cause & Malicious Detection
// ---------------------------------------------------------------------------
phase('Classify');

// ---------------------------------------------------------------------------
// Phase 0: block chunking (semantic annotation units)
// ---------------------------------------------------------------------------
log('Phase 0: chunking SKILL.md into trigger-condition blocks...');
const phase0 = await (async () => {
  try {
    const seedRaw = await agent(
      `Run this shell command and return its EXACT raw stdout (a JSON object {unit,frontmatter_block,body_offset,body_lines,body_text,blocks}), with NO commentary, NO markdown code fences:

python scripts/skill_chunk.py ${skillDir}

The output is a single JSON object. Output ONLY that JSON object.`,
      { label: 'chunk-seed' }
    );
    const seed = parseJsonOutput(seedRaw);
    if (!seed || !Array.isArray(seed.body_lines)) {
      log('Phase 0 seed invalid');
      return { unit: 'trigger-block', count: 0, blocks: [] };
    }
    const fmBlock = seed.frontmatter_block || null;
    const bodyLines = seed.body_lines;
    const bodyOffset = seed.body_offset || 0;
    const bodyTotal = bodyOffset + bodyLines.length;
    const blocks = fmBlock ? [fmBlock] : [];

    let start = bodyOffset + 1;
    let iter = 0;
    const MAX_ITER = 60;
    while (start <= bodyTotal && iter < MAX_ITER) {
      const startIdx = start - bodyOffset - 1;
      const remaining = bodyLines.slice(startIdx).join('\n');
      const r = parseJsonOutput(await agent(
        `You divide a SKILL.md body into "trigger-condition blocks": each block is the MAX line range that would be executed under ONE trigger condition (e.g. one section / scenario / instruction set).

## SKILL.md body (uncovered range starting at global line ${start}; body offset ${bodyOffset}; last global line ${bodyTotal})
${remaining}

## Task
From global line ${start}, cut out the FIRST trigger-condition block (the max consecutive line range belonging to one trigger condition).
Return ONLY a JSON object:
{"line_start": ${start}, "line_end": <global line, >= line_start, <= ${bodyTotal}>, "trigger_condition": "<short condition, e.g. install CLI | sign-in | read secrets>"}`,
        { label: `chunk-part-${iter}` }
      ));
      const effStart = (r && typeof r.line_start === 'number') ? r.line_start : start;
      const le = (r && typeof r.line_end === 'number') ? r.line_end : start;
      const effEnd = Math.max(effStart, le, start);
      const li = Math.max(0, effStart - bodyOffset - 1);
      const ri = Math.min(effEnd, bodyTotal) - bodyOffset - 1;
      const lines = bodyLines.slice(li, Math.max(0, ri) + 1);
      blocks.push({
        block_id: blocks.length + 1,
        kind: 'trigger',
        line_start: Math.max(1, effStart),
        line_end: Math.min(bodyTotal, effEnd),
        trigger_condition: (r && r.trigger_condition) || '',
        text: lines.join('\n'),
        sentences: lines,
      });
      start = Math.min(bodyTotal, effEnd) + 1;
      iter += 1;
    }
    return { unit: 'trigger-block', count: blocks.length, blocks };
  } catch (e) {
    log(`Phase 0 chunking failed: ${e}`);
    return { unit: 'trigger-block', count: 0, blocks: [] };
  }
})();
const blocks = phase0.blocks || [];
log(`Phase 0 blocks: ${blocks.length}`);

// ---------------------------------------------------------------------------
// V_decl: block-level malicious classification (no-deviation-malicious)
// ---------------------------------------------------------------------------
log('Running V_decl block-level classification...');

// Render sentence_classifier prompt (blocks from Phase 0; D/A/U/O via stdin)
// D = 声明能力全集（确定性 ∪ D_llm 语义）
// A = 真实执行的所有敏感操作：确定性(A_ast+A_regex) ∪ A_llm（完整能力）
// U = 超出声明意图（covered_by_declared=false）的操作 → 语义偏差，非集合差
const vdeclVars = {
  D: Array.from(new Set([
    ...(detEvidence?.D_det || []),
    ...(dLlmResult?.declared_capabilities || []).map(c => c.capability),
  ])),
  A: Array.from(new Set([
    ...(detEvidence?.A_ast || []),
    ...(detEvidence?.A_regex || []),
    ...(aLlmInstrResult?.actual_capabilities || []).map(c => c.capability),
  ])),
  U: (aLlmInstrResult?.actual_capabilities || [])
    .filter(c => c.covered_by_declared === false)
    .map(c => c.capability),
  O: detEvidence?.overdeclared || [],
};

const VDECL_SCHEMA = {
  type: 'object',
  properties: {
    block_classifications: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          block_id: { type: 'integer' },
          text: { type: 'string' },
          kind: { type: 'string', enum: ['action_instruction', 'non_action'] },
          deviation_label: { type: 'string', enum: ['deviated', 'no_deviation'] },
          malicious_label: { type: 'string', enum: ['malicious', 'benign'] },
          classification: { type: 'string', enum: ['no-deviation-malicious', 'no-deviation-benign', 'deviated-malicious', 'deviated-benign'] },
          capabilities: { type: 'array', items: { type: 'string' } },
          core_instruction: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['block_id', 'text', 'kind', 'deviation_label', 'malicious_label', 'classification', 'capabilities', 'core_instruction', 'reason'],
      },
    },
    unconditional_harmful: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          pattern: { type: 'string' },
          anchor: { type: 'string' },
          block_id: { type: 'integer' },
          evidence: { type: 'string' },
        },
        required: ['pattern', 'anchor', 'block_id', 'evidence'],
      },
    },
    coverage: {
      type: 'object',
      properties: {
        total_blocks: { type: 'integer' },
        classified_blocks: { type: 'integer' },
      },
      required: ['total_blocks', 'classified_blocks'],
    },
  },
  required: ['block_classifications', 'unconditional_harmful', 'coverage'],
};

// Long skills are classified in chunks by BLOCK count; blocks carry real global
// block_id so each chunk needs no offset — results merge by block_id.
const VDECL_CHUNK = 120;
const chunks = [];
for (let i = 0; i < blocks.length; i += VDECL_CHUNK) {
  chunks.push(blocks.slice(i, i + VDECL_CHUNK));
}

const renderVdeclPrompt = (blockSubset, idx) => {
  const vars = { ...vdeclVars, blocks: blockSubset };
  return agent(
    `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py sentence_classifier --skill-dir ${skillDir} --variant single <<'VARS_JSON'
${JSON.stringify(vars)}
VARS_JSON`,
    { label: `render-vdecl-prompt${chunks.length > 1 ? '-' + idx : ''}` }
  );
};

let vdeclResult = null;
if (chunks.length <= 1) {
  const vdeclPrompt = await renderVdeclPrompt(blocks, 0);
  vdeclResult = await agent(
    vdeclPrompt,
    { label: 'vdecl_block_classifier', phase: 'Classify', schema: VDECL_SCHEMA }
  );
} else {
  // Multi-chunk: one agent per block subset, merge by block_id (dedup).
  const chunkResults = await Promise.all(chunks.map(async (chunk, idx) => {
    const prompt = await renderVdeclPrompt(chunk, idx);
    const r = await agent(
      prompt,
      { label: `vdecl_block_classifier-${idx}`, phase: 'Classify', schema: VDECL_SCHEMA }
    );
    log(`V_decl chunk ${idx + 1}/${chunks.length}: ${r ? (r.block_classifications || []).length : 0} blocks`);
    return r;
  }));
  const merged = chunkResults.filter(Boolean);
  const byId = {};
  for (const r of merged) {
    for (const c of (r.block_classifications || [])) {
      if (c && typeof c.block_id === 'number') byId[c.block_id] = c;
    }
  }
  const sortedCls = Object.keys(byId).map(Number).sort((a, b) => a - b).map(k => byId[k]);
  const uncond = merged.flatMap(r => r.unconditional_harmful || []).filter(h => h && h.pattern);
  vdeclResult = {
    block_classifications: sortedCls,
    unconditional_harmful: uncond,
    coverage: { total_blocks: blocks.length, classified_blocks: sortedCls.length },
  };
}

// --- coverage 校验：缺失块补测 ---
// vdecl 可能漏标部分块（LLM 输出不完整）。对缺失 block_id 单独补测并合并。
const _classifiedIds = new Set((vdeclResult?.block_classifications || []).map(c => c.block_id));
const missingBlocks = blocks.filter(b => !_classifiedIds.has(b.block_id));
if (missingBlocks.length > 0) {
  log(`Phase 4/vdecl missing ${missingBlocks.length} block(s), backfilling...`);
  const backfillResults = await Promise.all(missingBlocks.map(async (mb, idx) => {
    const vars = { ...vdeclVars, blocks: [mb] };
    const prompt = await agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py sentence_classifier --skill-dir ${skillDir} --variant single <<'VARS_JSON'
${JSON.stringify(vars)}
VARS_JSON

Return ONLY the rendered prompt text.`,
      { label: `render-vdecl-backfill-${idx}` }
    );
    return agent(
      prompt,
      { label: `vdecl_backfill-${idx}`, phase: 'Classify', schema: VDECL_SCHEMA }
    );
  }));
  const bf = backfillResults.filter(Boolean);
  const _byId = {};
  for (const c of (vdeclResult?.block_classifications || [])) {
    if (c && typeof c.block_id === 'number') _byId[c.block_id] = c;
  }
  for (const r of bf) {
    for (const c of (r.block_classifications || [])) {
      if (c && typeof c.block_id === 'number') _byId[c.block_id] = c;
    }
  }
  const sorted = Object.keys(_byId).map(Number).sort((a, b) => a - b).map(k => _byId[k]);
  const uncond = [...(vdeclResult?.unconditional_harmful || []),
    ...bf.flatMap(r => r.unconditional_harmful || [])].filter(h => h && h.pattern);
  vdeclResult = {
    block_classifications: sorted,
    unconditional_harmful: uncond,
    coverage: { total_blocks: blocks.length, classified_blocks: sorted.length },
  };
  log(`vdecl backfilled: ${sorted.length}/${blocks.length} blocks`);
}

const vdeclHits = (vdeclResult?.unconditional_harmful || []).filter(h => h && h.pattern);
const vdeclFired = vdeclHits.length > 0;
const vdeclNoDevMal = (vdeclResult?.block_classifications || [])
  .filter(s => s && s.classification === 'no-deviation-malicious').length;
log(`V_decl: ${vdeclHits.length} unconditional-harmful hit(s), ${vdeclNoDevMal} no-deviation-malicious block(s), coverage=${vdeclResult?.coverage?.classified_blocks || 0}/${vdeclResult?.coverage?.total_blocks || 0}`);

// Build the evidence summary for the LLM Judge (deterministic Φ(s) + LLM extraction + V_decl)
const evidenceSummary = `
## Deterministic Analysis Φ(s) (from Python pipeline)
${buildDetEvidenceText(detEvidence)}

## Declared Capabilities (semantic extraction)
${(dLlmResult?.declared_capabilities || []).map(c => `- ${c.capability}: "${c.evidence.substring(0, 100)}"`).join('\n') || '(none)'}

## Instruction-Level Analysis
${(aLlmInstrResult?.actual_capabilities || []).map(c => `- ${c.capability} (adversarial: ${c.is_adversarial}): "${c.evidence.substring(0, 100)}"`).join('\n') || '(none)'}

## Analysis Summary
${aLlmInstrResult?.analysis_summary || 'No instruction-level threats detected.'}

## V_decl 声明轨道恶意通道（块级分类 — 无偏差恶意识别）
${vdeclHits.length
    ? vdeclHits.map(h => `- [!] ${h.pattern}: "${h.evidence}" (block ${h.block_id}, anchor: ${h.anchor})`).join('\n')
    : 'no unconditional-harmful declaration detected'}
no-deviation-malicious 块数: ${vdeclNoDevMal}
`;

// LLM Judge: Final verdict
log('Running LLM Judge for final verdict...');

// Render judge prompt (skill content read from skill-dir; evidence summary via stdin)
const judgePrompt = await agent(
  `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py judge --skill-dir ${skillDir} --variant single <<'VARS_JSON'
${JSON.stringify({ evidence_summary: evidenceSummary })}
VARS_JSON`,
  { label: 'render-judge-prompt' }
);

const judgeResult = await agent(
  judgePrompt,
  {
    label: 'llm_judge',
    phase: 'Classify',
    effort: 'xhigh',
    schema: {
      type: 'object',
      properties: {
        verdict: { type: 'string', enum: ['benign', 'malware'] },
        confidence: { type: 'number' },
        reasoning: { type: 'string' },
        intent_category: { type: 'string', enum: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'] },
        key_evidence: { type: 'array', items: { type: 'string' } },
      },
      required: ['verdict', 'confidence', 'reasoning', 'intent_category', 'key_evidence'],
    },
  }
);

// ---------------------------------------------------------------------------
// Final Output
// ---------------------------------------------------------------------------

// Intent branch → Chinese name mapping (mirrors taxonomy.INTENT_CATEGORY_NAMES)
const INTENT_NAMES = {
  A: '数据窃取与间谍', B: '财务与变现', C: '载荷与基础设施',
  D: '内容与社会工程', E: '破坏性', F: 'AI Agent 特定',
  G: '非对抗性', H: '模糊',
};

// --- Phase 4: malicious attack chain construction (per malicious block) ---
log('Phase 4: constructing malicious attack chains...');
let attackChains = [];
const maliciousBlocks = (vdeclResult?.block_classifications || [])
  .filter(b => b && b.classification && b.classification.includes('malicious'));
if (maliciousBlocks.length > 0) {
  // capability_code_evidence 不在 --evidence 紧凑输出里，需取完整确定性结果
  const detFull = parseJsonOutput(await agent(
    `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences:

python scripts/biv_audit.py ${skillDir}

The output is a single JSON object. Output ONLY that JSON object.`,
    { label: 'det-full-phase4' }
  ));
  const cce = (detFull && detFull.phase1 && detFull.phase1.capability_code_evidence) || {};
  const chainResults = await Promise.all(maliciousBlocks.map(async (mb, idx) => {
    // 精简 vars：block.text 截短、code_evidence 只保留该块涉及的能力，
    // 避免超长 heredoc 在 subagent 执行时损坏（曾导致 block 字段丢失）。
    const capsOfBlock = mb.capabilities || [];
    const cceFiltered = {};
    for (const cap of capsOfBlock) {
      if (cce[cap]) cceFiltered[cap] = cce[cap];
    }
    // trigger_condition 从 Phase 0 blocks 关联（block_classification 无此字段）
    const mbTrigger = (blocks.find(b => b.block_id === mb.block_id) || {}).trigger_condition || '';
    const chainVars = {
      block: {
        block_id: mb.block_id,
        trigger_condition: mbTrigger || mb.trigger_condition || '',
        classification: mb.classification || '',
        capabilities: capsOfBlock,
        text: (mb.text || '').slice(0, 600),
      },
      code_evidence: cceFiltered,
    };
    const prompt = await agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py attack_chain --skill-dir ${skillDir} --variant single <<'VARS_JSON'
${JSON.stringify(chainVars)}
VARS_JSON

Return ONLY the rendered prompt text.`,
      { label: `render-chain-${idx}` }
    );
    const r = await agent(
      prompt,
      {
        label: `attack_chain-${idx}`,
        phase: 'Classify',
        schema: {
          type: 'object',
          properties: {
            block_id: { type: 'integer' },
            user_input: { type: 'string' },
            flow_items: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  capability: { type: 'string' },
                  file: { type: 'string' },
                  line_start: { type: 'integer' },
                  code: { type: 'string' },
                },
                required: ['capability', 'file', 'line_start', 'code'],
              },
            },
          },
          required: ['block_id', 'user_input', 'flow_items'],
        },
      }
    );
    if (r) log(`Phase 4 chain for block ${r.block_id}: ${(r.flow_items || []).length} flow-item(s)`);
    return r;
  }));
  attackChains = chainResults.filter(Boolean);
}
log(`Phase 4: ${attackChains.length} attack chain(s)`);

const finalResult = {
  skill_name: skillName,
  skill_dir: skillDir,
  // V_decl 无条件有害命中即恶意（不看上下文）；否则归 LLM Judge
  verdict: vdeclFired ? 'malware' : (judgeResult?.verdict || 'benign'),
  confidence: vdeclFired ? Math.max(0.9, judgeResult?.confidence || 0.5) : (judgeResult?.confidence || 0.5),
  verdict_source: vdeclFired ? 'vdecl' : 'llm_judge',
  verdict_reasoning: judgeResult?.reasoning || '',
  declared_capabilities: dLlmResult?.declared_capabilities || [],
  actual_capabilities: aLlmInstrResult?.actual_capabilities || [],
  a_llm_instr_caps: (aLlmInstrResult?.actual_capabilities || []).map(c => c.capability),
  a_llm_adv_caps: (aLlmInstrResult?.actual_capabilities || []).filter(c => c.is_adversarial).map(c => c.capability),
  intended_workflow: dLlmResult?.intended_workflow || '',
  judge_intent_category: judgeResult?.intent_category || 'H',
  judge_intent_category_name: INTENT_NAMES[judgeResult?.intent_category] || '',
  judge_key_evidence: judgeResult?.key_evidence || [],
  // V_decl: 声明轨道恶意通道（无偏差恶意）— 块级分类结果
  vdecl: {
    fired: vdeclFired,
    verdict: vdeclFired ? 'malware' : 'benign',
    unconditional_harmful: vdeclHits,
    block_classifications: vdeclResult?.block_classifications || [],
    no_deviation_malicious_count: vdeclNoDevMal,
    coverage: vdeclResult?.coverage || {},
  },
  // Phase 4: 恶意调用链（每个恶意块 → 构造触发输入 + 恶意代码片段）
  attack_chains: attackChains,
  // Phase 0: structured blocks (downstream annotation units)
  phase0: phase0,
  // Deterministic evidence passed through for traceability
  deterministic_evidence: detEvidence || null,
  _meta: {
    workflow_version: '0.2.1',
  },
};

// --- Write result to experiment/results/ mirroring the cases structure ---
// The Workflow script has no filesystem access, so the file is written by a
// subagent. Override the path via args.output.
const relPath = skillDir.replace('experiment/cases/', '');
const outputFile = (args && args.output) || `experiment/results/${relPath}/result.json`;
const outputDir = outputFile.substring(0, outputFile.lastIndexOf('/'));
try {
  await agent(
    `Write the JSON content below to the file at ${outputFile}.
First create the parent directory if it does not exist: mkdir -p ${outputDir}
Output ONLY the single word "ok" on success. Do not modify the JSON content.

${JSON.stringify(finalResult, null, 2)}`,
    { label: 'write-result' }
  );
  log(`Result written to ${outputFile}`);
} catch (e) {
  log(`Warning: could not write ${outputFile}: ${e}`);
}

log(`Verdict: ${finalResult.verdict} (confidence: ${(finalResult.confidence * 100).toFixed(0)}%)`);

return finalResult;
