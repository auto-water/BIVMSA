// Batch BIV Audit Workflow — full pipeline with LLM calls across all cases
//
// Usage (inside Claude Code):
//   Workflow({scriptPath: "scripts/batch_workflow.js"})
//
// For each case in experiment/cases/:
//   1. Run deterministic Python pipeline
//   2. Call Agent for D_llm (semantic declared cap extraction)
//   3. Call Agent for A_llm_instr (instruction-level hidden cap detection)
//   4. Call Agent for LLM Judge (final verdict with CoT+xhigh)
//   5. Aggregate all results

export const meta = {
  name: 'biv-batch-audit',
  description: 'Batch BIV audit with LLM — scans experiment/cases/ and runs full pipeline on each',
  phases: [
    { title: 'Discover', detail: 'Scan cases directory and read skill content' },
    { title: 'Audit', detail: 'Full pipeline (deterministic + LLM) per case' },
    { title: 'Report', detail: 'Aggregate results and verdict summary' },
  ],
};

// =============================================================================
// Helpers: run deterministic Python pipeline and format its evidence
// =============================================================================

// Intent branch → Chinese name mapping (mirrors taxonomy.INTENT_CATEGORY_NAMES)
const INTENT_NAMES = {
  A: '数据窃取与间谍', B: '财务与变现', C: '载荷与基础设施',
  D: '内容与社会工程', E: '破坏性', F: 'AI Agent 特定',
  G: '非对抗性', H: '模糊',
};

// Runs `python scripts/biv_audit.py <caseDir> --evidence` via a subagent and
// parses the JSON output. Returns null on failure.
async function runDetPipeline(caseDir) {
  try {
    const raw = await agent(
      `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences, NO extra text around it:

python scripts/biv_audit.py ${caseDir} --evidence

The output is a single JSON object. Output ONLY that JSON object.`,
      { label: `det-${caseDir.split('/').pop()}`, phase: 'Audit' }
    );
    return parseJsonOutput(raw);
  } catch (e) {
    log(`[${caseDir}] Deterministic pipeline failed: ${e}`);
    return null;
  }
}

// Runs the FULL deterministic pipeline (`python scripts/biv_audit.py <caseDir>`)
// via a subagent and returns the complete result (phase1 with skill_body +
// capability_code_evidence, phase2, phase3_deterministic, classification, etc).
// Used only for result.json persistence (the LLM Judge reasons over the compact
// evidence from runDetPipeline). Returns null on failure.
async function runDetFull(caseDir) {
  try {
    const raw = await agent(
      `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences, NO extra text around it:

python scripts/biv_audit.py ${caseDir}

The output is a single JSON object (the full deterministic pipeline result with phase1/phase2/phase3_deterministic/classification/_det_verdict). Output ONLY that JSON object.`,
      { label: `det-full-${caseDir.split('/').pop()}`, phase: 'Audit' }
    );
    return parseJsonOutput(raw);
  } catch (e) {
    log(`[${caseDir}] Deterministic full pipeline failed: ${e}`);
    return null;
  }
}

// Extracts the first JSON object from agent output (strips markdown fences,
// leading prose, trailing text). Returns null if nothing parses.
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
  // If there's prose before/after the JSON, find the first { ... } block.
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

// Formats the compact Φ(s) evidence object as a readable text block for the Judge.
function buildDetEvidenceText(det) {
  const fmtList = (arr) => (arr && arr.length ? arr.map(x => `  - ${x}`).join('\n') : '  (none)');
  const fmtFlows = (flows) => {
    if (!flows || !flows.length) return '  (no data flows detected)';
    return flows.map(f => `  ${f.source} (${f.source_location}) -> ${f.sink} (${f.sink_location})`).join('\n');
  };
  const flagged = det.compound_flags
    ? Object.entries(det.compound_flags).filter(([, v]) => v).map(([k]) => k)
    : [];

  return `### Declared Capabilities D(s) (deterministic):
${fmtList(det.D_det)}
### Actual Capabilities A(s) (AST + regex):
${fmtList(det.A_merged)}
### Undeclared Capabilities U(s) = A - D (HIDDEN POWERS):
${fmtList(det.undeclared)}
### Overdeclared Capabilities O(s) = D - A (false claims):
${fmtList(det.overdeclared)}
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

// Ground truth comes from the path segment (std-cases-4: benign/ malware/).
// Never read a .expected file — it leaks the label into the audit context.
function deriveClass(caseDir) {
  const parts = (caseDir || '').split('/');
  if (parts.includes('benign')) return 'benign';
  if (parts.includes('malware')) return 'malware';
  return 'unknown';
}

// =============================================================================
// Phase 1: Discover cases
// =============================================================================
phase('Discover');

log('Scanning experiment/cases/ for skills...');

// 目标案例过滤:可通过 args 传入,例如 args = { cases: ["ai-wrapper-product__CI_B6"] }
// 未指定时扫描全部案例
const targetCases = Array.isArray(args?.cases) && args.cases.length
  ? args.cases.map(String).filter(Boolean)
  : null;

// List all directories under experiment/cases/ that contain SKILL.md
const caseDirs = await (async () => {
  const result = await (() => {
    // Use bash to find cases
    return agent(
      'Run this shell command and return the output exactly: find experiment/cases -name SKILL.md | sort',
      { label: 'discover-cases' }
    );
  })();

  const lines = (result || '').split('\n').filter(l => l.trim());
  let dirs = lines.map(l => l.replace('/SKILL.md', ''));
  if (targetCases) {
    dirs = dirs.filter(d => targetCases.some(t => d === t || d.endsWith('/' + t)));
    log(`Targeting ${dirs.length}/${lines.length} case(s): ${dirs.join(', ')}`);
  }
  return dirs;
})();

log(`Found ${caseDirs.length} cases: ${caseDirs.join(', ')}`);

if (caseDirs.length === 0) {
  const reason = targetCases
    ? `No matching case found for: ${targetCases.join(', ')}`
    : 'No cases found';
  log(reason + '. Exiting.');
  return { summary: { total: 0, message: reason } };
}

// =============================================================================
// Phase 2: Audit each case (pipeline pattern — cases run independently)
// =============================================================================
phase('Audit');

const results = await pipeline(
  caseDirs,
  async (caseDir) => {
    const caseName = caseDir.split('/').pop();
    log(`[${caseName}] Starting audit...`);

    // --- Step 1: Parse the skill via the stable Python parser ---
    // Shares the same parsing logic (frontmatter/body/name/scripts) as the
    // deterministic pipeline and single-case workflow. See scripts/skill_parse.py.
    const parsedSkill = parseJsonOutput(await agent(
      `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences:

python scripts/skill_parse.py ${caseDir}

The output is a single JSON object. Output ONLY that JSON object.`,
      { label: `parse-${caseName}` }
    ));
    if (!parsedSkill || parsedSkill.error || !parsedSkill.body) {
      log(`[${caseName}] ERROR: Cannot parse skill (${(parsedSkill && parsedSkill.error) || 'skill_parse failed'})`);
      return { case: caseName, case_dir: caseDir, class: deriveClass(caseDir), error: (parsedSkill && parsedSkill.error) || 'Cannot parse skill' };
    }
    const skillName = parsedSkill.name || caseName;
    const bodyContent = parsedSkill.body || '';
    const skillContent = parsedSkill.content_full || '';

    // --- Step 2: Run deterministic Python pipeline (Φ(s) evidence) ---
    // detEvidence: compact evidence for the LLM Judge; detFull: complete result
    // (phase1.skill_body + capability_code_evidence) for result.json persistence.
    log(`[${caseName}] Running deterministic pipeline...`);
    const [detEvidence, detFull] = await Promise.all([
      runDetPipeline(caseDir),
      runDetFull(caseDir),
    ]);

    // --- Step 3: Parallel LLM extraction ---
    log(`[${caseName}] Running LLM extraction...`);

    // Render D_llm prompt (single template → plain rendered prompt text).
    const dLlmPrompt = await agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py d_llm_extract --skill-dir ${caseDir} --variant batch

Return ONLY the rendered prompt text.`,
      { label: `render-dllm-prompt-${caseName}` }
    );

    // D_llm: Semantic declared capability extraction (runs FIRST; A_llm needs its intent).
    const dLlmResult = await agent(
      dLlmPrompt,
      {
        label: `d_llm-${caseName}`,
        phase: 'Audit',
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
    const dCaps = (dLlmResult?.declared_capabilities || []).map(c => c.capability);

    // A_llm: extract actual capabilities AND judge coverage by declared intent (D).
    // Runs AFTER D_llm — covered_by_declared needs the declared intent.
    const aLlmVars = {
      declared_caps: dCaps,
      intended_workflow: dLlmResult?.intended_workflow || '',
    };
    const aLlmInstrPrompt = await agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py a_llm_instr --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify(aLlmVars)}
VARS_JSON

Return ONLY the rendered prompt text.`,
      { label: `render-allm-prompt-${caseName}` }
    );
    const aLlmInstrResult = await agent(
      aLlmInstrPrompt,
      {
        label: `a_llm_instr-${caseName}`,
        phase: 'Audit',
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

    // A_llm：真实执行的所有敏感操作（完整 A）
    const aActualCaps = (aLlmInstrResult?.actual_capabilities || []).map(c => c.capability);
    const aAdvCaps = (aLlmInstrResult?.actual_capabilities || [])
      .filter(c => c.is_adversarial)
      .map(c => c.capability);
    // U 语义化：仅超出声明意图（covered_by_declared=false）的操作才是真偏差
    const aUncoveredCaps = (aLlmInstrResult?.actual_capabilities || [])
      .filter(c => c.covered_by_declared === false)
      .map(c => c.capability);

    log(`[${caseName}] D_llm: ${dCaps.length} declared, A_llm: ${aActualCaps.length} actual (${aAdvCaps.length} adv, ${aUncoveredCaps.length} over-intent)`);

    // --- Step 4: LLM Judge — final verdict ---
    log(`[${caseName}] Running LLM Judge...`);

    const declaredSummary = (dLlmResult?.declared_capabilities || [])
      .map(c => `- ${c.capability}: "${c.evidence.substring(0, 100)}"`)
      .join('\n') || '(none)';

    const instructionSummary = (aLlmInstrResult?.actual_capabilities || [])
      .map(c => `- ${c.capability} (adversarial=${c.is_adversarial}): "${c.evidence.substring(0, 100)}"`)
      .join('\n') || '(none)';

    // Deterministic Φ(s) evidence section (from Python pipeline)
    const detSummary = detEvidence
      ? buildDetEvidenceText(detEvidence)
      : '(deterministic pipeline failed or unavailable)';

    // --- Phase 0: block chunking v2 (trigger-condition blocks, agent-driven) ---
    // Deterministic seed (frontmatter metadata block + body lines), then incrementally
    // divide the body into "max line range executed under one trigger condition" blocks.
    // Each step opens a FRESH historyless agent on the still-uncovered body range
    // (IncrementalAgent pattern), shrinks the range, and repeats until fully covered.
    log(`[${caseName}] Phase 0: chunking SKILL.md into trigger-condition blocks...`);
    const phase0 = await (async () => {
      try {
        const seedRaw = await agent(
          `Run this shell command and return its EXACT raw stdout (a JSON object {unit,frontmatter_block,body_offset,body_lines,body_text,blocks}), with NO commentary, NO markdown code fences:

python scripts/skill_chunk.py ${caseDir}

The output is a single JSON object. Output ONLY that JSON object.`,
          { label: `chunk-seed-${caseName}` }
        );
        const seed = parseJsonOutput(seedRaw);
        if (!seed || !Array.isArray(seed.body_lines)) {
          log(`[${caseName}] Phase 0 seed invalid`);
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
            { label: `chunk-part-${caseName}-${iter}` }
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
        log(`[${caseName}] Phase 0 chunking failed: ${e}`);
        return { unit: 'trigger-block', count: 0, blocks: [] };
      }
    })();
    const blocks = phase0.blocks || [];
    log(`[${caseName}] Phase 0 blocks: ${blocks.length}`);

    // --- V_decl: block-level malicious classification (no-deviation-malicious) ---
    log(`[${caseName}] Running V_decl block-level classification...`);

    const vdeclVars = {
      // D = 声明能力全集（确定性 ∪ D_llm 语义）
      D: Array.from(new Set([...(detEvidence?.D_det || []), ...dCaps])),
      // A = 真实执行的所有敏感操作：确定性(A_ast+A_regex) ∪ A_llm（完整能力）
      A: Array.from(new Set([
        ...(detEvidence?.A_ast || []),
        ...(detEvidence?.A_regex || []),
        ...aActualCaps,
      ])),
      // U = 超出声明意图（covered_by_declared=false）的操作 → 语义偏差，非集合差
      U: aUncoveredCaps,
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

    // Long skills are classified in chunks by BLOCK count; a single
    // StructuredOutput retry-caps on ~250 rows. Blocks carry real global
    // block_id, so each chunk needs no offset — results merge by block_id.
    const VDECL_CHUNK = 120;
    const chunks = [];
    for (let i = 0; i < blocks.length; i += VDECL_CHUNK) {
      chunks.push(blocks.slice(i, i + VDECL_CHUNK));
    }

    const renderVdeclPrompt = (blockSubset, idx) => {
      const vars = { ...vdeclVars, blocks: blockSubset };
      return agent(
        `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py sentence_classifier --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify(vars)}
VARS_JSON`,
        { label: `render-vdecl-${caseName}${chunks.length > 1 ? '-' + idx : ''}` }
      );
    };

    let vdeclResult = null;
    if (chunks.length <= 1) {
      const vdeclPrompt = await renderVdeclPrompt(blocks, 0);
      vdeclResult = await agent(
        vdeclPrompt,
        { label: `vdecl_classifier-${caseName}`, phase: 'Audit', schema: VDECL_SCHEMA }
      );
    } else {
      // Multi-chunk: one agent per block subset, merge by block_id (dedup).
      const chunkResults = await Promise.all(chunks.map(async (chunk, idx) => {
        const prompt = await renderVdeclPrompt(chunk, idx);
        const r = await agent(
          prompt,
          { label: `vdecl_classifier-${caseName}-${idx}`, phase: 'Audit', schema: VDECL_SCHEMA }
        );
        log(`[${caseName}] vdecl chunk ${idx + 1}/${chunks.length}: ${r ? (r.block_classifications || []).length : 0} blocks`);
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
    // vdecl 可能漏标部分块（LLM 输出不完整）。对缺失 block_id 单独补测并合并，
    // 确保 phase0 每个块都有分类（前端未标注块灰底 = 数据缺失，应避免）。
    const classifiedIds = new Set((vdeclResult?.block_classifications || []).map(c => c.block_id));
    const missingBlocks = blocks.filter(b => !classifiedIds.has(b.block_id));
    if (missingBlocks.length > 0) {
      log(`[${caseName}] vdecl missing ${missingBlocks.length} block(s), backfilling...`);
      const backfillResults = await Promise.all(missingBlocks.map(async (mb, idx) => {
        const vars = { ...vdeclVars, blocks: [mb] };
        const prompt = await agent(
          `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py sentence_classifier --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify(vars)}
VARS_JSON

Return ONLY the rendered prompt text.`,
          { label: `render-vdecl-backfill-${caseName}-${idx}` }
        );
        return agent(
          prompt,
          { label: `vdecl_backfill-${caseName}-${idx}`, phase: 'Audit', schema: VDECL_SCHEMA }
        );
      }));
      const bf = backfillResults.filter(Boolean);
      const byId = {};
      for (const c of (vdeclResult?.block_classifications || [])) {
        if (c && typeof c.block_id === 'number') byId[c.block_id] = c;
      }
      for (const r of bf) {
        for (const c of (r.block_classifications || [])) {
          if (c && typeof c.block_id === 'number') byId[c.block_id] = c;
        }
      }
      const sorted = Object.keys(byId).map(Number).sort((a, b) => a - b).map(k => byId[k]);
      const uncond = [...(vdeclResult?.unconditional_harmful || []),
        ...bf.flatMap(r => r.unconditional_harmful || [])].filter(h => h && h.pattern);
      vdeclResult = {
        block_classifications: sorted,
        unconditional_harmful: uncond,
        coverage: { total_blocks: blocks.length, classified_blocks: sorted.length },
      };
      log(`[${caseName}] vdecl backfilled: ${sorted.length}/${blocks.length} blocks`);
    }

    const vdeclHits = (vdeclResult?.unconditional_harmful || []).filter(h => h && h.pattern);
    const vdeclFired = vdeclHits.length > 0;
    const vdeclNoDevMal = (vdeclResult?.block_classifications || [])
      .filter(s => s && s.classification === 'no-deviation-malicious').length;

    const judgeEvidenceSummary = `${detSummary}

## Declared Capabilities (semantic extraction):
${declaredSummary}

## Instruction-Level Analysis:
${instructionSummary}
Analysis summary: ${aLlmInstrResult?.analysis_summary || 'none'}

## V_decl 声明轨道恶意通道（块级分类 — 无偏差恶意识别）
${vdeclHits.length
    ? vdeclHits.map(h => `- [!] ${h.pattern}: "${h.evidence}" (block ${h.block_id}, anchor: ${h.anchor})`).join('\n')
    : 'no unconditional-harmful declaration detected'}
no-deviation-malicious 块数: ${vdeclNoDevMal}`;

    const judgePrompt = await agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py judge --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify({ evidence_summary: judgeEvidenceSummary })}
VARS_JSON`,
      { label: `render-judge-prompt-${caseName}` }
    );

    const judgeResult = await agent(
      judgePrompt,
      {
        label: `judge-${caseName}`,
        phase: 'Audit',
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

    log(`[${caseName}] VERDICT: ${judgeResult?.verdict} (${((judgeResult?.confidence || 0) * 100).toFixed(0)}%)`);

    // --- Phase 4: malicious attack chain construction (per malicious block) ---
    // For each malicious block, a subagent builds user_input (trigger) + flow_items
    // (the actual malicious code snippets from capability_code_evidence).
    log(`[${caseName}] Phase 4: constructing malicious attack chains...`);
    const attackChains = [];
    const maliciousBlocks = (vdeclResult?.block_classifications || [])
      .filter(b => b && b.classification && b.classification.includes('malicious'));
    if (maliciousBlocks.length > 0) {
      const cce = (detFull?.phase1?.capability_code_evidence) || {};
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

python scripts/prompt_render.py attack_chain --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify(chainVars)}
VARS_JSON

Return ONLY the rendered prompt text.`,
          { label: `render-chain-${caseName}-${idx}` }
        );
        const r = await agent(
          prompt,
          {
            label: `attack_chain-${caseName}-${idx}`,
            phase: 'Audit',
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
        if (r) log(`[${caseName}] Phase 4 chain for block ${r.block_id}: ${(r.flow_items || []).length} flow-item(s)`);
        return r;
      }));
      attackChains.push(...chainResults.filter(Boolean));
    }
    log(`[${caseName}] Phase 4: ${attackChains.length} attack chain(s)`);

    return {
      case: caseName,
      case_dir: caseDir,
      class: deriveClass(caseDir),
      skill_name: skillName,
      verdict: vdeclFired ? 'malware' : (judgeResult?.verdict || 'error'),
      confidence: vdeclFired ? Math.max(0.9, judgeResult?.confidence || 0) : (judgeResult?.confidence || 0),
      reasoning: judgeResult?.reasoning || '',
      intent_category: judgeResult?.intent_category || 'H',
      intent_category_name: INTENT_NAMES[judgeResult?.intent_category] || '',
      key_evidence: judgeResult?.key_evidence || [],
      d_llm_count: dCaps.length,
      d_llm_caps: dCaps,
      // A_llm: 真实执行的所有敏感操作（完整能力，非仅恶意指令）
      a_llm_instr_count: aActualCaps.length,
      a_llm_instr_caps: aActualCaps,
      a_llm_adv_caps: aAdvCaps,
      intended_workflow: dLlmResult?.intended_workflow || '',
      // Deterministic evidence passed through for downstream aggregation
      det: detEvidence
        ? {
            U: detEvidence.undeclared || [],
            O: detEvidence.overdeclared || [],
            compound_flags: detEvidence.compound_flags || {},
            rule_engine: detEvidence.rule_engine || {},
            relaxed_veto: detEvidence.relaxed_veto || {},
            _det_verdict: detEvidence._det_verdict || {},
            finding_counts: detEvidence.finding_counts || {},
          }
        : null,
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
      // Complete deterministic result (phase1 with skill_body + capability_code_evidence)
      // persisted alongside the LLM verdict — the frontend needs these for code snippets.
      det_full: detFull || null,
      error: null,
    };
  }
);

// =============================================================================
// Phase 3: Report
// =============================================================================
phase('Report');

const valid = results.filter(r => r && !r.error);
const errors = results.filter(r => r && r.error);
const malware = valid.filter(r => r.verdict === 'malware');
const benign = valid.filter(r => r.verdict === 'benign');

// Ground truth comes from the path segment (std-cases-4: benign/ malware/).
// Never read .expected — that would leak the label into the audit context.
const expectedResults = valid.map((r) => {
  r.expected = (r.class && r.class !== 'unknown') ? r.class : 'unknown';
  r.match = r.expected === r.verdict;
  return r;
});

const matched = expectedResults.filter(r => r.match === true);
const mismatched = expectedResults.filter(r => r.match === false);

const summary = {
  total: caseDirs.length,
  audited: valid.length,
  errors: errors.length,
  malware: malware.length,
  benign: benign.length,
  matched: matched.length,
  mismatched: mismatched.length,
};

log('');
log('========================================');
log('BATCH AUDIT COMPLETE');
log('========================================');
log(`Total: ${summary.total} | Audited: ${summary.audited} | Errors: ${summary.errors}`);
log(`Malware: ${summary.malware} | Benign: ${summary.benign}`);
log(`Label match: ${summary.matched}/${summary.matched + summary.mismatched}`);
log('');
for (const r of expectedResults) {
  const matchIcon = r.match === true ? '✓' : r.match === false ? '✗' : '?';
  const conf = ((r.confidence || 0) * 100).toFixed(0);
  log(`${matchIcon} ${r.case.padEnd(50)} ${r.verdict.padEnd(8)} conf=${conf}% intent=${r.intent_category}`);
}

// --- Write results to experiment/results/ (default output path) ---
// The Workflow script has no filesystem access, so the file is written by a
// subagent. Override the output path via args.output or args.results_file.
// Error cases are included in the report so no case is silently dropped.
const outputFile = (args && (args.output || args.results_file)) || 'experiment/results/batch_workflow_result.json';
const reportResults = [
  ...expectedResults,
  ...errors.map(e => ({ ...e, expected: 'unknown', match: null })),
];
const reportJson = JSON.stringify({ summary, results: reportResults }, null, 2);

try {
  const writeRes = await agent(
    `Write the JSON content below to the file at ${outputFile}.
First create the parent directory (mkdir -p experiment/results) if it does not exist.
Output ONLY the single word "ok" on success. Do not modify the JSON content.

${reportJson}`,
    { label: 'write-batch-result' }
  );
  log(`Results written to ${outputFile}`);
} catch (e) {
  log(`Warning: could not write ${outputFile}: ${e}`);
}

// --- Write per-case results mirroring the cases directory structure ---
// Each case gets experiment/results/<rel>/result.json where <rel> is the case
// path relative to experiment/cases/ (e.g. std-cases-4/benign/<skill>).
const casesRoot = 'experiment/cases/';
const resultsRoot = (args && args.results_dir) || 'experiment/results';
await Promise.all(reportResults.map(async (r) => {
  const rel = r.case_dir && r.case_dir.startsWith(casesRoot)
    ? r.case_dir.slice(casesRoot.length)
    : `${r.class || 'unknown'}/${r.case}`;
  const outPath = `${resultsRoot}/${rel}/result.json`;
  const parentDir = outPath.replace(/\/[^/]+$/, '');
  // Merge the full deterministic phase1 (skill_body + capability_code_evidence)
  // into the persisted result so the frontend has everything in one file.
  const payload = r && r.det_full && r.det_full.phase1
    ? { ...r, phase1: r.det_full.phase1 }
    : r;
  if (payload && payload.det_full) delete payload.det_full;
  try {
    await agent(
      `Write the JSON content below to the file at ${outPath}.
First create the parent directory (mkdir -p "${parentDir}") if it does not exist.
Output ONLY the single word "ok" on success. Do not modify the JSON content.

${JSON.stringify(payload, null, 2)}`,
      { label: `write-${r.case}` }
    );
    log(`Results written to ${outPath}`);
  } catch (e) {
    log(`Warning: could not write ${outPath}: ${e}`);
  }
}));

return { summary, results: reportResults, output_file: outputFile };
