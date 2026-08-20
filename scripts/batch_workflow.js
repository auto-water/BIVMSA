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
  description: 'Batch BIVMSA audit with LLM — scans experiment/cases/ and runs full pipeline on each',
  phases: [
    { title: 'Discover', detail: 'Scan cases directory and read skill content' },
    { title: 'Audit', detail: 'Full pipeline (deterministic + LLM) per case' },
    { title: 'Report', detail: 'Aggregate results and verdict summary' },
  ],
};

// =============================================================================
// Sanitize + base64 写盘（硬性过滤落盘 JSON）
//   - 反斜杠 -> 正斜杠（Windows 路径否则产生非法 \x 转义）
//   - 移除 emoji / 补充平面(4 字节宽字符) / C0-C1 控制字符 / 零宽与格式字符 / BOM
//   - 保留 CJK（中文）与 BMP 可打印字符
//   - 写盘用 base64 传输：subagent 只"盲抄"不可读的 base64（杜绝二次格式化/还原转义），
//     decode 用 python（base64 命令在 Windows 可能缺失；外层脚本还会兜底 decode .b64）
// =============================================================================
function sanitizeText(s) {
  if (typeof s !== 'string') return s;
  let out = '';
  for (const ch of s) {
    if (ch === '\\') { out += '/'; continue; }                    // 反斜杠 -> 正斜杠
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) continue;         // C0/C1 控制字符
    if ((cp >= 0x200b && cp <= 0x200f) || cp === 0x2028 || cp === 0x2029
        || cp === 0x2060 || cp === 0xfeff) continue;               // 零宽/行分隔/BOM
    if (cp >= 0x10000) continue;                                   // 补充平面（emoji/宽字节）
    if ((cp >= 0x2600 && cp <= 0x27bf) || (cp >= 0x2b00 && cp <= 0x2bff)) continue; // BMP emoji/符号块
    out += ch;
  }
  return out;
}

function sanitizeValue(v) {
  if (typeof v === 'string') return sanitizeText(v);
  if (Array.isArray(v)) return v.map(sanitizeValue);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v)) o[k] = sanitizeValue(v[k]);
    return o;
  }
  return v;
}

// 纯 JS UTF-8 -> base64（workflow 运行时无 Node Buffer / TextEncoder / btoa）。
// sanitizeValue 已剔除补充平面字符，但保留代理对分支以防万一。
function utf8ToBase64(input) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let utf8 = '';
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c < 0x80) utf8 += String.fromCharCode(c);
    else if (c < 0x800) utf8 += String.fromCharCode(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0xd800 || c >= 0xe000) {
      utf8 += String.fromCharCode(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      i += 1;
      const c2 = input.charCodeAt(i);
      const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
      utf8 += String.fromCharCode(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
  }
  let b64 = '';
  let i = 0;
  for (; i + 3 <= utf8.length; i += 3) {
    const n = (utf8.charCodeAt(i) << 16) | (utf8.charCodeAt(i + 1) << 8) | utf8.charCodeAt(i + 2);
    b64 += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + chars[n & 63];
  }
  const rem = utf8.length - i;
  if (rem === 1) {
    const n = utf8.charCodeAt(i) << 16;
    b64 += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (utf8.charCodeAt(i) << 16) | (utf8.charCodeAt(i + 1) << 8);
    b64 += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + '=';
  }
  return b64;
}

// 规范化路径：/e/xxx -> E:/xxx（bash 的 MSYS 路径 Write/Python 工具不识别）。
function normPath(p) {
  if (typeof p !== 'string') return p;
  const m = p.match(/^\/([a-zA-Z])\/(.*)$/);
  return m ? `${m[1].toUpperCase()}:/${m[2]}` : p;
}

async function writeJsonViaBase64(agentFn, obj, outputFile, label = 'write-result') {
  outputFile = normPath(outputFile);
  const outputDir = outputFile.substring(0, outputFile.lastIndexOf('/'));
  const jsonText = JSON.stringify(sanitizeValue(obj), null, 2);
  const b64 = utf8ToBase64(jsonText);
  await agentFn(
    `Write the file ${outputFile}:
1. Create the directory: mkdir -p ${outputDir}
2. Write the ENTIRE base64 payload below VERBATIM to ${outputFile}.b64 using the Write tool. It is opaque data — do NOT decode, wrap, modify, or add line breaks:
${b64}
3. Decode it with python: python -c "import base64;open('${outputFile}','wb').write(base64.b64decode(open('${outputFile}.b64').read()))"
4. Remove the payload: rm -f ${outputFile}.b64
5. Output ONLY the single word "ok".`,
    { label }
  );
}

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
        let stall = 0;
        const MAX_ITER = 60;
        let stalled = false;
        while (start <= bodyTotal && iter < MAX_ITER) {
          const prevStart = start;
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
          if (start <= prevStart) {
            // 硬约束：effEnd 未推进 start（agent 无新产出）→ 停滞计数；连续 3 轮终止，
            // 防止切块 agent 反复无产出造成 session 风暴。
            stall += 1;
            log(`[${caseName}] Phase 0 切块停滞 ${stall} 轮（start=${prevStart}）`);
            if (stall >= 3) { stalled = true; break; }
          } else {
            stall = 0;
          }
          iter += 1;
        }
        return { unit: 'trigger-block', count: blocks.length, blocks, stalled };
      } catch (e) {
        log(`[${caseName}] Phase 0 chunking failed: ${e}`);
        return { unit: 'trigger-block', count: 0, blocks: [] };
      }
    })();
    const blocks = phase0.blocks || [];
    // 每块提取引用的脚本名（det 静态证据按脚本名归因到这些块）
    const SCRIPT_RE = /(?:scripts|\/scripts)\/([\w.-]+\.(?:py|js|ts|sh|mjs|cjs|ps1|bat))/gi;
    for (const b of blocks) {
      b.scripts = [];
      const re = new RegExp(SCRIPT_RE.source, 'gi');
      let m;
      while ((m = re.exec(b.text || ''))) b.scripts.push(m[1]);
    }
    log(`[${caseName}] Phase 0 blocks: ${blocks.length}`);

    // 切块停滞硬约束：连续 3 轮无新块 → 终止该 case（防 session 风暴），返回 error 结果
    if (phase0.stalled) {
      log(`[${caseName}] Phase 0 切块停滞，终止该 case（防 session 风暴）`);
      return {
        case: caseName, case_dir: caseDir, class: deriveClass(caseDir),
        skill_name: skillName,
        verdict: 'error', verdict_source: 'phase0-stalled',
        reasoning: 'phase0 stalled: no new block in 3 rounds',
        error: 'phase0 stalled',
        phase0: { unit: 'trigger-block', count: blocks.length, blocks },
      };
    }

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
    // VDECL_CHUNK=40: 单批 prompt/输出体积控制（120 对长文本仍过大导致 retry 超限）。
    const VDECL_CHUNK = 40;
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

    // 单批分类 helper：render → agent(schema)。单批失败重试 2 次。
    // 主分批与 backfill 分批共用（E1：backfill 不再逐块，按批补测）。
    const classifyBlockChunk = async (chunk, idx, labelPrefix, phaseLabel) => {
      const prompt = await renderVdeclPrompt(chunk, idx);
      for (let t = 0; t < 2; t++) {
        const r = await agent(
          prompt,
          { label: `${labelPrefix}-${caseName}-${idx}${t ? '-r' + t : ''}`, phase: phaseLabel, schema: VDECL_SCHEMA }
        );
        if (r) return r;
        log(`[${caseName}] V_decl chunk ${idx} attempt ${t + 1} failed, retrying...`);
      }
      return null;
    };

    let vdeclResult = null;
    if (chunks.length <= 1) {
      vdeclResult = await classifyBlockChunk(blocks, 0, 'vdecl_classifier', 'Audit');
    } else {
      // Multi-chunk: one agent per block subset, merge by block_id (dedup).
      const chunkResults = await Promise.all(chunks.map((chunk, idx) =>
        classifyBlockChunk(chunk, idx, 'vdecl_classifier', 'Audit')));
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

    // --- coverage 校验：缺失块按批补测，迭代收敛（≤3 轮）---
    // E1：由"逐块 backfill"改为按 VDECL_CHUNK 分批（每批一次 agent，复用 classifyBlockChunk），
    // 补测后重算缺失；≤3 轮收敛、无进展即停，避免 696 次逐块调用造成卡死与 session 风暴。
    const _byId = {};
    for (const c of (vdeclResult?.block_classifications || [])) {
      if (c && typeof c.block_id === 'number') _byId[c.block_id] = c;
    }
    let _missing = blocks.filter(b => !_byId[b.block_id]);
    let _bfUncond = [...(vdeclResult?.unconditional_harmful || [])];
    for (let round = 0; round < 3 && _missing.length > 0; round++) {
      const bfChunks = [];
      for (let i = 0; i < _missing.length; i += VDECL_CHUNK) bfChunks.push(_missing.slice(i, i + VDECL_CHUNK));
      log(`[${caseName}] vdecl backfill round ${round + 1}: ${_missing.length} missing -> ${bfChunks.length} chunk(s)`);
      const results = await Promise.all(bfChunks.map((chunk, i) =>
        classifyBlockChunk(chunk, i, `vdecl-backfill-${round}`, 'Audit')));
      for (const r of results.filter(Boolean)) {
        for (const c of (r.block_classifications || [])) {
          if (c && typeof c.block_id === 'number') _byId[c.block_id] = c;
        }
        _bfUncond.push(...(r.unconditional_harmful || []));
      }
      const _next = blocks.filter(b => !_byId[b.block_id]);
      if (_next.length >= _missing.length) break;   // 无进展 → 停止，避免死循环
      _missing = _next;
    }
    const sorted = Object.keys(_byId).map(Number).sort((a, b) => a - b).map(k => _byId[k]);
    const uncond = _bfUncond.filter(h => h && h.pattern);
    vdeclResult = {
      block_classifications: sorted,
      unconditional_harmful: uncond,
      coverage: { total_blocks: blocks.length, classified_blocks: sorted.length },
    };
    if (_missing.length) log(`[${caseName}] vdecl 仍有 ${_missing.length} 块未能覆盖（尽力而为，前端将灰底显示）`);
    else log(`[${caseName}] vdecl coverage 完整: ${sorted.length}/${blocks.length} blocks`);

    // B3：unconditional_harmful 硬校验——命中必须对应 action_instruction 块、
    // 不与块级分类自相矛盾、且非惰性 markdown 引用（图片/链接且无执行动词）。
    const _EXEC_VERBS = /\b(curl|wget|fetch|Invoke-WebRequest|exec|spawn|Popen|subprocess|child_process|download|pip install|npm install|chmod|bash\s+-c|sh\s+-c|eval\(|system\(|Start-Process|Install-Module)\b/i;
    const _isInertReference = (text) => {
      const t = String(text || '');
      if (!/!?\[[^\]]*\]\([^)]*\)/.test(t)) return false;   // 无链接/图片语法 → 不豁免
      return !_EXEC_VERBS.test(t);                          // 无执行动词 → 惰性引用，豁免
    };
    function filterUnconditionalHits(hits, p0blocks, classifs) {
      const clsById = new Map((classifs || [])
        .filter(c => c && typeof c.block_id === 'number').map(c => [c.block_id, c]));
      return (hits || []).filter(h => {
        if (!h || !h.pattern) return false;
        if (typeof h.block_id !== 'number') return true;    // 无 block_id → 保守保留
        const cls = clsById.get(h.block_id);
        const blk = (p0blocks || []).find(b => b.block_id === h.block_id);
        if (cls && cls.kind === 'non_action') return false; // ① non_action 不参与 U
        if (blk && blk.kind === 'non_action') return false;
        if (cls && cls.malicious_label === 'benign') return false; // ② 与块级分类矛盾
        if (blk && _isInertReference(blk.text)) return false;     // ③ 惰性引用豁免
        return true;
      });
    }

    const vdeclHits = filterUnconditionalHits(
      vdeclResult?.unconditional_harmful || [], blocks, vdeclResult?.block_classifications || []);
    const vdeclFired = vdeclHits.length > 0;
    const vdeclNoDevMal = (vdeclResult?.block_classifications || [])
      .filter(s => s && s.classification === 'no-deviation-malicious').length;

    // 静态 det → block 级命中：SKILL.md 内证据直接对位；scripts/* 证据按 block.scripts 脚本名归因。
    function buildDetBlockHits(detFull, blocks) {
      const cce = (detFull && detFull.phase1 && detFull.phase1.capability_code_evidence) || {};
      const hits = [];
      for (const cap of Object.keys(cce)) {
        for (const loc of (cce[cap].locations || [])) {
          const f = String(loc.file || '');
          if (f.toLowerCase().includes('skill.md') && loc.line_start) {
            const blk = blocks.find(b => typeof b.line_start === 'number' && typeof b.line_end === 'number'
              && loc.line_start >= b.line_start && loc.line_start <= b.line_end);
            if (blk) hits.push({ block_id: blk.block_id, capability: cap, source: 'skill-md', evidence: loc });
            continue;
          }
          const scriptName = f.split(/[\\/]/).pop();
          if (scriptName) {
            for (const b of blocks) {
              if ((b.scripts || []).includes(scriptName))
                hits.push({ block_id: b.block_id, capability: cap, source: 'script:' + scriptName, evidence: loc });
            }
          }
        }
      }
      return hits;
    }
    let detBlockHits = buildDetBlockHits(detFull, blocks);
    // 三级兜底：det 判恶意但无任何块命中 → 首个 action_instruction 块（保证 det 恶意必有 block）
    if (detBlockHits.length === 0 && detFull?._det_verdict?.verdict === 'malware') {
      const firstAction = (vdeclResult?.block_classifications || []).find(c => c.kind === 'action_instruction');
      if (firstAction && typeof firstAction.block_id === 'number') {
        detBlockHits = [{ block_id: firstAction.block_id, capability: null, source: 'det-fallback', evidence: null }];
      }
    }
    log(`[${caseName}] det_block_hits: ${detBlockHits.length} (det_verdict=${detFull?._det_verdict?.verdict || '?'})`);

    // --- LLM Judge：逐块审计（审计对象 = 块审计信息；全局结论由 block 归约，禁止直接出全局 verdict）---
    log(`[${caseName}] Running LLM Judge (block-level audit)...`);

    const JUDGE_SCHEMA = {
      type: 'object',
      properties: {
        block_judgments: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              block_id: { type: 'integer' },
              verdict: { type: 'string', enum: ['benign', 'malicious'] },
              intent_category: { type: 'string' },
              confidence: { type: 'number' },
              reasoning: { type: 'string' },
            },
            required: ['block_id', 'verdict', 'reasoning'],
          },
        },
      },
      required: ['block_judgments'],
    };

    // 每块的审计信息：text(截断) + vdecl 标注 + det 命中 + scripts；D/A/U/O 仅作全局上下文
    const judgeVars = { skill_name: skillName, D: vdeclVars.D, A: vdeclVars.A, U: vdeclVars.U, O: vdeclVars.O };
    const buildJudgeChunk = (blockSubset) => ({
      ...judgeVars,
      blocks: blockSubset.map(b => {
        const cls = (vdeclResult?.block_classifications || []).find(c => c.block_id === b.block_id);
        const uHit = vdeclHits.find(h => h.block_id === b.block_id);
        const dets = detBlockHits.filter(h => h.block_id === b.block_id);
        return {
          block_id: b.block_id,
          text: String(b.text || '').slice(0, 600),
          scripts: b.scripts || [],
          kind: (cls && cls.kind) || null,
          vdecl_classification: (cls && cls.classification) || null,
          vdecl_capabilities: (cls && cls.capabilities) || [],
          core_instruction: (cls && cls.core_instruction) || '',
          unconditional_harmful: uHit ? { pattern: uHit.pattern, evidence: uHit.evidence } : null,
          det_hits: dets.map(d => ({ capability: d.capability, source: d.source })),
        };
      }),
    });
    const renderJudgePrompt = (blockSubset, idx) => agent(
      `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py judge --skill-dir ${caseDir} --variant batch <<'VARS_JSON'
${JSON.stringify(buildJudgeChunk(blockSubset))}
VARS_JSON`,
      { label: `render-judge-prompt-${caseName}${judgeChunks.length > 1 ? '-' + idx : ''}` }
    );
    const classifyJudgeChunk = async (chunk, idx) => {
      const prompt = await renderJudgePrompt(chunk, idx);
      for (let t = 0; t < 2; t++) {
        const r = await agent(prompt, {
          label: `judge-${caseName}-${idx}${t ? '-r' + t : ''}`,
          phase: 'Audit', effort: 'xhigh', schema: JUDGE_SCHEMA,
        });
        if (r) return r;
        log(`[${caseName}] judge chunk ${idx} attempt ${t + 1} failed, retrying...`);
      }
      return null;
    };
    const judgeChunks = [];
    for (let i = 0; i < blocks.length; i += VDECL_CHUNK) judgeChunks.push(blocks.slice(i, i + VDECL_CHUNK));
    const judgeResults = await Promise.all(judgeChunks.map((chunk, idx) => classifyJudgeChunk(chunk, idx)));
    const judgeById = {};
    for (const r of judgeResults.filter(Boolean)) {
      for (const j of (r.block_judgments || [])) {
        if (j && typeof j.block_id === 'number') judgeById[j.block_id] = j;
      }
    }
    const judgeMissingCount = blocks.filter(b => !judgeById[b.block_id]).length;
    if (judgeMissingCount) log(`[${caseName}] Judge 缺 ${judgeMissingCount} 个块的判定（对应 block_verdicts.judge=null）`);
    const judgeResult = { block_judgments: Object.values(judgeById) };
    log(`[${caseName}] Judge 逐块完成: ${judgeResult.block_judgments.length} 个块的判定`);

    // ---------------------------------------------------------------------------
    // Phase 3 汇总：三路 block 级判定 → block_verdicts → 全局 verdict（简单规则）
    //   原则：任何阶段都不直接产全局 verdict；全局结论 = 存在恶意 block 则全局恶意。
    // ---------------------------------------------------------------------------
    const blockVerdicts = blocks.map(b => {
      const cls = (vdeclResult?.block_classifications || []).find(c => c.block_id === b.block_id);
      const uHit = vdeclHits.find(h => h.block_id === b.block_id);
      const dets = detBlockHits.filter(h => h.block_id === b.block_id);
      const jg = judgeById[b.block_id];
      const sources = [];
      if (dets.length) sources.push('det');
      if (uHit || (cls && String(cls.classification || '').includes('malicious'))) sources.push('vdecl');
      if (jg && jg.verdict === 'malicious') sources.push('judge');
      return {
        block_id: b.block_id,
        text: b.text,
        scripts: b.scripts || [],
        det: dets.length ? dets : null,
        vdecl: uHit
          ? { pattern: uHit.pattern }
          : (cls && String(cls.classification).includes('malicious') ? { classification: cls.classification } : null),
        judge: jg
          ? { verdict: jg.verdict, intent_category: jg.intent_category || null, reasoning: jg.reasoning || '', confidence: jg.confidence || null }
          : null,
        is_malicious: sources.length > 0,
        sources,
      };
    });
    const maliciousBlocks = blockVerdicts.filter(v => v.is_malicious);
    const verdict = maliciousBlocks.length > 0 ? 'malware' : 'benign';
    const verdict_source = maliciousBlocks.length > 0 ? maliciousBlocks[0].sources[0] : 'llm_judge';
    const verdictReasoning = maliciousBlocks.length > 0
      ? `共 ${maliciousBlocks.length} 个恶意块: ${maliciousBlocks.slice(0, 5).map(v => `block ${v.block_id}(${(v.sources || []).join('+')})`).join(', ')}${maliciousBlocks.length > 5 ? '...' : ''}`
      : '无恶意块（三路 block 判定均为 benign）';
    log(`[${caseName}] Phase 3 汇总: ${blockVerdicts.length} 块, ${maliciousBlocks.length} 恶意块, verdict=${verdict} (source=${verdict_source})`);

    // --- Phase 4: malicious attack chain construction (per malicious block) ---
    // For each malicious block, a subagent builds user_input (trigger) + flow_items
    // (the actual malicious code snippets from capability_code_evidence).
    log(`[${caseName}] Phase 4: constructing malicious attack chains...`);
    const attackChains = [];
    if (maliciousBlocks.length > 0) {
      const cce = (detFull?.phase1?.capability_code_evidence) || {};
      const chainResults = await Promise.all(maliciousBlocks.map(async (mb, idx) => {
        // mb 是 block_verdicts 项：capabilities/classification 从 vdecl 块分类回溯
        const cls = (vdeclResult?.block_classifications || []).find(c => c.block_id === mb.block_id);
        const capsOfBlock = (cls && cls.capabilities) || [];
        const cceFiltered = {};
        for (const cap of capsOfBlock) {
          if (cce[cap]) cceFiltered[cap] = cce[cap];
        }
        // trigger_condition 从 Phase 0 blocks 关联（block_classification 无此字段）
        const mbTrigger = (blocks.find(b => b.block_id === mb.block_id) || {}).trigger_condition || '';
        const chainVars = {
          block: {
            block_id: mb.block_id,
            trigger_condition: mbTrigger || '',
            classification: (mb.vdecl && mb.vdecl.classification) || (cls && cls.classification) || 'deviated-malicious',
            capabilities: capsOfBlock,
            sources: mb.sources || [],
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
      // 全局结论 = 简单规则：存在恶意 block 则全局恶意（Phase 3 三路 block 判定归约）
      verdict,
      verdict_source,
      confidence: maliciousBlocks.length > 0 ? 0.9 : 0,
      reasoning: verdictReasoning,
      intent_category: (() => {
        const fm = maliciousBlocks.find(v => v.judge && v.judge.verdict === 'malicious');
        return (fm && fm.judge.intent_category) || 'H';
      })(),
      intent_category_name: (() => {
        const fm = maliciousBlocks.find(v => v.judge && v.judge.verdict === 'malicious');
        return INTENT_NAMES[(fm && fm.judge.intent_category) || 'H'] || '';
      })(),
      key_evidence: (judgeResult?.block_judgments || [])
        .filter(j => j.verdict === 'malicious')
        .map(j => `block ${j.block_id}: ${String(j.reasoning || '').slice(0, 120)}`),
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
      // Phase 3: block 级三路判定汇总（det / vdecl / judge）— Phase 4 与前端消费
      block_verdicts: blockVerdicts,
      det_block_hits: detBlockHits,
      judge: judgeResult,   // { block_judgments: [...] }
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

try {
  await writeJsonViaBase64(agent, { summary, results: reportResults }, outputFile, 'write-batch-result');
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
  // Merge the full deterministic phase1 (skill_body + capability_code_evidence)
  // into the persisted result so the frontend has everything in one file.
  const payload = r && r.det_full && r.det_full.phase1
    ? { ...r, phase1: r.det_full.phase1 }
    : r;
  if (payload && payload.det_full) delete payload.det_full;
  try {
    await writeJsonViaBase64(agent, payload, outPath, `write-${r.case}`);
    log(`Results written to ${outPath}`);
  } catch (e) {
    log(`Warning: could not write ${outPath}: ${e}`);
  }
}));

return { summary, results: reportResults, output_file: outputFile };
