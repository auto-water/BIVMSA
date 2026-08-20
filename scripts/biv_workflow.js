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

// 通用 render：subagent 用 base64 把 vars 写到临时文件，再 `python prompt_render.py < file`。
// 替代 heredoc 传大 vars —— heredoc 命令超长（bash 单次调用限制）会导致 blocks 丢失，
// prompt_render 静默 fallback 成"每行一块"（E1 的 412 块风暴根因）。
async function renderPromptViaBase64Vars(name, skillDirArg, variant, vars, label) {
  const tmpFile = normPath(`experiment/results/_render_vars_${name}_${label.replace(/[^a-z0-9]/gi, '')}.json`);
  await writeJsonViaBase64(agent, vars, tmpFile, `${label}-write-vars`);
  return agent(
    `Run this shell command and return its EXACT raw stdout (the rendered prompt text), with NO commentary, NO markdown code fences:

python scripts/prompt_render.py ${name} --skill-dir ${skillDirArg} --variant ${variant} < ${tmpFile}; rm -f ${tmpFile}

Return ONLY the rendered prompt text.`,
    { label: `${label}-run` }
  );
}

// =============================================================================
// Main Workflow
// =============================================================================

const skillDir = args?.skill_dir;
if (!skillDir) {
  throw new Error("Missing required argument: skill_dir. Usage: Workflow({scriptPath: 'scripts/biv_workflow.js', args: {skill_dir: '...'}})");
}

log(`Starting BIV audit for: ${skillDir}`);

const relPath = skillDir.replace('experiment/cases/', '');
const outputFile = (args && args.output) || `experiment/results/${relPath}/result.json`;

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
      return { unit: 'action-block', count: 0, blocks: [] };
    }
    const fmBlock = seed.frontmatter_block || null;
    const bodyLines = seed.body_lines;
    const bodyOffset = seed.body_offset || 0;
    const bodyTotal = bodyOffset + bodyLines.length;
    const actionBlocks = [];

    // ---- 第一层 partition：按触发条件切 trigger Entry（同条件合并，仅条件变化才拆）----
    // 迁移自 reference/SKILL_CHUNKING_MIGRATION.md（partition.md）。prompt 直接拼
    // （remaining 大文本不经 prompt_render heredoc，避免命令长度限制导致 blocks 丢失
    // fallback 成"每行一块"）。agent 一次只提交一个 Entry，或 finish。
    const PARTITION_RULES = `You are a skill-chunking assistant (layer 1: trigger partition) for the AI agent skill "${skillName}".

## Goal
Find ONE trigger region in the assigned scope of SKILL.md body. A trigger region is the MAXIMAL line range that fires under ONE condition (when the skill loads, when the user asks, on a schedule, on second use, ...).

## Rules
- A frontmatter "description" or "when this Skill is loaded" statement can start an on-load trigger.
- GROUPING (important): everything that fires under the SAME condition belongs in ONE region — KEEP IT TOGETHER rather than splitting. A trigger region spans from the firing statement through ALL content it causes to run (prose, code blocks, conditionals, follow-on actions), even if separated by blank lines or headings. Only split when the firing condition ACTUALLY changes (e.g. load section vs. a separate user-query keyword vs. a schedule). If the whole remaining body loads and runs together, submit ONE on-load region covering it.
- Submit EXACTLY ONE region starting at or after the given global line. Do not cover more.

## Output
Return a single JSON object:
{"action": "submit", "start_line": N, "end_line": M, "subkind": "<trigger.* vocab>", "summary": "<why this subkind — quote the trigger phrasing>"}
OR {"action": "finish"} if the remaining scope has NO trigger-worthy content (only headings, blank lines, list markers, comments, or prose that does not itself fire or cause execution).

subkind must be one of:
on-load.always | on-load.include | on-load.other
on-exec.user-query | on-exec.schedule | on-exec.env-match | on-exec.compose | on-exec.fallback | on-exec.other
on-update.second-use | on-update.mutate-self | on-update.other
other`;

    // ---- 第二层 action_extract：Entry 内按原子操作切 action（迁移自 action_extract.md）----
    const ACTION_RULES = `You are a skill-chunking assistant (layer 2: atomic action extraction) for the AI agent skill "${skillName}".

## Goal
Find ONE atomic action in the assigned scope (a trigger Entry range of SKILL.md body).

## Rules
An atomic action is ONE observable operation:
- execute: a command / code block / subprocess;
- I/O: a file, network, or environment read/write/fetch;
- agent-directed prose: an imperative to the agent — "run ...", "always/never ...", "load/follow ...", "assume the role ...", "invoke tool ...", a hook/trigger-word binding, or framing text that directs behavior;
- other transforms, privilege/config changes, memory, or a terminal/return step.
Do NOT confuse descriptive prose ("This script does X") with a directive ("Run this script"). Only the latter is an action.

## Boundaries
- A fenced code block (\`\`\` ... \`\`\`) is ONE action: include BOTH fence lines in its range.
- One imperative prose sentence = one action.
- Submit EXACTLY ONE action starting at or after the given global line. Do not cover more.

## Output
Return a single JSON object:
{"action": "submit", "start_line": N, "end_line": M, "summary": "<what this one operation does, <=200 chars>"}
OR {"action": "finish"} if the remaining scope has NO operation and NO directive (only headings, blank lines, list markers, code-fence lines, comments, or purely descriptive prose).`;

    // ---- Phase 0 截断预算 ----
    // 防止对超大 body 逐块切造成 agent 调用风暴（后端慢时 40+ 次串行调用极慢）。
    // 达到预算即停止细粒度切分，剩余未覆盖行合并为一个兜底块。
    const PHASE0_MAX_AGENTS = 40;       // partition + action 总 agent 预算
    const MAX_ACTIONS_PER_ENTRY = 30;   // 每 Entry 内 action 上限
    const MAX_TOTAL_BLOCKS = 60;        // 总块数上限（含 frontmatter）
    let phase0Agents = 0;

    const entries = [];
    let pStart = bodyOffset + 1;
    let pIter = 0, pStall = 0;
    const P_MAX = 40;
    let stalled = false;
    let pFinished = false;
    while (pStart <= bodyTotal && pIter < P_MAX && phase0Agents < PHASE0_MAX_AGENTS) {
      phase0Agents += 1;
      const prevP = pStart;
      const remainingP = bodyLines.slice(pStart - bodyOffset - 1).join('\n');
      const r = parseJsonOutput(await agent(
        `${PARTITION_RULES}\n\n## Assigned scope (global de-blanked lines)\n${pStart}..${bodyTotal}\n\n## Uncovered remaining body text (starting at global line ${pStart})\n${remainingP}\n\n## Output JSON`,
        { label: `partition-${pIter}` }
      ));
      if (r && r.action === 'finish') {
        log(`Phase 0 partition finish at line ${pStart}`);
        break;
      }
      const eS = (r && typeof r.start_line === 'number') ? r.start_line : pStart;
      const eE = (r && typeof r.end_line === 'number') ? r.end_line : pStart;
      // 硬约束：agent 提交的区间必须覆盖当前起点（line_start <= pStart <= line_end），
      // 否则视为无效提交 → 计停滞（防止 agent 无产出时用 pStart 兜底强制前进、停滞守卫失效）。
      const valid = eS <= pStart && eE >= pStart;
      if (!valid) {
        pStall += 1;
        log(`Phase 0 partition 无效提交（start=${pStart}）第 ${pStall} 次`);
        if (pStall >= 3) { stalled = true; break; }
        continue;   // 不推进，等下一个 agent
      }
      const effEnd = Math.max(eE, pStart);
      entries.push({
        start_line: Math.max(pStart, eS),
        end_line: Math.min(bodyTotal, effEnd),
        subkind: (r && typeof r.subkind === 'string' && r.subkind) ? r.subkind : 'other',
        summary: (r && r.summary) || '',
      });
      pStart = Math.min(bodyTotal, effEnd) + 1;
      pStall = 0;
      pIter += 1;
    }
    // partition 截断兜底：因预算/上限停止且仍有未分区 body → 作为兜底 Entry（避免剩余行丢失）
    if (!pFinished && pStart <= bodyTotal) {
      entries.push({ start_line: pStart, end_line: bodyTotal, subkind: 'other',
        summary: '[截断] partition 预算耗尽，剩余行兜底' });
    }
    log(`Phase 0 partition: ${entries.length} trigger entries`);

    for (const e of entries) {
      if (phase0Agents >= PHASE0_MAX_AGENTS || actionBlocks.length + 1 >= MAX_TOTAL_BLOCKS) break;
      let aStart = e.start_line;
      let aIter = 0, aStall = 0;
      let aFinished = false;
      while (aStart <= e.end_line && aIter < MAX_ACTIONS_PER_ENTRY
             && phase0Agents < PHASE0_MAX_AGENTS
             && actionBlocks.length + 1 < MAX_TOTAL_BLOCKS) {
        phase0Agents += 1;
        const prevA = aStart;
        const remainingA = bodyLines.slice(aStart - bodyOffset - 1, e.end_line - bodyOffset).join('\n');
        const r = parseJsonOutput(await agent(
          `${ACTION_RULES}\n\n## Assigned scope (global de-blanked lines)\n${e.start_line}..${e.end_line}\n\n## Uncovered remaining Entry text (starting at global line ${aStart})\n${remainingA}\n\n## Output JSON`,
          { label: `action-extract-${e.start_line}-${aIter}` }
        ));
        if (r && r.action === 'finish') { aFinished = true; break; }
        const aS = (r && typeof r.start_line === 'number') ? r.start_line : aStart;
        const aE = (r && typeof r.end_line === 'number') ? r.end_line : aStart;
        // 硬约束：action 起点必须 >= 当前未覆盖起点（允许跳过标题/描述等非动作前缀行），
        // 且区间在 Entry 内、end>=start；否则视为无效提交 → 停滞。
        const validA = aS >= aStart && aE >= aS && aE <= e.end_line;
        if (!validA) {
          aStall += 1;
          log(`Phase 0 action-extract 无效提交（start=${aStart}）第 ${aStall} 次`);
          if (aStall >= 3) break;
          continue;   // 不推进，等下一个 agent
        }
        const effEndA = Math.max(aE, aStart);
        const liA = Math.max(0, Math.max(aStart, aS) - bodyOffset - 1);
        const riA = Math.min(Math.min(e.end_line, effEndA), bodyTotal) - bodyOffset - 1;
        const linesA = bodyLines.slice(liA, Math.max(0, riA) + 1);
        actionBlocks.push({
          block_id: actionBlocks.length + 2,  // block_id=1 是 frontmatter（若存在）
          kind: 'action',
          line_start: Math.max(aStart, aS),
          line_end: Math.min(e.end_line, effEndA),
          trigger_condition: e.subkind,
          entry_summary: e.summary,
          summary: (r && r.summary) || '',
          text: linesA.join('\n'),
          sentences: linesA,
        });
        aStart = Math.min(e.end_line, effEndA) + 1;
        aStall = 0;
        aIter += 1;
      }
      // 截断兜底：因预算/上限停止且该 Entry 仍有未覆盖行 → 合并为一个兜底 action 块
      if (!aFinished && aStart <= e.end_line && actionBlocks.length + 1 < MAX_TOTAL_BLOCKS) {
        const restLines = bodyLines.slice(aStart - bodyOffset - 1, e.end_line - bodyOffset);
        actionBlocks.push({
          block_id: actionBlocks.length + 2,
          kind: 'action',
          line_start: aStart,
          line_end: e.end_line,
          trigger_condition: e.subkind,
          entry_summary: e.summary,
          summary: '[截断] 达到分块预算，剩余行合并',
          text: restLines.join('\n'),
          sentences: restLines,
        });
        log(`Phase 0 action-extract 截断：entry ${e.start_line}-${e.end_line} 剩余 ${aStart}..${e.end_line} 合并兜底块`);
      }
    }
    const blocksOut = fmBlock ? [fmBlock, ...actionBlocks] : actionBlocks;
    return { unit: 'action-block', count: blocksOut.length, blocks: blocksOut, entries, stalled };
  } catch (e) {
    log(`Phase 0 chunking failed: ${e}`);
    return { unit: 'action-block', count: 0, blocks: [] };
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
log(`Phase 0 blocks: ${blocks.length}`);

// 切块停滞硬约束：连续 3 轮无新块 → 终止 workflow，写 error result 供外层判定并清理会话
if (phase0.stalled) {
  log('Phase 0 切块停滞，终止 workflow（防 session 风暴）');
  const errResult = {
    verdict: 'error',
    verdict_source: 'phase0-stalled',
    skill_name: skillName,
    skill_dir: skillDir,
    phase0: { unit: 'action-block', count: blocks.length, blocks },
    _error: 'phase0 stalled: no new block in 3 rounds',
  };
  try {
    await writeJsonViaBase64(agent, errResult, outputFile, 'write-result-error');
    log(`Error result written to ${outputFile}`);
  } catch (e) {
    log(`Warning: could not write error result: ${e}`);
  }
  return errResult;
}

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
// VDECL_CHUNK=40: 单批 prompt/输出体积控制（120 对长文本仍过大导致 retry 超限）。
const VDECL_CHUNK = 40;
const chunks = [];
for (let i = 0; i < blocks.length; i += VDECL_CHUNK) {
  chunks.push(blocks.slice(i, i + VDECL_CHUNK));
}

const renderVdeclPrompt = (blockSubset, idx) => {
  const vars = { ...vdeclVars, blocks: blockSubset };
  // 文件方式传 vars（base64 写盘 + 重定向），避免 heredoc 大 JSON 超 bash 命令长度限制
  return renderPromptViaBase64Vars('sentence_classifier', skillDir, 'single', vars,
    `render-vdecl${chunks.length > 1 ? '-' + idx : ''}`);
};

// 单批分类 helper：render → agent(schema)。单批失败重试 2 次。
// 主分批与 backfill 分批共用（E1：backfill 不再逐块，按批补测）。
const classifyBlockChunk = async (chunk, idx, labelPrefix, phaseLabel) => {
  const prompt = await renderVdeclPrompt(chunk, idx);
  for (let t = 0; t < 2; t++) {
    const r = await agent(
      prompt,
      { label: `${labelPrefix}-${idx}${t ? '-r' + t : ''}`, phase: phaseLabel, schema: VDECL_SCHEMA }
    );
    if (r) return r;
    log(`V_decl chunk ${idx} attempt ${t + 1} failed, retrying...`);
  }
  return null;
};

let vdeclResult = null;
if (chunks.length <= 1) {
  vdeclResult = await classifyBlockChunk(blocks, 0, 'vdecl_block_classifier', 'Classify');
} else {
  // Multi-chunk: one agent per block subset, merge by block_id (dedup).
  const chunkResults = await Promise.all(chunks.map((chunk, idx) =>
    classifyBlockChunk(chunk, idx, 'vdecl_block_classifier', 'Classify')));
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
  log(`vdecl backfill round ${round + 1}: ${_missing.length} missing -> ${bfChunks.length} chunk(s)`);
  const results = await Promise.all(bfChunks.map((chunk, i) =>
    classifyBlockChunk(chunk, i, `vdecl-backfill-${round}`, 'Classify')));
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
if (_missing.length) log(`vdecl 仍有 ${_missing.length} 块未能覆盖（尽力而为，前端将灰底显示）`);
else log(`vdecl coverage 完整: ${sorted.length}/${blocks.length} blocks`);

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
log(`V_decl: ${vdeclHits.length} unconditional-harmful hit(s), ${vdeclNoDevMal} no-deviation-malicious block(s), coverage=${vdeclResult?.coverage?.classified_blocks || 0}/${vdeclResult?.coverage?.total_blocks || 0}`);

// 完整确定性结果（phase1 含 D_deterministic / A_ast / A_regex / capability_code_evidence /
// flows_ast）——--evidence 紧凑输出不含这些，无条件补跑完整管道供 det_block_hits、前端与 Phase 4 使用。
const detFull = parseJsonOutput(await agent(
  `Run this shell command and return its EXACT raw stdout output with NO commentary, NO markdown code fences:

python scripts/biv_audit.py ${skillDir}

The output is a single JSON object. Output ONLY that JSON object.`,
  { label: 'det-full-phase1' }
));

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
log(`det_block_hits: ${detBlockHits.length} (det_verdict=${detFull?._det_verdict?.verdict || '?'})`);

// --- LLM Judge：逐块审计（审计对象 = 块审计信息；全局结论由 block 归约，禁止直接出全局 verdict）---
log('Running LLM Judge (block-level audit)...');

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
const renderJudgePrompt = (blockSubset, idx) => {
  const vars = buildJudgeChunk(blockSubset);
  // 文件方式传 vars，避免 heredoc 大 JSON 超 bash 命令长度限制
  return renderPromptViaBase64Vars('judge', skillDir, 'single', vars,
    `render-judge${judgeChunks.length > 1 ? '-' + idx : ''}`);
};
const classifyJudgeChunk = async (chunk, idx) => {
  const prompt = await renderJudgePrompt(chunk, idx);
  for (let t = 0; t < 2; t++) {
    const r = await agent(prompt, {
      label: `llm_judge-${idx}${t ? '-r' + t : ''}`,
      phase: 'Classify', effort: 'xhigh', schema: JUDGE_SCHEMA,
    });
    if (r) return r;
    log(`judge chunk ${idx} attempt ${t + 1} failed, retrying...`);
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
if (judgeMissingCount) log(`Judge 缺 ${judgeMissingCount} 个块的判定（对应 block_verdicts.judge=null）`);
const judgeResult = { block_judgments: Object.values(judgeById) };

// ---------------------------------------------------------------------------
// Final Output
// ---------------------------------------------------------------------------

// Intent branch → Chinese name mapping (mirrors taxonomy.INTENT_CATEGORY_NAMES)
const INTENT_NAMES = {
  A: '数据窃取与间谍', B: '财务与变现', C: '载荷与基础设施',
  D: '内容与社会工程', E: '破坏性', F: 'AI Agent 特定',
  G: '非对抗性', H: '模糊',
};

// ---------------------------------------------------------------------------
// Phase 3 汇总：三路 block 级判定 → block_verdicts → 全局 verdict（简单规则）
//   原则：任何阶段都不直接产全局 verdict；全局结论 = 存在恶意 block 则全局恶意。
// ---------------------------------------------------------------------------
log('Phase 3 汇总：合并 det / vdecl / judge 三路 block 级判定...');
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
log(`Phase 3 汇总: ${blockVerdicts.length} 块, ${maliciousBlocks.length} 恶意块, verdict=${verdict} (source=${verdict_source})`);

// --- Phase 4: malicious attack chain construction (per malicious block) ---
log('Phase 4: constructing malicious attack chains...');
let attackChains = [];
if (maliciousBlocks.length > 0) {
  const cce = (detFull && detFull.phase1 && detFull.phase1.capability_code_evidence) || {};
  const chainResults = await Promise.all(maliciousBlocks.map(async (mb, idx) => {
    // mb 是 block_verdicts 项：capabilities/classification 从 vdecl 块分类回溯，
    // code_evidence 只保留该块涉及的能力（避免超长 heredoc 在 subagent 执行时损坏）。
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
    const prompt = await renderPromptViaBase64Vars('attack_chain', skillDir, 'single', chainVars, `render-chain-${idx}`);
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

// 全局结论的辅助展示字段（仍由 block 归约派生，非独立判定）
const judgeMalConf = maliciousBlocks
  .map(v => (v.judge && v.judge.confidence) || 0)
  .filter(c => typeof c === 'number' && c > 0);
const confidence = maliciousBlocks.length > 0
  ? (judgeMalConf.length ? Math.max(0.9, ...judgeMalConf) : 0.9)
  : 0.5;
const firstJudgeMal = maliciousBlocks.find(v => v.judge && v.judge.verdict === 'malicious');
const judgeIntent = (firstJudgeMal && firstJudgeMal.judge.intent_category) || 'H';

const finalResult = {
  skill_name: skillName,
  skill_dir: skillDir,
  // 全局结论 = 简单规则：存在恶意 block 则全局恶意（Phase 3 三路 block 判定归约）
  verdict,
  confidence,
  verdict_source,
  verdict_reasoning: verdictReasoning,
  declared_capabilities: dLlmResult?.declared_capabilities || [],
  actual_capabilities: aLlmInstrResult?.actual_capabilities || [],
  a_llm_instr_caps: (aLlmInstrResult?.actual_capabilities || []).map(c => c.capability),
  a_llm_adv_caps: (aLlmInstrResult?.actual_capabilities || []).filter(c => c.is_adversarial).map(c => c.capability),
  intended_workflow: dLlmResult?.intended_workflow || '',
  judge_intent_category: judgeIntent,
  judge_intent_category_name: INTENT_NAMES[judgeIntent] || '',
  judge_key_evidence: (judgeResult?.block_judgments || [])
    .filter(j => j.verdict === 'malicious')
    .map(j => `block ${j.block_id}: ${String(j.reasoning || '').slice(0, 120)}`),
  // V_decl: 声明轨道恶意通道（无偏差恶意）— 块级分类结果
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
  // Phase 1: full deterministic pipeline result merged so the frontend has
  // D_deterministic / A_ast / A_regex / capability_code_evidence / flows_ast
  phase1: (detFull && detFull.phase1) || null,
  // D_llm capability codes (skill_page reads this; keep parity with batch_workflow)
  d_llm_caps: (dLlmResult?.declared_capabilities || []).map(c => c.capability),
  // Deterministic evidence passed through for traceability
  deterministic_evidence: detEvidence || null,
  _meta: {
    workflow_version: '0.3.0',
  },
};

// --- Write result to experiment/results/ mirroring the cases structure ---
// The Workflow script has no filesystem access, so the file is written by a
// subagent. Override the path via args.output.
// 硬性过滤：sanitizeValue 清洗文本（反斜杠→斜杠、去 emoji/宽字节/控制字符）后
// 经 base64 传输写盘，subagent 只盲抄不解释；decode 失败时外层脚本兜底。
try {
  await writeJsonViaBase64(agent, finalResult, outputFile, 'write-result');
  log(`Result written to ${outputFile}`);
} catch (e) {
  log(`Warning: could not write ${outputFile}: ${e}`);
}

log(`Verdict: ${finalResult.verdict} (confidence: ${(finalResult.confidence * 100).toFixed(0)}%)`);

return finalResult;
