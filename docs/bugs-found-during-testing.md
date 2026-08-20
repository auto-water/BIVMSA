# BIVMSA 近期测试发现的问题汇总

> 日期：2026-08-20
> 范围：hard 批量测试（48 case 镜像）、roster 补跑、sentry-skill-scanner 对比、Phase 4 兜底冒烟期间发现的所有系统缺陷
> 状态：✓ 已修复（附 commit） · ⚠ 待修复 · ◆ 外部限制

---

## A. 结果落盘与 JSON 完整性

### A1. LLM `evidence_location` 非法转义导致 result.json 损坏　✓（`5923662`）
- **现象**：LLM 输出的 `evidence_location` 使用 Windows 反斜杠路径（`E:\workbench\...`），JSON 字符串里 `\w`/`\b` 为非法转义，整个 result.json 严格解析失败。
- **根因**：LLM 在 Windows 环境输出反斜杠路径，写入前未做清洗。
- **修复**：`sanitizeValue` 递归清洗所有字符串（**反斜杠→正斜杠**、移除 emoji/补充平面宽字节/C0-C1 控制/零宽/BOM，保留中文与 BMP 可打印字符），写盘前过滤。

### A2. subagent 写盘二次格式化破坏 JSON　✓（`5923662`）
- **现象**：直接让 subagent 写 JSON 时，LLM 会"理解"并二次格式化内容（还原 `\n`、`\\`、`\"` 转义），破坏结构。
- **根因**：LLM subagent 写文件不可靠，无法"原样"传输含转义的文本。
- **修复**：**base64 写盘**——subagent 只盲抄不可读的 base64（无法二次格式化），python 解码；batch_claude_test.sh 另加 `.b64` 兜底解码。

### A3. `Buffer` 在 workflow 运行时未定义　✓（`dbdced9`）
- **现象**：`biv_workflow.js` 用 `Buffer.from(...).toString('base64')`，但 workflow 沙箱无 Node `Buffer` → 抛 ReferenceError，result.json 写不出。
- **修复**：纯 JS `utf8ToBase64`（逐字节验证与 `Buffer.from` 一致，含中文/转义/代理对）。

### A4. MSYS 路径不被 subagent 工具识别　✓（`dbdced9`）
- **现象**：git-bash 的 `/e/xxx`（MSYS 路径）subagent 的 Write/Python 不识别 → 写盘路径错误。
- **修复**：`normPath`（`/e/xxx` → `E:/xxx`）。

### A5. 脚本侧 verdict 提取编码崩溃（Windows GBK）　✓（`308baa3` 后续）
- **现象**：`batch_claude_test.sh` 的 `extract_verdict` 用系统默认 gbk 读 UTF-8 result.json → `UnicodeDecodeError`，verdict 全成 `parse_error`。
- **修复**：显式 `encoding='utf-8'` + 脏 JSON 正则 fallback。

---

## B. 数据完整性 / 前端

### B1. biv_workflow result.json 缺 phase1 → 前端 D(s) 缺失　✓（`27325ec`）
- **现象**：per-case 标注页 D(s)（声明能力空间）完全为空。
- **根因**：`biv_workflow.js` 只跑 `--evidence` 紧凑输出（无 phase1），finalResult 未合并 `phase1`（含 `D_deterministic`/`A_ast`/`A_regex`/`capability_code_evidence`/`flows_ast`），也无 `d_llm_caps` 字段；前端 `skill_page` 恰好读这些字段。
- **修复**：无条件补跑完整确定性管道，合并 `phase1` + 增加 `d_llm_caps`；`skill_page` 加 `declared_capabilities` 兜底。

### B2. 判 malware 却无红色块（前端与判定脱节）　✓（`f56670b` 已提交，待完整验证）
- **现象**：**10/21** 个判 malware 的 case 页面无任何红色（malicious）block。
- **根因**：V_decl 只标注"声明轨道"恶意块（U1-U8）；LLM Judge 基于全局证据（能力偏差/flows/compound）判 malware 时，块级往往无恶意块；而前端只用块级 2×2 着色。
- **修复**：**Phase 4 一致性兜底**——最终判定 malware 但无恶意块时，按 ① vdecl `unconditional_harmful` 命中块 → ② Judge 证据能力 → `capability_code_evidence`（SKILL.md 行号）→ 块 → ③ 兜底首个 action_instruction 块，定位恶意块、标 `deviated-malicious`（红）、构造攻击链。**保证"判恶意必有红块 + 攻击链"。**

### B3. hallo123 误报（V_decl 惰性 markdown 误判）　✓（`c0b99f7`）
- **现象**：良性 skill 的 `[test](javascript:alert(1))` 与 `![ClawMeme](https://test.com/what-the-flip)` 被 U8/U3 命中 → `vdecl.fired` 误判 malware；且同一 LLM 把这两块标 `no-deviation-benign`（**自相矛盾**）。
- **根因**：`unconditional_harmful` 对 `non_action` 块（惰性 markdown 链接/图片）也触发；U 判定与块 2×2 分类无一致性约束。
- **修复（已实施）**：`filterUnconditionalHits` 确定性硬校验——① `non_action` 块不参与 U 命中 ② 与块级 `malicious_label="benign"` 矛盾的命中丢弃 ③ U3/U8 锚校验（惰性引用豁免：纯 markdown 链接/图片且无 `curl/wget/exec` 等执行动词 → 丢弃）。prompt 层同步加约束文本（`prompts.py` sentence_classifier Task 3 / U3 / U8 / IMPORTANT）。

---

## C. 批量测试脚本

### C1. 空格目录名 word splitting　✓（`32f2268`）
- **现象**：`Data Privacy Compliance`、`Test Engineer` 等含空格目录被拆成 `Data`/`Privacy`/`Compliance` 等假 case 跑，产生错误 result。
- **根因**：`for cdir in $(discover_cases)` 按空白拆分。
- **修复**：`while read` 数组收集。

### C2. DONE 判定子串误匹配　✓（`32f2268`）
- **现象**：case `tron` 被误判为已完成（`grep -F "tron"` 匹配到 `tronlink` 的 DONE 行）→ 被跳过不跑。
- **根因**：`grep -F` 子串匹配 case 名。
- **修复**：`awk` 精确匹配 summary 首列。

### C3. 进程残留 / 多 resume 并发混乱　✓（`c0b99f7`）
- **现象**：`TaskStop` 只杀外层 shell，bash 子进程残留 → 多次 resume 并发写同一目录 + 僵尸 working 会话风暴（一度 13 个），互相抢 API 导致推进停滞。
- **处理**：`taskkill /F /T` 全清 + 单进程重启。
- **修复（已实施）**：`batch_claude_test.sh` 增加 ① `OUT_ROOT/.lock` 单实例锁（目录锁，防并发写同一 result.json）② DONE/TIMEOUT 后立即 `claude stop <token>`（防 `--bg` 会话残留吃 API）③ `trap cleanup INT TERM EXIT` 全清（遍历 logs/*/session 与 pid，Windows `taskkill //F //T` / Unix 负 PID 杀进程树）④ resume/重跑前 stop 旧 token ⑤ `extract_verdict` 正则兼容 `error` 判定。

---

## D. 判分

### D1. benchmark 不识别 biv_workflow 的 det 位置　✓（`48a3f59`）
- **现象**：benchmark 对 biv_workflow result.json 的 **det-track n=0**（全无判分）。
- **根因**：`extract_verdicts` 只认顶层 `_det_verdict` 和 `det` 字段；biv_workflow 的 det 嵌在 `deterministic_evidence._det_verdict`。
- **修复**：`extract_verdicts` 增加 `deterministic_evidence` 分支。

---

## E. 已知限制（非纯代码 bug）

### E1. roster 696 块 V_decl backfill 风暴　✓（`c0b99f7`）
- **现象**：941 行 SKILL.md 被 Phase 0 切成 **696 块**，V_decl 分类单次输出超限（~141KB）反复失败 → 缺失块**逐块** backfill 696 次 → 卡死并拖垮并行任务。
- **根因**：块粒度过细（约 1.35 行/块）+ `VDECL_CHUNK=120` 对长文本仍过大 + backfill 逐块无分组。
- **修复（已实施）**：① `VDECL_CHUNK` 120→40 ② backfill 由"逐块"改为**按批补测 + 迭代收敛（≤3 轮，无进展即停）**，单批失败重试 2 次（抽 `classifyBlockChunk` 复用主分批与 backfill）③ Phase 0 相邻同 trigger_condition 块合并（可选 pass）。

### E2. DeepSeek 后端对长输出任务不稳定（外部环境）
- **现象**：roster（V_decl 风暴）与 000-jeremy（Phase 4 攻击链 agent）均卡在**单个 LLM agent 调用** 20–40 分钟未完成。
- **性质**：deepseek-v4-flash 对长输出/复杂任务的性能波动，非系统代码问题；建议错峰/降并发。

---

## 修复状态总览

| 编号 | 问题 | 状态 | 提交 |
|------|------|:---:|------|
| A1 | 非法转义损坏 JSON | ✓ | `5923662` |
| A2 | subagent 二次格式化 | ✓ | `5923662` |
| A3 | Buffer 未定义 | ✓ | `dbdced9` |
| A4 | MSYS 路径 | ✓ | `dbdced9` |
| A5 | GBK 编码崩溃 | ✓ | `308baa3` 后续 |
| B1 | phase1/D(s) 缺失 | ✓ | `27325ec` |
| B2 | malware 无红块 | ✓ 待验证 | `f56670b` |
| B3 | hallo123 误报 | ✓ | `c0b99f7` |
| C1 | 空格目录拆分 | ✓ | `32f2268` |
| C2 | 子串误匹配 | ✓ | `32f2268` |
| C3 | 进程残留并发 | ✓ | `c0b99f7` |
| D1 | benchmark det=0 | ✓ | `48a3f59` |
| E1 | 696 块 backfill 风暴 | ✓ | `c0b99f7` |
| E2 | DeepSeek 后端波动 | ◆ 外部 | — |
