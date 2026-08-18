#!/usr/bin/env bash
# =============================================================================
# BIVMSA 批量测试脚本
#
# 对 experiment/cases 下的每个 skill 用例，启动一个 `claude --bg` 后台会话，
# 在会话内用 Workflow 工具执行完整审计（scripts/biv_workflow.js，含 LLM）。
# 脚本层做并发控制、独立日志、超时判定、失败重试，最后汇总判定结果。
#
# 跨主机可用性：
#   - 命令名自动探测 claude / cc，可用 CLAUDE_BIN 覆盖
#   - 仓库根从脚本位置自动推导（不硬编码路径）
#   - Python 命令自动探测 python / python3
#   - 全部使用 POSIX 兼容写法（兼容 git-bash / Linux / macOS bash 3.2+）
#   - 关键路径/参数均可经环境变量覆盖（见下方"可覆盖环境变量"）
#
# 用法:
#   bash scripts/batch_claude_test.sh                         # 扫描 experiment/cases，并发 3
#   bash scripts/batch_claude_test.sh --cases-dir <dir>       # 指定数据集目录
#   bash scripts/batch_claude_test.sh --parallel 5            # 并发窗口大小
#   bash scripts/batch_claude_test.sh --retry 2               # 失败/超时重试次数
#   bash scripts/batch_claude_test.sh --timeout 30            # 每 case 轮询上限（分钟）
#   bash scripts/batch_claude_test.sh --name run1             # 结果目录名（默认 run_<时间戳>）
#   bash scripts/batch_claude_test.sh --headless              # 用 nohup claude -p 代替 --bg（旧版本兼容）
#   bash scripts/batch_claude_test.sh --resume                # 对已有 run 继续轮询（断点续跑）
#   bash scripts/batch_claude_test.sh --dry-run               # 只列出将执行的 case，不启动
#
# 输出目录:
#   experiment/results/batch_claude_test/<run_name>/
#     logs/<case>/session    session_id（或 headless 模式 pid）
#     logs/<case>/prompt     workflow 提示词原文
#     <n>_<case>/result.json workflow 输出（biv_workflow.js 经 args.output 写入）
#     summary.tsv            case / verdict / source / status / token
#
# 可覆盖环境变量:
#   CLAUDE_BIN        claude 命令路径（默认自动探测 claude/cc）
#   PYTHON_BIN        python 命令（默认自动探测 python/python3）
#   CASES_DIR         用例根目录（默认 $REPO_ROOT/experiment/cases）
#   RESULTS_ROOT      结果根目录（默认 $REPO_ROOT/experiment/results）
#   POLL_SEC          轮询间隔秒数（默认 10）
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# 0. 定位仓库根（从脚本位置推导，不硬编码）
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# 1. 默认值与可覆盖环境变量
# ---------------------------------------------------------------------------
CASES_DIR="${CASES_DIR:-$REPO_ROOT/experiment/cases}"
RESULTS_ROOT="${RESULTS_ROOT:-$REPO_ROOT/experiment/results}"
PARALLEL=3
RETRY=0
TIMEOUT_MIN=30
POLL_SEC="${POLL_SEC:-10}"
RUN_NAME=""
DRY_RUN=0
RESUME=0
MODE="bg"                    # bg | headless
CLAUDE_BIN="${CLAUDE_BIN:-}"
PYTHON_BIN="${PYTHON_BIN:-}"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
err()  { printf '[%s] 错误: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

usage() {
    # 提取本文件顶部注释块（## 之间）作为帮助
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------------------------------------------------------------------------
# 2. 探测工具（跨主机）
# ---------------------------------------------------------------------------
detect_claude() {
    if [ -n "$CLAUDE_BIN" ]; then
        command -v "$CLAUDE_BIN" >/dev/null 2>&1 \
            || { err "找不到 \$CLAUDE_BIN=$CLAUDE_BIN"; exit 1; }
        return 0
    fi
    for c in claude cc; do
        if command -v "$c" >/dev/null 2>&1; then CLAUDE_BIN="$c"; return 0; fi
    done
    err "未找到 claude / cc 命令。请安装 Claude Code 或用 CLAUDE_BIN 指定。"
    exit 1
}

detect_python() {
    if [ -n "$PYTHON_BIN" ]; then return 0; fi
    for p in python python3; do
        if command -v "$p" >/dev/null 2>&1; then PYTHON_BIN="$p"; return 0; fi
    done
    err "未找到 python / python3 命令。请用 PYTHON_BIN 指定。"
    exit 1
}

# ---------------------------------------------------------------------------
# 3. 解析参数
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --cases-dir)  CASES_DIR="$2";    shift 2 ;;
        --parallel)   PARALLEL="$2";     shift 2 ;;
        --retry)      RETRY="$2";        shift 2 ;;
        --timeout)    TIMEOUT_MIN="$2";  shift 2 ;;
        --name)       RUN_NAME="$2";     shift 2 ;;
        --headless)   MODE="headless";   shift ;;
        --resume)     RESUME=1;          shift ;;
        --dry-run)    DRY_RUN=1;         shift ;;
        -h|--help)    usage ;;
        *) err "未知参数: $1"; usage ;;
    esac
done

detect_claude
detect_python

# 参数校验
case "$PARALLEL" in *[!0-9]*) err "--parallel 必须是数字: $PARALLEL"; exit 1;; esac
case "$RETRY"    in *[!0-9]*) err "--retry 必须是数字: $RETRY";     exit 1;; esac
case "$TIMEOUT_MIN" in *[!0-9]*) err "--timeout 必须是数字: $TIMEOUT_MIN"; exit 1;; esac
[ "$PARALLEL" -lt 1 ] && PARALLEL=1

if [ -z "$RUN_NAME" ]; then
    RUN_NAME="run_$(date +%Y%m%d_%H%M%S)"
fi
OUT_ROOT="$RESULTS_ROOT/batch_claude_test/$RUN_NAME"
LOG_DIR="$OUT_ROOT/logs"
SUMMARY="$OUT_ROOT/summary.tsv"

# ---------------------------------------------------------------------------
# 4. 发现用例：与 batch_audit 一致（递归 SKILL.md，取父目录），目录深度任意
# ---------------------------------------------------------------------------
discover_cases() {
    [ -d "$CASES_DIR" ] || { err "用例目录不存在: $CASES_DIR"; exit 1; }
    find "$CASES_DIR" -name SKILL.md 2>/dev/null \
        | sed 's|/SKILL\.md$||' \
        | sort
}

# ---------------------------------------------------------------------------
# 5. 构建 workflow 提示词（相对脚本路径 + 仓库根 cwd，跨主机可移植）
# ---------------------------------------------------------------------------
build_prompt() {
    local case_dir="$1" result_path="$2"
    cat <<EOF
你是 BIVMSA 批量审计执行器。请对 skill 目录完成一次完整审计 workflow，仅此一次：

1. 使用 Workflow 工具执行脚本 scripts/biv_workflow.js，参数 args = {"skill_dir": "$case_dir", "output": "$result_path"}
2. 等待 workflow 全部阶段完成（Phase 0-4 含 LLM 调用），确认 $result_path 已生成且包含顶层 verdict 字段。
3. 用一行简短回复最终 verdict 与 verdict_source，不要展开其他工作。

工作目录：$REPO_ROOT
EOF
}

# ---------------------------------------------------------------------------
# 6. 提取 result.json 的判定（stdout: verdict \t verdict_source）
# ---------------------------------------------------------------------------
extract_verdict() {
    local f="$1"
    "$PYTHON_BIN" - "$f" <<'PYEOF'
import json, re, sys
try:
    d = json.load(open(sys.argv[1], encoding='utf-8'))
    det = d.get('_det_verdict') or {}
    v = d.get('verdict') or det.get('verdict') or '?'
    s = d.get('verdict_source') or det.get('source') or ''
    print(f"{v}\t{s}")
except Exception:
    # 脏 JSON 容错（如 LLM 输出的 evidence_location 含 Windows 反斜杠导致转义非法）：
    # 正则宽松提取顶层 verdict / verdict_source，避免整行判为失败
    try:
        txt = open(sys.argv[1], encoding='utf-8', errors='replace').read()
        mv = re.search(r'"verdict"\s*:\s*"(benign|malware)"', txt)
        ms = re.search(r'"verdict_source"\s*:\s*"([^"]+)"', txt)
        v = mv.group(1) if mv else '?'
        s = ms.group(1) if ms else ''
        print(f"{v}\t{s}")
    except Exception:
        print("?\tparse_error")
PYEOF
}

# ---------------------------------------------------------------------------
# 7. 启动单个 case 的后台会话
#    输出 token：bg 模式 = session_id；headless 模式 = pid
# ---------------------------------------------------------------------------
start_case() {
    local case_dir="$1" result_path="$2"
    local name prompt case_log
    name="$(basename "$case_dir")"
    case_log="$LOG_DIR/$name"
    mkdir -p "$case_log" "$(dirname "$result_path")"
    prompt="$(build_prompt "$case_dir" "$result_path")"
    printf '%s\n' "$prompt" > "$case_log/prompt"

    if [ "$MODE" = "headless" ]; then
        # 旧版本兼容：nohup claude -p（headless），进程退出时 result.json 已写
        ( cd "$REPO_ROOT" && nohup "$CLAUDE_BIN" -p "$prompt" \
            --dangerously-skip-permissions --output-format json \
            > "$case_log/out.json" 2> "$case_log/err.log" & echo $! ) > "$case_log/pid"
        cat "$case_log/pid"
        return 0
    fi

    # 默认：claude --bg 后台会话，解析 "backgrounded · <session_id>"
    local raw sid
    raw="$(cd "$REPO_ROOT" && "$CLAUDE_BIN" --bg "$prompt" --dangerously-skip-permissions 2>&1)"
    # 优先从含 "backgrounded" 的行提取 hex token，其次任意行的 hex token
    sid="$(printf '%s\n' "$raw" \
        | awk '/backgrounded/{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-f]{6,}$/){print $i; exit}}' | head -1)"
    if [ -z "$sid" ]; then
        sid="$(printf '%s\n' "$raw" \
            | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-f]{6,}$/){print $i; exit}}' | head -1)"
    fi
    if [ -z "$sid" ]; then
        err "启动失败 [$name]: 未能解析 session id。原始输出:"
        printf '%s\n' "$raw" | sed 's/^/    /' >&2
        return 1
    fi
    printf '%s\n' "$sid" > "$case_log/session"
    printf '%s\n' "$raw" > "$case_log/start_output"
    printf '%s\n' "$sid"
    return 0
}

# ---------------------------------------------------------------------------
# 8. 主循环：滑动窗口并发 + 轮询完成 + 汇总
#    active 条目格式: "<name>|<case_dir>|<result_path>|<token>|<start_ts>"
# ---------------------------------------------------------------------------
run_wave() {
    local total="$#"
    local -a args=("$@")
    local -a active=()
    local idx=0 done=0 fail=0 timo=0
    local deadline_sec=$((TIMEOUT_MIN * 60))

    : > "$SUMMARY"

    while [ "$idx" -lt "$total" ] || [ "${#active[@]}" -gt 0 ]; do
        # 填充并发窗口
        while [ "${#active[@]}" -lt "$PARALLEL" ] && [ "$idx" -lt "$total" ]; do
            local cdir="${args[$idx]}"
            local cname="$(basename "$cdir")"
            local rpath="$OUT_ROOT/$((idx+1))_$cname/result.json"
            local token now
            log "启动 [$cname] ($((idx+1))/$total, mode=$MODE)"
            token="$(start_case "$cdir" "$rpath")" || token=""
            if [ -z "$token" ]; then
                printf '%s\t?\tstart_failed\tFAIL\t-\n' "$cname" >> "$SUMMARY"
                fail=$((fail+1))
            else
                now="$(date +%s)"
                active+=("$cname|$cdir|$rpath|$token|$now")
            fi
            idx=$((idx+1))
        done

        # 轮询：回收完成项 / 保留等待项 / 标记超时项
        local -a keep=()
        for entry in "${active[@]}"; do
            local cname cdir rpath token start_ts
            IFS='|' read -r cname cdir rpath token start_ts <<< "$entry"
            # .b64 兜底解码：workflow 内 subagent 若未完成 decode，脚本确定性解码
            if [ ! -s "$rpath" ] && [ -s "$rpath.b64" ]; then
                "$PYTHON_BIN" - "$rpath" "$rpath.b64" <<'PYEOF' >/dev/null 2>&1 || true
import base64, sys
try:
    open(sys.argv[1], 'wb').write(base64.b64decode(open(sys.argv[2], 'rb').read()))
except Exception:
    pass
PYEOF
                rm -f "$rpath.b64"
            fi
            if [ -s "$rpath" ]; then
                local v s
                IFS=$'\t' read -r v s <<< "$(extract_verdict "$rpath")"
                printf '%s\t%s\t%s\tDONE\t%s\n' "$cname" "$v" "$s" "$token" >> "$SUMMARY"
                log "完成 [$cname]  verdict=$v source=$s"
                done=$((done+1))
            elif [ $(( $(date +%s) - start_ts )) -ge "$deadline_sec" ]; then
                printf '%s\t?\t\tTIMEOUT\t%s\n' "$cname" "$token" >> "$SUMMARY"
                err "超时 [$cname] token=$token（可手动: $CLAUDE_BIN logs $token）"
                timo=$((timo+1))
            else
                keep+=("$entry")
            fi
        done
        active=("${keep[@]}")

        if [ "${#active[@]}" -gt 0 ]; then
            sleep "$POLL_SEC"
        fi
    done

    log "本波次完成: 共 $total，完成 $done，失败 $fail，超时 $timo"
}

# ---------------------------------------------------------------------------
# 9. 重试逻辑：读取 summary 中非 DONE 的 case，再跑一轮
# ---------------------------------------------------------------------------
retry_pending() {
    local round="$1"
    while [ "$round" -lt "$RETRY" ]; do
        round=$((round+1))
        local -a pend=()
        local cdir cname
        local -a all=()
        while IFS= read -r c; do all+=("$c"); done < <(discover_cases)
        for cdir in "${all[@]}"; do
            cname="$(basename "$cdir")"
            # 该 case 在 summary 中既无 DONE 也无需重试则跳过；有 FAIL/TIMEOUT 则重试
            # 精确匹配 summary 首列（避免 "tron" 误匹配 "tronlink" 等子串）
            if ! awk -F'\t' -v n="$cname" '$1==n && $4=="DONE"' "$SUMMARY" 2>/dev/null | grep -q .; then
                pend+=("$cdir")
            fi
        done
        if [ "${#pend[@]}" -eq 0 ]; then
            log "第 $round 轮重试: 无待重试 case"
            return 0
        fi
        log "第 $round 轮重试: ${#pend[@]} 个 case"
        run_wave "${pend[@]}"
    done
}

# ---------------------------------------------------------------------------
# 10. 主流程
# ---------------------------------------------------------------------------
main() {
    if [ "$DRY_RUN" = "1" ]; then
        log "干跑模式（不启动后台会话）。命令=$CLAUDE_BIN 仓库=$REPO_ROOT 用例=$CASES_DIR"
        log "将执行的 case（共 $(discover_cases | wc -l | tr -d ' ') 个）:"
        discover_cases | sed 's/^/  /'
        return 0
    fi

    if [ "$RESUME" = "1" ]; then
        if [ ! -f "$SUMMARY" ]; then
            err "无可恢复的 run（$SUMMARY 不存在）。可用 --name 指定已有 run。"
            exit 1
        fi
        log "恢复模式: $OUT_ROOT"
        local -a rcases=()
        local cdir cname
        local -a all=()
        while IFS= read -r c; do all+=("$c"); done < <(discover_cases)
        for cdir in "${all[@]}"; do
            cname="$(basename "$cdir")"
            # 精确匹配 summary 首列（避免 "tron" 误匹配 "tronlink" 等子串）
            if ! awk -F'\t' -v n="$cname" '$1==n && $4=="DONE"' "$SUMMARY" 2>/dev/null | grep -q .; then
                rcases+=("$cdir")
            fi
        done
        run_wave "${rcases[@]}"
        retry_pending 0
        return 0
    fi

    mkdir -p "$OUT_ROOT"
    log "BIVMSA 批量测试  命令=$CLAUDE_BIN 并发=$PARALLEL 超时=${TIMEOUT_MIN}min 重试=$RETRY mode=$MODE"
    log "用例目录: $CASES_DIR"
    log "输出目录: $OUT_ROOT"

    # Ctrl+C 时提示当前活跃会话，便于后续 --resume / 手动 stop
    trap 'err "中断！活跃 session 见 $LOG_DIR 下各 case/session 文件。可用: $CLAUDE_BIN stop <id> 停止，或 --resume 续跑。"' INT

    local -a cases=()
    while IFS= read -r c; do cases+=("$c"); done < <(discover_cases)
    if [ "${#cases[@]}" -eq 0 ]; then
        err "未发现任何含 SKILL.md 的用例（$CASES_DIR）"
        exit 1
    fi
    log "发现 ${#cases[@]} 个用例"

    run_wave "${cases[@]}"
    retry_pending 0
    log "全部完成。汇总: $SUMMARY"
}

main "$@"
