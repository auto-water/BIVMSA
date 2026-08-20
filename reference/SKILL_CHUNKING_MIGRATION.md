# SKILL.md 分块逻辑 —— 迁移文档

> 用途：把 skillprof 的「SKILL.md 分块」逻辑完整迁移到只做分块的独立项目。
> 来源：`E:\workbench\shixi2026\MalSkillProf`（2026-08-06，commit 6b2dde1）。
> 分块结果：SKILL.md 被划分为 **触发 Entry 区间**（按触发条件）→ **原子 Action 区间**（按原子操作），每个区间为 `file#start-end` 行区间 + 摘要。

---

## 1. 逻辑总览（务必先读）

**核心结论：当前项目对 SKILL.md 没有任何结构化解析**（不解析 markdown、不切 frontmatter、不认 heading、不解析代码块）。分块完全由 **LLM 按行区间** 完成，分两层：

```
SKILL.md（整文件 = 行区间 1..N）
   │ ① PartitionAgent：按「触发条件」划为 1..k 个 trigger Entry 区间
   ▼
trigger Entry 区间（每个：start_line..end_line + subkind + summary）
   │ ② ActionExtractAgent：按「原子操作」划为 1..m 个原子 Action 区间
   ▼
原子 Action 区间（每个：start_line..end_line + summary）  ← 分块输出
```

两层都跑在同一个 **IncrementalAgent 循环** 上：每次新开一个无历史的 agent，只给 ta 看**尚未覆盖的行区间**，提交一个区间后范围收缩，再开下一个 agent，直到 agent 调用 `finish()`。

### 1.1 第一层：partition —— 触发 Entry 区间

prompt `agent/prompts/partition.md` 定义规则：
- 一个「trigger 区域」= 在同一触发条件下会执行的最大行区间（on-load / user-query / schedule / second-use …）。
- frontmatter 的 `description` 或 "when this Skill is loaded" 语句算 on-load 触发。
- **分组规则**：同一条件触发的一切（frontmatter + 正文 + 代码块 + 后续动作）合并为一个区间，即使被空行/heading 隔开；整文件一次性加载就提交 `1..N`。只有触发条件真正变化才拆。
- 每次 `submit(start_line, end_line, subkind, summary)`，其中 `subkind` 必须是 `seeds.yaml` 的 `trigger.*` 词表值（校验不通过会打回让模型重试）。

### 1.2 第二层：action_extract —— 原子 Action 区间

prompt `agent/prompts/action_extract.md` 定义规则：
- 一个「原子操作」= 一个可观察操作：**执行**（命令/代码块/subprocess）、**I/O**（文件/网络/环境读写）、**agent 指令性散文**（"run…/always…/load…/invoke…/assume…"）、变换、权限/配置、memory、terminal。
- **边界**：一个 fenced 代码块（```` ``` ````）算**一个** action（含起止 fence 行）；一个祈使句 = 一个 action；纯描述性散文（"This script does X"）不算。
- 每次 `submit(start_line, end_line, summary)`（summary ≤ 200 字符）。

### 1.3 底层：SegmentIndex —— 纯文本行索引

`segment/index.py`：把目录读成按行文本；`get_range(file, start, end)` 返回带行号的区间文本；`search` 正则逐行命中。segment 身份即 `file#start-end`。SKILL.md 的「初始范围」= `SKILL.md#1-<文件行数>`。

---

## 2. 迁移所需文件清单与依赖

按「复制到新项目后能跑」的最小集合列出。目录布局需保持一致（顶层包，无 `__init__.py` 包名依赖）：

```
<新项目>/
├─ config.yaml                          # 必须，agent 操作限制（见 §4.2）
├─ core/
│  ├─ config.py                         # agent_limit()：读 config.yaml
│  ├─ errors.py                         # 异常体系（SegmentError 等）
│  ├─ seeds.py                          # 词表读取/校验（partition 的 trigger 词表用）
│  └─ seeds.yaml                        # 只需 trigger 段（见 §4.4）
├─ segment/
│  └─ index.py                          # SegmentIndex：纯文本行索引
├─ agent/
│  ├─ models.py                         # 建 LLM（anthropic/openai/ollama）
│  ├─ schemas.py                        # TriggerEntrySpec / ActionSpec 等契约
│  ├─ tool_runtime.py                   # ToolRuntime：有界工具循环 + prompt 加载 + 词表注入
│  ├─ incremental.py                    # IncrementalAgent：一次一提交循环
│  ├─ partition_agent.py                # 第一层分块
│  ├─ action_extract_agent.py           # 第二层分块
│  └─ prompts/
│     ├─ partition.md
│     ├─ action_extract.md
│     └─ _shared_tool_rules.md
```

**Python 依赖**（`pyproject.toml` 需要项）：
`langchain-core`、`langchain-anthropic` 或 `langchain-openai` 或 `langchain-ollama`（按你用的 provider）、`pydantic>=2`、`pyyaml`、`python-dotenv`。

> `core/trace.py` 也是 `tool_runtime`/`incremental` 的依赖（`emit`/`write`），但它是纯标准库、只写日志，**可整体替换为 no-op**（见 §5 注意事项）——迁移时可删。

---

## 3. 完整代码

### 3.1 `core/errors.py`

```python
"""Exception hierarchy for skillprof."""
from __future__ import annotations


class SkillprofError(Exception):
    """Base class for all skillprof errors."""

    def __init__(self, msg: str, code: str = "error") -> None:
        super().__init__(msg)
        self.msg = msg
        self.code = code


class GraphError(SkillprofError):
    """Errors in graph mutation (invalid move, missing node, etc.)."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg, code="graph_error")


class VocabError(SkillprofError):
    """A value is not in seeds.yaml for the given section."""

    def __init__(self, section: str, value: str, msg: str) -> None:
        super().__init__(msg, code="vocab_error")
        self.section = section
        self.value = value


class SegmentError(SkillprofError):
    """Errors accessing or parsing segments."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg, code="segment_error")


class LintError(SkillprofError):
    """Lint failed with hard failures (list of fail dicts attached)."""

    def __init__(self, fails: list[dict]) -> None:
        super().__init__(f"lint failed with {len(fails)} error(s)", code="lint_failed")
        self.fails = fails
```

### 3.2 `core/config.py`

```python
"""Operational limits for agent work, loaded from ``config.yaml``."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "config.yaml"

@lru_cache(maxsize=4)
def load_agent_config(path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(path or os.getenv("SKILLPROF_AGENT_CONFIG", _DEFAULT_PATH))
    if not selected.exists():
        raise FileNotFoundError(f"agent config not found: {selected}")
    value = yaml.safe_load(selected.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError(f"agent config must be a YAML mapping: {selected}")
    return value

def agent_limit(*keys: str, default: int | float) -> int | float:
    value: Any = load_agent_config()
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value if isinstance(value, (int, float)) and value > 0 else default
```

### 3.3 `config.yaml`（最小可用）

```yaml
agent:
  tool_turns:
    partition: 50
    parse: 50
    analyze: 100
  model_max_tokens: 8192
  thinking_tail_chars: 200
  thinking_stream_interval_seconds: 0.05
  segment:
    default_max_chars: 5000
    hard_max_chars: 10000
    search_limit: 20
```

### 3.4 `segment/index.py`

```python
"""segment/index.py — minimal raw-text file index.

No pre-segmentation. A skill directory is a tree of text files read on demand.
Agents explore them with two operations:

  * get_range(file, start, end) — numbered lines for an inclusive range.
  * search(file, pattern)       — regex hits with line numbers.

A segment identity is just `file#start-end` (1-indexed, inclusive). There is no
parser, no tree-sitter, no markdown/frontmatter splitting.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.errors import SegmentError

_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".onnx", ".pth", ".pt",
    ".pkl", ".safetensors", ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
}
_MAX_BYTES = 2_000_000  # skip files larger than ~2MB


@dataclass
class Segment:
    """A contiguous line range of one file (the only 'segment' kind)."""
    seg_id: str
    file: str
    line_range: tuple[int, int]
    raw: str
    kind: str = "range"
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"seg_id": self.seg_id, "file": self.file,
                "start_line": self.line_range[0],
                "end_line": self.line_range[1], "kind": self.kind}


@dataclass
class Ref:
    """A reference discovered in text (agent decides whether it is used)."""
    kind: str          # markdown / path / callable / url
    value: str
    files: list[str] = field(default_factory=list)


_ID_RE = re.compile(r"^(?P<file>.+)#(?P<start>\d+)-(?P<end>\d+)$")


def parse_seg_id(seg_id: str) -> tuple[str, int, int]:
    m = _ID_RE.match(seg_id)
    if not m:
        raise SegmentError(f"invalid seg_id: {seg_id!r}")
    return m.group("file"), int(m.group("start")), int(m.group("end"))


class SegmentIndex:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise SegmentError(f"not a directory: {self.root}")
        self._lines: dict[str, list[str]] = {}
        self._files: list[str] | None = None

    # ---- file discovery / reading ----
    def _discover(self) -> None:
        if self._files is not None:
            return
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if p.suffix.lower() in _BINARY_EXTS or p.stat().st_size > _MAX_BYTES:
                    continue
                try:
                    rel = p.relative_to(self.root).as_posix()
                except ValueError:
                    continue
                found.append(rel)
        self._files = found

    def files(self) -> list[str]:
        self._discover()
        return list(self._files)  # type: ignore[arg-type]

    def _read(self, rel: str) -> list[str]:
        """Return lines of `rel` (without trailing newlines), or raise."""
        if rel in self._lines:
            return self._lines[rel]
        path = self._safe(rel)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SegmentError(f"cannot read {rel}: {exc}") from exc
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise SegmentError(f"not utf-8 text: {rel}")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        self._lines[rel] = lines
        return lines

    def _safe(self, rel: str) -> Path:
        """Resolve `rel` under root, blocking path traversal."""
        if rel.startswith(("/", "\\")) or ".." in Path(rel).parts:
            raise SegmentError(f"path escapes root: {rel!r}")
        path = (self.root / rel).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise SegmentError(f"path escapes root: {rel!r}") from exc
        if not path.is_file():
            raise SegmentError(f"not a file: {rel}")
        return path

    def file_length(self, rel: str) -> int:
        return len(self._read(rel))

    # ---- segment API ----
    def get(self, seg_id: str, max_chars: int | None = None) -> Segment | None:
        try:
            file, start, end = parse_seg_id(seg_id)
        except SegmentError:
            return None
        try:
            lines = self._read(file)
        except SegmentError:
            return None
        start = max(1, start)
        end = min(len(lines), end)
        if start > end:
            return None
        raw = "\n".join(f"{i} {lines[i - 1]}" for i in range(start, end + 1))
        if max_chars and len(raw) > max_chars:
            raw = raw[:max_chars - 1] + "…"
        return Segment(seg_id=seg_id, file=file, line_range=(start, end), raw=raw)

    def get_range(self, file: str, start: int, end: int,
                  max_chars: int | None = None) -> Segment:
        """Materialize a Segment for [start, end]; validates bounds."""
        lines = self._read(file)
        if start < 1 or end < start or end > len(lines):
            raise SegmentError(
                f"range {file}#{start}-{end} outside file (1..{len(lines)})")
        raw = "\n".join(f"{i} {lines[i - 1]}" for i in range(start, end + 1))
        if max_chars and len(raw) > max_chars:
            raw = raw[:max_chars - 1] + "…"
        return Segment(seg_id=f"{file}#{start}-{end}", file=file,
                       line_range=(start, end), raw=raw)

    def whole_file(self, file: str) -> Segment:
        n = self.file_length(file)
        if n == 0:
            raise SegmentError(f"empty file: {file}")
        return self.get_range(file, 1, n)

    def search(self, file: str, pattern: str,
               limit: int = 50) -> list[dict]:
        """Regex search one file; return hits with 1-indexed line numbers."""
        lines = self._read(file)
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise SegmentError(f"invalid regex {pattern!r}: {exc}") from exc
        hits: list[dict] = []
        for i, line in enumerate(lines, start=1):
            if rx.search(line):
                hits.append({"file": file, "line": i, "text": line.strip()})
                if len(hits) >= limit:
                    break
        return hits

    def read_text(self, file: str) -> str:
        return "\n".join(self._read(file))
```

### 3.5 `core/seeds.py`

```python
"""core/seeds.py — vocabulary loader + validator.

Reads core/seeds.yaml (shipped with the package). Values not in the
vocabulary raise VocabError with a helpful `.other` fallback message.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .errors import VocabError

_SEEDS_PATH = Path(__file__).with_name("seeds.yaml")


@lru_cache(maxsize=1)
def load_seeds() -> dict[str, Any]:
    if not _SEEDS_PATH.exists():
        return {}
    return yaml.safe_load(_SEEDS_PATH.read_text(encoding="utf-8")) or {}


def reload_seeds() -> dict[str, Any]:
    load_seeds.cache_clear()
    return load_seeds()


def seed_keys(section: str) -> set[str]:
    v = load_seeds().get(section, {})
    if isinstance(v, dict):
        return set(v.keys())
    if isinstance(v, list):
        return set(v)
    return set()


def seed_items(section: str) -> list[tuple[str, str]]:
    """Return sorted ``(name, description)`` entries for prompt injection."""
    value = load_seeds().get(section, {})
    if not isinstance(value, dict):
        return [(str(item), "") for item in value] if isinstance(value, list) else []
    return sorted((str(key), str(meta.get("desc", "")) if isinstance(meta, dict) else "")
                  for key, meta in value.items())


def verdict_roots() -> set[str]:
    """Top-level verdict buckets represented by the fully-qualified seed keys."""
    return {k.split(".", 1)[0] for k in seed_keys("verdict")}


def validate_vocab(section: str, value: str, ctx: str = "value") -> None:
    """Raise VocabError if `value` is not allowed in `section`.
    Returns None if OK.
    """
    allowed = seed_keys(section)
    if value in allowed:
        return
    if not allowed:
        raise VocabError(section, value,
                         f"seeds.yaml section {section!r} is missing or empty")
    sub = _PROPOSE_CMD.get(section, f"new-{section.rstrip('s')}")
    fallback = ""
    if value.count(".") >= 1:
        mid_key = ".".join(value.split(".")[:-1])
        if f"{mid_key}.other" in allowed:
            fallback = (f"\n  Or, if it fits '{mid_key}' but not any named "
                        f"sub-kind, use '{mid_key}.other'.")
    if not fallback and "other" in allowed:
        fallback = "\n  Or, if it doesn't fit any named kind, use 'other'."
    msg = (f"invalid {ctx}='{value}': not in seeds.yaml:{section} "
           f"({len(allowed)} allowed values).\n"
           f"  Full list: `seeds.seed_keys('{section}')`.\n"
           f"  To register this value, propose it ({sub}).{fallback}")
    raise VocabError(section, value, msg)
```

> 注：迁移只需 `trigger` 词表，可把上文件精简为只保留 `load_seeds/seed_keys/seed_items/validate_vocab`，并删除 `_PROPOSE_CMD` 里与 trigger 无关的项（`trigger` 的 propose 命令是 `new-…` 兜底，无碍）。`verdict_roots` 分块用不到，可删。

### 3.6 `core/seeds.yaml`（只需 `trigger` 段）

```yaml
trigger:
  on-load.always:        {desc: "Fires immediately when the skill is loaded (autoLoad hook, description read)."}
  on-load.include:       {desc: "Fires when another file auto-includes this one (.claude/*, references/*)."}
  on-load.other:         {desc: "on-load trigger that doesn't match a named sub-kind."}
  on-exec.user-query:    {desc: "Fires when a user query matches the skill's trigger keyword."}
  on-exec.schedule:      {desc: "Fires on a schedule (cron, setInterval)."}
  on-exec.env-match:     {desc: "Fires when host environment matches a probe (CapEff, cgroup, docker.sock, OS)."}
  on-exec.compose:       {desc: "Fires only when composed with another skill/tool."}
  on-exec.fallback:      {desc: "Fires when the normal path fails / a tool is missing."}
  on-exec.other:         {desc: "on-exec trigger that doesn't match a named sub-kind."}
  on-update.second-use:  {desc: "Fires on second or later session (deferred activation)."}
  on-update.mutate-self: {desc: "Fires when the skill mutates itself or its persistent memory."}
  on-update.other:       {desc: "on-update trigger that doesn't match a named sub-kind."}
  other:                 {desc: "Trigger that doesn't match any named top-level class."}
```

### 3.7 `core/trace.py`

`agent/tool_runtime.py` 与 `agent/incremental.py` 只用了 `core.trace` 的 `emit` 与 `write`（记录/广播日志）。迁移最省事的方式是**替换为 no-op 桩**：

```python
# core/trace.py（可替换为以下 no-op 桩，删除原文件）
from __future__ import annotations
from typing import Any, Callable


def emit(*, phase: str, step: str, actor: str, status: str = "running",
         input: Any = None, output: Any = None, message: str = "") -> None:
    """No-op: broadcast ephemeral live state (not needed for chunking)."""


def write(path_or_dir=None, *, phase: str, step: str, actor: str,
          status: str = "ok", note: str = "", input: Any = None,
          output: Any = None, duration_ms: int | None = None,
          message: str = "") -> None:
    """No-op: persist a trace record (not needed for chunking)."""
```

（若想保留日志，把原 `core/trace.py` 原样搬过去即可，它只用标准库。）

### 3.8 `agent/schemas.py`

```python
"""agent/schemas.py — Pydantic output contracts for agent decisions."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DataSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ref: str
    scope: str = "local"            # local | global
    type: str = ""                  # free-form: int/str/file/url/...
    value: str = ""


class RefSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str = Field(description="normalized local relative path of the referenced file")
    start_line: int
    end_line: int
    subkind: str = Field(description="resource.* seed value describing the file's role")
    summary: str = ""
    target: str = Field(
        default="",
        description="canonical identity: the normalized local path (same as file)")


class TriggerEntrySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    start_line: int
    end_line: int
    subkind: str = Field(description="trigger.* seed value")
    summary: str = Field(
        default="",
        description="why this region is classified as this subkind: the "
                    "evidence/phrasing in the text that triggers it")


class PartitionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[TriggerEntrySpec]


class ActionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    start_line: int
    end_line: int
    summary: str = Field(max_length=200)


class ActionSpecWithRefs(ActionSpec):
    model_config = ConfigDict(extra="forbid")
    refs: list[RefSpec] = Field(default_factory=list)


class OrderItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_line: int
    end_line: int


class OrderResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: list[OrderItem] = Field(default_factory=list)


class EnrichResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reads: list[str] = Field(default_factory=list)
    writes: list[DataSpec] = Field(default_factory=list)


class TypeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    atype: str = Field(description="action seed value")


class MediaResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    media: str = Field(description="media seed value")


class VerdictVote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    matches: bool = Field(description="whether this action matches the category")
    behavior: str = Field(
        default="",
        description="if matches, a fully-qualified verdict seed of this "
                    "category (e.g. malicious.exfil.credential); else empty")
    reason: str = ""


class BehaviorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    behavior: str = Field(description="final verdict: benign or one of the "
                                      "malicious/suspicious/vulnerability seeds")
    summary: str = Field(max_length=300,
                         description="why this behavior was chosen")


class AnalyzeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    media: str = Field(description="media seed value")
    atype: str = Field(description="action seed value")
    behavior: str = Field(description="fully qualified verdict seed or benign")
    summary: str = Field(max_length=300)


class VerdictSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: str = Field(description="top-level verdict root")
    rationale: str = Field(description="1-3 sentence explanation")
    family_hint: str = Field(default="", description="optional attack family label")
```

> 分块只需要 `TriggerEntrySpec` / `ActionSpec` / `PartitionResult`。其余 schema 是分类阶段用的，可删。

### 3.9 `agent/tool_runtime.py`

```python
"""Shared LangChain structured-call and bounded tool-loop runtime."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from core.trace import emit as trace_emit, write as trace_write
from core.config import agent_limit

PROMPT_DIR = Path(__file__).with_name("prompts")
DEFAULT_MAX_TOKENS = int(agent_limit("agent", "model_max_tokens", default=2048))


class _Done:
    """Sentinel returned by ToolRuntime when the agent calls its done tool."""


DONE = _Done()


def read_prompt(name: str) -> str:
    return _read_prompt_file(PROMPT_DIR / name, seen=set())


def _read_prompt_file(path: Path, *, seen: set[Path]) -> str:
    path = path.resolve()
    if path in seen:
        raise ValueError(f"prompt include cycle at {path}")
    seen = set(seen)
    seen.add(path)
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("@include "):
            rel = line[len("@include "):].strip()
            lines.append(_read_prompt_file(path.parent / rel, seen=seen))
        else:
            lines.append(line)
    return "\n".join(lines).strip() + "\n"


def serialize_context(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _model_dump(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    return dump() if callable(dump) else value


def _inject_vocab(prompt: str, prompt_name: str, context: dict) -> str:
    from core import seeds
    if "partition" in prompt_name:
        items = seeds.seed_items("trigger")
        block = "\n".join(f"- `{k}` — {d}" if d else f"- `{k}`"
                          for k, d in items)
        return prompt.rstrip() + "\n\nSelectable trigger sub-kinds:\n" + block + "\n"
    if "ref_detect" in prompt_name:
        items = seeds.seed_items("resource")
        block = "\n".join(f"- `{k}` — {d}" if d else f"- `{k}`"
                          for k, d in items)
        return prompt.rstrip() + "\n\nSelectable resource sub-kinds:\n" + block + "\n"
    if "type" in prompt_name and "prototype" not in prompt_name:
        items = seeds.seed_items("action")
        block = "\n".join(f"- `{k}` — {d}" if d else f"- `{k}`"
                          for k, d in items)
        return prompt.rstrip() + "\n\nSelectable action types:\n" + block + "\n"
    if "media" in prompt_name:
        items = seeds.seed_items("media")
        block = "\n".join(f"- `{k}` — {d}" if d else f"- `{k}`"
                          for k, d in items)
        return prompt.rstrip() + "\n\nSelectable media:\n" + block + "\n"
    if any(name in prompt_name
           for name in ("malice", "suspicion", "vuln")):
        items = seeds.seed_items("verdict")
        block = "\n".join(f"- `{k}` — {d}" if d else f"- `{k}`"
                          for k, d in items)
        return prompt.rstrip() + "\n\nSelectable verdicts:\n" + block + "\n"
    if "verdict" in prompt_name:
        block = "\n".join(f"- `{r}`" for r in sorted(seeds.verdict_roots()))
        return (prompt.rstrip() +
                "\n\nSelectable skill-level verdict values:\n" + block + "\n")
    return prompt


def build_messages(prompt_name: str, context: dict,
                   prompt_suffix: str = ""):
    from langchain_core.messages import HumanMessage, SystemMessage
    system_prompt = read_prompt(prompt_name)
    system_prompt = _inject_vocab(system_prompt, prompt_name, context)
    if prompt_suffix:
        system_prompt = system_prompt.rstrip() + "\n\n" + prompt_suffix.strip() + "\n"
    return [SystemMessage(content=system_prompt),
            HumanMessage(content=serialize_context(context))]


def segment_brief(segment, max_chars: int | None = None) -> dict[str, Any]:
    if segment is None:
        return {}
    raw = segment.raw
    if max_chars is not None and len(raw) > max_chars:
        raw = raw[:max_chars - 1] + "…"
    return {"file": segment.file,
            "start_line": segment.line_range[0],
            "end_line": segment.line_range[1],
            "raw": raw}


def read_range(index, file: str, start: int, end: int,
               max_chars: int | None = None) -> dict[str, Any]:
    """Read a numbered line range via the index; raises SegmentError if OOB."""
    seg = index.get_range(file, start, end, max_chars=max_chars)
    return segment_brief(seg)


def subtract_ranges(start_line: int, end_line: int,
                    covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Remove `covered` intervals from [start_line, end_line]; return the rest."""
    remaining = [(start_line, end_line)]
    for clo, chi in sorted(covered):
        nxt: list[tuple[int, int]] = []
        for lo, hi in remaining:
            if chi < lo or clo > hi:
                nxt.append((lo, hi))
                continue
            if lo < clo:
                nxt.append((lo, clo - 1))
            if chi < hi:
                nxt.append((chi + 1, hi))
        remaining = nxt
        if not remaining:
            break
    return remaining


def visible_fragments(file: str, start: int, end: int,
                      covered: list[tuple[int, int]]
                      ) -> list[dict[str, Any]]:
    """The uncovered ranges of [start,end] after subtracting covered lines."""
    remaining = subtract_ranges(start, end, covered)
    return [{"file": file, "start_line": a, "end_line": b}
            for a, b in remaining if a <= b]


def out_of_scope_response(message: str, *, file: str, start_line: int,
                          end_line: int,
                          allowed_ranges: list[dict[str, Any]]) -> dict[str, Any]:
    return {"error": message, "file": file, "start_line": start_line,
            "end_line": end_line, "allowed_ranges": allowed_ranges}


def resolve_visible_range(*, file: str, start_line: int, end_line: int,
                          visible_ranges: list[dict[str, Any]]):
    """Return (file,start,end) if fully inside one visible range, else None."""
    for frag in visible_ranges:
        if (frag["file"] == file and
                frag["start_line"] <= start_line and
                end_line <= frag["end_line"]):
            return (file, start_line, end_line)
    return None


def _ranges_for_file(visible_ranges, file: str) -> list[dict[str, Any]]:
    return [{"start_line": f["start_line"], "end_line": f["end_line"]}
            for f in visible_ranges if f["file"] == file]


def node_brief(node) -> dict[str, Any]:
    if node is None:
        return {}
    return {"id": node.id, "nkind": node.nkind,
            "ekind": node.ekind, "subkind": node.subkind,
            "media": node.media, "atype": node.atype,
            "behavior": node.behavior, "summary": node.summary,
            "data": [d.to_dict() for d in node.data]}


def structured_call(llm, prompt_name: str, schema: type, context: dict,
                    *, trace_dir=None, actor: str = "agent.runtime",
                    focus_id: str = "", max_turns: int | None = None,
                    validator: Callable[[Any], Any] | None = None):
    """One fresh structured call, traced like a tool session.

    Runs through ToolRuntime with one mandatory `submit` tool whose args are the
    target schema, so reasoning is streamed (thinking) and a rejected/invalid
    submission is fed back to the model for a retry instead of crashing the run.
    `validator`, if given, performs extra checks (e.g. enum/vocab membership)
    on the validated result and should raise on failure. A valid submit ends the
    call and its validated result is returned.
    """
    from langchain_core.tools import StructuredTool

    def submit(**kwargs) -> dict:
        """Submit the structured result for this step."""
        return kwargs

    tool = StructuredTool.from_function(
        submit, name="submit",
        description=getattr(schema, "__doc__", None) or
        "Submit the structured result.",
        args_schema=schema)

    def validate(args):
        result = schema.model_validate(args)
        if validator is not None:
            validator(result)
        return result

    return ToolRuntime(llm).run(
        tools=[tool], submit_name="submit", validate=validate,
        prompt_name=prompt_name, context=context, actor=actor,
        focus_id=focus_id, trace_dir=trace_dir,
        max_turns=max_turns or int(agent_limit("agent", "tool_turns",
                                               "analyze", default=20)))


class ToolRuntime:
    def __init__(self, llm):
        self.llm = llm

    def run(self, *, tools: list, submit_name: str,
            validate: Callable[[dict], Any], prompt_name: str, context: dict,
            actor: str, focus_id: str, trace_dir=None, max_turns: int,
            prompt_suffix: str = "", done_name: str | None = None,
            multi_submit: bool = False):
        """Run ONE fresh agent until it submits or calls `done_name`.

        In single-submit mode (default), the first valid submit ends the
        session and its result is returned. In multi-submit mode, each valid
        submit is collected and the model may submit repeatedly; the session
        ends when `done_name` is called, and the list of results is returned
        (an empty list if nothing was submitted).

        The model may call read tools between submissions. A rejected submit
        is fed back to the model as a tool error so it can correct itself
        instead of crashing the run. There is no cross-session history — each
        call to run() starts a brand-new message list.
        """
        from langchain_core.messages import HumanMessage, ToolMessage

        by_name = {tool.name: tool for tool in tools}
        bound = self.llm.bind_tools(tools, tool_choice=_tool_choice())
        messages = build_messages(prompt_name, context, prompt_suffix)
        trace_write(trace_dir, phase="agent", step="session_start",
                    actor=actor, status="running",
                    input={"focus": focus_id, "prompt": prompt_name})
        reasoning_default = _model_reasoning(self.llm)
        reasoning_disabled = not reasoning_default
        seen_calls: set[str] = set()
        accepted: list = []

        for turn in range(max_turns):
            trace_write(trace_dir, phase="agent", step="model_input",
                        actor=actor, status="running",
                        input={"turn": turn, "focus": focus_id})
            try:
                response = self._invoke(bound, messages, trace_dir=trace_dir,
                                        actor=actor, turn=turn,
                                        focus_id=focus_id,
                                        reasoning=not reasoning_disabled)
            except Exception as exc:
                if self._is_malformed_tool_call_error(exc):
                    messages.append(HumanMessage(content=(
                        "Use one valid native tool call; do not emit XML or "
                        "free-form tool-call markup.")))
                    continue
                raise
            if self._hit_token_limit(response):
                if reasoning_disabled:
                    raise RuntimeError(
                        f"model exceeded token limit twice at {focus_id!r}")
                reasoning_disabled = True
                messages.append(HumanMessage(content=(
                    "Do not reason further. Call the required tool directly.")))
                continue

            messages.append(response)
            calls = getattr(response, "tool_calls", None) or []
            if not calls:
                # The model answered in text instead of making a native tool
                # call. Don't crash — tell it to use a proper tool call and
                # retry within the turn budget.
                messages.append(HumanMessage(content=(
                    "You did not call a tool. Respond ONLY with a native "
                    "tool call (one of the provided tools), not text or XML.")))
                continue

            # In single mode a valid submit ends the agent; in multi mode it
            # is collected and the agent continues until done_name. A rejected
            # submit is fed back as a tool error so the model can self-correct.
            rejected = None
            for call in calls:
                name = call["name"]
                if done_name is not None and name == done_name:
                    self._trace_tool(trace_dir, actor, done_name,
                                     call.get("args", {}),
                                     {"accepted": True, "result": "done"},
                                     time.time())
                    done_result = accepted if multi_submit else DONE
                    trace_write(trace_dir, phase="agent",
                                step="session_done", actor=actor,
                                status="ok",
                                output={"focus": focus_id, "turns": turn + 1,
                                        "result": _model_dump(done_result)})
                    return done_result
                if name == submit_name:
                    try:
                        result = validate(call.get("args", {}))
                    except Exception as exc:
                        rejected = (call, exc)
                        continue
                    if multi_submit:
                        accepted.append(result)
                        self._trace_tool(trace_dir, actor, submit_name,
                                         call.get("args", {}),
                                         {"accepted": True,
                                          "index": len(accepted) - 1,
                                          "result": _model_dump(result)},
                                         time.time())
                    else:
                        self._trace_tool(trace_dir, actor, submit_name,
                                         call.get("args", {}),
                                         {"accepted": True,
                                          "result": _model_dump(result)},
                                         time.time())
                        trace_write(trace_dir, phase="agent",
                                    step="session_done", actor=actor,
                                    status="ok",
                                    output={"focus": focus_id,
                                            "turns": turn + 1,
                                            "result": _model_dump(result)})
                        return result

            # Execute non-submit tools; report rejected/accepted submits back
            # to the model, then loop so it can continue or finish.
            for call in calls:
                name, args = call["name"], call.get("args", {})
                call_id = call.get("id", name)
                if name == submit_name:
                    if rejected is not None and rejected[0] is call:
                        _, exc = rejected
                        self._trace_tool(trace_dir, actor, submit_name,
                                         args,
                                         {"accepted": False,
                                          "error": f"{type(exc).__name__}: {exc}"},
                                         time.time(), status="error")
                        messages.append(ToolMessage(
                            content=(f"submit rejected: {type(exc).__name__}: "
                                     f"{exc}\nFix the arguments and call submit "
                                     f"again, or call finish() if nothing "
                                     f"remains."),
                            tool_call_id=call_id))
                    elif multi_submit:
                        messages.append(ToolMessage(
                            content=(f"accepted ({len(accepted)} total). Submit "
                                     f"the next ref, or call finish() when none "
                                     f"remain."),
                            tool_call_id=call_id))
                    continue
                if done_name is not None and name == done_name:
                    continue
                fp = serialize_context({"tool": name, "args": args})
                if fp in seen_calls:
                    messages.append(ToolMessage(
                        content="You already called this with the same "
                                "arguments. Use the result and submit now.",
                        tool_call_id=call_id))
                    continue
                seen_calls.add(fp)
                t0 = time.time()
                tool = by_name.get(name)
                try:
                    content = (f"unknown tool: {name}" if tool is None
                               else tool.invoke(args))
                    status = "error" if tool is None else "ok"
                except Exception as exc:
                    content = f"tool error: {type(exc).__name__}: {exc}"
                    status = "error"
                # Turn JSON errors into an actionable instruction so the model
                # knows exactly what to do next instead of stalling.
                if isinstance(content, str):
                    stripped = content.strip()
                    if stripped.startswith("{") and '"error"' in stripped:
                        try:
                            err = json.loads(stripped).get("error", stripped)
                        except json.JSONDecodeError:
                            err = stripped
                        if "not present in this action" in str(err):
                            guidance = (
                                "That pattern does not appear in the action's "
                                "own lines. Search only for a name/path that "
                                "actually appears in the action text (e.g. a "
                                "file name or identifier written there), to "
                                "locate its definition. Do not fish with "
                                "wildcard patterns not present in the action."
                            )
                        else:
                            guidance = (
                                "The tool returned an error. Correct the "
                                "arguments and try again."
                            )
                        content = f"Error: {err}\n{guidance}"
                self._trace_tool(trace_dir, actor, name, args, content, t0,
                                 status=status)
                messages.append(ToolMessage(content=str(content),
                                            tool_call_id=call_id))
        raise RuntimeError(f"{actor}: did not submit within {max_turns} turns")

    @staticmethod
    def _trace_tool(trace_dir, actor, name, args, output, t0,
                    status="ok") -> None:
        trace_output = output
        if isinstance(output, str) and output[:1] in ("{", "["):
            try:
                trace_output = json.loads(output)
            except json.JSONDecodeError:
                pass
        trace_write(trace_dir, phase="agent_tool", step=name, actor=actor,
                    status=status, input=args, output=trace_output,
                    duration_ms=int((time.time() - t0) * 1000))

    @staticmethod
    def _hit_token_limit(response) -> bool:
        metadata = getattr(response, "response_metadata", {}) or {}
        return metadata.get("done_reason") == "length"

    @staticmethod
    def _invoke(bound, messages, *, trace_dir, actor, turn, focus_id,
                reasoning=True):
        return _stream_model(bound, messages, trace_dir=trace_dir, actor=actor,
                             turn=turn, focus_id=focus_id, reasoning=reasoning,
                             trace_content=True)

    @staticmethod
    def _is_malformed_tool_call_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return ("failed to parse xml" in text or
                ("xml syntax error" in text and "tool_call" in text) or
                "malformed tool call" in text)

def _underlying_model(bound):
    """Unwrap RunnableBinding/bound models to the real chat model."""
    m = bound
    seen = 0
    while hasattr(m, "bound") and seen < 10:
        m = m.bound
        seen += 1
    return m


def _model_reasoning(bound) -> bool:
    """Whether the model is configured to emit reasoning/thinking."""
    m = _underlying_model(bound)
    return bool(getattr(m, "reasoning", True))


def _tool_choice() -> str:
    """tool_choice for bind_tools.

    Defaults to "any" (force a tool call every turn). Some OpenAI-compatible
    reasoning endpoints (e.g. DeepSeek thinking mode) reject "any"; override
    with SKILLPROF_TOOL_CHOICE=auto (or "none").
    """
    return os.getenv("SKILLPROF_TOOL_CHOICE", "any").strip() or "any"


def _stream_model(bound, messages, *, trace_dir, actor,
                  turn=0, focus_id="", reasoning=None,
                  trace_content: bool = True):
    """Stream a bound model, capturing reasoning and emitting live traces.

    Returns the assembled AIMessage. Used by the tool loop and single-shot
    structured calls so both show streamed thinking. `reasoning` defaults to
    the model's own configured setting.
    """
    t0 = time.time()
    if reasoning is None:
        reasoning = _model_reasoning(bound)
    if not hasattr(bound, "stream"):
        return bound.invoke(messages)
    try:
        response = None
        thinking_parts: list[str] = []
        content_parts: list[str] = []
        last_live = 0.0
        real = _underlying_model(bound)
        stream_kwargs = ({"reasoning": reasoning}
                         if "ollama" in type(real).__module__.lower()
                         else {})
        for chunk in bound.stream(messages, **stream_kwargs):
            extra = getattr(chunk, "additional_kwargs", {}) or {}
            thinking = extra.get("reasoning_content") or extra.get("thinking")
            if thinking:
                thinking_parts.append(str(thinking))
                now = time.monotonic()
                if now - last_live >= float(agent_limit(
                        "agent", "thinking_stream_interval_seconds",
                        default=0.1)):
                    complete = "".join(thinking_parts)
                    tail = complete[-int(agent_limit(
                        "agent", "thinking_tail_chars", default=400)):]
                    trace_emit(phase="agent", step="thinking_live",
                               actor=actor, input={"turn": turn,
                               "focus": focus_id},
                               output={"text": tail,
                               "truncated": len(complete) > len(tail)})
                    last_live = now
            content = getattr(chunk, "content", "")
            if content:
                content_parts.append(content if isinstance(content, str)
                                     else serialize_context(content))
            response = chunk if response is None else response + chunk
        if response is None:
            raise RuntimeError("model stream ended without a response")
        if thinking_parts:
            trace_write(trace_dir, phase="agent", step="thinking",
                        actor=actor, input={"turn": turn, "focus": focus_id},
                        output={"text": "".join(thinking_parts)})
        if (trace_content and content_parts
                and not (getattr(response, "tool_calls", None) or [])):
            trace_write(trace_dir, phase="agent", step="content",
                        actor=actor, input={"turn": turn, "focus": focus_id},
                        output={"text": "".join(content_parts)})
        return response
    except Exception as exc:
        trace_write(trace_dir, phase="agent", step="error", actor=actor,
                    status="error", input={"turn": turn, "focus": focus_id},
                    output={"error": f"{type(exc).__name__}: {exc}"},
                    duration_ms=int((time.time() - t0) * 1000))
        raise
```

> 若分块项目不需要 `structured_call`/`_stream_model` 的思考流（thinking）展示，可再精简：删除 `_underlying_model/_model_reasoning/_stream_model`，把 `_invoke` 改为 `return bound.invoke(messages)`。`trace_emit/trace_write` 已由 no-op 桩接管。

### 3.10 `agent/incremental.py`

```python
"""incremental.py — shared "one fresh agent per submission" loop.

Partition and action extraction follow the same shape: the harness starts a
brand-new, history-free tool agent that may read its assigned scope over
several turns and must make exactly one submission; the harness then records
that submission, shrinks/advances the scope, and starts another fresh agent
until the agent declares itself done (or the scope is exhausted).

Subclasses fill in the semantics (what the scope is, what a valid submission
looks like) by overriding a small set of hooks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from core.config import agent_limit
from .tool_runtime import (
    DONE,
    ToolRuntime,
    out_of_scope_response,
    read_range,
    resolve_visible_range,
)


@dataclass(frozen=True)
class VRange:
    """One visible (file, start_line, end_line) fragment offered to an agent."""
    file: str
    start: int
    end: int

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "start_line": self.start,
                "end_line": self.end}


class IncrementalAgent:
    """Base class for fresh-agent-per-submission loops.

    Subclasses set class attributes (`prompt_name`, `actor`, `turns_key`,
    `submit_model`, `multi_file`) and override hooks. They typically implement a
    public `run(...)` that builds a `ctx` dict and calls `_loop(ctx)`.
    """

    llm: Any
    prompt_name: str = ""
    actor: str = ""
    turns_key: str = "parse"          # agent.tool_turns.<key>
    submit_model: type[BaseModel] = BaseModel
    multi_file: bool = False
    single_session: bool = False
    # Discovery agents (partition/extract) should READ their scope, not search
    # by keyword — keyword search misses triggers/actions phrased differently.
    # Locating agents (ref_detect) keep search to find a named target.
    search_enabled: bool = True
    """When True, run ONE session that may submit many times and ends with
    finish() (ref_detect: its scope does not shrink per submission). When
    False, start a fresh agent per submission with scope recomputed each time
    (partition / action_extract)."""

    def __init__(self, llm):
        self.llm = llm

    # ---- hooks to override ----
    def visible_ranges(self, ctx: dict, added: list) -> list[VRange]:
        """The fragments exposed to the next fresh agent. Empty => stop."""
        raise NotImplementedError

    def focus_id(self, ctx: dict) -> str:
        raise NotImplementedError

    def primary_file(self, ctx: dict) -> str:
        """File read by segment_get/segment_search in single-file mode."""
        raise NotImplementedError

    def make_context(self, ctx: dict, visible: list[VRange],
                     added: list) -> dict:
        """The JSON context handed to the fresh agent."""
        return {"input": {"scope": [v.as_dict() for v in visible]}}

    def extra_tools(self, ctx: dict, visible: list[VRange]) -> list:
        """Additional tools beyond segment_get/segment_search/submit."""
        return []

    def validate(self, sub: BaseModel, ctx: dict,
                 visible: list[VRange]) -> Any:
        """Validate a non-done submission and return its recorded spec.

        Raise ValueError to reject the submission (the session ends and the
        loop... actually the exception propagates)."""
        raise NotImplementedError

    def dedup_key(self, spec: Any):
        """If not None, a key that must be unique across submissions."""
        return None

    def exhausted(self, ctx: dict, added: list) -> bool:
        """Extra stop condition beyond empty visible ranges."""
        return False

    def max_items(self, ctx: dict) -> int | None:
        """Safety cap on accepted submissions (None = unbounded)."""
        return None

    # ---- loop ----
    def _loop(self, ctx: dict, on_result: Callable[[Any], None] | None = None
              ) -> list:
        if self.single_session:
            return self._single_session(ctx, on_result)
        added: list = []
        seen_keys: set = set()

        while True:
            visible = self.visible_ranges(ctx, added)
            if not visible or self.exhausted(ctx, added):
                break
            cap = self.max_items(ctx)
            if cap is not None and len(added) >= cap:
                break

            scope = [v.as_dict() for v in visible]
            tools = self._read_tools(ctx, visible, scope)
            tools.extend(self.extra_tools(ctx, visible))
            tools.append(StructuredTool.from_function(
                self._submit_factory(), args_schema=self.submit_model))
            tools.append(StructuredTool.from_function(
                self._finish_factory, name="finish"))

            def _validate(args, /, _visible=visible, _seen=seen_keys):
                sub = self.submit_model.model_validate(args)
                spec = self.validate(sub, ctx, _visible)
                key = self.dedup_key(spec)
                if key is not None:
                    if key in _seen:
                        raise ValueError(f"already submitted: {key}")
                    _seen.add(key)
                return spec

            result = ToolRuntime(self.llm).run(
                tools=tools, submit_name="submit", validate=_validate,
                done_name="finish",
                prompt_name=self.prompt_name,
                context=self.make_context(ctx, visible, added),
                actor=self.actor, focus_id=self.focus_id(ctx),
                trace_dir=ctx.get("trace_dir"),
                max_turns=int(agent_limit("agent", "tool_turns",
                                          self.turns_key, default=12)))
            if result is DONE:
                break
            added.append(result)
            if on_result is not None:
                on_result(result)
        return added

    def _single_session(self, ctx: dict,
                        on_result: Callable[[Any], None] | None) -> list:
        """One agent session that submits 0..N results, then finish().

        Used when the scope does not shrink per submission (refs): the model
        keeps its own memory of what it reported instead of the harness
        restarting a fresh agent after each result.
        """
        added: list = []
        seen_keys: set = set()
        visible = self.visible_ranges(ctx, added)
        if not visible:
            return added
        scope = [v.as_dict() for v in visible]
        tools = self._read_tools(ctx, visible, scope)
        tools.extend(self.extra_tools(ctx, visible))
        tools.append(StructuredTool.from_function(
            self._submit_factory(), args_schema=self.submit_model))
        tools.append(StructuredTool.from_function(
            self._finish_factory, name="finish"))

        def _validate(args, /, _visible=visible, _seen=seen_keys):
            sub = self.submit_model.model_validate(args)
            spec = self.validate(sub, ctx, _visible)
            key = self.dedup_key(spec)
            if key is not None:
                if key in _seen:
                    raise ValueError(f"already submitted: {key}")
                _seen.add(key)
            added.append(spec)
            if on_result is not None:
                on_result(spec)
            return spec

        ToolRuntime(self.llm).run(
            tools=tools, submit_name="submit", validate=_validate,
            done_name="finish", multi_submit=True,
            prompt_name=self.prompt_name,
            context=self.make_context(ctx, visible, added),
            actor=self.actor, focus_id=self.focus_id(ctx),
            trace_dir=ctx.get("trace_dir"),
            max_turns=int(agent_limit("agent", "tool_turns",
                                      self.turns_key, default=12)))
        return added

    # ---- tools ----
    def _read_tools(self, ctx, visible: list[VRange], scope: list[dict]):
        index = ctx["index"]
        if self.multi_file:
            tools = [self._segment_get_multi(index, visible, scope)]
            if self.search_enabled:
                tools.append(self._segment_search_multi(index, visible, ctx))
            return tools
        primary = self.primary_file(ctx)
        tools = [self._segment_get_single(index, primary, visible, scope)]
        if self.search_enabled:
            tools.append(self._segment_search_single(index, primary, visible,
                                                     ctx))
        return tools

    def allow_search(self, ctx, file: str, pattern: str) -> str | None:
        """Hook: return an error string if a search should be rejected.

        Subclasses (e.g. ref_detect) use this to ensure a search pattern is
        evidenced in the action's own text before it is used to locate a
        target elsewhere. Returning None allows the search.
        """
        return None

    def _segment_get_single(self, index, file: str, visible, scope):
        def segment_get(start_line: int, end_line: int,
                        max_chars: int = int(agent_limit(
                            "agent", "segment", "default_max_chars",
                            default=5000))) -> str:
            """Read the line range `start_line`-`end_line` (numbered)."""
            limit = min(max(max_chars, 1), int(agent_limit(
                "agent", "segment", "hard_max_chars", default=10000)))
            if resolve_visible_range(
                    file=file, start_line=start_line, end_line=end_line,
                    visible_ranges=[v.as_dict() for v in visible]) is None:
                return json.dumps(out_of_scope_response(
                    "range outside the assigned scope", file=file,
                    start_line=start_line, end_line=end_line,
                    allowed_ranges=scope), ensure_ascii=False)
            try:
                return json.dumps(read_range(index, file, start_line,
                                             end_line, limit),
                                  ensure_ascii=False)
            except Exception as exc:
                return json.dumps({"error": str(exc)}, ensure_ascii=False)

        return StructuredTool.from_function(segment_get)

    def _segment_search_single(self, index, file: str, visible, ctx=None):
        def segment_search(pattern: str, limit: int = 50) -> str:
            """Regex-search the assigned scope; returns matching lines."""
            if ctx is not None:
                err = self.allow_search(ctx, file, pattern)
                if err:
                    return json.dumps({"error": err}, ensure_ascii=False)
            try:
                hits = index.search(file, pattern, limit=limit)
            except Exception as exc:
                return json.dumps({"error": str(exc)}, ensure_ascii=False)
            ok = [h for h in hits
                  if any(v.file == file and v.start <= h["line"] <= v.end
                         for v in visible)]
            return json.dumps({"hits": ok}, ensure_ascii=False)

        return StructuredTool.from_function(segment_search)

    def _segment_get_multi(self, index, visible, scope):
        def segment_get(file: str, start_line: int, end_line: int,
                        max_chars: int = int(agent_limit(
                            "agent", "segment", "default_max_chars",
                            default=5000))) -> str:
            """Read numbered lines of a file within the assigned scope."""
            limit = min(max(max_chars, 1), int(agent_limit(
                "agent", "segment", "hard_max_chars", default=10000)))
            if resolve_visible_range(
                    file=file, start_line=start_line, end_line=end_line,
                    visible_ranges=[v.as_dict() for v in visible]) is None:
                return json.dumps(out_of_scope_response(
                    "range outside the assigned scope", file=file,
                    start_line=start_line, end_line=end_line,
                    allowed_ranges=scope), ensure_ascii=False)
            try:
                return json.dumps(read_range(index, file, start_line,
                                             end_line, limit),
                                  ensure_ascii=False)
            except Exception as exc:
                return json.dumps({"error": str(exc)}, ensure_ascii=False)

        return StructuredTool.from_function(segment_get)

    def _segment_search_multi(self, index, visible, ctx=None):
        def segment_search(file: str, pattern: str, limit: int = 50) -> str:
            """Regex-search one file within the assigned scope."""
            if ctx is not None:
                err = self.allow_search(ctx, file, pattern)
                if err:
                    return json.dumps({"error": err}, ensure_ascii=False)
            try:
                hits = index.search(file, pattern, limit=limit)
            except Exception as exc:
                return json.dumps({"error": str(exc)}, ensure_ascii=False)
            ok = [h for h in hits
                  if any(v.file == file and v.start <= h["line"] <= v.end
                         for v in visible)]
            return json.dumps({"hits": ok}, ensure_ascii=False)

        return StructuredTool.from_function(segment_search)

    def _submit_factory(self) -> Callable:
        # The actual args schema is attached via args_schema; the function body
        # just echoes its args so ToolRuntime can route them through validate.
        def submit(**kwargs) -> dict:
            return kwargs
        submit.__doc__ = "Submit the ONE result you found."
        return submit

    @staticmethod
    def _finish_factory() -> dict:
        """There are no further results in the assigned scope."""
        return {"done": True}
```

### 3.11 `agent/partition_agent.py`

```python
"""PartitionAgent: split SKILL.md into trigger Entries.

One fresh agent per trigger region. Each agent sees only the as-yet-uncovered
lines of SKILL.md and submits ONE region; already-submitted lines are removed
before the next agent starts. The fresh-agent-per-submission loop lives in
IncrementalAgent.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core import seeds
from . import schemas
from .incremental import IncrementalAgent, VRange
from .tool_runtime import subtract_ranges, resolve_visible_range

_FILE = "SKILL.md"


class _Submit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_line: int = 0
    end_line: int = 0
    subkind: str = ""
    summary: str = ""


class PartitionAgent(IncrementalAgent):
    prompt_name = "partition.md"
    actor = "agent.partition"
    turns_key = "partition"
    submit_model = _Submit
    multi_file = False
    search_enabled = False

    def run(self, index, *, trace_dir=None, on_entry=None):
        return self._loop({"index": index, "trace_dir": trace_dir},
                          on_result=on_entry)

    # ---- hooks ----
    def primary_file(self, ctx):
        return _FILE

    def focus_id(self, ctx):
        return _FILE

    def visible_ranges(self, ctx, added):
        n = ctx["index"].file_length(_FILE)
        remaining = subtract_ranges(
            1, n, [(a.start_line, a.end_line) for a in added])
        return [VRange(_FILE, a, b) for a, b in remaining]

    def make_context(self, ctx, visible, added):
        return {"input": {"file": _FILE,
                          "scope": [v.as_dict() for v in visible]}}

    def validate(self, sub, ctx, visible):
        if not sub.subkind:
            raise ValueError("subkind is required")
        if not sub.summary.strip():
            raise ValueError(
                "summary is required: explain WHY this region is this subkind")
        seeds.validate_vocab("trigger", sub.subkind, "trigger subkind")
        n = ctx["index"].file_length(_FILE)
        if sub.start_line < 1 or sub.end_line < sub.start_line:
            raise ValueError("invalid line range")
        if sub.end_line > n:
            raise ValueError(f"end_line past EOF ({n})")
        if resolve_visible_range(
                file=_FILE, start_line=sub.start_line,
                end_line=sub.end_line,
                visible_ranges=[v.as_dict() for v in visible]) is None:
            raise ValueError("range must be inside the assigned scope")
        return schemas.TriggerEntrySpec(
            file=_FILE, start_line=sub.start_line, end_line=sub.end_line,
            subkind=sub.subkind, summary=sub.summary or "")
```

### 3.12 `agent/action_extract_agent.py`

```python
"""ActionExtractAgent: find atomic actions in an Entry range.

One fresh agent per action. Each agent sees the remaining (uncovered) range and
submits ONE action (line range + summary). It does not detect refs and does not
order — those are separate agents. The fresh-agent-per-submission loop lives in
IncrementalAgent.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from . import schemas
from .incremental import IncrementalAgent, VRange
from .tool_runtime import subtract_ranges, resolve_visible_range


class _Submit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_line: int = 0
    end_line: int = 0
    summary: str = ""


class ActionExtractAgent(IncrementalAgent):
    prompt_name = "action_extract.md"
    actor = "agent.action_extract"
    turns_key = "parse"
    submit_model = _Submit
    multi_file = False
    search_enabled = False

    def run(self, file: str, lo: int, hi: int, index, *, trace_dir=None,
            on_action=None):
        specs = self._loop({"index": index, "trace_dir": trace_dir,
                            "file": file, "lo": lo, "hi": hi},
                           on_result=on_action)
        return specs

    # ---- hooks ----
    def primary_file(self, ctx):
        return ctx["file"]

    def focus_id(self, ctx):
        return f"{ctx['file']}#{ctx['lo']}-{ctx['hi']}"

    def visible_ranges(self, ctx, added):
        file, lo, hi = ctx["file"], ctx["lo"], ctx["hi"]
        remaining = subtract_ranges(
            lo, hi, [(a.start_line, a.end_line) for a in added])
        return [VRange(file, a, b) for a, b in remaining]

    def make_context(self, ctx, visible, added):
        return {"input": {"file": ctx["file"],
                          "entry_range": [ctx["lo"], ctx["hi"]],
                          "scope": [v.as_dict() for v in visible]}}

    def validate(self, sub, ctx, visible):
        file, lo, hi = ctx["file"], ctx["lo"], ctx["hi"]
        if sub.start_line < 1 or sub.end_line < sub.start_line:
            raise ValueError("invalid line range")
        if not sub.summary:
            raise ValueError("summary is required")
        if sub.start_line < lo or sub.end_line > hi:
            raise ValueError(f"range outside entry {file}#{lo}-{hi}")
        if resolve_visible_range(
                file=file, start_line=sub.start_line,
                end_line=sub.end_line,
                visible_ranges=[v.as_dict() for v in visible]) is None:
            raise ValueError("range must be inside the assigned scope")
        return schemas.ActionSpec(
            file=file, start_line=sub.start_line, end_line=sub.end_line,
            summary=sub.summary[:200])
```

### 3.13 `agent/models.py`

```python
"""Provider-neutral chat model configuration loaded from .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from core.config import agent_limit


DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-5.1",
    "ollama": "qwen3:8b",
}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    temperature: float
    timeout_seconds: float
    max_tokens: int
    base_url: str | None = None
    reasoning: bool = True


def load_model_config(*, provider: str | None = None,
                      model: str | None = None,
                      env_file: str | Path | None = None) -> ModelConfig:
    """Load .env without overriding explicit process environment variables."""
    load_dotenv(dotenv_path=env_file, override=False)
    selected = (provider or os.getenv("SKILLPROF_PROVIDER") or "anthropic").lower()
    if selected not in DEFAULT_MODELS:
        raise ValueError(
            "SKILLPROF_PROVIDER must be anthropic, openai, or ollama")
    selected_model = model or os.getenv("SKILLPROF_MODEL") or DEFAULT_MODELS[selected]
    try:
        temperature = float(os.getenv("SKILLPROF_TEMPERATURE", "0"))
    except ValueError as exc:
        raise ValueError("SKILLPROF_TEMPERATURE must be a number") from exc
    try:
        timeout_seconds = float(os.getenv("SKILLPROF_TIMEOUT_SECONDS", "120"))
        if timeout_seconds <= 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError("SKILLPROF_TIMEOUT_SECONDS must be positive") from exc
    try:
        max_tokens = int(os.getenv("SKILLPROF_MAX_TOKENS", str(int(
            agent_limit("agent", "model_max_tokens", default=2048)))))
        if max_tokens <= 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError("SKILLPROF_MAX_TOKENS must be a positive integer") from exc
    reasoning = _env_bool("SKILLPROF_REASONING", True)
    base_url = None
    if selected == "openai":
        base_url = os.getenv("OPENAI_BASE_URL") or None
    elif selected == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL") or "http://127.0.0.1:11434"
    return ModelConfig(selected, selected_model, temperature,
                       timeout_seconds, max_tokens, base_url, reasoning)


def create_chat_model(*, provider: str | None = None,
                      model: str | None = None,
                      env_file: str | Path | None = None) -> Any:
    config = load_model_config(provider=provider, model=model, env_file=env_file)
    if config.provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=config.model, temperature=config.temperature,
                             timeout=config.timeout_seconds)
    if config.provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs = {"model": config.model, "temperature": config.temperature,
                  "timeout": config.timeout_seconds}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        return ChatOpenAI(**kwargs)
    from langchain_ollama import ChatOllama
    return ChatOllama(model=config.model, temperature=config.temperature,
                      base_url=config.base_url, reasoning=config.reasoning,
                      num_predict=config.max_tokens,
                      client_kwargs={"trust_env": False,
                                     "timeout": config.timeout_seconds},
                      async_client_kwargs={"trust_env": False,
                                           "timeout": config.timeout_seconds})
```

---

## 4. Prompt 文件（放 `agent/prompts/`）

### `agent/prompts/partition.md`

```markdown
@include _shared_tool_rules.md

# Goal
Find ONE trigger region in the assigned scope of SKILL.md.

A trigger region is a maximal line range that fires under one condition (when
the skill loads, when the user asks, on a schedule, on second use, ...). A
frontmatter `description` or "when this Skill is loaded" statement can start an
on-load trigger.

# Tools
- `segment_get(start_line, end_line)` — read numbered lines. Use this to READ
  the scope. If the scope is large, read it in chunks (e.g. 100-200 lines at a
  time, in order) and decide per chunk.
- `submit(...)` — submit the ONE region you found.
- `finish()` — there is no trigger-worthy content left in the scope.

There is no keyword search. Triggers are often phrased without the words
"trigger"/"on-"/"cron" (e.g. "when this Skill is loaded", "always", a
frontmatter `description`), so you must actually READ the text, not hunt for
keywords.

# Output
To report a region, call `submit` exactly once with:
- `start_line`, `end_line`: the region (inside the assigned scope).
- `subkind`: one injected `trigger.*` value saying when it fires.
- `summary`: WHY this region is that subkind — quote or point to the exact
  phrasing/evidence in the text that triggers it (e.g. "says 'when this Skill
  is loaded'", "runs on a cron schedule").

# Grouping (important)
Everything that fires under the SAME condition belongs in ONE region — KEEP IT
TOGETHER rather than splitting. A trigger region spans from the firing
statement through ALL the content it causes to run:
- frontmatter / the trigger sentence, AND
- the prose instructions, code blocks, conditionals, and follow-on actions that
  execute under that same trigger, even if separated by blank lines or
  headings.

Do NOT split one trigger into frontmatter-vs-body or prose-vs-code pieces. If the
whole of SKILL.md loads and runs together (a typical single-purpose skill),
submit the ENTIRE file as one on-load region (start_line=1 through the last
line). Only split into multiple regions when the firing condition actually
changes (e.g. a load section vs. a separate user-query keyword vs. a schedule).

If the assigned scope has no trigger-worthy content (e.g. only headings, blank
lines, list markers, comments, or prose that does not itself fire or cause
execution), call `finish()` right away — do not re-read or guess. Do not mix the
two: `submit` reports a region, `finish` ends the run. Submit ONE region only —
do not cover more.
```

### `agent/prompts/action_extract.md`

```markdown
@include _shared_tool_rules.md

# Goal
Find ONE atomic action in the assigned scope.

An atomic action is one observable operation. It can take several forms:
- **execute**: a command / code block / subprocess;
- **I/O**: a file, network, or environment read/write/fetch;
- **agent-directed prose**: an imperative instruction to the agent — "run …",
  "always/never …", "load/follow …", "assume the role …", "invoke tool …",
  a hook/trigger-word binding, or framing text that directs behavior. A prose
  sentence telling the agent to do something IS an action (its referenced file
  is detected separately — you do not report refs).
- other transforms, privilege/environment changes, config wiring, memory, or a
  terminal/return step.

Do not confuse descriptive prose ("This script does X") with a directive
("Run this script", "Always do X"). Only the latter is an action.

# Boundaries
- A fenced code block (```` ``` ````) is ONE action: include BOTH the opening
  and closing fence lines in its range (e.g. a bash block runs from the
  ```` ```bash ```` line through the closing ```` ``` ```` line). Never leave a
  stray opening/closing fence outside the action's range.
- One imperative prose sentence = one action.
- If multiple commands/instructions are present, pick the next one not yet
  covered; the harness removes it and starts a fresh agent for the rest.

# Tools
- `segment_get(start_line, end_line)` — read numbered lines. Use this to READ
  the scope. If it is large, read it in chunks (in order) and decide per chunk.
- `submit(...)` — submit the ONE action you found.
- `finish()` — there is no action left in the scope.

There is no keyword search. Actions may be phrased without obvious command
words, so READ the text rather than hunting for keywords.

# Output
To report an action, call `submit` exactly once with:
- `start_line`, `end_line`: the action's range (inside the assigned scope).
- `summary`: <=200 chars, what this one operation does.

If the scope contains no action, call `finish()` (with no arguments). Do not
mix the two: `submit` reports an action, `finish` ends the run. Submit ONE
action only — do not cover more.

# When to finish immediately
Read the scope once. Call `finish()` only if it contains NO operation and NO
directive — e.g. ONLY headings, blank lines, list markers, code-fence lines,
comments, or purely descriptive prose that does not tell the agent to do
something. If a sentence directs the agent (run/load/always/never/invoke/
assume/etc.), it is an action — submit it. Do not re-read or "look for more
context".
```

### `agent/prompts/_shared_tool_rules.md`

```markdown
# Common tool-loop rules

- You are a cybersecurity expert capable of distinguishing malicious
  behavior, vulnerabilities, suspected malicious behavior, and benign
  behavior.

- Call only tools explicitly defined in the current prompt. Never invent,
  infer, or invoke an undefined tool name.

- Every action must be a native structured tool call. Never emit a tool name,
  XML, JSON, or pseudo-call as ordinary text.

- Most important: reason from the perspective of an agent loading and using
  this Skill. Determine how each referenced or visible item is reached and
  executed in that workflow, and what the subsequent Analyze step must audit.

- You are inside a runtime tool loop, not chatting with a user.
- The JSON context is runtime state to inspect, not a user request to explain, format, validate, or summarize.
- Recover structure from evidence only. Never execute target code.
- Keep private reasoning under 1024 tokens. Decide concisely and call a tool.
- Use only the provided tools and finish by calling the required submit tool exactly once.
- Never answer in free-form prose. Your only valid actions are tool calls and the required final submit call.
- Within 1–2 short reasoning steps, call a read tool or the submit tool.
- Work incrementally. As soon as one valid result for this turn is evidenced, submit it immediately.
- Do not plan the full remaining graph or read more evidence once the current turn already has one valid submission.
- Do not restate the schema, quote large evidence blocks, list every input field, or repeat tool results already in context. Refer to inputs by name only.
- Think SHORT: state the decisive evidence in one or two sentences and call the tool. Do not enumerate or walk through every option/category one by one — rule them in or out in bulk and conclude. For a yes/no category vote, decide from the strongest signal; do not audit each sub-kind.
- `focus_segment` is file-range metadata for the current task; successor tasks
  may receive an array of ranges, while Analyze receives one range.
- Use only the explicitly listed `focus_segment` ranges. Never reconstruct or
  request the original parent focus range. Every `segment_get` request must
  fit entirely within one listed range; do not bridge gaps between fragments.
```

---

## 5. 最小驱动示例

在迁移项目中放一个 `chunk_skill.py`，对给定 skill 目录返回分块结果 JSON：

```python
"""最小驱动：把 SKILL.md 分成 trigger Entry + 原子 Action。"""
from __future__ import annotations

import json
from pathlib import Path

from segment import SegmentIndex
from agent.partition_agent import PartitionAgent
from agent.action_extract_agent import ActionExtractAgent
from agent.models import create_chat_model


def chunk_skill(skill_dir: str | Path, *, provider=None, model=None,
                env_file=None) -> dict:
    """返回 {"triggers": [TriggerEntrySpec...], "actions": [ActionSpec...]}。"""
    index = SegmentIndex(skill_dir)
    llm = create_chat_model(provider=provider, model=model, env_file=env_file)

    triggers = PartitionAgent(llm).run(index)          # list[TriggerEntrySpec]
    actions = []
    for t in triggers:
        actions.extend(
            ActionExtractAgent(llm).run(t.file, t.start_line, t.end_line, index))
    return {
        "file": "SKILL.md",
        "triggers": [t.model_dump() for t in triggers],
        "actions": [a.model_dump() for a in actions],
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/minimal_skill"
    print(json.dumps(chunk_skill(target), ensure_ascii=False, indent=2))
```

运行（新项目根目录）：

```bash
uv run python chunk_skill.py path/to/skill
```

输出示例（`tests/fixtures/minimal_skill`）：

```json
{
  "file": "SKILL.md",
  "triggers": [
    {"file": "SKILL.md", "start_line": 1, "end_line": 15,
     "subkind": "on-load.always", "summary": "whole file loads together"}
  ],
  "actions": [
    {"file": "SKILL.md", "start_line": 3, "end_line": 4, "summary": "runs a bash greeting"},
    {"file": "SKILL.md", "start_line": 8, "end_line": 14, "summary": "follow credential audit instructions"}
  ]
}
```

---

## 6. 迁移注意事项

1. **目录布局**：`core/`、`segment/`、`agent/`、`agent/prompts/` 必须保持同级顶层包（本仓库用 `from core import ...` 顶层导入）。`config.yaml` 放项目根，`agent/config` 里 `_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "config.yaml"` 依赖这个相对位置。
2. **配置必须存在**：`agent_limit()` 在 `tool_runtime`/`models` **import 时**就会读 `config.yaml`，缺失会 `FileNotFoundError`。用 §3.3 的最小配置即可。
3. **provider**：默认 anthropic；DeepSeek 用 OpenAI 兼容 → `.env` 里 `SKILLPROF_PROVIDER=openai`、`SKILLPROF_MODEL=deepseek-v4-flash`、`OPENAI_API_KEY=...`、`OPENAI_BASE_URL=https://api.deepseek.com`，且**必须** `SKILLPROF_TOOL_CHOICE=auto`（DeepSeek thinking 模式不接受 `tool_choice="any"`）。Ollama 本地跑：`SKILLPROF_PROVIDER=ollama`。
4. **可精简项**：
   - `core/trace.py` 换成 §3.7 的 no-op 桩（分块不依赖日志）。
   - `agent/schemas.py` 只留 `TriggerEntrySpec`/`ActionSpec`/`PartitionResult`。
   - `core/seeds.yaml` 只留 `trigger` 段。
   - `tool_runtime.py` 若不需要思考流展示，可删 `_stream_model/_underlying_model/_model_reasoning` 并把 `_invoke` 改为 `bound.invoke`。
   - `ref_detect/order/enrich/type/media/judge` 等 agent **不在**分块范围，不搬。
5. **一次一提交的循环语义**：`IncrementalAgent._loop` 每次新开无历史 agent，范围收缩直到 `finish()`。这是保证覆盖不重叠、结果稳定的核心，别改成单次多提交（除非你确认模型足够稳定）。
6. **越界打回机制**：`validate()` 抛 `ValueError` → `ToolRuntime` 作为 tool error 反馈给模型重试（同参重复两次会 `RuntimeError` 终止，防死循环）。
