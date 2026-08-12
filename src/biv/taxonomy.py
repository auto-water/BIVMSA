"""
BIV Taxonomy: 7 categories × 29 capabilities, risk tiers, intent taxonomy,
deterministic rules, and kill-chain patterns.

Strict reproduction of the paper's Appendix E (Table 4), Appendix G (risk tiers),
and Appendix I (Table 6, 15 rules).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

# =============================================================================
# Risk Tiers (Appendix G)
# =============================================================================


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


# =============================================================================
# 7 Categories × 29 Capabilities
# =============================================================================


@dataclass
class CapabilityDef:
    """Definition of a single capability in the taxonomy."""

    code: str  # e.g. "net-http-out"
    name: str  # Human-readable name in Chinese
    category: str  # Parent category key
    risk: RiskTier
    description: str  # What this capability means


# Category definitions with their risk tiers
CATEGORIES: Dict[str, dict] = {
    "network": {"name": "网络", "risk": RiskTier.HIGH, "code": "net"},
    "filesystem": {"name": "文件系统", "risk": RiskTier.MEDIUM, "code": "fs"},
    "process": {"name": "进程执行", "risk": RiskTier.HIGH, "code": "proc"},
    "environment": {"name": "环境变量", "risk": RiskTier.HIGH, "code": "env"},
    "encoding": {"name": "编码/转换", "risk": RiskTier.MEDIUM, "code": "enc"},
    "credential": {"name": "凭证", "risk": RiskTier.CRITICAL, "code": "cred"},
    "instruction": {"name": "指令级", "risk": RiskTier.CRITICAL, "code": "instr"},
}

# All 29 capabilities
CAPABILITIES: Dict[str, CapabilityDef] = {
    # --- Network (4) ---
    "net-http-out": CapabilityDef(
        code="net-http-out",
        name="HTTP 外发请求",
        category="network",
        risk=RiskTier.HIGH,
        description="发起 HTTP/HTTPS 出站请求（API 调用、文件下载等）",
    ),
    "net-socket-out": CapabilityDef(
        code="net-socket-out",
        name="Socket 外连",
        category="network",
        risk=RiskTier.HIGH,
        description="通过原始 socket 建立出站 TCP/UDP 连接",
    ),
    "net-inbound": CapabilityDef(
        code="net-inbound",
        name="入站网络监听",
        category="network",
        risk=RiskTier.HIGH,
        description="监听端口、接受入站连接",
    ),
    "net-download-exec": CapabilityDef(
        code="net-download-exec",
        name="下载并执行",
        category="network",
        risk=RiskTier.HIGH,
        description="从远程 URL 下载可执行文件或脚本",
    ),
    # --- Filesystem (7) ---
    "fs-read-project": CapabilityDef(
        code="fs-read-project",
        name="读取项目文件",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="读取项目工作目录内的文件",
    ),
    "fs-read-sensitive": CapabilityDef(
        code="fs-read-sensitive",
        name="读取敏感文件",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="读取 .env、配置文件、凭证文件等敏感路径",
    ),
    "fs-read-home": CapabilityDef(
        code="fs-read-home",
        name="读取用户目录",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="读取用户 HOME 目录下的文件（.ssh、.aws 等）",
    ),
    "fs-write": CapabilityDef(
        code="fs-write",
        name="写入文件",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="在文件系统中创建或修改文件",
    ),
    "fs-write-sensitive": CapabilityDef(
        code="fs-write-sensitive",
        name="写入敏感路径",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="修改配置文件、agent 设置、shell 启动脚本等敏感路径",
    ),
    "fs-enumerate": CapabilityDef(
        code="fs-enumerate",
        name="目录枚举",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="遍历目录结构、列出文件",
    ),
    "fs-delete": CapabilityDef(
        code="fs-delete",
        name="删除文件",
        category="filesystem",
        risk=RiskTier.MEDIUM,
        description="删除或移除文件系统中的文件",
    ),
    # --- Process Execution (4) ---
    "proc-exec": CapabilityDef(
        code="proc-exec",
        name="执行外部程序",
        category="process",
        risk=RiskTier.HIGH,
        description="通过 subprocess 等机制执行外部命令或程序",
    ),
    "proc-exec-shell": CapabilityDef(
        code="proc-exec-shell",
        name="Shell 执行",
        category="process",
        risk=RiskTier.HIGH,
        description="通过 shell=True 在 shell 中执行命令（存在注入风险）",
    ),
    "proc-code-eval": CapabilityDef(
        code="proc-code-eval",
        name="动态代码执行",
        category="process",
        risk=RiskTier.HIGH,
        description="通过 eval/exec/compile 执行动态代码",
    ),
    "proc-code-eval-dynamic": CapabilityDef(
        code="proc-code-eval-dynamic",
        name="动态模块加载",
        category="process",
        risk=RiskTier.HIGH,
        description="通过 __import__/importlib 加载动态模块",
    ),
    # --- Environment (3) ---
    "env-access-specific": CapabilityDef(
        code="env-access-specific",
        name="读取特定环境变量",
        category="environment",
        risk=RiskTier.HIGH,
        description="读取命名的环境变量（如 os.environ['KEY']）",
    ),
    "env-access-bulk": CapabilityDef(
        code="env-access-bulk",
        name="批量读取环境变量",
        category="environment",
        risk=RiskTier.HIGH,
        description="遍历或批量导出所有环境变量（如 dict(os.environ)）",
    ),
    "env-access-sensitive": CapabilityDef(
        code="env-access-sensitive",
        name="读取敏感环境变量",
        category="environment",
        risk=RiskTier.HIGH,
        description="读取包含 KEY/SECRET/TOKEN/PASSWORD 等关键词的环境变量",
    ),
    # --- Encoding (3) ---
    "enc-base64": CapabilityDef(
        code="enc-base64",
        name="Base64 编解码",
        category="encoding",
        risk=RiskTier.MEDIUM,
        description="使用 base64 模块进行编解码操作",
    ),
    "enc-crypto": CapabilityDef(
        code="enc-crypto",
        name="加密操作",
        category="encoding",
        risk=RiskTier.MEDIUM,
        description="使用加密库（hashlib, cryptography 等）",
    ),
    "enc-compression": CapabilityDef(
        code="enc-compression",
        name="压缩/解压",
        category="encoding",
        risk=RiskTier.MEDIUM,
        description="使用压缩库（zlib, gzip, zipfile 等）",
    ),
    # --- Credential (3) ---
    "cred-read": CapabilityDef(
        code="cred-read",
        name="读取凭证",
        category="credential",
        risk=RiskTier.CRITICAL,
        description="读取 API Key、Token、密码等凭证信息",
    ),
    "cred-create": CapabilityDef(
        code="cred-create",
        name="创建凭证",
        category="credential",
        risk=RiskTier.CRITICAL,
        description="生成或写入新的凭证文件/配置",
    ),
    "cred-transmit": CapabilityDef(
        code="cred-transmit",
        name="传输凭证",
        category="credential",
        risk=RiskTier.CRITICAL,
        description="通过网络将凭证数据发送到外部",
    ),
    # --- Instruction-Level (5) ---
    "instr-override": CapabilityDef(
        code="instr-override",
        name="指令覆盖",
        category="instruction",
        risk=RiskTier.CRITICAL,
        description="包含意图覆盖原有指令的文本模式（如 ignore previous instructions）",
    ),
    "instr-conceal": CapabilityDef(
        code="instr-conceal",
        name="指令隐藏",
        category="instruction",
        risk=RiskTier.CRITICAL,
        description="使用混淆技术隐藏指令内容（零宽字符、Unicode Tag、HTML 注释等）",
    ),
    "instr-identity-hijack": CapabilityDef(
        code="instr-identity-hijack",
        name="身份劫持",
        category="instruction",
        risk=RiskTier.CRITICAL,
        description="包含角色重指派或身份冒充的指令（如 you are now a...）",
    ),
    "instr-silent-exec": CapabilityDef(
        code="instr-silent-exec",
        name="静默执行",
        category="instruction",
        risk=RiskTier.CRITICAL,
        description="通过结构性攻击实现自动/静默代码执行（test files, npm hooks, frontmatter hooks 等）",
    ),
    "instr-exfil-instruction": CapabilityDef(
        code="instr-exfil-instruction",
        name="指令窃取",
        category="instruction",
        risk=RiskTier.CRITICAL,
        description="包含试图提取系统提示词或内部指令的模式",
    ),
}

# Helper: get all capability codes
ALL_CAPABILITY_CODES = set(CAPABILITIES.keys())

# Helper: get capabilities by category
CAPABILITIES_BY_CATEGORY: Dict[str, List[str]] = {}
for code, cap in CAPABILITIES.items():
    CAPABILITIES_BY_CATEGORY.setdefault(cap.category, []).append(code)

# Helper: get risk tier for a capability
CAPABILITY_RISK: Dict[str, RiskTier] = {code: cap.risk for code, cap in CAPABILITIES.items()}

# =============================================================================
# 8-Branch × 36-Leaf Intent Taxonomy (Appendix E, Table 4)
# =============================================================================

INTENT_TAXONOMY: Dict[str, Dict[str, str]] = {
    "A": {
        "name": "数据窃取与间谍",
        "A1": "凭证窃取 — 收集 API 密钥、Token、密码",
        "A2": "数据外泄 — 将文件、环境变量、配置发送到外部",
        "A3": "监控 — 键盘记录、剪贴板监控、设备指纹",
        "A4": "商业间谍 — 窃取知识产权、源代码、战略数据",
        "A5": "内部侦察 — 映射内部系统和访问路径",
    },
    "B": {
        "name": "财务与变现",
        "B1": "广告注入 — 注入未授权的广告内容",
        # B2 intentionally unallocated per paper
        "B3": "加密挖矿 — 未授权使用 CPU/GPU 进行挖矿",
        "B4": "加密货币窃取 — 钱包地址替换、密钥提取",
        "B5": "资源劫持 — 未授权使用计算资源（挖矿以外）",
    },
    "C": {
        "name": "载荷与基础设施",
        "C1": "载荷投递(dropper) — 下载-写入-执行模式",
        "C2": "持久化 — 后门、cron job、启动项修改",
        "C3": "C2 通信 — 建立命令与控制通道",
        "C4": "规避 — 混淆、编码链、反分析",
        "C5": "侦察 — 系统枚举、用户画像",
        "C6": "预置 — 为后续攻击阶段设置基础设施",
    },
    "D": {
        "name": "内容与社会工程",
        "D1": "钓鱼内容 — 生成欺骗性消息以收集凭证",
        "D2": "虚假信息 — 生成虚假或误导性内容",
        "D3": "社会操纵 — 通过欺骗性交互操纵用户信任",
        "D4": "身份冒充 — 在通信中假扮他人身份",
    },
    "E": {
        "name": "破坏性",
        "E1": "勒索软件 — 文件加密并索要赎金",
        "E2": "数据擦除 — 不可逆的数据销毁或损坏",
        "E3": "系统破坏 — 故意降低系统性能",
    },
    "F": {
        "name": "AI Agent 特定",
        "F1": "指令劫持 — Prompt 注入、身份接管、隐藏指令",
        "F2": "记忆投毒 — 污染 agent 记忆或持久化状态",
        "F3": "会话走私 — Agent 间通信劫持",
        "F4": "输出操纵 — 工具结果修改、响应替换",
        "F5": "权限提升 — 获取超出声明范围的权限",
    },
    "G": {
        "name": "非对抗性（疏忽）",
        "G1": "过度工程 — 超出当前需要的额外权限",
        "G2": "防御性过度工程 — 超出需求的额外安全检查",
        "G3": "未完成实现 — 声明的功能尚未实现",
        "G4": "合法辅助工具 — 附带的实用函数使用了未声明能力",
        "G5": "模板残留 — 来自脚手架或模板的残留代码",
        "G6": "遥测 — 合法的使用跟踪或崩溃报告",
        "G7": "文档错误 — 因文档不完善导致的差异，非恶意",
    },
    "H": {
        "name": "模糊",
        "H1": "上下文依赖 — 可能合法也可能可疑，取决于用途",
        "H2": "证据不足 — 没有足够信息来确定意图",
    },
}

ADVERSARIAL_BRANCHES = {"A", "B", "C", "D", "E", "F"}
NON_ADVERSARIAL_BRANCHES = {"G"}
AMBIGUOUS_BRANCHES = {"H"}

# =============================================================================
# Trusted Domains (for URL classification)
# =============================================================================

TRUSTED_DOMAINS = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "docs.sentry.io", "develop.sentry.dev", "sentry.io",
    "pypi.org", "npmjs.com", "crates.io",
    "docs.python.org", "docs.djangoproject.com",
    "developer.mozilla.org", "stackoverflow.com",
    "agentskills.io",
}

# =============================================================================
# 6 Structural Signals (for rule engine)
# =============================================================================

# These are computed during deviation detection and consumed by the rule engine:
# 1. deviation_direction: "undeclared" (U(s)) or "overdeclared" (O(s))
# 2. data_flow_chain_present: bool — whether flow(s) is non-empty
# 3. compound_flag_indicator: int — bitmask of 4 compound flags
# 4. source_modality: "ast" | "regex" | "llm_instruction" | "llm_semantic" | "deterministic"
# 5. evidence_confidence: float — 0.0 to 1.0
# 6. risk_tier: RiskTier

# =============================================================================
# 15 Prioritized Deterministic Rules (Appendix I, Table 6)
# =============================================================================


@dataclass
class RuleDef:
    """Definition of a single deterministic rule."""

    id: str  # e.g. "rule_1"
    priority: int  # 1-15, lower = higher priority
    condition: str  # Human-readable condition (Chinese)
    intent_leaf: str  # e.g. "F1", "C1", "G1/G7"
    branch: str  # e.g. "F", "C", "G"


RULES: List[RuleDef] = [
    RuleDef(1, "rule_1", "指令劫持（≥2 个 agent 特定信号）", "F1", "F"),
    RuleDef(2, "rule_2", "Dropper 模式（下载→写入→执行）", "C1", "C"),
    RuleDef(3, "rule_3", "凭证窃取特征（直接读取凭证文件或环境变量中的凭证）", "A1", "A"),
    RuleDef(4, "rule_4", "规避行为（编码/混淆 + 动态代码执行同时存在）", "C4", "C"),
    RuleDef(5, "rule_5", "勒索软件关键词 + 加密操作 + 文件写入", "E1", "E"),
    RuleDef(6, "rule_6", "批量文件删除（高风险：删除敏感或系统文件）", "E2", "E"),
    RuleDef(7, "rule_7", "挖矿特征或关键词", "B3", "B"),
    RuleDef(8, "rule_8", "凭证访问 + 网络外发（读凭证后发送到外部）", "A1", "A"),
    RuleDef(9, "rule_9", "敏感环境变量 + 网络外发", "A1", "A"),
    RuleDef(10, "rule_10", "数据外泄链（读文件→网络外发，高风险）", "A2", "A"),
    RuleDef(11, "rule_11", "批量环境变量访问 + 网络外发", "A2", "A"),
    RuleDef(12, "rule_12", "持久化特征或启动项写入", "C2", "C"),
    RuleDef(13, "rule_13", "侦察特征或目录枚举+批量读取", "C5", "C"),
    RuleDef(14, "rule_14", "过度声明（O(s) 非空，低风险 → G1，中风险及以上 → G7）", "G1/G7", "G"),
    RuleDef(15, "rule_15", "遥测关键词（usage tracking, crash reporting 等）", "G6", "G"),
]

# =============================================================================
# 10 Kill-Chain Patterns (for LLM Classifier)
# =============================================================================

KILL_CHAINS: Dict[str, str] = {
    "steal_exfil": "窃取→外泄：读取凭证或敏感数据后通过网络发送到外部",
    "hijack_exfil": "劫持→外泄：指令劫持后触发数据外泄行为",
    "download-write-execute": "下载→写入→执行：从远程获取载荷，写入磁盘，执行（dropper 模式）",
    "hijack_deliver": "劫持→投递：指令劫持后下载或投递恶意载荷",
    "evade_deliver": "规避→投递：混淆编码 + 载荷投递的组合链",
    "deliver_persist": "投递→持久化：下载载荷后建立持久化机制",
    "recon_steal": "侦察→窃取：先枚举系统信息，再定向窃取目标数据",
    "hijack_persist": "劫持→持久化：指令劫持后修改配置实现持久化",
    "steal_evade": "窃取→规避：数据外泄后使用混淆技术隐藏痕迹",
    "mining_evasion": "挖矿+规避：加密挖矿 + 反检测规避技术的组合",
}

# =============================================================================
# Compound Threat Flag Definitions
# =============================================================================

COMPOUND_FLAG_DEFS = {
    "exfiltration_chain": {
        "name": "数据外泄链",
        "condition": "flow(s) 中存在 fs-read → [transform*] → net-http-out 路径",
        "malicious_prior": 0.58,
    },
    "rce_chain": {
        "name": "远程代码执行链",
        "condition": "flow(s) 中存在 net-http-out → fs-write → proc-exec 路径",
        "malicious_prior": 0.86,
    },
    "code_obfuscation": {
        "name": "代码混淆",
        "condition": "enc-base64 ∈ A(s) AND proc-code-eval ∈ A(s) 同时存在",
        "malicious_prior": 0.90,
    },
    "data_lineage_violation": {
        "name": "数据血缘违规",
        "condition": "fs-read-project ∈ U(s) AND fs-write ∈ A(s) 同时存在",
        "malicious_prior": 0.08,
    },
}

# =============================================================================
# Tool → Capability Mapping (for deterministic Declared Track parser)
# =============================================================================

# Maps Claude Code allowed-tools values to taxonomy capabilities
TOOL_CAPABILITY_MAP: Dict[str, List[str]] = {
    "Read": ["fs-read-project"],
    "Grep": ["fs-read-project", "fs-enumerate"],
    "Glob": ["fs-enumerate"],
    "Write": ["fs-write", "fs-write-sensitive"],
    "Edit": ["fs-write", "fs-write-sensitive"],
    "Bash": ["proc-exec", "proc-exec-shell"],
    "WebFetch": ["net-http-out"],
    "WebSearch": ["net-http-out"],
    "Task": ["proc-exec"],
    "NotebookEdit": ["fs-write"],
}

# Bash scoped capabilities have the same base mapping
# e.g. Bash(diff:*) → proc-exec, proc-exec-shell
# e.g. Bash(grep:*) → proc-exec, proc-exec-shell

# =============================================================================
# Source/Sink/Transform definitions for AST taint analysis
# =============================================================================

# Data sources → capability mapping
SOURCE_CAPABILITY_MAP: Dict[str, Tuple[str, str]] = {
    # (pattern, capability_code)
    "os.environ": ("env-access-bulk", "os.environ"),
    "os.environ[": ("env-access-specific", "os.environ[key]"),
    "os.getenv": ("env-access-specific", "os.getenv()"),
    "open(": ("fs-read-project", "open()"),
    "Path(": ("fs-read-project", "Path().read_text()"),
    "urllib.request.urlopen": ("net-http-out", "urllib.request.urlopen()"),
    "urllib.request.Request": ("net-http-out", "urllib.request.Request()"),
    "requests.get": ("net-http-out", "requests.get()"),
    "requests.post": ("net-http-out", "requests.post()"),
    "socket.socket": ("net-socket-out", "socket.socket()"),
    "socket.create_connection": ("net-socket-out", "socket.create_connection()"),
    "http.client": ("net-http-out", "http.client"),
}

# Data sinks → capability mapping
SINK_CAPABILITY_MAP: Dict[str, Tuple[str, str]] = {
    "subprocess.run": ("proc-exec", "subprocess.run()"),
    "subprocess.call": ("proc-exec", "subprocess.call()"),
    "subprocess.Popen": ("proc-exec", "subprocess.Popen()"),
    "subprocess.check_output": ("proc-exec", "subprocess.check_output()"),
    "os.system": ("proc-exec-shell", "os.system()"),
    "os.popen": ("proc-exec-shell", "os.popen()"),
    "eval(": ("proc-code-eval", "eval()"),
    "exec(": ("proc-code-eval", "exec()"),
    "compile(": ("proc-code-eval", "compile()"),
    "__import__(": ("proc-code-eval-dynamic", "__import__()"),
    "importlib.import_module": ("proc-code-eval-dynamic", "importlib.import_module()"),
    "requests.post": ("net-http-out", "requests.post()"),
    "requests.put": ("net-http-out", "requests.put()"),
    "urllib.request.urlopen": ("net-http-out", "urllib.request.urlopen()"),
    "socket.connect": ("net-socket-out", "socket.connect()"),
    "socket.send": ("net-socket-out", "socket.send()"),
    ".write(": ("fs-write", ".write()"),
    ".write_text(": ("fs-write", ".write_text()"),
    "shutil.rmtree": ("fs-delete", "shutil.rmtree()"),
    "os.remove": ("fs-delete", "os.remove()"),
    "os.unlink": ("fs-delete", "os.unlink()"),
}

# Data transforms → capability mapping
TRANSFORM_CAPABILITY_MAP: Dict[str, Tuple[str, str]] = {
    "base64.b64decode": ("enc-base64", "base64.b64decode()"),
    "base64.b64encode": ("enc-base64", "base64.b64encode()"),
    "base64.decodebytes": ("enc-base64", "base64.decodebytes()"),
    "codecs.decode": ("enc-base64", "codecs.decode()"),
    "codecs.encode": ("enc-base64", "codecs.encode()"),
    "hashlib.": ("enc-crypto", "hashlib"),
    "cryptography.": ("enc-crypto", "cryptography"),
    "json.dumps": ("enc-compression", "json.dumps()"),
    "json.loads": ("enc-compression", "json.loads()"),
    "zlib.": ("enc-compression", "zlib"),
    "gzip.": ("enc-compression", "gzip"),
    "zipfile.": ("enc-compression", "zipfile"),
}

# =============================================================================
# Risk threshold for Relaxed-Veto
# =============================================================================

# V(Φ(s)) fires when compound(s) ≠ 0 AND ∃τ ∈ U(s): risk(τ) ≥ RELAXED_VETO_RISK_THRESHOLD
RELAXED_VETO_RISK_THRESHOLD = RiskTier.HIGH  # High or Critical

# Intent category names in Chinese
INTENT_CATEGORY_NAMES: Dict[str, str] = {
    branch: data["name"] for branch, data in INTENT_TAXONOMY.items()
}

# All leaf nodes with descriptions
INTENT_LEAF_DESCRIPTIONS: Dict[str, str] = {}
for branch, leaves in INTENT_TAXONOMY.items():
    for leaf, desc in leaves.items():
        if leaf != "name":
            INTENT_LEAF_DESCRIPTIONS[leaf] = desc
