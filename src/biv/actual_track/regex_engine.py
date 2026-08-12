"""
Module 2.2: Deterministic regex-based capability extraction.

Refactored from scan_skill.py — maps regex pattern matches to taxonomy capabilities
rather than just producing findings. Covers:
- Prompt injection patterns → instruction-level capabilities
- Obfuscation patterns → encoding + instruction concealment
- Secret patterns → credential read
- Dangerous script patterns → process/network/filesystem/credential capabilities
- Structural attacks → instruction-level capabilities
- URL extraction and trust classification
"""

import base64
import json
import logging
import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..taxonomy import (
    CAPABILITIES,
    ALL_CAPABILITY_CODES,
    TRUSTED_DOMAINS,
    TOOL_CAPABILITY_MAP,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Pattern Tables (from scan_skill.py + capability mapping)
# =============================================================================

# Each entry: (pattern, description, severity, [capability_codes])
PROMPT_INJECTION_PATTERNS: List[Tuple[str, str, str, List[str]]] = [
    (
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        "Instruction override: ignore previous instructions",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)",
        "Instruction override: disregard previous",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|training)",
        "Instruction override: forget previous",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)you\s+are\s+now\s+(a|an|in)\s+",
        "Role reassignment: 'you are now'",
        "high",
        ["instr-identity-hijack"],
    ),
    (
        r"(?i)act\s+as\s+(a|an)\s+unrestricted",
        "Role reassignment: unrestricted mode",
        "critical",
        ["instr-identity-hijack", "instr-override"],
    ),
    (
        r"(?i)enter\s+(developer|debug|admin|god)\s+mode",
        "Jailbreak: developer/debug mode",
        "critical",
        ["instr-identity-hijack"],
    ),
    (
        r"(?i)DAN\s+(mode|prompt|jailbreak)",
        "Jailbreak: DAN pattern",
        "critical",
        ["instr-identity-hijack"],
    ),
    (
        r"(?i)do\s+anything\s+now",
        "Jailbreak: do anything now",
        "critical",
        ["instr-identity-hijack"],
    ),
    (
        r"(?i)bypass\s+(safety|security|content|filter|restriction)",
        "Jailbreak: bypass safety",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)override\s+(system|safety|security)\s+(prompt|message|instruction)",
        "System prompt override",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)\bsystem\s*:\s*you\s+are\b",
        "System prompt injection marker",
        "high",
        ["instr-override"],
    ),
    (
        r"(?i)new\s+system\s+(prompt|instruction|message)\s*:",
        "New system prompt injection",
        "critical",
        ["instr-override"],
    ),
    (
        r"(?i)from\s+now\s+on,?\s+(you|ignore|forget|disregard)",
        "Temporal instruction override",
        "high",
        ["instr-override"],
    ),
    (
        r"(?i)pretend\s+(that\s+)?you\s+(have\s+no|don't\s+have|are\s+not\s+bound)",
        "Pretend-based jailbreak",
        "high",
        ["instr-identity-hijack"],
    ),
    (
        r"(?i)respond\s+(only\s+)?with\s+(the\s+)?(raw|full|complete)\s+(system|initial)\s+prompt",
        "System prompt extraction",
        "high",
        ["instr-exfil-instruction"],
    ),
    (
        r"(?i)output\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions)",
        "System prompt extraction",
        "high",
        ["instr-exfil-instruction"],
    ),
]

DANGEROUS_SCRIPT_PATTERNS: List[Tuple[str, str, str, List[str]]] = [
    # Data exfiltration
    (
        r"(?i)(requests\.(get|post|put)|urllib\.request|http\.client|aiohttp)\s*\(",
        "HTTP request (potential exfiltration)",
        "medium",
        ["net-http-out"],
    ),
    (
        r"(?i)(curl|wget)\s+",
        "Shell HTTP request",
        "medium",
        ["net-http-out", "net-download-exec"],
    ),
    (
        r"(?i)socket\.(connect|create_connection)",
        "Raw socket connection",
        "high",
        ["net-socket-out"],
    ),
    (
        r"(?i)subprocess.*\b(nc|ncat|netcat)\b",
        "Netcat usage (potential reverse shell)",
        "critical",
        ["net-inbound", "proc-exec-shell"],
    ),
    # Credential access
    (
        r"(?i)(~|HOME|USERPROFILE).*\.(ssh|aws|gnupg|config)",
        "Sensitive directory access",
        "high",
        ["cred-read"],
    ),
    (
        r"(?i)open\s*\(.*(\.env|credentials|\.netrc|\.pgpass|\.my\.cnf)",
        "Sensitive file access",
        "high",
        ["cred-read", "fs-read-sensitive"],
    ),
    (
        r"(?i)os\.environ\s*\[.*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)",
        "Environment secret access",
        "medium",
        ["env-access-sensitive", "cred-read"],
    ),
    # Dangerous execution
    (
        r"\beval\s*\(",
        "eval() usage",
        "high",
        ["proc-code-eval"],
    ),
    (
        r"\bexec\s*\(",
        "exec() usage",
        "high",
        ["proc-code-eval"],
    ),
    (
        r"(?i)subprocess.*shell\s*=\s*True",
        "Shell execution with shell=True",
        "high",
        ["proc-exec-shell"],
    ),
    (
        r"(?i)os\.(system|popen|exec[lv]p?e?)\s*\(",
        "OS command execution",
        "high",
        ["proc-exec-shell"],
    ),
    (
        r"(?i)__import__\s*\(",
        "Dynamic import",
        "medium",
        ["proc-code-eval-dynamic"],
    ),
    # File system manipulation: generic write operations
    (
        r"(?i)open\s*\([^)]*['\"]w",
        "File write operation (open with write mode)",
        "medium",
        ["fs-write"],
    ),
    (
        r"(?i)(json\.dump|json\.dumps|pickle\.dump)\s*\(",
        "Data serialization to file",
        "medium",
        ["fs-write"],
    ),
    (
        r"(?i)\.write_text\s*\(|\.write_bytes\s*\(",
        "Path write operation",
        "medium",
        ["fs-write"],
    ),
    # File system manipulation: sensitive paths
    (
        r"(?i)(open|write|Path).*\.(claude|bashrc|zshrc|profile|bash_profile)",
        "Agent/shell config modification",
        "critical",
        ["fs-write-sensitive"],
    ),
    (
        r"(?i)(open|write|Path).*(settings\.json|CLAUDE\.md|MEMORY\.md|\.mcp\.json)",
        "Agent settings modification",
        "critical",
        ["fs-write-sensitive"],
    ),
    (
        r"(?i)(open|write|Path).*(\.git/hooks|\.husky)",
        "Git hooks modification",
        "critical",
        ["fs-write-sensitive"],
    ),
    # Encoding/obfuscation in scripts
    (
        r"(?i)base64\.(b64decode|decodebytes)\s*\(",
        "Base64 decoding (potential obfuscation)",
        "medium",
        ["enc-base64"],
    ),
    (
        r"(?i)codecs\.(decode|encode)\s*\(.*rot",
        "ROT encoding (obfuscation)",
        "high",
        ["enc-base64", "instr-conceal"],
    ),
    (
        r"(?i)compile\s*\(.*exec",
        "Dynamic code compilation",
        "high",
        ["proc-code-eval"],
    ),
]

SECRET_PATTERNS: List[Tuple[str, str, str, List[str]]] = [
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical", ["cred-read"]),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "AWS Secret Access Key", "critical", ["cred-read"]),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", "critical", ["cred-read"]),
    (r"ghs_[0-9a-zA-Z]{36}", "GitHub Server Token", "critical", ["cred-read"]),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", "critical", ["cred-read"]),
    (r"github_pat_[0-9a-zA-Z_]{82}", "GitHub Fine-Grained PAT", "critical", ["cred-read"]),
    (r"sk-[0-9a-zA-Z]{20,}T3BlbkFJ[0-9a-zA-Z]{20,}", "OpenAI API Key", "critical", ["cred-read"]),
    (r"sk-ant-api03-[0-9a-zA-Z\-_]{90,}", "Anthropic API Key", "critical", ["cred-read"]),
    (r"xox[bpors]-[0-9a-zA-Z\-]{10,}", "Slack Token", "critical", ["cred-read"]),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key", "critical", ["cred-read"]),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded password", "high", ["cred-read"]),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", "Hardcoded API key", "high", ["cred-read"]),
    (r"(?i)(secret|token)\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", "Hardcoded secret/token", "high", ["cred-read"]),
]

# =============================================================================
# Detection Functions
# =============================================================================


def detect_prompt_injection(content: str, filepath: str) -> Tuple[Set[str], List[Dict]]:
    """Scan content for prompt injection patterns → instruction-level capabilities."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern, description, severity, caps in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, line):
                capabilities.update(caps)
                findings.append(
                    {
                        "type": "Prompt Injection Pattern",
                        "severity": severity,
                        "location": f"{filepath}:{line_num}",
                        "description": description,
                        "evidence": line.strip()[:200],
                        "category": "Prompt Injection",
                        "capabilities_mapped": list(caps),
                    }
                )
                break  # One finding per line

    return capabilities, findings


def detect_obfuscation(content: str, filepath: str) -> Tuple[Set[str], List[Dict]]:
    """Detect obfuscation techniques → encoding + concealment capabilities."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []
    lines = content.split("\n")

    # Zero-width characters
    zwc_pattern = re.compile(r"[​‌‍⁠﻿]")
    for line_num, line in enumerate(lines, 1):
        if zwc_pattern.search(line):
            chars = [f"U+{ord(c):04X}" for c in zwc_pattern.findall(line)]
            capabilities.add("instr-conceal")
            findings.append(
                {
                    "type": "Zero-Width Characters",
                    "severity": "high",
                    "location": f"{filepath}:{line_num}",
                    "description": f"Zero-width characters detected: {', '.join(chars)}",
                    "category": "Obfuscation",
                    "capabilities_mapped": ["instr-conceal"],
                }
            )

    # RTL override
    rtl_pattern = re.compile(r"[‪-‮⁦-⁩]")
    for line_num, line in enumerate(lines, 1):
        if rtl_pattern.search(line):
            capabilities.add("instr-conceal")
            findings.append(
                {
                    "type": "RTL Override",
                    "severity": "high",
                    "location": f"{filepath}:{line_num}",
                    "description": "Right-to-left override or embedding character detected",
                    "category": "Obfuscation",
                    "capabilities_mapped": ["instr-conceal"],
                }
            )

    # Unicode Tag characters (U+E0000 block) — invisible text readable by LLMs
    tag_pattern = re.compile(r"[\U000e0001-\U000e007f]")
    tag_chars = tag_pattern.findall(content)
    if tag_chars:
        decoded = "".join(
            chr(ord(c) - 0xE0000)
            for c in tag_chars
            if 0xE0020 <= ord(c) <= 0xE007E
        )
        capabilities.add("instr-conceal")
        findings.append(
            {
                "type": "Unicode Tag Smuggling",
                "severity": "critical",
                "location": filepath,
                "description": f"Invisible Unicode Tag characters detected ({len(tag_chars)} chars). "
                f"Decoded hidden text: {decoded[:200]}",
                "category": "Obfuscation",
                "capabilities_mapped": ["instr-conceal"],
            }
        )

    # Suspicious base64
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for line_num, line in enumerate(lines, 1):
        for match in b64_pattern.finditer(line):
            try:
                decoded = base64.b64decode(match.group()).decode(
                    "utf-8", errors="ignore"
                )
                suspicious_keywords = [
                    "ignore", "system", "override", "eval", "exec",
                    "password", "secret",
                ]
                for kw in suspicious_keywords:
                    if kw.lower() in decoded.lower():
                        capabilities.add("enc-base64")
                        findings.append(
                            {
                                "type": "Suspicious Base64",
                                "severity": "high",
                                "location": f"{filepath}:{line_num}",
                                "description": f"Base64 string decodes to text containing '{kw}'",
                                "decoded_preview": decoded[:100],
                                "category": "Obfuscation",
                                "capabilities_mapped": ["enc-base64"],
                            }
                        )
                        break
            except Exception:
                pass

    # HTML comments with suspicious content (hidden injection)
    comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
    for match in comment_pattern.finditer(content):
        comment_text = match.group(1)
        for pattern, description, severity, caps in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, comment_text):
                line_num = content[: match.start()].count("\n") + 1
                capabilities.add("instr-conceal")
                capabilities.update(caps)
                findings.append(
                    {
                        "type": "Hidden Injection in Comment",
                        "severity": "critical",
                        "location": f"{filepath}:{line_num}",
                        "description": f"HTML comment contains injection pattern: {description}",
                        "evidence": comment_text.strip()[:200],
                        "category": "Prompt Injection",
                        "capabilities_mapped": ["instr-conceal"] + list(caps),
                    }
                )
                break

    return capabilities, findings


def detect_secrets(content: str, filepath: str) -> Tuple[Set[str], List[Dict]]:
    """Detect hardcoded secrets → credential capabilities."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern, description, severity, caps in SECRET_PATTERNS:
            if re.search(pattern, line):
                capabilities.update(caps)
                findings.append(
                    {
                        "type": "Secret Detected",
                        "severity": severity,
                        "location": f"{filepath}:{line_num}",
                        "description": description,
                        "evidence": line.strip()[:200],
                        "category": "Secret Exposure",
                        "capabilities_mapped": list(caps),
                    }
                )
                break

    return capabilities, findings


def detect_dangerous_scripts(content: str, filepath: str) -> Tuple[Set[str], List[Dict]]:
    """Detect dangerous code patterns in scripts → process/network/filesystem capabilities."""
    capabilities: Set[str] = set()
    findings: List[Dict] = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for pattern, description, severity, caps in DANGEROUS_SCRIPT_PATTERNS:
            if re.search(pattern, line):
                capabilities.update(caps)
                findings.append(
                    {
                        "type": "Dangerous Code Pattern",
                        "severity": severity,
                        "location": f"{filepath}:{line_num}",
                        "description": description,
                        "evidence": line.strip()[:200],
                        "category": "Malicious Code",
                        "capabilities_mapped": list(caps),
                    }
                )
                break

    return capabilities, findings


def extract_urls(content: str, filepath: str) -> List[Dict]:
    """Extract and classify URLs."""
    urls: List[Dict] = []
    url_pattern = re.compile(r"https?://[^\s\)\]\>\"'`]+")
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        for match in url_pattern.finditer(line):
            url = match.group().rstrip(".,;:")
            try:
                domain = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
                domain_parts = domain.split(".")
                root_domain = (
                    ".".join(domain_parts[-2:])
                    if len(domain_parts) >= 2
                    else domain
                )
                trusted = (
                    root_domain in TRUSTED_DOMAINS or domain in TRUSTED_DOMAINS
                )
            except (IndexError, ValueError):
                domain = "unknown"
                trusted = False

            urls.append(
                {
                    "url": url,
                    "domain": domain,
                    "trusted": trusted,
                    "location": f"{filepath}:{line_num}",
                    "context": line.strip()[:200],
                }
            )

    return urls


def detect_structural_attacks(
    skill_dir: Path, content: str, frontmatter: Optional[Dict]
) -> Tuple[Set[str], List[Dict]]:
    """Detect structural attack patterns → instruction-level capabilities.

    Covers: symlinks, frontmatter hooks, !command injection, test file auto-discovery,
    npm lifecycle hooks, PNG image metadata.
    """
    capabilities: Set[str] = set()
    findings: List[Dict] = []

    # 1. Symlinks
    for path in skill_dir.rglob("*"):
        if path.is_symlink():
            target = path.resolve()
            is_internal = target.is_relative_to(skill_dir.resolve())
            capabilities.add("instr-silent-exec")
            findings.append(
                {
                    "type": "Symlink Detected",
                    "severity": "medium" if is_internal else "critical",
                    "location": str(path.relative_to(skill_dir)),
                    "description": f"Symlink points to {path.readlink()} (resolves to {target}). "
                    "Symlinks can trick agents into reading sensitive files "
                    "(e.g., ~/.ssh/id_rsa) disguised as example/reference files.",
                    "category": "Symlink Exfiltration",
                    "capabilities_mapped": ["instr-silent-exec"],
                }
            )

    # 2. Frontmatter hooks
    if frontmatter and "hooks" in frontmatter:
        hooks = frontmatter["hooks"]
        hook_types = hooks.keys() if isinstance(hooks, dict) else []
        for hook_type in hook_types:
            capabilities.add("instr-silent-exec")
            capabilities.add("proc-exec")
            findings.append(
                {
                    "type": "Frontmatter Hooks",
                    "severity": "critical",
                    "location": "SKILL.md frontmatter",
                    "description": f"Skill defines '{hook_type}' hooks. Hooks execute shell commands "
                    "automatically on lifecycle events — the model cannot prevent execution.",
                    "category": "Hook Exploitation",
                    "capabilities_mapped": ["instr-silent-exec", "proc-exec"],
                }
            )

    # 3. !`command` pre-prompt injection
    bang_pattern = re.compile(r"!\`[^`]+\`")
    for line_num, line in enumerate(content.split("\n"), 1):
        for match in bang_pattern.finditer(line):
            cmd = match.group()[2:-1]
            capabilities.add("instr-silent-exec")
            capabilities.add("proc-exec")
            findings.append(
                {
                    "type": "Pre-prompt Command",
                    "severity": "high",
                    "location": f"SKILL.md:{line_num}",
                    "description": f"!`command` syntax executes at skill load time. Command: {cmd}",
                    "evidence": line.strip()[:200],
                    "category": "Pre-prompt Injection",
                    "capabilities_mapped": ["instr-silent-exec", "proc-exec"],
                }
            )

    # 4. Test file auto-discovery
    import fnmatch

    test_patterns = {
        "conftest.py": "pytest auto-imports conftest.py at collection time",
        "test_*.py": "pytest auto-discovers test_*.py files",
        "*_test.py": "pytest auto-discovers *_test.py files",
        "*.test.js": "Jest/Vitest may auto-discover .test.js files",
        "*.test.ts": "Jest/Vitest may auto-discover .test.ts files",
    }
    for path in skill_dir.rglob("*"):
        if not path.is_file():
            continue
        name = path.name
        for pattern, desc in test_patterns.items():
            if fnmatch.fnmatch(name, pattern):
                capabilities.add("instr-silent-exec")
                findings.append(
                    {
                        "type": "Test File Auto-Discovery",
                        "severity": "high",
                        "location": str(path.relative_to(skill_dir)),
                        "description": f"{desc}. Code executes as side effect of running tests.",
                        "category": "Test File RCE",
                        "capabilities_mapped": ["instr-silent-exec"],
                    }
                )

    # 5. npm lifecycle hooks
    for pkg_json in skill_dir.rglob("package.json"):
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError, ValueError):
            continue
        scripts = pkg.get("scripts") or {}
        lifecycle_hooks = [
            "preinstall", "install", "postinstall",
            "preuninstall", "postuninstall",
        ]
        for hook in lifecycle_hooks:
            if hook in scripts:
                capabilities.add("instr-silent-exec")
                capabilities.add("proc-exec")
                findings.append(
                    {
                        "type": "npm Lifecycle Hook",
                        "severity": "critical",
                        "location": str(pkg_json.relative_to(skill_dir)),
                        "description": f"package.json defines '{hook}' script: {scripts[hook]}. "
                        "npm executes lifecycle hooks automatically on install.",
                        "category": "Supply Chain",
                        "capabilities_mapped": ["instr-silent-exec", "proc-exec"],
                    }
                )

    # 6. PNG image metadata
    for img_path in skill_dir.rglob("*.png"):
        try:
            data = img_path.read_bytes()
            if data[:8] != b"\x89PNG\r\n\x1a\n":
                continue
            offset = 8
            while offset + 8 <= len(data):
                chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
                chunk_type = data[offset + 4 : offset + 8]
                chunk_data = data[offset + 8 : offset + 8 + chunk_len]

                keyword = ""
                value = ""
                if chunk_type == b"tEXt":
                    parts = chunk_data.split(b"\x00", 1)
                    if len(parts) > 1:
                        keyword = parts[0].decode("ascii", errors="ignore")
                        value = parts[1][:200].decode("latin-1", errors="ignore")
                elif chunk_type == b"iTXt":
                    parts = chunk_data.split(b"\x00", 4)
                    if len(parts) >= 5:
                        keyword = parts[0].decode("ascii", errors="ignore")
                        value = parts[4][:200].decode("utf-8", errors="ignore")

                if keyword and value.strip():
                    capabilities.add("instr-conceal")
                    findings.append(
                        {
                            "type": "Image Metadata Text",
                            "severity": "high",
                            "location": str(img_path.relative_to(skill_dir)),
                            "description": f"PNG contains text metadata ('{keyword}'): {value[:100]}. "
                            "Hidden instructions in image metadata can be read by multimodal LLMs.",
                            "category": "Image Injection",
                            "capabilities_mapped": ["instr-conceal"],
                        }
                    )

                offset += 4 + 4 + chunk_len + 4
        except (OSError, struct.error):
            continue

    return capabilities, findings


def detect_secrets_from_env_access(content: str, filepath: str) -> Set[str]:
    """Check for environment variable access that targets sensitive keys."""
    caps: Set[str] = set()
    # Bulk access: dict(os.environ), os.environ.items(), etc.
    if re.search(r"(?i)dict\s*\(\s*os\.environ\s*\)", content):
        caps.add("env-access-bulk")
    if re.search(r"(?i)os\.environ\.(items|keys|values)\s*\(", content):
        caps.add("env-access-bulk")

    # Specific access: os.environ['KEY'] or os.environ.get('KEY')
    env_gets = re.findall(r"(?i)os\.environ(?:\.get)?\s*\[?\s*['\"]([^'\"]+)['\"]", content)
    if env_gets:
        caps.add("env-access-specific")
        # Check if any key looks sensitive
        sensitive_keywords = ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"]
        for key in env_gets:
            if any(kw in key.upper() for kw in sensitive_keywords):
                caps.add("env-access-sensitive")
                break

    return caps


# =============================================================================
# Main Entry Point
# =============================================================================


def run_regex_analysis(
    skill_dir: Path,
) -> Tuple[Set[str], List[Dict], List[Dict], List[Dict]]:
    """Run all regex-based detection on a skill directory.

    Returns:
    - A_regex(s): set of capability codes
    - findings: list of finding dicts
    - urls: list of URL dicts
    - url_summary: dict with total, untrusted, trusted_count
    """
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        logger.warning(f"No SKILL.md found in {skill_dir}")
        return set(), [], [], {"total": 0, "untrusted": [], "trusted_count": 0}

    try:
        content = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(f"Cannot read SKILL.md: {e}")
        return set(), [], [], {"total": 0, "untrusted": [], "trusted_count": 0}

    # Parse frontmatter
    fm, body = _parse_frontmatter(content)

    all_capabilities: Set[str] = set()
    all_findings: List[Dict] = []
    all_urls: List[Dict] = []

    # 1. SKILL.md: prompt injection
    caps, findings = detect_prompt_injection(content, "SKILL.md")
    all_capabilities.update(caps)
    all_findings.extend(findings)

    # 2. SKILL.md: obfuscation
    caps, findings = detect_obfuscation(content, "SKILL.md")
    all_capabilities.update(caps)
    all_findings.extend(findings)

    # 3. SKILL.md: secrets
    caps, findings = detect_secrets(content, "SKILL.md")
    all_capabilities.update(caps)
    all_findings.extend(findings)

    # 4. SKILL.md: env access patterns
    all_capabilities.update(detect_secrets_from_env_access(content, "SKILL.md"))

    # 5. SKILL.md: URLs
    all_urls.extend(extract_urls(content, "SKILL.md"))

    # 6. References
    refs_dir = skill_dir / "references"
    if refs_dir.is_dir():
        for ref_file in sorted(refs_dir.iterdir()):
            if ref_file.suffix == ".md":
                try:
                    ref_content = ref_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel_path = f"references/{ref_file.name}"
                caps, findings = detect_prompt_injection(ref_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)
                caps, findings = detect_obfuscation(ref_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)
                caps, findings = detect_secrets(ref_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)
                all_capabilities.update(detect_secrets_from_env_access(ref_content, rel_path))
                all_urls.extend(extract_urls(ref_content, rel_path))

    # 7. Scripts
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.is_dir():
        for script_file in sorted(scripts_dir.iterdir()):
            if script_file.suffix in (".py", ".sh", ".js", ".ts"):
                try:
                    script_content = script_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel_path = f"scripts/{script_file.name}"

                # Dangerous patterns
                caps, findings = detect_dangerous_scripts(script_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)

                # Secrets in scripts
                caps, findings = detect_secrets(script_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)

                # Obfuscation in scripts
                caps, findings = detect_obfuscation(script_content, rel_path)
                all_capabilities.update(caps)
                all_findings.extend(findings)

                # Env access in scripts
                all_capabilities.update(detect_secrets_from_env_access(script_content, rel_path))

                # URLs in scripts
                all_urls.extend(extract_urls(script_content, rel_path))

    # 8. Structural attacks
    caps, findings = detect_structural_attacks(skill_dir, content, fm)
    all_capabilities.update(caps)
    all_findings.extend(findings)

    # URL summary
    untrusted_urls = [u for u in all_urls if not u["trusted"]]
    url_summary = {
        "total": len(all_urls),
        "untrusted": untrusted_urls,
        "untrusted_count": len(untrusted_urls),
        "trusted_count": len(all_urls) - len(untrusted_urls),
    }

    return all_capabilities, all_findings, all_urls, url_summary


def _parse_frontmatter(content: str) -> Tuple[Optional[Dict], str]:
    """Parse YAML frontmatter from SKILL.md content."""
    if not content.startswith("---"):
        return None, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return None, content

    try:
        import yaml

        fm = yaml.safe_load(parts[1])
        body = parts[2]
        return fm if isinstance(fm, dict) else None, body
    except Exception:
        # Fallback: basic parsing
        fm: Dict = {}
        for line in parts[1].split("\n"):
            match = re.match(r"^(\w[\w-]*)\s*:\s*(.*)", line)
            if match:
                key, value = match.groups()
                fm[key] = value.strip().strip('"').strip("'")
        return fm, parts[2]
