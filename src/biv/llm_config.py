"""LLM configuration — loads .env for the business LLM endpoint.

Reads OpenAI-compatible endpoint config from environment variables:
- LLM_BASE_URL: e.g. http://<host>:<port>/v1
- LLM_API_KEY
- LLM_MODEL
- LLM_MAX_TOKENS
- LLM_MAX_RETRIES
"""

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    _ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"
    load_dotenv(_ENV_PATH)
except ImportError:
    # python-dotenv not installed — rely on actual environment variables
    pass


@dataclass
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    max_tokens: int = 8192
    max_retries: int = 3


def load_llm_config() -> LLMConfig:
    """Load LLM config from environment (with .env fallback)."""
    base_url = os.getenv("LLM_BASE_URL", "").strip()
    api_key = os.getenv("LLM_API_KEY", "").strip()
    model = os.getenv("LLM_MODEL", "").strip() or "deepseek-v4-flash"

    try:
        max_tokens = int(os.getenv("LLM_MAX_TOKENS", "8192"))
    except ValueError:
        max_tokens = 8192
    try:
        max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    except ValueError:
        max_retries = 3

    return LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        max_tokens=max_tokens,
        max_retries=max_retries,
    )


def config_missing_reason(cfg: LLMConfig) -> str | None:
    """Return a human-readable message if the config is not usable, else None."""
    if not cfg.base_url:
        return "LLM_BASE_URL 未设置 — 请在 .env 中填写业务 LLM 接口地址 (如 http://<host>:<port>/v1)"
    if not cfg.api_key:
        return "LLM_API_KEY 未设置 — 请在 .env 中填写业务 LLM 接口 API Key"
    if not cfg.model:
        return "LLM_MODEL 未设置"
    return None
