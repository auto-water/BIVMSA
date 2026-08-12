"""
LLM client — OpenAI-compatible interface to the business LLM endpoint.

Wraps the `openai` SDK against any OpenAI-compatible /v1 endpoint
(Qwen3-32B-V1, MiniMax-M2.7, deepseek-v4-flash, etc.).

Provides:
- complete_raw(): single completion, returns text (with optional JSON mode)
- complete_structured(): complete → extract JSON → validate via a validator
  callable → retry on parse/validation failure

This replaces the Claude Code `agent()` calls from biv_workflow.js /
batch_workflow.js with plain HTTP calls to the business endpoint.
"""

import json
import logging
import re
from typing import Callable, Dict, Optional

from .llm_config import LLMConfig, load_llm_config, config_missing_reason

logger = logging.getLogger(__name__)

# A validator takes a parsed JSON dict and returns a result, or None if invalid.
Validator = Callable[[Dict], Optional[Dict]]


class LLMError(Exception):
    """Base LLM error."""


class LLMConfigError(LLMError):
    """Config missing or invalid."""


class LLMValidationError(LLMError):
    """Model output could not be parsed/validated after retries."""


def extract_json(text: str) -> Optional[Dict]:
    """Extract the first JSON object from model output.

    Handles:
    - Raw JSON: {"key": "value"}
    - JSON wrapped in markdown code fences ```json ... ```
    - JSON surrounded by prose/thinking text
    """
    if not text or not isinstance(text, str):
        return None
    t = text.strip()

    # Strip markdown code fences
    fence = re.match(r"```(?:json)?\s*([\s\S]*?)```", t)
    if fence:
        t = fence.group(1).strip()

    # Direct parse first
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass

    # Fall back to first { ... } block
    start = t.find("{")
    end = t.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(t[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


class LLMClient:
    """OpenAI-compatible client for the business LLM endpoint."""

    def __init__(self, cfg: Optional[LLMConfig] = None):
        self.cfg = cfg or load_llm_config()
        reason = config_missing_reason(self.cfg)
        if reason:
            raise LLMConfigError(reason)

        from openai import OpenAI

        self.client = OpenAI(
            base_url=self.cfg.base_url,
            api_key=self.cfg.api_key or "not-needed",  # some local endpoints ignore key
        )
        self.model = self.cfg.model

    # ------------------------------------------------------------------
    # Low-level completion
    # ------------------------------------------------------------------

    def complete_raw(
        self,
        prompt: str,
        *,
        json_mode: bool = True,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Single chat completion, returns the assistant text."""
        kwargs: Dict = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens or self.cfg.max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            resp = self.client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content or ""
        except Exception as e:
            raise LLMError(f"LLM call failed ({self.model}): {e}") from e

    # ------------------------------------------------------------------
    # Structured completion with validation + retry
    # ------------------------------------------------------------------

    def complete_structured(
        self,
        prompt: str,
        validator: Validator,
        *,
        json_mode: bool = True,
        retries: Optional[int] = None,
        **kwargs,
    ) -> Optional[Dict]:
        """Complete → extract JSON → validate → retry on failure.

        validator: callable(parsed_dict) -> result_dict | None
        Returns None if all retries exhausted.
        """
        attempts = retries or self.cfg.max_retries
        last_err = None

        for attempt in range(attempts):
            try:
                text = self.complete_raw(prompt, json_mode=json_mode, **kwargs)
                parsed = extract_json(text)
                if parsed is None:
                    last_err = f"attempt {attempt + 1}: no JSON found in output"
                    logger.warning(f"[LLM] {last_err} (len={len(text)})")
                    continue
                result = validator(parsed)
                if result is not None:
                    return result
                last_err = f"attempt {attempt + 1}: validator rejected output"
                logger.warning(f"[LLM] {last_err}: {json.dumps(parsed, ensure_ascii=False)[:200]}")
            except LLMError as e:
                last_err = str(e)
                logger.warning(f"[LLM] {last_err}")
                continue

        logger.error(f"[LLM] all {attempts} attempts failed: {last_err}")
        return None
