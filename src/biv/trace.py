"""
Structured tracing module for BIV pipeline debugging.

Provides TraceContext — a thread-safe recorder that captures:
- Phase transitions and timestamps
- Step-level inputs, outputs, and intermediate data
- Warnings and errors with context
- Duration measurements

Usage:
    from biv.trace import TraceContext

    trace = TraceContext(skill_name="my-skill")
    trace.phase("extract")
    trace.step("deterministic_parse", input_data={"frontmatter": ...}, output_data={"D": [...]})
    trace.warn("Low description-body overlap", data={"overlap": 0.1})
    trace.finalize(verdict="malware", confidence=0.95)
    print(trace.to_json())
"""

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TraceRecord:
    """A single trace entry."""

    timestamp: str
    phase: str
    step: str
    level: str  # "INFO", "WARN", "ERROR", "PHASE", "METRIC"
    message: str
    data: Optional[Dict[str, Any]] = None
    duration_ms: Optional[float] = None


@dataclass
class PhaseInfo:
    """Metadata about a pipeline phase."""

    name: str
    start_time: str
    end_time: Optional[str] = None
    step_count: int = 0
    error_count: int = 0
    warn_count: int = 0


class TraceContext:
    """Thread-safe trace recorder for BIV pipeline execution.

    Tracks phases, steps, warnings, errors, and metrics throughout
    the pipeline, then produces structured JSON output for debugging.
    """

    def __init__(self, skill_name: str = "unknown", skill_dir: str = ""):
        self.skill_name = skill_name
        self.skill_dir = skill_dir
        self.start_time = time.time()
        self.records: List[TraceRecord] = []
        self.phases: Dict[str, PhaseInfo] = {}
        self._current_phase: str = "init"
        self._lock = threading.Lock()

        # Initial bootstrap record
        self._add(
            phase="init",
            step="bootstrap",
            level="INFO",
            message=f"Trace started for skill: {skill_name}",
            data={"skill_dir": skill_dir},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def phase(self, name: str) -> None:
        """Begin a new pipeline phase."""
        with self._lock:
            self._current_phase = name
            if name not in self.phases:
                self.phases[name] = PhaseInfo(
                    name=name,
                    start_time=self._now_iso(),
                )
        self._add(
            phase=name,
            step="phase_enter",
            level="PHASE",
            message=f"Entering phase: {name}",
        )

    def step(
        self,
        name: str,
        *,
        message: str = "",
        input_data: Optional[Dict] = None,
        output_data: Optional[Dict] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Record a pipeline step with optional I/O data."""
        with self._lock:
            phase_info = self.phases.get(self._current_phase)
            if phase_info:
                phase_info.step_count += 1

        data = {}
        if input_data is not None:
            data["input"] = self._truncate_data(input_data)
        if output_data is not None:
            data["output"] = self._truncate_data(output_data)

        self._add(
            phase=self._current_phase,
            step=name,
            level="INFO",
            message=message or f"Step: {name}",
            data=data if data else None,
            duration_ms=duration_ms,
        )

    def warn(self, message: str, *, data: Optional[Dict] = None) -> None:
        """Record a warning."""
        with self._lock:
            phase_info = self.phases.get(self._current_phase)
            if phase_info:
                phase_info.warn_count += 1
        self._add(
            phase=self._current_phase,
            step="warning",
            level="WARN",
            message=message,
            data=data,
        )

    def error(self, message: str, *, data: Optional[Dict] = None) -> None:
        """Record an error."""
        with self._lock:
            phase_info = self.phases.get(self._current_phase)
            if phase_info:
                phase_info.error_count += 1
        self._add(
            phase=self._current_phase,
            step="error",
            level="ERROR",
            message=message,
            data=data,
        )

    def metric(self, name: str, value: Any, *, message: str = "") -> None:
        """Record a named metric."""
        self._add(
            phase=self._current_phase,
            step=f"metric:{name}",
            level="METRIC",
            message=message or f"Metric {name} = {value}",
            data={"metric_name": name, "metric_value": value},
        )

    def finalize(self, verdict: str, confidence: float) -> None:
        """Mark pipeline as complete with final verdict."""
        total_duration = (time.time() - self.start_time) * 1000
        self._add(
            phase=self._current_phase,
            step="finalize",
            level="INFO",
            message=f"Pipeline complete. Verdict: {verdict}, confidence: {confidence:.4f}",
            data={"verdict": verdict, "confidence": confidence},
            duration_ms=total_duration,
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Export full trace as a dict."""
        with self._lock:
            # Finalize phase durations
            phase_summaries = {}
            for name, info in self.phases.items():
                # Count records in this phase
                phase_records = [r for r in self.records if r.phase == name]
                phase_summaries[name] = {
                    "name": info.name,
                    "start_time": info.start_time,
                    "step_count": info.step_count,
                    "error_count": info.error_count,
                    "warn_count": info.warn_count,
                    "record_count": len(phase_records),
                }

            total_duration_ms = (time.time() - self.start_time) * 1000

            return {
                "skill_name": self.skill_name,
                "skill_dir": self.skill_dir,
                "start_time": datetime.fromtimestamp(
                    self.start_time, tz=timezone.utc
                ).isoformat(),
                "total_duration_ms": round(total_duration_ms, 1),
                "phases": phase_summaries,
                "total_records": len(self.records),
                "records": [self._record_to_dict(r) for r in self.records],
            }

    def to_json(self, indent: int = 2) -> str:
        """Export full trace as JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    def summary(self) -> str:
        """Return a human-readable summary of the trace."""
        lines = [
            f"Trace: {self.skill_name}",
            f"Total duration: {(time.time() - self.start_time) * 1000:.0f}ms",
            f"Phases: {len(self.phases)}",
            f"Records: {len(self.records)}",
        ]
        for name, info in self.phases.items():
            lines.append(
                f"  Phase [{name}]: {info.step_count} steps, "
                f"{info.warn_count} warnings, {info.error_count} errors"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _add(
        self,
        *,
        phase: str,
        step: str,
        level: str,
        message: str,
        data: Optional[Dict] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        record = TraceRecord(
            timestamp=self._now_iso(),
            phase=phase,
            step=step,
            level=level,
            message=message,
            data=data,
            duration_ms=duration_ms,
        )
        with self._lock:
            self.records.append(record)

    def _record_to_dict(self, r: TraceRecord) -> Dict:
        d = {
            "timestamp": r.timestamp,
            "phase": r.phase,
            "step": r.step,
            "level": r.level,
            "message": r.message,
        }
        if r.data:
            d["data"] = r.data
        if r.duration_ms is not None:
            d["duration_ms"] = r.duration_ms
        return d

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _truncate_data(data: Dict, max_str_len: int = 500, max_items: int = 20) -> Dict:
        """Truncate large data structures for trace readability."""
        result = {}
        for i, (k, v) in enumerate(data.items()):
            if i >= max_items:
                result["_truncated"] = f"... {len(data) - max_items} more keys"
                break
            if isinstance(v, str) and len(v) > max_str_len:
                result[k] = v[:max_str_len] + f"... [{len(v)} chars total]"
            elif isinstance(v, (list, set, tuple)):
                if len(v) > max_items:
                    result[k] = list(v)[:max_items] + [f"... {len(v) - max_items} more"]
                else:
                    result[k] = list(v)
            elif isinstance(v, dict):
                result[k] = TraceContext._truncate_data(v, max_str_len, max_items)
            else:
                result[k] = v
        return result
