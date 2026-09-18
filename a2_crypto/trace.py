"""
trace.py - the step recorder that makes the pipeline visible.

Every stage of protect()/verify() appends a TraceStep. The debug GUI renders
these; person 6's evidence scripts consume the JSON export rather than
screenshotting a GUI by hand.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class TraceStep:
    stage: str                  # "hash" | "payload" | "sign" | "derive_start" | ...
    label: str                  # human-readable one-liner
    detail: dict                # structured values (ints, short strings)
    blob: bytes | None = None   # optional binary, rendered as a truncated hex dump
    ok: bool = True
    ms: float = 0.0

    def to_dict(self, blob_preview_bytes: int = 128) -> dict:
        out = {
            "stage": self.stage,
            "label": self.label,
            "detail": _jsonable(self.detail),
            "ok": self.ok,
            "ms": round(self.ms, 3),
        }
        if self.blob is not None:
            out["blob_len"] = len(self.blob)
            out["blob_hex"] = self.blob[:blob_preview_bytes].hex()
            out["blob_truncated"] = len(self.blob) > blob_preview_bytes
        return out


class Trace:
    """Collects TraceSteps. No global state - one Trace per pipeline run."""

    def __init__(self, name: str = "run"):
        self.name = name
        self.steps: list[TraceStep] = []
        self._t0 = time.perf_counter()

    # -- recording ----------------------------------------------------------
    def add(self, stage: str, label: str, detail: dict | None = None,
            blob: bytes | None = None, ok: bool = True) -> TraceStep:
        now = time.perf_counter()
        step = TraceStep(
            stage=stage,
            label=label,
            detail=detail or {},
            blob=blob,
            ok=ok,
            ms=(now - self._t0) * 1000.0,
        )
        self._t0 = now
        self.steps.append(step)
        return step

    def fail(self, stage: str, label: str, detail: dict | None = None) -> TraceStep:
        return self.add(stage, label, detail, ok=False)

    # -- export -------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "total_ms": round(sum(s.ms for s in self.steps), 3),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)


class NullTrace(Trace):
    """Drop-in that records nothing - used when a caller passes trace=None."""

    def add(self, stage, label, detail=None, blob=None, ok=True):
        return TraceStep(stage, label, detail or {}, blob, ok, 0.0)


def hexdump(data: bytes, limit: int = 128, width: int = 16) -> str:
    """Classic offset/hex/ascii dump, truncated. Used by the GUI's blob pane."""
    if not data:
        return "(empty)"
    view = data[:limit]
    lines = []
    for off in range(0, len(view), width):
        chunk = view[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes")
    return "\n".join(lines)


def _jsonable(obj: Any) -> Any:
    """Coerce detail dicts into something json.dumps will accept."""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)
