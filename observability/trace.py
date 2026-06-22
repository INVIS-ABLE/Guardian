"""Trace & correlation IDs across Guardian decisions and workflows (area 12 / observability).

A single security case touches many components — policy decisions, approvals, workflow steps,
containment. To investigate or audit one, you need to stitch those events together. This module
gives every case a **correlation id** and records nested **spans**, propagated through
``contextvars`` so a span opened deep inside a call chain automatically inherits the active
trace and parent without threading an id through every function.

It is dependency-free and in-process. A real OTel exporter can later consume ``Tracer.spans``;
nothing here makes a network call.
"""

from __future__ import annotations

import secrets
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Iterator

# The trace/span currently in scope on this execution context (async-safe, thread-safe).
_current_trace: ContextVar[str | None] = ContextVar("guardian_trace_id", default=None)
_current_span: ContextVar[str | None] = ContextVar("guardian_span_id", default=None)


def new_id(nbytes: int = 8) -> str:
    """A short, unguessable hex id (16 hex chars by default)."""
    return secrets.token_hex(nbytes)


def current_correlation_id() -> str | None:
    """The trace id in scope right now, or None outside any trace."""
    return _current_trace.get()


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: str | None
    attributes: dict[str, object] = field(default_factory=dict)
    start: float = field(default_factory=time.monotonic)
    end: float | None = None
    status: str = "ok"  # "ok" | "error"

    def duration_ms(self) -> float | None:
        if self.end is None:
            return None
        return (self.end - self.start) * 1000.0


@dataclass
class Tracer:
    """Records spans in memory; the active trace/span propagate via contextvars."""

    spans: list[Span] = field(default_factory=list)

    @contextmanager
    def span(self, name: str, **attributes: object) -> Iterator[Span]:
        """Open a span. Inherits the active trace/parent, or starts a new trace if none."""
        trace_id = _current_trace.get() or new_id()
        parent_id = _current_span.get()
        span = Span(
            name=name,
            trace_id=trace_id,
            span_id=new_id(),
            parent_id=parent_id,
            attributes=dict(attributes),
        )
        self.spans.append(span)
        trace_tok = _current_trace.set(trace_id)
        span_tok = _current_span.set(span.span_id)
        try:
            yield span
        except Exception:
            span.status = "error"
            raise
        finally:
            span.end = time.monotonic()
            _current_span.reset(span_tok)
            _current_trace.reset(trace_tok)

    def spans_for(self, trace_id: str) -> list[Span]:
        return [s for s in self.spans if s.trace_id == trace_id]
