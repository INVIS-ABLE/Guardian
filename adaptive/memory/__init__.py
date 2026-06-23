"""Immune memory — five decaying-trust memory classes (directive §21)."""

from .immune import (
    DEFAULT_HALF_LIFE_DAYS,
    ImmuneMemory,
    ImmuneMemoryItem,
    MemoryClass,
)

__all__ = [
    "DEFAULT_HALF_LIFE_DAYS",
    "MemoryClass",
    "ImmuneMemoryItem",
    "ImmuneMemory",
]
