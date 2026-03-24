"""
Project layout: ``tiktok_final/`` (PROJECT_ROOT) with ``ttk/``, ``fixtures/``, ``tests/``, ``docs/``, ``tools/``.
"""
from __future__ import annotations

import os

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_PKG_DIR)
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "fixtures")
# Parent of this repo folder (e.g. sibling ``tik-api-1`` captures)
WORKSPACE_ROOT = os.path.dirname(PROJECT_ROOT)


def resolve_data_path(rel_or_abs: str) -> str:
    """
    Resolve a CLI or config path: absolute unchanged; otherwise try
    ``PROJECT_ROOT / rel``, then ``FIXTURES_DIR / rel``, then ``FIXTURES_DIR / basename``.
    """
    p = (rel_or_abs or "").strip()
    if not p:
        return p
    if os.path.isabs(p):
        return p
    for base in (PROJECT_ROOT, FIXTURES_DIR):
        cand = os.path.join(base, p)
        if os.path.isfile(cand):
            return cand
    bn = os.path.basename(p)
    if bn != p:
        cand = os.path.join(FIXTURES_DIR, bn)
        if os.path.isfile(cand):
            return cand
    return os.path.join(PROJECT_ROOT, p)
