"""バージョン文字列の比較（勧告とライフサイクルの両方で使う）。

``1.2`` / ``1.2.0`` / ``5.9.9.1`` を数値として比べる。厳密な semver ではなく、
WordPress プラグインや PHP の版表記を扱うための割り切り（README の制限参照）。
"""

from __future__ import annotations

import re

_SEGMENT_RE = re.compile(r"\d+|[A-Za-z]+")


def version_key(version: str) -> tuple[tuple[int, object], ...]:
    """比較用のキー。英字を含む版（``1.2-beta``）は数値より後ろに置く。"""
    parts = _SEGMENT_RE.findall(version.strip().lstrip("vV"))
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts)


def compare_versions(left: str, right: str) -> int:
    """``left`` と ``right`` を比べる（-1 / 0 / 1）。``1.2`` と ``1.2.0`` は等しい。"""
    a, b = version_key(left), version_key(right)
    width = max(len(a), len(b))
    pad = (0, 0)
    a = a + (pad,) * (width - len(a))
    b = b + (pad,) * (width - len(b))
    return (a > b) - (a < b)
