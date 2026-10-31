"""拡張（JavaScript）と Python の判定が一致することを確かめる。

同じ索引・同じ検出結果を両方に渡し、``level`` / ``action`` / ``note`` /
該当 CVE が一致することを固定する（片方だけ直して食い違うのを防ぐ）。

Node が無い環境ではスキップする。``NODE_BIN`` で実行ファイルを指定できる。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from site_vuln_checker.advisories import judge
from site_vuln_checker.detect import Analysis, Finding

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "extension" / "tests" / "parity_runner.mjs"
NODE = os.environ.get("NODE_BIN") or shutil.which("node")

TODAY = "2026-10-30T00:00:00Z"

#: 共通の索引（PHP の CVE 2 系統 + EOL、プラグイン 2 件）
INDEX = {
    "generated_at": "2026-10-29T00:00:00Z",
    "advisories": [
        {
            "id": "CVE-2026-109618",
            "name": "PHP",
            "slug": "php",
            "affected_at_or_above": "7.3.0",
            "affected_below": "8.2.35",
            "fixed": "8.2.35",
            "cvss": 9.2,
            "kev": True,
        },
        {
            "id": "CVE-2025-90001",
            "name": "Contact Form 7",
            "slug": "contact-form-7",
            "affected_below": "5.9.9",
            "fixed": "5.9.9",
            "cvss": 9.8,
            "kev": True,
        },
        {
            "id": "CVE-2025-90002",
            "name": "Elementor",
            "slug": "elementor",
            "affected_below": "3.20.0",
            "fixed": "3.20.0",
            "cvss": 6.1,
        },
    ],
    "lifecycles": {
        "products": {
            "php": {
                "name": "PHP",
                "cycles": [
                    {"cycle": "8.5", "eol": "2029-12-31", "latest": "8.5.12"},
                    {"cycle": "8.4", "eol": "2028-12-31", "latest": "8.4.27"},
                    {"cycle": "8.1", "eol": "2025-12-31", "latest": "8.1.34"},
                ],
            }
        }
    },
}

#: 検出結果のケース（Finding の dict）
CASES = [
    [{"kind": "plugin", "name": "contact-form-7", "version": "5.9.8", "confidence": 0.85}],
    [{"kind": "plugin", "name": "elementor", "version": "3.19.0", "confidence": 0.8}],
    [{"kind": "plugin", "name": "elementor", "version": "3.21.0", "confidence": 0.8}],
    [{"kind": "plugin", "name": "elementor", "version": None, "confidence": 0.6}],
    [{"kind": "plugin", "name": "no-such-plugin", "version": None, "confidence": 0.6}],
    # PHP: 脆弱性 + EOL（1 行にまとまる）
    [{"kind": "language", "name": "php", "version": "8.1.27", "confidence": 1}],
    # PHP: 該当なし + 同じ系に新しい版（情報）
    [{"kind": "language", "name": "php", "version": "8.4.20", "confidence": 1}],
]


def _python_results(case: list[dict]) -> list[dict]:
    findings = [
        Finding(
            kind=item["kind"],
            name=item["name"],
            version=item["version"],
            confidence=item.get("confidence", 0.0),
        )
        for item in case
    ]
    analysis = Analysis(url="https://example.com/", findings=findings)
    # lifecycle.check は date を期待する（datetime ではない）
    today = datetime.fromisoformat(TODAY.replace("Z", "+00:00")).astimezone(UTC).date()
    return [
        {
            "component": judgement.component,
            "version": judgement.version,
            "level": judgement.level,
            "action": judgement.action,
            "note": judgement.note,
            "advisories": [a.id for a in judgement.advisories],
        }
        for judgement in judge(analysis, _load_index(), today)
    ]


def _load_index():
    from site_vuln_checker.advisories import AdvisoryIndex

    return AdvisoryIndex.from_dict(INDEX)


@pytest.mark.skipif(NODE is None, reason="Node が無い環境ではスキップ（CI では実行）")
def test_js_and_python_judge_agree() -> None:
    payload = json.dumps({"index": INDEX, "today": TODAY, "cases": CASES})
    completed = subprocess.run(
        [NODE, str(RUNNER)],
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    js_results = json.loads(completed.stdout)

    for index, case in enumerate(CASES):
        assert js_results[index] == _python_results(case), f"ケース {index} で判定が違います"
