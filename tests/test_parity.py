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
from site_vuln_checker.detect import (
    ANALYTICS_TAG_HOSTS,
    CDN_SERVER_NAMES,
    CDN_SIGNATURES,
    IMAGE_CDN_HOSTS,
    SECURITY_HEADERS,
    SHOPIFY_APP_DOMAINS,
    Analysis,
    Finding,
    analyze,
)

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
            "id": "CVE-2026-109618",
            "name": "PHP",
            "slug": "php",
            "affected_at_or_above": "7.4.0",
            "affected_below": "8.1.30",
            "fixed": "8.1.30",
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
            version_confidence=item.get("confidence", 0.0),
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
            "advisories": [
                {"id": advisory.id, "ranges": list(advisory.ranges)}
                for advisory in judgement.advisories
            ],
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
    cases = js_results["cases"]

    for index, case in enumerate(CASES):
        assert cases[index] == _python_results(case), f"ケース {index} で判定が違います"


@pytest.mark.skipif(NODE is None, reason="Node が無い環境ではスキップ（CI では実行）")
def test_shopify_app_dictionary_is_identical() -> None:
    """Shopify アプリの辞書が Python と JavaScript で**同じ内容・同じ順**か。

    片方だけ足すと「拡張では出るのに CLI では出ない」が起きるため、辞書そのものを
    突き合わせる（レビュー #14）。
    """
    completed = subprocess.run(
        [NODE, str(RUNNER)],
        input=json.dumps({"index": INDEX, "today": TODAY, "cases": []}),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    js_domains = [tuple(pair) for pair in json.loads(completed.stdout)["shopifyDomains"]]
    assert js_domains == list(SHOPIFY_APP_DOMAINS)
    assert len(js_domains) >= 50

#: 1.1.0 で追加した検出の突き合わせ用ケース（拡張と Python で同じ結果になること）
DETECT_CASE = {
    "url": "https://example.com/",
    "html": (
        "<html><head>"
        '<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>'
        '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
        "</head><body>"
        '<img src="https://i0.wp.com/example.com/a.png">'
        "</body></html>"
    ),
    "resources": [
        "https://www.googletagmanager.com/gtag/js?id=G-XXXX",
        "https://connect.facebook.net/en_US/fbevents.js",
        "https://i0.wp.com/example.com/a.png",
    ],
    "headers": {
        "cf-ray": "8f2b1c3d4e5f-NRT",
        "server": "cloudflare",
        "strict-transport-security": "max-age=60",
    },
}


def _run_runner(payload: dict) -> dict:
    completed = subprocess.run(
        [NODE, str(RUNNER)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(completed.stdout)


@pytest.mark.skipif(NODE is None, reason="Node が無い環境ではスキップ（CI では実行）")
def test_new_dictionaries_are_identical() -> None:
    """CDN / セキュリティ / タグ / 画像配信の辞書が Python と**同じ内容・同じ順**か。"""
    dictionaries = _run_runner({"index": INDEX, "today": TODAY, "cases": []})["dictionaries"]

    assert [[name, list(needles)] for name, needles in dictionaries["cdnSignatures"]] == [
        [name, list(needles)] for name, needles in CDN_SIGNATURES
    ]
    assert [tuple(pair) for pair in dictionaries["cdnServerNames"]] == list(CDN_SERVER_NAMES)
    assert [tuple(pair) for pair in dictionaries["securityHeaders"]] == list(SECURITY_HEADERS)
    assert [tuple(pair) for pair in dictionaries["analyticsTagHosts"]] == list(ANALYTICS_TAG_HOSTS)
    assert [tuple(pair) for pair in dictionaries["imageCdnHosts"]] == list(IMAGE_CDN_HOSTS)


@pytest.mark.skipif(NODE is None, reason="Node が無い環境ではスキップ（CI では実行）")
def test_new_detections_agree() -> None:
    """CDN・セキュリティ・タグ・画像配信の検出結果が拡張と Python で一致するか。"""
    detected = _run_runner(
        {"index": INDEX, "today": TODAY, "cases": [], "detect": DETECT_CASE}
    )["detected"]
    js = [(item["kind"], item["name"]) for item in detected]

    analysis = analyze(DETECT_CASE["url"], DETECT_CASE["html"], DETECT_CASE["headers"])
    kinds = ("cdn", "security", "tag", "image")
    python = [(f.kind, f.name) for f in analysis.findings if f.kind in kinds]

    assert js == python
    assert js, "ケースが空（検出できていない）"
