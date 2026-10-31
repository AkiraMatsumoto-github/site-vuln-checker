"""レポート描画（report）のテスト。

判定（赤/黄/不明）が HTML に出ること・索引が無いときに空節を出さないことを固定する。
"""

from site_vuln_checker.report import render


def _payload_with_judgement() -> dict:
    return {
        "summary": {
            "sites_tried": 1,
            "sites_fetched": 1,
            "wordpress_rate": 1.0,
            "advisories_applied": True,
            "levels": {"red": 1, "yellow": 0, "gray": 0, "none": 0},
        },
        "sites": [
            {
                "url": "https://example.com/",
                "ok": True,
                "status": 200,
                "elapsed_ms": 120,
                "analysis": {
                    "findings": [
                        {
                            "kind": "plugin",
                            "name": "contact-form-7",
                            "version": "5.9.8",
                            "confidence": 0.85,
                            "evidence": ["asset:?ver=5.9.8"],
                            "active": True,
                        }
                    ],
                    "notes": [],
                },
                "judgements": [
                    {
                        "component": "contact-form-7",
                        "version": "5.9.8",
                        "level": "red",
                        "action": "修正版 5.9.9 に更新してください",
                        "note": "",
                        "advisories": [
                            {"id": "CVE-2025-90001", "cvss": 9.8, "kev": True, "epss": 0.42}
                        ],
                    }
                ],
            }
        ],
    }


def test_render_includes_judgement_section() -> None:
    html_text = render(_payload_with_judgement())
    assert "更新すべきもの（判定）" in html_text
    assert "CVE-2025-90001" in html_text
    assert "実際に悪用あり" in html_text
    assert "悪用の可能性 42%" in html_text
    assert "修正版 5.9.9 に更新してください" in html_text
    assert "赤（要対応）" in html_text


def test_render_without_judgements_has_no_section() -> None:
    payload = {
        "summary": {"sites_tried": 1, "sites_fetched": 1},
        "sites": [
            {
                "url": "https://example.com/",
                "ok": True,
                "status": 200,
                "elapsed_ms": 10,
                "analysis": {"findings": [], "notes": ["プラットフォームを判定できませんでした"]},
            }
        ],
    }
    html_text = render(payload)
    assert "更新すべきもの（判定）" not in html_text
    assert "プラットフォームを判定できませんでした" in html_text


def test_render_escapes_values() -> None:
    payload = {
        "summary": {},
        "sites": [
            {
                "url": "https://example.com/",
                "ok": False,
                "error": "<script>alert(1)</script>",
            }
        ],
    }
    html_text = render(payload)
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;" in html_text


def test_render_warns_when_advisories_not_applied() -> None:
    """索引を渡していないのに「赤 0」と表示しない（レビュー H2）。"""
    payload = {
        "summary": {"sites_tried": 1, "sites_fetched": 1},
        "sites": [
            {
                "url": "https://example.com/",
                "ok": True,
                "status": 200,
                "elapsed_ms": 10,
                "analysis": {"findings": [], "notes": []},
            }
        ],
    }
    html_text = render(payload)
    assert "脆弱性の判定はしていません" in html_text
    assert "赤 0 は「問題なし」ではありません" in html_text
    assert "赤（要対応）" not in html_text
    assert "赤（未判定）" in html_text
