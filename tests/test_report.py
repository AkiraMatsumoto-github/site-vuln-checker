"""レポート描画（report）のテスト。

判定（赤/黄/灰）が HTML に出ること・索引が無いときに空節を出さないことを固定する。
"""

from site_vuln_checker.report import render


def _payload_with_judgement() -> dict:
    return {
        "summary": {
            "sites_tried": 1,
            "sites_fetched": 1,
            "wordpress_rate": 1.0,
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
                        "action": "→ 5.9.9 へ更新",
                        "note": "",
                        "advisories": [{"id": "CVE-2025-90001", "cvss": 9.8, "kev": True}],
                    }
                ],
            }
        ],
    }


def test_render_includes_judgement_section() -> None:
    html_text = render(_payload_with_judgement())
    assert "更新すべきもの（判定）" in html_text
    assert "CVE-2025-90001" in html_text
    assert "KEV" in html_text
    assert "→ 5.9.9 へ更新" in html_text
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
