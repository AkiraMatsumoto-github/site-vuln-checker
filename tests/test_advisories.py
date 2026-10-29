"""勧告との突き合わせ（advisories）の受け入れテスト。

索引は ``tests/fixtures/advisories.json``（合成データ）を使う。
実際の取り込み（NVD / OSV）は別コマンドで行い、ここでは**照合と判定**だけを固定する。
"""

from pathlib import Path

import pytest

from site_vuln_checker.advisories import (
    LEVEL_GRAY,
    LEVEL_NONE,
    LEVEL_RED,
    LEVEL_YELLOW,
    AdvisoryIndex,
    compare_versions,
    judge,
    normalize_slug,
    summarize,
)
from site_vuln_checker.detect import Analysis, Finding, analyze

FIXTURES = Path(__file__).parent / "fixtures"


def _index() -> AdvisoryIndex:
    return AdvisoryIndex.load(FIXTURES / "advisories.json")


def _wp_analysis() -> Analysis:
    html = (FIXTURES / "wp_home.html").read_text(encoding="utf-8")
    return analyze("https://example.com/", html, {})


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2", "1.2.0", 0),
        ("5.9.8", "5.9.9", -1),
        ("5.9.10", "5.9.9", 1),
        ("10.0", "9.9.9", 1),
        ("1.0", "1.0-beta", -1),  # 英字を含む版は数値の後ろ
        ("v5.9.9", "5.9.9", 0),  # 先頭の v は無視する
    ],
)
def test_compare_versions(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected


def test_normalize_slug() -> None:
    assert normalize_slug("Contact Form 7") == "contact-form-7"
    assert normalize_slug("contact-form-7") == "contact-form-7"
    assert normalize_slug("WooCommerce / Extra") == "woocommerce-extra"


def test_red_when_kev() -> None:
    judgements = {j.component: j for j in judge(_wp_analysis(), _index())}
    cf7 = judgements["contact-form-7"]
    assert cf7.level == LEVEL_RED, "KEV に載っている勧告があるので赤"
    assert cf7.version == "5.9.8"
    assert cf7.action == "→ 5.9.9 へ更新"
    assert cf7.is_issue is True
    assert cf7.advisories[0].kev is True
    assert cf7.advisories[0].id == "CVE-2025-90001"


def test_not_affected_when_version_is_at_or_after_fix() -> None:
    judgements = {j.component: j for j in judge(_wp_analysis(), _index())}
    elementor = judgements["elementor"]
    assert elementor.level == LEVEL_NONE, "3.21.0 は修正版 3.20.0 以降なので該当しない"
    assert elementor.is_issue is False


def test_yellow_when_cvss_is_below_red() -> None:
    finding = Finding("plugin", "elementor", "3.19.0", 0.85, (), active=True)
    analysis = Analysis(url="https://example.com/", findings=[finding])
    judgements = judge(analysis, _index())
    assert len(judgements) == 1
    assert judgements[0].level == LEVEL_YELLOW
    assert judgements[0].action == "→ 3.20.0 へ更新"


def test_unknown_version_is_gray_not_green() -> None:
    finding = Finding("plugin", "hello-dolly", None, 0.6, ("inline:path",), active=True)
    analysis = Analysis(url="https://example.com/", findings=[finding])
    judgements = judge(analysis, _index())
    assert len(judgements) == 1
    assert judgements[0].level == LEVEL_GRAY
    assert judgements[0].version is None
    assert "1 件の勧告" in judgements[0].note
    assert judgements[0].is_issue is False, "灰は「更新すべきもの」とは別枠"


def test_unknown_version_without_history_is_skipped() -> None:
    finding = Finding("plugin", "no-such-plugin", None, 0.6, (), active=True)
    analysis = Analysis(url="https://example.com/", findings=[finding])
    assert judge(analysis, _index()) == []


def test_order_and_summary() -> None:
    judgements = judge(_wp_analysis(), _index())
    assert [j.component for j in judgements] == ["contact-form-7", "elementor"]
    assert summarize(judgements) == {
        LEVEL_RED: 1,
        LEVEL_YELLOW: 0,
        LEVEL_GRAY: 0,
        LEVEL_NONE: 1,
    }


def test_index_is_serializable() -> None:
    index = _index()
    restored = AdvisoryIndex.from_dict(index.to_dict())
    assert [a.id for a in restored.advisories] == [a.id for a in index.advisories]
    assert restored.lookup("contact-form-7")[0].cvss == 9.8
