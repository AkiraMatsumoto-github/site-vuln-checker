"""勧告との突き合わせ（advisories）の受け入れテスト。

索引は ``tests/fixtures/advisories.json``（合成データ）を使う。
実際の取り込み（NVD / OSV）は別コマンドで行い、ここでは**照合と判定**だけを固定する。
"""

from datetime import date
from pathlib import Path

import pytest

from site_vuln_checker.advisories import (
    LEVEL_GRAY,
    LEVEL_NONE,
    LEVEL_RED,
    LEVEL_YELLOW,
    Advisory,
    AdvisoryIndex,
    compare_versions,
    is_affected,
    judge,
    normalize_slug,
    summarize,
)
from site_vuln_checker.detect import Analysis, Finding, analyze
from site_vuln_checker.eol import Cycle, Lifecycle, LifecycleIndex

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


@pytest.mark.parametrize(
    ("version", "expected"),
    [("1.4.1", True), ("1.4.2", True), ("1.4.3", False), ("2.0", False)],
)
def test_is_affected_upto(version: str, expected: bool) -> None:
    """「X 以下」は境界を含む（NVD の "up to, and including, X"）。"""
    advisory = Advisory(id="CVE-X", name="Example", affected_upto="1.4.2")
    assert is_affected(version, advisory) is expected


def test_affected_upto_is_red_and_reports_unknown_fix() -> None:
    finding = Finding("plugin", "wplp-cookie-consent", "1.4.2", 0.85, (), active=True)
    judgements = judge(Analysis(url="https://example.com/", findings=[finding]), _index())
    assert len(judgements) == 1
    judgement = judgements[0]
    assert judgement.level == LEVEL_RED, "CVSS 9.8 なので赤"
    assert judgement.component == "wplp-cookie-consent"
    assert judgement.action == "修正版不明（ベンダに確認）", "「X 以下」だけでは修正版が分からない"


def test_affected_upto_excludes_later_version() -> None:
    finding = Finding("plugin", "wplp-cookie-consent", "1.4.3", 0.85, (), active=True)
    judgements = judge(Analysis(url="https://example.com/", findings=[finding]), _index())
    assert [j.level for j in judgements] == [LEVEL_NONE]


def test_prefix_match_handles_marketing_names() -> None:
    """CVE 本文の名前は「正式名 - 説明」になりがちなので前方一致で拾う。"""
    index = _index()
    found = index.advisories_for(Finding("plugin", "wplp-cookie-consent", None, 0.6))
    assert [a.id for a in found] == ["CVE-2026-90004"]


def test_short_slug_does_not_prefix_match() -> None:
    """短すぎる slug は前方一致させない（誤爆よけ）。"""
    index = _index()
    assert index.advisories_for(Finding("plugin", "seo", None, 0.6)) == []


def test_load_broken_index_raises_value_error(tmp_path: Path) -> None:
    """壊れた索引はトレースバックではなく案内つきで失敗する（レビュー M7）。"""
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError, match="索引を読めません"):
        AdvisoryIndex.load(bad)


def test_prefix_lookup_scales_to_large_index() -> None:
    """前方一致は索引が大きくても正しく引ける（レビュー M4）。"""
    advisories = [
        Advisory(id=f"CVE-2026-{i:05d}", name=f"Plugin Number {i}", affected_below="9.9.9")
        for i in range(2000)
    ]
    advisories.append(
        Advisory(id="CVE-2026-99999", name="My Calendar - Accessible Event Manager",
                 affected_upto="3.8.7", cvss=9.8)
    )
    index = AdvisoryIndex(advisories=advisories)

    found = index.advisories_for(Finding("plugin", "my-calendar", None, 0.6))
    assert [a.id for a in found] == ["CVE-2026-99999"]
    # 名前の完全一致も拾える
    found_exact = index.advisories_for(Finding("plugin", "plugin-number-10", None, 0.6))
    assert [a.id for a in found_exact] == ["CVE-2026-00010"]


# --- CPE 由来の下限つき範囲（PHP 本体・フレームワーク）-----------------------------


def test_lower_bound_is_respected() -> None:
    """CPE の下限（``7.3.0 以上``）より下の版を「影響あり」としない。"""
    advisory = Advisory(
        id="CVE-2026-109618",
        name="PHP",
        slug="php",
        affected_at_or_above="7.3.0",
        affected_below="8.2.35",
        fixed="8.2.35",
        cvss=9.8,
    )
    assert is_affected("8.1.27", advisory) is True
    assert is_affected("8.2.35", advisory) is False
    assert is_affected("7.2.34", advisory) is False  # 下限より下


def test_php_cve_and_eol_are_merged_into_one_line() -> None:
    """脆弱性（赤）と EOL（黄）が同じ PHP に当たったら 1 行にまとめる。"""
    advisories = [
        Advisory(
            id="CVE-2026-109618",
            name="PHP",
            slug="php",
            affected_at_or_above="7.3.0",
            affected_below="8.2.35",
            fixed="8.2.35",
            cvss=9.8,
        )
    ]
    lifecycles = LifecycleIndex(
        products={
            "php": Lifecycle(
                product="php",
                name="PHP",
                cycles=[
                    Cycle(cycle="8.5", eol="2029-12-31", latest="8.5.12"),
                    Cycle(cycle="8.1", eol="2025-12-31", latest="8.1.34"),
                ],
            )
        }
    )
    index = AdvisoryIndex(advisories=advisories, lifecycles=lifecycles)
    analysis = Analysis(
        url="https://example.com/",
        findings=[Finding("language", "php", "8.1.27", 1.0, ("input:php",))],
    )

    judgements = judge(analysis, index, today=date(2026, 10, 29))
    assert len(judgements) == 1
    merged = judgements[0]
    assert merged.level == LEVEL_RED  # 重い方（脆弱性）を採用
    assert "8.2.35" in merged.action  # 修正版
    assert "8.5.12" in merged.action  # 移行先
    assert "サポート終了" in merged.note
    assert [a.id for a in merged.advisories] == ["CVE-2026-109618"]


def test_core_name_is_not_prefix_matched() -> None:
    """コア名（wordpress）に前方一致を許すと、プラグイン名を拾って誤検知になる。

    実データで ``WordPress User Extra Fields``（プラグイン）が WordPress コアに
    紐づいた例があるため、コア・言語・フレームワークは完全一致のみにする。
    """
    index = AdvisoryIndex(
        advisories=[
            Advisory(
                id="CVE-2025-7846",
                name="WordPress User Extra Fields",
                affected_upto="16.7",
                cvss=8.8,
            )
        ]
    )
    core = Finding("core", "wordpress", "6.2.6", 1.0)
    assert index.advisories_for(core) == []

    plugin = Finding("plugin", "wordpress-user-extra-fields", "16.0", 0.8)
    assert [a.id for a in index.advisories_for(plugin)] == ["CVE-2025-7846"]


def test_same_cve_across_branches_is_shown_once() -> None:
    """同じ CVE が系統ごとに複数レコードあっても、判定では 1 件にまとめる。

    実データでは WordPress コアの CVE が 6.0 / 6.1 / 6.2 / 7.0 … と系統別に
    別レコードになるため、そのまま並べると同じ行が十数個並んで見える。
    """
    advisories = [
        Advisory(
            id="CVE-2026-87902",
            name="WordPress",
            slug="wordpress",
            affected_below=fixed,
            fixed=fixed,
            cvss=8.1,
            kev=True,
        )
        for fixed in ("6.0.9", "6.1.9", "6.2.9", "7.0.5")
    ]
    index = AdvisoryIndex(advisories=advisories)
    analysis = Analysis(url="", findings=[Finding("core", "wordpress", "7.1.4", 1.0)])

    judgements = judge(analysis, index)
    assert len(judgements) == 1
    assert judgements[0].level == LEVEL_NONE
    assert "該当なし" in judgements[0].action
    assert "すべて修正済み" in judgements[0].note
    assert len(judgements[0].advisories) == 1, "同じ CVE は 1 行にまとめる"



def test_eol_only_is_yellow_and_outdated_is_none() -> None:
    """EOL は黄（更新すべき）、同一枝のパッチ遅れは「—」（情報のみ）。"""
    lifecycles = LifecycleIndex(
        products={
            "php": Lifecycle(
                product="php",
                name="PHP",
                cycles=[
                    Cycle(cycle="8.5", eol="2029-12-31", latest="8.5.12"),
                    Cycle(cycle="8.4", eol="2028-12-31", latest="8.4.27"),
                    Cycle(cycle="8.1", eol="2025-12-31", latest="8.1.34"),
                ],
            )
        }
    )
    index = AdvisoryIndex(lifecycles=lifecycles)

    eol_only = judge(
        Analysis(url="", findings=[Finding("language", "php", "8.1.27", 1.0)]),
        index,
        today=date(2026, 10, 29),
    )
    assert [j.level for j in eol_only] == [LEVEL_YELLOW]

    outdated = judge(
        Analysis(url="", findings=[Finding("language", "php", "8.4.20", 1.0)]),
        index,
        today=date(2026, 10, 29),
    )
    assert [j.level for j in outdated] == [LEVEL_NONE]
    assert "8.4.27" in outdated[0].action


def test_plugin_is_not_judged_by_lifecycle() -> None:
    """プラグインは系統（cycle）を持たないので EOL 判定の対象外。"""
    lifecycles = LifecycleIndex(
        products={"php": Lifecycle(product="php", cycles=[Cycle(cycle="8.1", eol="2025-12-31")])}
    )
    index = AdvisoryIndex(lifecycles=lifecycles)
    analysis = Analysis(url="", findings=[Finding("plugin", "php", "8.1.27", 0.8)])
    assert judge(analysis, index, today=date(2026, 10, 29)) == []

