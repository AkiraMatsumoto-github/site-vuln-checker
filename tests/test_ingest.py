"""NVD 本文の解析（ingest）のテスト。

**ネットワークは使わない**。実際の NVD で観測された言い回しを固定する。
"""

from datetime import UTC, datetime, timedelta

import pytest

from site_vuln_checker.ingest import (
    FULL_START,
    _params,
    _windows,
    build_index,
    cpe_product,
    cpe_version,
    extract_cvss,
    extract_name,
    extract_names,
    extract_range,
    is_plausible_name,
    merge_index,
    parse_cpe_cve,
    parse_cve,
    parse_cves,
    published_at,
    summarize,
)

# 実際の NVD で見られた形（名前とバージョンの書き方が違う）
DESC_BEFORE = (
    "The Contact Form by Supsystic WordPress plugin before 1.11.1 does not strip CR/LF characters."
)
DESC_AND_EARLIER = (
    "Directory traversal vulnerability in wp-db-backup.php in the Skippy WP-DB-Backup plugin "
    "for WordPress 1.7 and earlier allows remote authenticated users to read arbitrary files."
)
DESC_UPTO_INCLUDING = (
    "The Frontend Admin by DynamiApps plugin for WordPress is vulnerable to Stored Cross-Site "
    "Scripting in all versions up to, and including, 3.29.11 due to insufficient input sanitizing."
)
DESC_NO_VERSION = "The Example plugin for WordPress is vulnerable to an unknown issue."
# 別製品（WordPress コア）のバージョンが先に出てくる形。プラグインの範囲は「1.2 以下」。
DESC_OTHER_PRODUCT = (
    "WordPress before 6.0.1 allows X, and the Foo Bar plugin for WordPress 1.2 and earlier "
    "is also affected."
)
# 修正版が書かれている形（レビュー M5）
DESC_FIXED_IN = "The Foo plugin for WordPress is vulnerable to X. This is fixed in 2.0.0."
# 1 つの CVE が複数プラグインを列挙する形（レビュー M6）
DESC_MULTI = (
    "The Foo plugin for WordPress, the Bar plugin for WordPress and the Baz plugin are "
    "vulnerable before 3.1."
)


def test_extract_name() -> None:
    assert extract_name(DESC_BEFORE) == "Contact Form by Supsystic"
    assert extract_name(DESC_UPTO_INCLUDING) == "Frontend Admin by DynamiApps"
    assert extract_name("No plugin mentioned here.") is None


def test_extract_range_before() -> None:
    assert extract_range(DESC_BEFORE) == ("1.11.1", None)


def test_extract_range_and_earlier() -> None:
    assert extract_range(DESC_AND_EARLIER) == (None, "1.7")


def test_extract_range_upto_including() -> None:
    assert extract_range(DESC_UPTO_INCLUDING) == (None, "3.29.11")


def test_extract_range_without_version() -> None:
    assert extract_range(DESC_NO_VERSION) == (None, None)


def test_extract_range_ignores_other_product_version() -> None:
    """別製品（WordPress コア）の `before 6.0.1` を拾わない（誤検知の源）。"""
    assert extract_range(DESC_OTHER_PRODUCT) == (None, "1.2")


def test_extract_range_without_plugin_mention_is_none() -> None:
    assert extract_range("WordPress before 6.0.1 allows X.") == (None, None)


def test_extract_range_fixed_in() -> None:
    """「fixed in X」は「X 未満が影響」として扱う（レビュー M5）。"""
    assert extract_range(DESC_FIXED_IN) == ("2.0.0", None)


def test_parse_cves_multiple_plugins() -> None:
    """1 つの CVE が複数プラグインを列挙していれば、すべて拾う（レビュー M6）。"""
    advisories, reason = parse_cves(_item(DESC_MULTI, "CVE-2026-0009"))
    assert reason == "ok"
    assert [a.name for a in advisories] == ["Foo", "Bar", "Baz"]
    assert {a.affected_below for a in advisories} == {"3.1"}
    assert {a.id for a in advisories} == {"CVE-2026-0009"}


@pytest.mark.parametrize(
    "name",
    [
        "WP Photo Album Plus",
        "Contact Form by Supsystic",
        "WPLP Cookie Consent - Cookie Banner & Consent Management",
        "Elementor",
        # 長い正規名（, を含む。60 文字超）
        "Tourfic - AI Powered Travel Booking, Hotel Booking & Car Rental",
        # 小文字始まりの正規名
        "wpDiscuz",
    ],
)
def test_plausible_names_are_accepted(name: str) -> None:
    assert is_plausible_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "`value` parameter of the `update-photo` action in the",  # 実データで出た断片
        "'action (also function",  # 実データで出た断片（記号始まり）
        "customer role is freely self-registerable without admin approval, expl",  # 断片
        "plugin not properly verifying that a user is authorized to perform an",  # 断片
        "site. If a POP chain is present via an additional",  # 断片
        "reported behaviour was determined not to be a vulnerability: the Shop",  # 入れ子 the
        "plugin that allows",  # 途中で切れている
        "",  # 空
    ],
)
def test_implausible_names_are_rejected(name: str) -> None:
    assert is_plausible_name(name) is False


def test_extract_names_skips_fragments() -> None:
    """本文の別の "the ... plugin" を名前として採用しない（実データで発生した不具合）。"""
    description = (
        "The WP Photo Album Plus plugin for WordPress is vulnerable to privilege escalation "
        "via the `value` parameter of the `update-photo` action in the plugin."
    )
    assert extract_names(description) == ["WP Photo Album Plus"]


def test_build_index_keeps_multiple_plugins_per_cve() -> None:
    items = [_item(DESC_MULTI, "CVE-2026-0009")]
    index = build_index(items)
    assert [a.name for a in index.advisories] == ["Foo", "Bar", "Baz"]
    assert summarize(items) == {"total": 1, "kept": 1, "skipped": 0, "advisories": 3}


def test_params_without_window_has_no_dates() -> None:
    """期間を指定しなければ日付パラメータを付けない。"""
    assert set(_params("WordPress plugin")) == {"keywordSearch"}

    start = datetime(2026, 10, 16, tzinfo=UTC)
    end = datetime(2026, 10, 30, tzinfo=UTC)
    params = _params("WordPress plugin", start, end)
    assert params["pubStartDate"] == "2026-10-16T00:00:00.000"
    assert params["pubEndDate"] == "2026-10-30T00:00:00.000"


def test_windows_are_split_into_120_days() -> None:
    """NVD の期間指定は 120 日まで。長い期間は分割する。"""
    end = datetime(2026, 10, 30, tzinfo=UTC)
    windows = _windows(365, end)
    assert len(windows) == 4
    assert windows[0][1] - windows[0][0] == timedelta(days=120)
    assert windows[-1][1] == end

    # 全期間（--days なし）は FULL_START から
    assert _windows(None, end)[0][0] == FULL_START


def test_merge_index_dedupes_by_cve_and_name() -> None:
    """期間を分けて取った索引を積み上げるとき、重複を除いて足せる。"""
    base = build_index([_item(DESC_BEFORE, "CVE-2026-0001")])
    extra = build_index(
        [_item(DESC_BEFORE, "CVE-2026-0001"), _item(DESC_MULTI, "CVE-2026-0009")],
        generated_at="2026-10-30T00:00:00+00:00",
    )
    merged = merge_index(base, extra)
    # 0001 は base と extra で重複するので 1 件。0009 は 3 プラグインぶん残る
    assert [a.id for a in merged.advisories] == [
        "CVE-2026-0001",
        "CVE-2026-0009",
        "CVE-2026-0009",
        "CVE-2026-0009",
    ]
    assert [a.name for a in merged.advisories] == [
        "Contact Form by Supsystic",
        "Foo",
        "Bar",
        "Baz",
    ]
    assert merged.generated_at == "2026-10-30T00:00:00+00:00"


def test_extract_cvss_prefers_newer_standard() -> None:
    cve = {
        "metrics": {
            "cvssMetricV2": [{"cvssData": {"baseScore": 4.3}}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
        }
    }
    assert extract_cvss(cve) == 9.8
    assert extract_cvss({}) is None


def _item(description: str, cve_id: str = "CVE-2026-0001", score: float | None = 9.8) -> dict:
    cve: dict = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}],
    }
    if score is not None:
        cve["metrics"] = {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}
    return {"cve": cve}


def test_parse_cve_variants() -> None:
    before, reason = parse_cve(_item(DESC_BEFORE))
    assert reason == "ok"
    assert before is not None
    assert (before.affected_below, before.affected_upto) == ("1.11.1", None)
    assert before.fixed == "1.11.1", "before X の X は修正版として使える"
    assert before.cvss == 9.8
    assert before.source == "nvd"

    upto, _ = parse_cve(_item(DESC_UPTO_INCLUDING))
    assert upto is not None
    assert (upto.affected_below, upto.affected_upto) == (None, "3.29.11")
    assert upto.fixed is None, "「X 以下」からは修正版を決めない"


def test_parse_cve_rejects_unknown() -> None:
    advisory, reason = parse_cve(_item(DESC_NO_VERSION))
    assert advisory is None
    assert reason == "影響バージョンを特定できない"


def test_build_index_dedupes() -> None:
    items = [
        _item(DESC_BEFORE, "CVE-2026-0001"),
        _item(DESC_BEFORE, "CVE-2026-0001"),
        _item(DESC_UPTO_INCLUDING, "CVE-2026-0002"),
        _item(DESC_NO_VERSION, "CVE-2026-0003"),
    ]
    index = build_index(items, generated_at="2026-10-29T00:00:00+00:00")
    assert [a.id for a in index.advisories] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert index.generated_at == "2026-10-29T00:00:00+00:00"

    stats = summarize(items)
    assert stats["total"] == 4
    assert stats["kept"] == 2, "索引の件数と一致する"
    assert stats["skipped"] == 2, "重複 1 件 + 版が特定できない 1 件"
    assert stats["advisories"] == 2
    assert stats["重複"] == 1
    assert stats["影響バージョンを特定できない"] == 1


# --- CPE（PHP 本体・フレームワーク）-------------------------------------------------


def test_cpe_product_and_version() -> None:
    assert cpe_product("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*") == "php"
    assert cpe_product("cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*") == "wordpress"
    assert cpe_product("cpe:2.3:a:sensiolabs:symfony:*:*:*:*:*:*:*:*") == "symfony"
    assert cpe_product("cpe:2.3:a:somevendor:other:*:*:*:*:*:*:*:*") is None
    # 版が固定されていない CPE は None
    assert cpe_version("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*") is None
    assert cpe_version("cpe:2.3:a:php:php:8.1.27:*:*:*:*:*:*:*") == "8.1.27"


def php_cve_item() -> dict:
    """実際の NVD（CVE-2026-109618）の構造を縮めたもの。系統ごとに範囲が 4 つある。"""
    ranges = [
        ("7.3.0", "8.2.35"),
        ("8.3.0", "8.3.36"),
        ("8.4.0", "8.4.27"),
        ("8.5.0", "8.5.12"),
    ]
    return {
        "cve": {
            "id": "CVE-2026-109618",
            "published": "2026-10-21T14:17:09.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": start,
                                    "versionEndExcluding": end,
                                }
                                for start, end in ranges
                            ]
                        }
                    ]
                }
            ],
        }
    }


def test_parse_cpe_cve_keeps_each_branch() -> None:
    """同じ CVE でも系統ごとに修正版が違うので、4 件すべて残す。"""
    advisories, reason = parse_cpe_cve(php_cve_item())
    assert reason == "ok"
    assert len(advisories) == 4
    assert {a.slug for a in advisories} == {"php"}
    assert {a.name for a in advisories} == {"PHP"}
    assert {a.fixed for a in advisories} == {"8.2.35", "8.3.36", "8.4.27", "8.5.12"}
    assert all(a.affected_at_or_above for a in advisories)
    assert all(a.cvss == 9.8 for a in advisories)
    assert all(a.source == "nvd-cpe" for a in advisories)


def test_build_index_does_not_collapse_branches() -> None:
    index = build_index([php_cve_item()], parser=parse_cpe_cve)
    assert len(index.advisories) == 4


def test_parse_cpe_cve_ignores_other_products() -> None:
    item = {
        "cve": {
            "id": "CVE-2026-99999",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "1.2.3",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    }
    advisories, reason = parse_cpe_cve(item)
    assert advisories == []
    assert reason == "CPE に影響範囲が無い"


def test_published_at_is_timezone_aware() -> None:
    """NVD の published はタイムゾーン無しなので UTC を補う（比較で落ちないように）。"""
    value = published_at({"cve": {"published": "2026-10-21T14:17:09.000"}})
    assert value is not None
    assert value.tzinfo is not None
    assert value > datetime(2026, 10, 1, tzinfo=UTC)

