"""KEV / EPSS の結合（enrich）のテスト。

**ネットワークは使わない**。KEV の JSON・EPSS の CSV を最小限のサンプルで固定する。
"""

from site_vuln_checker.advisories import LEVEL_RED, LEVEL_YELLOW, Advisory, AdvisoryIndex
from site_vuln_checker.enrich import KevEntry, enrich, parse_epss_csv, parse_kev, summarize

KEV_PAYLOAD = {
    "catalogVersion": "2026.10.29",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-90001",
            "dateAdded": "2026-10-20",
            "dueDate": "2026-11-10",
            "knownRansomwareCampaignUse": "Known",
        },
        {"cveID": ""},
    ],
}

EPSS_CSV = """#model_version:v2025.03.14,score_date:2026-10-29T00:00:00+0000
cve,epss,percentile
CVE-2026-90001,0.91000,0.99900
CVE-2026-90002,0.02000,0.40000
CVE-2026-99999,0.50000,0.90000
"""


def _index() -> AdvisoryIndex:
    return AdvisoryIndex(
        advisories=[
            Advisory(id="CVE-2026-90001", name="Foo", affected_below="9.9.9", cvss=7.5),
            Advisory(id="CVE-2026-90002", name="Bar", affected_below="9.9.9", cvss=5.0),
            Advisory(id="CVE-2026-90003", name="Baz", affected_below="9.9.9", cvss=5.0),
        ]
    )


def test_parse_kev() -> None:
    kev = parse_kev(KEV_PAYLOAD)
    assert set(kev) == {"CVE-2026-90001"}
    assert kev["CVE-2026-90001"].date_added == "2026-10-20"
    assert kev["CVE-2026-90001"].due_date == "2026-11-10"
    assert kev["CVE-2026-90001"].ransomware is True


def test_parse_epss_csv() -> None:
    scores = parse_epss_csv(EPSS_CSV)
    assert scores["CVE-2026-90001"] == (0.91, 0.999)
    assert scores["CVE-2026-99999"] == (0.5, 0.9)
    # 欲しい CVE だけに絞れる（数百万行の CSV を全部持たない）
    only = parse_epss_csv(EPSS_CSV, wanted={"CVE-2026-90002"})
    assert set(only) == {"CVE-2026-90002"}


def test_enrich_sets_kev_and_epss() -> None:
    kev = parse_kev(KEV_PAYLOAD)
    epss = parse_epss_csv(EPSS_CSV)
    enriched = enrich(_index(), kev, epss)
    by_id = {a.id: a for a in enriched.advisories}

    first = by_id["CVE-2026-90001"]
    assert first.kev is True
    assert first.kev_added == "2026-10-20"
    assert first.kev_due == "2026-11-10"
    assert first.epss == 0.91
    assert first.epss_percentile == 0.999

    # EPSS だけある場合（KEV には無い）
    second = by_id["CVE-2026-90002"]
    assert second.kev is False
    assert second.epss == 0.02

    # どちらも無い場合はそのまま
    third = by_id["CVE-2026-90003"]
    assert third.kev is False
    assert third.epss is None


def test_enrich_without_data_keeps_index() -> None:
    original = _index()
    enriched = enrich(original)
    assert len(enriched.advisories) == len(original.advisories)
    assert all(a.kev is False and a.epss is None for a in enriched.advisories)


def test_summarize_counts() -> None:
    enriched = enrich(_index(), parse_kev(KEV_PAYLOAD), parse_epss_csv(EPSS_CSV))
    stats = summarize(enriched)
    assert stats["advisories"] == 3
    assert stats["kev"] == 1
    assert stats["epss"] == 2
    assert stats["epss_over_50pct"] == 1
    # 赤: KEV 1 件 + EPSS 0.91（CVSS 7.5 だが EPSS で赤）は同じ CVE。CVSS 5.0 の 2 件は黄
    assert stats["would_be_red"] >= 1
    assert stats["would_be_yellow"] >= 1


def test_epss_threshold_makes_red() -> None:
    """CVSS が低くても EPSS が 0.5 以上なら赤（企画書 7.5）。"""
    advisory = Advisory(id="CVE-X", name="Foo", affected_below="9.9.9", cvss=5.0, epss=0.8)
    from site_vuln_checker.advisories import _level_for

    assert _level_for([advisory]) == LEVEL_RED
    assert _level_for([Advisory(id="CVE-Y", name="Bar", affected_below="9.9.9", cvss=5.0)]) == (
        LEVEL_YELLOW
    )
    assert LEVEL_RED != LEVEL_YELLOW


def test_kev_entry_dataclass() -> None:
    entry = KevEntry(cve_id="CVE-2026-90001", date_added="2026-10-20")
    assert entry.ransomware is False
