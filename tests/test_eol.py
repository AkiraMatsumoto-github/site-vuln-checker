"""ライフサイクル（EOL）判定のテスト。ネットワークは使わない（フィクスチャのみ）。"""

from __future__ import annotations

from datetime import date

from site_vuln_checker.eol import Cycle, Lifecycle, LifecycleIndex

TODAY = date(2026, 10, 29)

#: 実際の endoflife.date の値に合わせた PHP の系統（一部）
PHP_CYCLES = [
    Cycle(cycle="8.5", eol="2029-12-31", latest="8.5.12"),
    Cycle(cycle="8.4", eol="2028-12-31", latest="8.4.27"),
    Cycle(cycle="8.3", eol="2027-12-31", latest="8.3.36"),
    Cycle(cycle="8.2", eol="2026-12-31", latest="8.2.35"),
    Cycle(cycle="8.1", eol="2025-12-31", latest="8.1.34"),
    Cycle(cycle="8.0", eol="2023-11-26", latest="8.0.30"),
]


def php_lifecycle() -> Lifecycle:
    return Lifecycle(product="php", name="PHP", cycles=list(PHP_CYCLES))


def test_cycle_for_uses_major_minor() -> None:
    lifecycle = php_lifecycle()
    assert lifecycle.cycle_for("8.1.27").cycle == "8.1"
    assert lifecycle.cycle_for("v8.3.36").cycle == "8.3"
    assert lifecycle.cycle_for("5.6.40") is None


def test_cycle_for_prefers_longest_cycle() -> None:
    """``3`` と ``3.7`` の両方があるとき、より長い系統で照合する。"""
    lifecycle = Lifecycle(
        product="jquery",
        name="jQuery",
        cycles=[
            Cycle(cycle="3", eol=None, latest="3.7.1"),
            Cycle(cycle="4", eol=None, latest="4.0.0"),
        ],
    )
    assert lifecycle.cycle_for("3.7.1").cycle == "3"
    assert lifecycle.cycle_for("4.0.0").cycle == "4"


def test_eol_state_for_old_branch() -> None:
    """PHP 8.1 は 2025-12-31 に終了している（今回の PHP2Shell の前提）。"""
    status = php_lifecycle().check("8.1.27", TODAY)
    assert status.state == "eol"
    assert status.cycle == "8.1"
    assert status.eol == "2025-12-31"
    # 移行先は「サポート中で最も新しい系統」の最新版
    assert status.move_to == "8.5.12"
    assert status.is_issue is True


def test_eol_soon_within_ninety_days() -> None:
    """8.2 系は 2026-12-31 終了。2026-10-29 時点では 90 日以内なので「近い」。"""
    status = php_lifecycle().check("8.2.35", TODAY)
    assert status.state == "eol_soon"


def test_supported_and_outdated() -> None:
    lifecycle = php_lifecycle()
    assert lifecycle.check("8.4.27", TODAY).state == "supported"
    # 同じ枝に新しいパッチがある（7.4 の「パッチ未適用」）
    outdated = lifecycle.check("8.4.20", TODAY)
    assert outdated.state == "outdated"
    assert outdated.latest == "8.4.27"


def test_unknown_cycle() -> None:
    status = php_lifecycle().check("5.6.40", TODAY)
    assert status.state == "unknown"
    assert status.is_issue is False


def test_supported_cycles_sorted_newest_first() -> None:
    alive = [cycle.cycle for cycle in php_lifecycle().supported_cycles(TODAY)]
    assert alive == ["8.5", "8.4", "8.3", "8.2"]


def test_lifecycle_index_roundtrip_and_alias() -> None:
    index = LifecycleIndex(products={"php": php_lifecycle()})
    restored = LifecycleIndex.from_dict(index.to_dict())
    assert restored is not None
    # 製品キーでも表示名（大文字小文字を無視）でも引ける
    assert restored.get("php") is not None
    assert restored.get("PHP") is not None
    assert restored.check("php", "8.1.27", TODAY).state == "eol"


def test_lifecycle_index_from_empty_returns_none() -> None:
    assert LifecycleIndex.from_dict(None) is None
    assert LifecycleIndex.from_dict({}) is None
