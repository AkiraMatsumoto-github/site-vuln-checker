"""Site Health 解析（P0-18）の受け入れテスト。

HTML 版（拡張が実際に読む形）と、コピー用テキスト版（正解データ）が
**同じ結果になる**ことを確かめる。
"""

from pathlib import Path

from site_vuln_checker.sitehealth import Component, parse_site_health, parse_site_health_html

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_html_parse() -> None:
    info = parse_site_health_html(_load("site_health.html"))

    assert info.core_version == "6.8.2"
    assert info.php_version == "8.1.31"
    assert info.php_sapi == "fpm-fcgi"
    assert info.httpd == "nginx/1.27.3"
    assert info.database == "MariaDB 10.6.18"

    assert [(p.name, p.version) for p in info.plugins_active] == [
        ("Akismet Anti-spam", "5.3.1"),
        ("Contact Form 7", "5.9.8"),
    ]
    assert [(p.name, p.version) for p in info.plugins_inactive] == [("Hello Dolly", "1.7.2")]
    assert [(t.name, t.version) for t in info.themes_active] == [("Twenty Twenty-Five", "1.2")]


def test_text_and_html_agree() -> None:
    html_info = parse_site_health(_load("site_health.html"))
    text_info = parse_site_health(_load("site_health.txt"))

    assert html_info.source == "html"
    assert text_info.source == "text"
    assert html_info.core_version == text_info.core_version
    assert html_info.php_version == text_info.php_version
    assert html_info.httpd == text_info.httpd
    assert html_info.database == text_info.database
    assert [(p.name, p.version) for p in html_info.plugins_active] == [
        (p.name, p.version) for p in text_info.plugins_active
    ]
    assert [(p.name, p.version) for p in html_info.plugins_inactive] == [
        (p.name, p.version) for p in text_info.plugins_inactive
    ]


def test_slug_and_findings() -> None:
    info = parse_site_health_html(_load("site_health.html"))

    # 表示名から slug を推定する（WordPress.org API で確認する前提の「推定」）
    assert [p.slug for p in info.plugins_active] == ["akismet-anti-spam", "contact-form-7"]

    findings = {f.key: f for f in info.to_findings()}
    assert findings["language:php"].version == "8.1.31"
    assert findings["language:php"].confidence >= 0.95, "Site Health 由来は確定扱い"
    assert findings["plugin:contact-form-7"].version == "5.9.8"
    assert findings["plugin:contact-form-7"].active is True
    assert findings["plugin:hello-dolly"].active is False
    assert findings["database:mariadb"].version == "10.6.18"
    assert info.counts == {
        "plugins_active": 2,
        "plugins_inactive": 1,
        "themes_active": 1,
        "themes_inactive": 0,
    }


def test_empty_input_is_safe() -> None:
    info = parse_site_health("<html><body>nothing</body></html>")
    assert info.core_version is None
    assert info.plugins_active == []
    assert info.to_findings() == []


def test_component_slug_falls_back_to_name_for_japanese() -> None:
    """日本語名は正規化すると空になるので、元の名前を slug として使う（レビュー H4）。"""
    component = Component(name="アドバンスドカスタムフィールド", version="1.0")
    assert component.slug == "アドバンスドカスタムフィールド"
    assert Component(name="Contact Form 7", version="1.0").slug == "contact-form-7"
