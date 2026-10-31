"""Site Health 解析（P0-18）の受け入れテスト。

HTML 版（拡張が実際に読む形）と、コピー用テキスト版（正解データ）が
**同じ結果になる**ことを確かめる。
"""

import json
from pathlib import Path

from site_vuln_checker.sitehealth import (
    Component,
    main,
    parse_site_health,
    parse_site_health_html,
)

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


def test_cli_prints_components_from_text_file(capsys) -> None:
    """``svc-sitehealth --text``: 画面の写しから構成を読み取って表示する（レビュー #8）。"""
    exit_code = main(["--text", str(FIXTURES / "site_health.txt")])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "WordPress 6.8.2" in out
    assert "PHP 8.1.31" in out
    assert "Contact Form 7 5.9.8" in out
    assert "Hello Dolly 1.7.2" in out


def test_cli_judges_with_index(capsys, tmp_path: Path) -> None:
    """索引を渡すと、サイトヘルスの Version で判定まで出す（CLI と拡張の橋渡し）。"""
    index_path = tmp_path / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-10-29T00:00:00Z",
                "advisories": [
                    {
                        "id": "CVE-2025-90001",
                        "name": "Contact Form 7",
                        "slug": "contact-form-7",
                        "affected_below": "5.9.9",
                        "fixed": "5.9.9",
                        "cvss": 9.8,
                        "kev": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["--text", str(FIXTURES / "site_health.txt"), "--index", str(index_path)])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "[赤] contact-form-7 5.9.8" in out
    assert "修正版 5.9.9 に更新してください" in out


def test_cli_json_output(capsys) -> None:
    """``--json`` は機械処理用（拡張と同じ項目名で出す）。"""
    main(["--html", str(FIXTURES / "site_health.html"), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["info"]["php_version"] == "8.1.31"
    assert payload["info"]["plugins_active"][1]["slug"] == "contact-form-7"
    assert "judgements" not in payload, "索引を渡していないときは判定を出さない"
