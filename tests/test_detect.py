"""外部検出（detect）の受け入れテスト。

このファイルとフィクスチャが、**拡張（JS）へ移植するときの正解データ**になる。
移植先でも同じフィクスチャで同じ結果になることを受け入れ条件にする。
"""

from pathlib import Path

from site_vuln_checker.detect import Analysis, analyze

FIXTURES = Path(__file__).parent / "fixtures"
HEADERS = {"x-powered-by": "PHP/8.1.27", "server": "nginx/1.27.3"}


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _get(analysis: Analysis, kind: str, name: str):
    for finding in analysis.findings:
        if finding.kind == kind and finding.name == name:
            return finding
    raise AssertionError(f"{kind}:{name} が見つからない: {analysis.to_dict()}")


def test_platform_wordpress() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), HEADERS)
    wp = _get(analysis, "platform", "wordpress")
    assert wp.confidence >= 0.9
    assert "meta:generator" in wp.evidence
    assert "path:/wp-content/" in wp.evidence


def test_core_version_from_generator() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), HEADERS)
    core = _get(analysis, "core", "wordpress")
    assert core.version == "6.8.2"
    assert core.confidence == 1.0
    assert core.evidence == ("meta:generator",)


def test_core_ignores_bundled_jquery_version() -> None:
    """同梱 jQuery の ?ver=3.7.1 をコア版と誤認しない（誤検知よけ）。"""
    html = """
    <html><head></head><body>
      <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
      <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.8.2"></script>
    </body></html>
    """
    analysis = analyze("https://example.com/", html, {})
    core = _get(analysis, "core", "wordpress")
    assert core.version == "6.8.2"
    assert core.confidence == 0.85


def test_plugins_with_and_without_version() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), HEADERS)
    assert analysis.plugin_slugs == ["contact-form-7", "elementor", "woocommerce"]

    cf7 = _get(analysis, "plugin", "contact-form-7")
    assert cf7.version == "5.9.8"
    assert cf7.confidence == 0.85
    assert cf7.active is True

    woo = _get(analysis, "plugin", "woocommerce")
    assert woo.version is None, "バージョンが取れないときは推測で埋めない"
    assert woo.confidence < 0.85


def test_theme_and_libraries() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), HEADERS)
    theme = _get(analysis, "theme", "twentytwentyfive")
    assert theme.version == "1.2"

    assert _get(analysis, "library", "jquery").version == "3.7.1"
    assert _get(analysis, "library", "bootstrap").version == "5.3.3"
    assert _get(analysis, "library", "lodash").version == "4.17.21"


def test_php_and_server_from_headers() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), HEADERS)
    php = _get(analysis, "language", "php")
    assert php.version == "8.1.27"
    assert php.confidence == 0.6, "ヘッダ由来は書き換えられることがあるので確度を下げる"
    assert _get(analysis, "server", "nginx").version == "1.27.3"


def test_without_headers_php_is_unknown() -> None:
    analysis = analyze("https://example.com/", _load("wp_home.html"), {})
    assert analysis.of_kind("language") == []
    assert any("PHP のバージョンは取得できませんでした" in n for n in analysis.notes)


def test_static_site_has_no_plugins() -> None:
    analysis = analyze("https://example.com/", _load("static_site.html"), {})
    assert analysis.platforms == []
    assert analysis.of_kind("plugin") == []
    assert any("プラットフォームを判定できませんでした" in n for n in analysis.notes)
