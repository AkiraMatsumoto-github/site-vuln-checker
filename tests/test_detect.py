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


def test_generator_platform_reads_jekyll() -> None:
    """静的サイト生成ツールは generator に Version を埋め込む（実在サイトの例）。"""
    html = (
        '<html><head><meta name="generator" content="Jekyll v4.4.1" />'
        '<script src="/assets/js/site.js"></script></head><body></body></html>'
    )
    analysis = analyze("https://example.com/", html, {"server": "cloudflare"})
    platform = _get(analysis, "platform", "jekyll")
    assert platform.version == "4.4.1"
    assert platform.confidence >= 0.9
    # 静的サイトなので「PHP のバージョンが不明」とは言わない
    assert not any("PHP のバージョン" in note for note in analysis.notes)
    assert any("jekyll" in note for note in analysis.notes)


def test_shopify_theme_and_apps() -> None:
    """Shopify は Version を出さないが、テーマ名とアプリは見える。"""
    html = (
        "<html><head>"
        '<script>Shopify.theme = {"name":"Dawn","id":1,"theme_store_id":887};</script>'
        '<script src="https://static.klaviyo.com/onsite/js/klaviyo.js"></script>'
        '<script src="https://cdn.shopify.com/s/files/theme.js"></script>'
        "</head><body></body></html>"
    )
    analysis = analyze("https://shop.example/", html, {})
    theme = _get(analysis, "theme", "dawn")
    assert theme.confidence >= 0.8
    assert [f.name for f in analysis.findings if f.kind == "app"] == ["klaviyo"]
    assert any("Shopify のサーバー側 Version は公開されません" in n for n in analysis.notes)


def test_wordpress_generator_is_not_treated_as_generator_platform() -> None:
    """WordPress は core として扱う（platform の二重計上をしない）。"""
    html = (
        '<html><head><meta name="generator" content="WordPress 6.8.2" /></head><body></body></html>'
    )
    analysis = analyze("https://example.com/", html, {})
    assert _get(analysis, "core", "wordpress").version == "6.8.2"
    assert not [f for f in analysis.findings if f.kind == "platform" and f.name == "jekyll"]

    assert any("PHP のバージョンは取得できませんでした" in n for n in analysis.notes)


def test_static_site_has_no_plugins() -> None:
    analysis = analyze("https://example.com/", _load("static_site.html"), {})
    assert analysis.platforms == []
    assert analysis.of_kind("plugin") == []
    assert any("プラットフォームを判定できませんでした" in n for n in analysis.notes)


def test_inline_only_plugin_is_unknown_not_active() -> None:
    """本文中の文字列だけで見つけたプラグインを「有効」と断定しない（レビュー H3）。"""
    html = "<html><body><pre>/wp-content/plugins/only-inline/lib.js</pre></body></html>"
    analysis = analyze("https://example.com/", html, {})
    plugin = _get(analysis, "plugin", "only-inline")
    assert plugin.active is None
    assert plugin.version is None


def test_plugin_version_uses_most_common_query_version() -> None:
    """同じ slug に複数の ?ver= があるときは最頻値を採る（レビュー M8）。"""
    html = """
    <html><head>
      <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/admin.css?ver=1.0">
      <script src="/wp-content/plugins/contact-form-7/app.js?ver=5.9.8"></script>
      <script src="/wp-content/plugins/contact-form-7/extra.js?ver=5.9.8"></script>
    </head><body></body></html>
    """
    analysis = analyze("https://example.com/", html, {})
    plugin = _get(analysis, "plugin", "contact-form-7")
    assert plugin.version == "5.9.8", "先頭の 1.0 ではなく最頻値"
