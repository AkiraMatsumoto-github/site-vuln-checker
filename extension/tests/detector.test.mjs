import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { SHOPIFY_APP_DOMAINS, analyze } from "../detector.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "tests", "fixtures");
const load = (name) => readFileSync(join(fixtures, name), "utf8");

/** フィクスチャの HTML から、拡張が集めるのと同じ形の証拠を作る。 */
function evidence(html, url = "https://example.com/") {
  const resources = [];
  for (const match of html.matchAll(/(?:src|href)=["']([^"']+)["']/gi)) {
    const value = match[1];
    if (!value || value.startsWith("data:") || value.startsWith("#")) continue;
    resources.push(new URL(value, url).href);
  }
  return { url, html, resources, headers: {} };
}

const find = (analysis, kind, name) =>
  analysis.findings.find((item) => item.kind === kind && item.name === name);

test("Shopify のテーマとアプリを読む（Version は出ない）", () => {
  const analysis = analyze({
    url: "https://shop.example/",
    html: '<script>Shopify.theme = {"name":"Dawn","theme_store_id":887};</script>',
    resources: [
      "https://static.klaviyo.com/onsite/js/klaviyo.js",
      "https://cdn.shopify.com/s/files/theme.js",
    ],
  });
  const theme = analysis.findings.find((item) => item.kind === "theme");
  assert.equal(theme.name, "dawn");
  assert.equal(theme.version, null, "Shopify のテーマは Version を出さない");
  const apps = analysis.findings.filter((item) => item.kind === "app").map((item) => item.name);
  assert.deepEqual(apps, ["klaviyo"]);
  assert.ok(analysis.notes.some((note) => note.includes("Shopify のサーバー側 Version")));
});

test("アプリ辞書は主要アプリを 50 ドメイン以上持つ（レビュー #14）", () => {
  const domains = SHOPIFY_APP_DOMAINS.map(([domain]) => domain);
  const apps = new Set(SHOPIFY_APP_DOMAINS.map(([, app]) => app));

  assert.ok(domains.length >= 50, `辞書が少なすぎます: ${domains.length}`);
  assert.equal(new Set(domains).size, domains.length, "同じドメインを二重に登録しない");
  assert.ok(apps.size >= 40);
  for (const expected of ["klaviyo", "omnisend", "judge-me", "smile-io", "weglot"]) {
    assert.ok(apps.has(expected), `${expected} が辞書に無い`);
  }
});

test("CDN のサブドメインでも拾い、同じアプリは 1 回だけ出す", () => {
  const analysis = analyze({
    url: "https://shop.example/",
    html: "",
    resources: [
      "https://cdn.omnisrc.com/onsite/js/omnisend.js",
      "https://static.klaviyo.com/onsite/js/klaviyo.js",
      "https://a.klaviyo.com/onsite/js/klaviyo.js",
      "https://cdn.smile.io/smile-ui-latest.js",
      "https://widget.trustpilot.com/trustbox.js",
      "https://static.triplewhale.com/pixel.js",
    ],
  });
  const apps = analysis.findings.filter((item) => item.kind === "app").map((item) => item.name);
  assert.deepEqual(apps.sort(), ["klaviyo", "omnisend", "smile-io", "triple-whale", "trustpilot"]);
});

test("似た名前の別ドメインをアプリと誤判定しない", () => {
  const analysis = analyze({
    url: "https://shop.example/",
    html: "",
    resources: ["https://notklaviyo.com/track.js", "https://klaviyo.com.evil.example/x.js"],
  });
  assert.deepEqual(
    analysis.findings.filter((item) => item.kind === "app"),
    [],
  );
});

test("WordPress を判定して根拠を残す", () => {
  const analysis = analyze(evidence(load("wp_home.html")));
  const wordpress = find(analysis, "platform", "wordpress");
  assert.ok(wordpress, "platform:wordpress が見つからない");
  assert.ok(wordpress.confidence >= 0.9);
  assert.ok(wordpress.evidence.includes("path:/wp-content/"));
});

test("コアのバージョンは meta generator から取る", () => {
  const analysis = analyze(evidence(load("wp_home.html")));
  const core = find(analysis, "core", "wordpress");
  assert.equal(core.version, "6.8.2");
  assert.equal(core.confidence, 1.0);
  assert.deepEqual(core.evidence, ["meta:generator"]);
});

test("プラグインは slug と版を返し、版が無ければ null", () => {
  const analysis = analyze(evidence(load("wp_home.html")));
  const slugs = analysis.findings.filter((item) => item.kind === "plugin").map((item) => item.name);
  assert.deepEqual(slugs, ["contact-form-7", "elementor", "woocommerce"]);

  const cf7 = find(analysis, "plugin", "contact-form-7");
  assert.equal(cf7.version, "5.9.8");
  assert.equal(cf7.confidence, 0.85);
  assert.equal(cf7.active, true);

  const woo = find(analysis, "plugin", "woocommerce");
  assert.equal(woo.version, null, "版が取れないときは推測で埋めない");
  assert.ok(woo.confidence < 0.85);
});

test("テーマと JS ライブラリ", () => {
  const analysis = analyze(evidence(load("wp_home.html")));
  assert.equal(find(analysis, "theme", "twentytwentyfive").version, "1.2");
  assert.equal(find(analysis, "library", "jquery").version, "3.7.1");
  assert.equal(find(analysis, "library", "bootstrap").version, "5.3.3");
  assert.equal(find(analysis, "library", "lodash").version, "4.17.21");
});

test("同梱 jQuery の ?ver をコア版と誤認しない", () => {
  const html = `<html><body>
    <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
    <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.8.2"></script>
  </body></html>`;
  const core = find(analyze(evidence(html)), "core", "wordpress");
  assert.equal(core.version, "6.8.2");
  assert.equal(core.confidence, 0.85);
});

test("同じ slug に複数の ?ver があるときは最頻値", () => {
  const html = `<html><head>
    <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/admin.css?ver=1.0">
    <script src="/wp-content/plugins/contact-form-7/app.js?ver=5.9.8"></script>
    <script src="/wp-content/plugins/contact-form-7/extra.js?ver=5.9.8"></script>
  </head></html>`;
  assert.equal(find(analyze(evidence(html)), "plugin", "contact-form-7").version, "5.9.8");
});

test("本文中の文字列だけのプラグインは「有効」と断定しない", () => {
  const html = "<html><body><pre>/wp-content/plugins/only-inline/lib.js</pre></body></html>";
  const plugin = find(analyze(evidence(html)), "plugin", "only-inline");
  assert.equal(plugin.active, null);
  assert.equal(plugin.version, null);
});

test("WordPress でないサイトではプラグインを出さない", () => {
  const analysis = analyze(evidence(load("static_site.html")));
  assert.equal(analysis.findings.filter((item) => item.kind === "plugin").length, 0);
  assert.ok(analysis.notes.includes("プラットフォームを判定できませんでした"));
});

// --- ヘッダから PHP（任意機能）-----------------------------------------------

test("X-Powered-By があれば PHP の版を読む", () => {
  const analysis = analyze({
    url: "https://example.com/",
    html: "<html><body>hello</body></html>",
    resources: [],
    headers: { "x-powered-by": "PHP/8.3.36" },
  });
  const php = analysis.findings.find((item) => item.kind === "language");
  assert.equal(php.name, "php");
  assert.equal(php.version, "8.3.36");
  assert.deepEqual(php.evidence, ["header:x-powered-by"]);
  // 版が分かったので「PHP のバージョンは取得できませんでした」は出さない
  assert.ok(!analysis.notes.some((note) => note.startsWith("PHP のバージョン")));
});

test("ヘッダが無ければ PHP は不明のまま（推測しない）", () => {
  const analysis = analyze({
    url: "https://example.com/",
    html: "<html><body>hello</body></html>",
    resources: [],
    headers: { server: "nginx" },
  });
  assert.equal(analysis.findings.filter((item) => item.kind === "language").length, 0);
  assert.ok(analysis.notes.some((note) => note.startsWith("PHP のバージョン")));
});

