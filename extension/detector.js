// 外部から観測できる情報だけを使って、サイトの技術構成を推定する。
//
// Python 版（src/site_vuln_checker/detect.py）と同じ判定を、拡張（MV3）で使えるように移植したもの。
// - 判定は必ず「推定」。finding は confidence と evidence を持つ
// - バージョンが取れないものは version=null のまま返す（推測で埋めない）
// - 本文中の文字列だけで見つけたプラグインは active=null（有効と断定しない）

const VERSION = String.raw`\d+\.\d+(?:\.\d+)*(?:[-+~][0-9A-Za-z.\-]+)?`;
const QUERY_VER_RE = new RegExp(`[?&](?:ver|v)=(${VERSION})`, "i");
const FIRST_VERSION_RE = new RegExp(VERSION);
const WP_PLUGIN_PATH_RE = /\/wp-content\/plugins\/([A-Za-z0-9_\-.]+)\//g;
const WP_THEME_PATH_RE = /\/wp-content\/themes\/([A-Za-z0-9_\-.]+)\//g;
const PHP_HEADER_RE = new RegExp(`PHP/(${VERSION})`, "i");
const SERVER_RE = /([A-Za-z][A-Za-z0-9-]*)\/(\d+(?:\.\d+)+)/;

//: JS ライブラリの判定。順序が重要（jquery-ui を jquery より先に見る）。
const LIB_TOKENS = [
  ["jquery-ui", ["jquery-ui", "jqueryui"]],
  ["jquery", ["jquery"]],
  ["bootstrap", ["bootstrap"]],
  ["lodash", ["lodash"]],
  ["moment", ["moment"]],
  ["angular", ["angular"]],
  ["vue", ["vue.", "vue.min", "/vue@"]],
  ["react", ["react.", "react-dom", "/react@"]],
  ["swiper", ["swiper"]],
  ["gsap", ["gsap", "tweenmax", "tweenlite"]],
];

/** サーバ側フレームワークの目印（版はほぼ取れないので version は null）。 */
const FRAMEWORK_SIGNALS = [
  ["django", ["csrfmiddlewaretoken"], 0.6],
  ["rails", ['name="authenticity_token"', 'content="authenticity_token"'], 0.6],
  ["laravel", ["laravel_session", "laravel/framework"], 0.5],
  ["nuxt", ["__nuxt__"], 0.6],
];

/** `<meta name="generator">` から読む既知のプラットフォーム（WordPress 以外）。 */
const GENERATOR_PLATFORMS = [
  ["jekyll", "jekyll"],
  ["hugo", "hugo"],
  ["ghost", "ghost"],
  ["drupal", "drupal"],
  ["joomla", "joomla"],
  ["gatsby", "gatsby"],
  ["next.js", "nextjs"],
  ["nextjs", "nextjs"],
  ["nuxt", "nuxt"],
  ["astro", "astro"],
  ["eleventy", "eleventy"],
  ["hexo", "hexo"],
  ["middleman", "middleman"],
];

const GENERATOR_RE = /^([A-Za-z][A-Za-z0-9 ._-]*?)\s*v?(\d+(?:\.\d+)*)/;

/**
 * generator から WordPress 以外のプラットフォームを読む（Jekyll など）。
 *
 * 静的サイト生成ツールはビルド時に Version を埋め込むため、そのまま読める。
 */
export function detectGeneratorPlatform(generator) {
  const text = String(generator ?? "").trim();
  if (!text || text.toLowerCase().includes("wordpress")) return null;

  const match = GENERATOR_RE.exec(text);
  const name = (match ? match[1] : text).trim().toLowerCase();
  const version = match ? match[2] : null;
  for (const [needle, slug] of GENERATOR_PLATFORMS) {
    if (name.includes(needle)) {
      return finding("platform", slug, version, version ? 0.95 : 0.8, ["meta:generator"]);
    }
  }
  return null;
}

export function detectFrameworks(htmlLower) {
  const findings = [];
  for (const [name, needles, confidence] of FRAMEWORK_SIGNALS) {
    const matched = needles.filter((needle) => htmlLower.includes(needle));
    if (matched.length) {
      findings.push(
        finding("framework", name, null, confidence, matched.map((n) => `dom:${n}`)),
      );
    }
  }
  return findings;
}

/** Shopify のテーマ定義（`Shopify.theme = {"name":"Dawn", ...};`） */
const SHOPIFY_THEME_RE = /Shopify\.theme\s*=\s*(\{[\s\S]*?\})\s*;/;

/**
 * Shopify アプリの配信ドメイン → 名前（「どのアプリが動いているか」の可視化まで）。
 *
 * **アプリの会社のドメイン**を書く（CDN のサブドメインは前方一致で拾える）。
 * ここに無いアプリは「不明」ではなく**単に出さない**（誤検出より取りこぼしを選ぶ）。
 * Python 側（`src/site_vuln_checker/detect.py`）と**同じ内容・同じ順**にする。
 */
export const SHOPIFY_APP_DOMAINS = [
  // メール / SMS 配信
  ["klaviyo.com", "klaviyo"],
  ["omnisend.com", "omnisend"],
  ["omnisrc.com", "omnisend"],
  ["postscript.io", "postscript"],
  ["attentive.com", "attentive"],
  ["attentivemobile.com", "attentive"],
  ["smsbump.com", "smsbump"],
  ["privy.com", "privy"],
  ["justuno.com", "justuno"],
  ["recart.com", "recart"],
  ["wisepops.com", "wisepops"],
  ["getsitecontrol.com", "getsitecontrol"],
  ["zotabox.com", "zotabox"],
  // レビュー / 口コミ
  ["judge.me", "judge-me"],
  ["yotpo.com", "yotpo"],
  ["stamped.io", "stamped-io"],
  ["loox.io", "loox"],
  ["loox.app", "loox"],
  ["okendo.io", "okendo"],
  ["fera.ai", "fera"],
  ["opinew.com", "opinew"],
  ["junip.co", "junip"],
  ["reviews.io", "reviews-io"],
  ["trustpilot.com", "trustpilot"],
  ["trustpilot.net", "trustpilot"],
  // チャット / サポート
  ["gorgias.com", "gorgias"],
  ["gorgias.chat", "gorgias"],
  ["tidio.com", "tidio"],
  ["tidio.co", "tidio"],
  ["tawk.to", "tawk-to"],
  ["reamaze.com", "reamaze"],
  ["chatra.io", "chatra"],
  // アップセル / 売上
  ["rechargeapps.com", "recharge"],
  ["rebuyengine.com", "rebuy"],
  ["zipify.com", "zipify"],
  ["reconvert.io", "reconvert"],
  ["kiwisizing.com", "kiwi-sizing"],
  ["boldapps.net", "bold"],
  ["boldcommerce.com", "bold"],
  ["hextom.com", "hextom"],
  ["secomapp.com", "secomapp"],
  ["avada.io", "avada"],
  ["fireapps.io", "fireapps"],
  // ロイヤルティ / 紹介
  ["smile.io", "smile-io"],
  ["loyaltylion.com", "loyaltylion"],
  ["referralcandy.com", "referralcandy"],
  ["tapfiliate.com", "tapfiliate"],
  ["refersion.com", "refersion"],
  ["growave.io", "growave"],
  ["swym.it", "swym"],
  // 配送 / 追跡
  ["aftership.com", "aftership"],
  ["parcelpanel.com", "parcelpanel"],
  ["track123.com", "track123"],
  // 翻訳
  ["weglot.com", "weglot"],
  ["langify-app.com", "langify"],
  // ページビルダー / 検索・レコメンド
  ["pagefly.io", "pagefly"],
  ["gempages.net", "gem-pages"],
  ["searchanise.com", "searchanise"],
  ["boostcommerce.net", "boost-commerce"],
  ["klevu.com", "klevu"],
  ["clerk.io", "clerk-io"],
  ["fastsimon.com", "fast-simon"],
  ["nosto.com", "nosto"],
  // 埋め込みウィジェット
  ["powr.io", "powr"],
  ["elfsight.com", "elfsight"],
  ["globosoftware.net", "globo"],
  // 分析 / アトリビューション
  ["triplewhale.com", "triple-whale"],
  ["getelevar.com", "elevar"],
  ["northbeam.io", "northbeam"],
];

/**
 * `cdn.klaviyo.com` は一致、`notklaviyo.com` は**一致させない**。
 *
 * `host.endsWith(domain)` だけだと、別会社の `notklaviyo.com` を klaviyo と
 * 誤って表示してしまう（ドメインの区切りを必ず見る）。
 */
export function hostMatches(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Shopify のテーマ名と、読み込まれているアプリを推定する。
 *
 * Shopify は**サーバー側の Version を公開しない**（常に最新が提供される）ため、
 * 見えるのは「テーマ名」と「どのアプリのスクリプトが動いているか」まで。
 */
export function detectShopify(html, resources) {
  const findings = [];

  const match = SHOPIFY_THEME_RE.exec(String(html ?? ""));
  if (match) {
    let theme = {};
    try {
      theme = JSON.parse(match[1]);
    } catch {
      theme = {};
    }
    const name = String(theme?.name ?? "").trim();
    if (name) findings.push(finding("theme", slugify(name), null, 0.85, ["dom:Shopify.theme"]));
  }

  const seen = new Set();
  for (const url of resources) {
    let host = "";
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      continue;
    }
    for (const [domain, app] of SHOPIFY_APP_DOMAINS) {
      if (seen.has(app)) continue;
      if (hostMatches(host, domain)) {
        seen.add(app);
        findings.push(finding("app", app, null, 0.7, [`host:${domain}`]));
      }
    }
  }
  return findings;
}

/** プラグイン名として扱う最小文字数（短すぎる slug は前方一致させない）。 */
export const MIN_PREFIX_MATCH = 6;

export function finding(kind, name, version, confidence, evidence, active = null) {
  return { kind, name, version: version ?? null, confidence, evidence: evidence ?? [], active };
}

function basename(url) {
  try {
    const path = new URL(url, "https://example.invalid").pathname;
    const base = path.split("/").pop();
    return base || "/";
  } catch {
    return String(url).split("/").pop() || "/";
  }
}

export function queryVersion(url) {
  const match = QUERY_VER_RE.exec(String(url));
  return match ? match[1] : null;
}

function unique(values) {
  return [...new Set(values)];
}

function isBundledLibrary(url) {
  const name = basename(url).toLowerCase();
  return LIB_TOKENS.some(([, tokens]) => tokens.some((token) => name.includes(token)));
}

function detectPlatforms(htmlLower, resources) {
  const evidence = new Map();
  const add = (platform, item) => {
    if (!evidence.has(platform)) evidence.set(platform, []);
    const list = evidence.get(platform);
    if (!list.includes(item)) list.push(item);
  };

  if (htmlLower.includes("wp-content/")) add("wordpress", "path:/wp-content/");
  if (resources.some((url) => url.includes("/wp-includes/"))) {
    add("wordpress", "path:/wp-includes/");
  }
  if (htmlLower.includes("wp-json/") || htmlLower.includes("api.w.org")) {
    add("wordpress", "link:api.w.org");
  }
  if (htmlLower.includes("shopify.theme") || htmlLower.includes("cdn.shopify.com")) {
    add("shopify", "dom:Shopify.theme");
  }
  if (htmlLower.includes("shopify-section")) add("shopify", "dom:shopify-section");
  if (htmlLower.includes("sites/default/files/")) add("drupal", "path:/sites/default/files/");
  if (htmlLower.includes("/media/system/js/")) add("joomla", "path:/media/system/js/");
  if (htmlLower.includes("__next_data__")) add("nextjs", "dom:__NEXT_DATA__");
  if (htmlLower.includes("/_next/static/")) add("nextjs", "path:/_next/static/");
  if (htmlLower.includes("laravel_session")) add("laravel", "cookie:laravel_session");

  return [...evidence.entries()].map(([name, items]) =>
    finding("platform", name, null, Math.min(0.99, 0.7 + 0.1 * items.length), items),
  );
}

function detectCore(generator, resources) {
  const match = new RegExp(`WordPress\\s+(${VERSION})`, "i").exec(generator || "");
  if (match) return finding("core", "wordpress", match[1], 1.0, ["meta:generator"]);

  // /wp-includes/ の ?ver= の最頻値（同梱ライブラリは除く）
  const versions = resources
    .filter((url) => url.includes("/wp-includes/") && !isBundledLibrary(url))
    .map(queryVersion)
    .filter(Boolean);
  if (!versions.length) return null;
  const counts = new Map();
  for (const version of versions) counts.set(version, (counts.get(version) || 0) + 1);
  const best = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
  return finding("core", "wordpress", best, 0.85, [`asset:wp-includes?ver=${best}`]);
}

export function detectThemes(resources, html) {
  const evidence = new Map();
  const versions = new Map();
  for (const url of resources) {
    const match = /\/wp-content\/themes\/([A-Za-z0-9_\-.]+)\//.exec(url);
    if (!match) continue;
    const slug = match[1];
    if (!evidence.has(slug)) evidence.set(slug, []);
    evidence.get(slug).push(`asset:${basename(url)}`);
    if (!versions.has(slug) && basename(url).startsWith("style.css")) {
      const version = queryVersion(url);
      if (version) versions.set(slug, version);
    }
  }
  for (const match of String(html || "").matchAll(WP_THEME_PATH_RE)) {
    const slug = match[1];
    if (!evidence.has(slug)) evidence.set(slug, []);
    if (!evidence.get(slug).includes("inline:path")) evidence.get(slug).push("inline:path");
  }

  return [...evidence.entries()]
    .map(([slug, items]) => {
      const version = versions.get(slug) ?? null;
      return finding("theme", slug, version, version ? 0.5 : 0.35, unique(items));
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function detectLibraries(resources) {
  const found = new Map();
  for (const url of resources) {
    const name = basename(url).toLowerCase();
    const entry = LIB_TOKENS.find(([, tokens]) => tokens.some((token) => name.includes(token)));
    if (!entry) continue;
    const [lib] = entry;
    const match = FIRST_VERSION_RE.exec(name);
    let candidate;
    if (match) {
      candidate = finding("library", lib, match[0], 0.9, [`file:${basename(url)}`]);
    } else {
      const version = queryVersion(url);
      candidate = finding("library", lib, version, version ? 0.85 : 0.7, [`asset:${basename(url)}`]);
    }
    const existing = found.get(lib);
    if (!existing || candidate.confidence > existing.confidence) found.set(lib, candidate);
  }
  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function detectServer(headers) {
  const lower = {};
  for (const [key, value] of Object.entries(headers || {})) lower[key.toLowerCase()] = value;
  const findings = [];

  const powered = String(lower["x-powered-by"] || "");
  const php = PHP_HEADER_RE.exec(powered);
  if (php) findings.push(finding("language", "php", php[1], 0.6, ["header:x-powered-by"]));

  const server = String(lower["server"] || "");
  if (server) {
    const match = SERVER_RE.exec(server);
    if (match) {
      findings.push(finding("server", match[1].toLowerCase(), match[2], 0.5, ["header:server"]));
    } else {
      findings.push(finding("server", server.split(/\s+/)[0].toLowerCase(), null, 0.4, ["header:server"]));
    }
  }
  return findings;
}

/**
 * 1 ページ分の証拠から技術構成を推定する。
 *
 * @param {{url: string, html?: string, resources?: string[], headers?: Record<string,string>}} evidence
 */
/**
 * 「判定できなかったこと」の一覧。入力で版が埋まったら作り直すため、単独で呼べるようにする。
 */
export function buildNotes(findings) {
  const notes = [];
  if (!findings.some((item) => item.kind === "platform")) {
    notes.push("プラットフォームを判定できませんでした");
  }
  const unknown = findings
    .filter((item) => item.kind === "plugin" && !item.version)
    .map((item) => item.name);
  if (unknown.length) {
    notes.push(`バージョンが分からないプラグイン: ${unknown.join(", ")}（不明として表示します）`);
  }

  // PHP の話は PHP 製のサイトだけにする（静的サイトに「PHP 不明」は無意味）
  const phpBased = ["wordpress", "laravel", "symfony", "codeigniter", "cakephp"];
  const platforms = findings.filter((item) => item.kind === "platform").map((item) => item.name);
  const isPhpBased = platforms.some((name) => phpBased.includes(name));
  if (!findings.some((item) => item.kind === "language") && (!platforms.length || isPhpBased)) {
    notes.push("PHP のバージョンは取得できませんでした（分かる場合は入力してください）");
  } else if (platforms.length && !isPhpBased) {
    if (platforms.includes("shopify")) {
      notes.push(
        "Shopify のサーバー側 Version は公開されません（常に最新が提供されます）。テーマ・アプリ・JS ライブラリのみ表示します",
      );
    } else {
      notes.push(`このサイトは ${platforms.join("/")} 製です（プラグインや PHP の判定はありません）`);
    }
  }

  const frameworks = findings
    .filter((item) => item.kind === "framework" && !item.version)
    .map((item) => item.name);
  if (frameworks.length) {
    notes.push(`フレームワークの版は外から分かりません: ${frameworks.join(", ")}（入力すると判定できます）`);
  }
  return notes;
}

export function analyze(evidence) {
  const { url = "", html = "", resources = [], headers = {} } = evidence;
  const htmlLower = String(html).toLowerCase();
  const generatorMatch = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']*)["']/i.exec(htmlLower);
  const generator = generatorMatch ? generatorMatch[1] : "";

  const findings = [
    ...detectPlatforms(htmlLower, resources),
    detectGeneratorPlatform(generator),
    detectCore(generator, resources),
    ...detectPlugins(resources, html),
    ...detectThemes(resources, html),
    ...detectShopify(html, resources),
    ...detectLibraries(resources),
    ...detectFrameworks(htmlLower),
    ...detectServer(headers),
  ].filter(Boolean);

  return { url, findings, notes: buildNotes(findings) };
}

export function detectPlugins(resources, html) {

  const evidence = new Map();
  const versions = new Map();
  const fromResources = new Set();

  for (const url of resources) {
    const match = /\/wp-content\/plugins\/([A-Za-z0-9_\-.]+)\//.exec(url);
    if (!match) continue;
    const slug = match[1];
    fromResources.add(slug);
    if (!evidence.has(slug)) evidence.set(slug, []);
    evidence.get(slug).push(`asset:${basename(url)}`);
    const version = queryVersion(url);
    if (version) {
      if (!versions.has(slug)) versions.set(slug, []);
      versions.get(slug).push(version);
    }
  }

  // 本文中の文字列（JSON や CSS 内）も拾う。有効とも言えないので active は付けない。
  for (const match of String(html || "").matchAll(WP_PLUGIN_PATH_RE)) {
    const slug = match[1];
    if (!evidence.has(slug)) evidence.set(slug, []);
    if (!evidence.get(slug).includes("inline:path")) evidence.get(slug).push("inline:path");
  }

  const findings = [];
  for (const [slug, items] of evidence.entries()) {
    const active = fromResources.has(slug) ? true : null;
    const candidates = versions.get(slug) || [];
    if (candidates.length) {
      const counts = new Map();
      for (const version of candidates) counts.set(version, (counts.get(version) || 0) + 1);
      const version = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
      findings.push(finding("plugin", slug, version, 0.85, [items[0], `asset:?ver=${version}`], active));
    } else {
      findings.push(finding("plugin", slug, null, 0.6, unique(items), active));
    }
  }
  return findings.sort((a, b) => a.name.localeCompare(b.name));
}
