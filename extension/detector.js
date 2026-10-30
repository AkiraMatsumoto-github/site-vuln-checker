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
    notes.push(`バージョンが分からないプラグイン: ${unknown.join(", ")}（灰判定になります）`);
  }
  if (!findings.some((item) => item.kind === "language")) {
    notes.push("PHP のバージョンは取得できませんでした（分かる場合は入力してください）");
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
    detectCore(generator, resources),
    ...detectPlugins(resources, html),
    ...detectThemes(resources, html),
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
