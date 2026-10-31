// WordPress「ツール → サイトヘルス → 情報」の解析。
//
// Python 版（src/site_vuln_checker/sitehealth.py）と同じ仕様。
// 外部からは分からない **PHP の Version** も、管理者としてログインしていれば
// この画面から確定できる（企画書 6.4）。DOM から読むだけで、追加の通信はしない。
//
// 入力は「セクション見出し + 表の行（ラベル / 値）」の配列:
//   [{ id: "wp-server", rows: [["php_version:", "8.1.31"], ...] }, ...]

/** セクション見出しの対応表。**上から順**に判定する（active を core より先に）。 */
const SECTION_ALIASES = [
  ["wp-plugins-active", ["wp-plugins-active", "active plugins", "有効なプラグイン"]],
  ["wp-plugins-inactive", ["wp-plugins-inactive", "inactive plugins", "無効なプラグイン"]],
  ["wp-themes-active", ["wp-active-theme", "active theme", "使用中のテーマ", "有効なテーマ"]],
  ["wp-themes-inactive", ["wp-themes-inactive", "inactive themes", "未使用のテーマ", "無効なテーマ"]],
  ["wp-server", ["wp-server", "server", "サーバー", "サーバ"]],
  ["wp-database", ["wp-database", "database", "データベース"]],
  ["wp-core", ["wp-core", "wordpress"]],
];

const NAME_VERSION_RE = /^(.+?)\s*[:：]\s*(\d[0-9A-Za-z.+-]*)\s*$/;
const VERSION_RE = /\d+\.\d+(?:\.\d+)*(?:[-+~][0-9A-Za-z.-]+)?/;

//: 表の行ラベルは翻訳される（例: `php_version` ではなく「PHP version」）。
//: 英語・日本語の表記ゆれを吸収するための別名。
const FIELD_ALIASES = {
  core: ["version", "バージョン"],
  php: ["php_version", "php version", "php バージョン", "phpのバージョン"],
  sapi: ["php_sapi", "php sapi"],
  httpd: [
    "httpd_software",
    "web server",
    "webserver",
    "ウェブサーバー",
    "webサーバー",
    "サーバーソフトウェア",
  ],
  database: [
    "server_version",
    "database server version",
    "データベースサーバーのバージョン",
    "データベースのバージョン",
  ],
};

//: テーマの「Name / Version / Author」のような**項目名**は、プラグイン名として扱わない。
const FIELD_LABELS = new Set([
  "name",
  "version",
  "author",
  "auto-update",
  "auto update",
  "status",
  "directory",
  "directory size",
  "translation",
  "text direction",
  "network",
  "must-use",
  "drop-in",
  "名前",
  "バージョン",
  "作成者",
  "自動更新",
  "状態",
  "ディレクトリ",
  "ディレクトリのサイズ",
  "翻訳",
  "テキストの方向",
  "ネットワーク",
  "ドロップイン",
]);

function canonicalSection(id) {
  const text = String(id ?? "").trim().toLowerCase();
  for (const [key, aliases] of SECTION_ALIASES) {
    if (aliases.some((alias) => text === alias || text.includes(alias))) return key;
  }
  return null;
}

function normalizeLabel(value) {
  return String(value ?? "")
    .trim()
    .replace(/[:：]\s*$/, "")
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function rowsToMap(rows) {
  const map = new Map();
  for (const [label, value] of rows) {
    map.set(normalizeLabel(label), String(value ?? "").trim());
  }
  return map;
}

/** 別名のどれかに一致する値を返す（`php_version` と「PHP version」の両方を受ける）。 */
function pick(map, names) {
  for (const name of names) {
    const value = map.get(normalizeLabel(name));
    if (value) return value;
  }
  return null;
}

function componentsFrom(rows) {
  // 形式 1: 「プラグイン名: 1.2.3」または「プラグイン名 | Version 1.2.3」
  const list = [];
  for (const [label, value] of rows) {
    const text = String(label ?? "").trim();
    const inline = NAME_VERSION_RE.exec(text);
    if (inline) {
      list.push({ name: inline[1].trim(), version: inline[2] });
      continue;
    }
    // 「Name / Version / Author」のような項目行は、名前として扱わない
    if (!text || FIELD_LABELS.has(normalizeLabel(text))) continue;
    const version = VERSION_RE.exec(String(value ?? ""));
    if (version) list.push({ name: text, version: version[0] });
  }
  if (list.length) return list;

  // 形式 2: 「name: / version:」の key-value 形式（テーマなど）
  const map = rowsToMap(rows);
  const name = pick(map, ["name", "名前", "テーマ名", "plugin name", "プラグイン名"]);
  if (!name) return [];
  return [{ name, version: pick(map, ["version", "バージョン"]) }];
}

/**
 * サイトヘルスのセクション配列を、判定に使える形へ変換する。
 *
 * @param {Array<{id: string, rows: Array<[string, string]>}>} sections
 */
export function parseSiteHealth(sections) {
  const info = {
    core: null,
    php: null,
    sapi: null,
    httpd: null,
    database: null,
    pluginsActive: [],
    pluginsInactive: [],
    themesActive: [],
    themesInactive: [],
  };

  for (const section of sections ?? []) {
    const key = canonicalSection(section?.id);
    if (!key) continue;
    const rows = (section.rows ?? []).map(([a, b]) => [a ?? "", b ?? ""]);
    const map = rowsToMap(rows);

    if (key === "wp-core") info.core = pick(map, FIELD_ALIASES.core) ?? info.core;
    if (key === "wp-server") {
      info.php = pick(map, FIELD_ALIASES.php) ?? info.php;
      info.sapi = pick(map, FIELD_ALIASES.sapi) ?? info.sapi;
      info.httpd = pick(map, FIELD_ALIASES.httpd) ?? info.httpd;
    }
    if (key === "wp-database") info.database = pick(map, FIELD_ALIASES.database) ?? info.database;
    if (key === "wp-plugins-active") info.pluginsActive = componentsFrom(rows);
    if (key === "wp-plugins-inactive") info.pluginsInactive = componentsFrom(rows);
    if (key === "wp-themes-active") info.themesActive = componentsFrom(rows);
    if (key === "wp-themes-inactive") info.themesInactive = componentsFrom(rows);
  }
  return info;
}

/**
 * サイトヘルスの「情報」の表が HTML に含まれているか（**URL に依存しない判定**）。
 *
 * WordPress は「状態」タブを開いていても情報タブの表を同じページに出力するので、
 * URL が `site-health.php` でなくても（管理画面の外でも）中身があれば読める。
 * ここは**取りこぼさない側**に倒し、実際に値が取れたかは `hasSiteHealthData` で見る。
 */
export function looksLikeSiteHealthHtml(html) {
  const text = String(html ?? "");
  if (/health-check/i.test(text)) return true;
  return /wp-core/i.test(text) && /wp-server/i.test(text);
}

/** 読み取れた中身が実質空かどうか（空なら保存しない・警告も出さない）。 */
export function hasSiteHealthData(info) {
  if (!info) return false;
  if (info.core || info.php || info.sapi || info.httpd || info.database) return true;
  return (
    info.pluginsActive.length > 0 ||
    info.pluginsInactive.length > 0 ||
    info.themesActive.length > 0 ||
    info.themesInactive.length > 0
  );
}

/** サイトヘルスの情報を検出結果（findings）へ変換する。 */
export function siteHealthFindings(info) {
  const findings = [];
  const add = (kind, name, version, evidence) => {
    if (!name) return;
    findings.push({ kind, name, version: version ?? null, confidence: 1, evidence: [evidence], active: null });
  };

  if (info.core) add("core", "wordpress", info.core, "site-health:wp-core");
  if (info.php) add("language", "php", info.php, "site-health:wp-server");
  if (info.httpd) {
    const match = /([A-Za-z][A-Za-z0-9-]*)\/(\d+(?:\.\d+)+)/.exec(info.httpd);
    if (match) add("server", match[1].toLowerCase(), match[2], "site-health:wp-server");
    else add("server", String(info.httpd).split(/\s+/)[0].toLowerCase(), null, "site-health:wp-server");
  }
  if (info.database) {
    const match = /([A-Za-z][A-Za-z0-9-]*)\s*(\d+(?:\.\d+)+)/.exec(info.database);
    if (match) add("database", match[1].toLowerCase(), match[2], "site-health:wp-database");
  }

  for (const plugin of info.pluginsActive) {
    findings.push({
      kind: "plugin",
      name: plugin.name,
      version: plugin.version,
      confidence: 1,
      evidence: ["site-health:wp-plugins-active"],
      active: true,
    });
  }
  for (const plugin of info.pluginsInactive) {
    findings.push({
      kind: "plugin",
      name: plugin.name,
      version: plugin.version,
      confidence: 1,
      evidence: ["site-health:wp-plugins-inactive"],
      active: false,
    });
  }
  for (const theme of info.themesActive) {
    findings.push({
      kind: "theme",
      name: theme.name,
      version: theme.version,
      confidence: 1,
      evidence: ["site-health:wp-themes-active"],
      active: true,
    });
  }
  return findings;
}
