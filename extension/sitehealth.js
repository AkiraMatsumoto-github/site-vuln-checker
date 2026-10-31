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

function canonicalSection(id) {
  const text = String(id ?? "").trim().toLowerCase();
  for (const [key, aliases] of SECTION_ALIASES) {
    if (aliases.some((alias) => text === alias || text.includes(alias))) return key;
  }
  return null;
}

function rowsToMap(rows) {
  const map = new Map();
  for (const [label, value] of rows) {
    const key = String(label ?? "")
      .trim()
      .replace(/[:：]\s*$/, "")
      .toLowerCase();
    map.set(key, String(value ?? "").trim());
  }
  return map;
}

function componentsFrom(rows) {
  // 形式 1: 「プラグイン名: 1.2.3」の 1 行形式
  const list = [];
  for (const [label, value] of rows) {
    const text = String(label ?? "").trim();
    const match = NAME_VERSION_RE.exec(text);
    if (match) {
      list.push({ name: match[1].trim(), version: match[2] });
      continue;
    }
    // 「名前」と「バージョン」が別の行になっている形式（テーマなど）
    const version = VERSION_RE.exec(String(value ?? ""));
    if (text && version && !text.endsWith(":") && !text.endsWith("：")) {
      list.push({ name: text, version: version[0] });
    }
  }
  if (list.length) return list;

  // 形式 2: 「name: / version:」の key-value 形式
  const map = rowsToMap(rows);
  const name = map.get("name") ?? map.get("名前") ?? map.get("テーマ名");
  if (!name) return [];
  const version = map.get("version") ?? map.get("バージョン") ?? null;
  return [{ name, version }];
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

    if (key === "wp-core") info.core = map.get("version") ?? info.core;
    if (key === "wp-server") {
      info.php = map.get("php_version") ?? info.php;
      info.sapi = map.get("php_sapi") ?? info.sapi;
      info.httpd = map.get("httpd_software") ?? info.httpd;
    }
    if (key === "wp-database") info.database = map.get("server_version") ?? info.database;
    if (key === "wp-plugins-active") info.pluginsActive = componentsFrom(rows);
    if (key === "wp-plugins-inactive") info.pluginsInactive = componentsFrom(rows);
    if (key === "wp-themes-active") info.themesActive = componentsFrom(rows);
    if (key === "wp-themes-inactive") info.themesInactive = componentsFrom(rows);
  }
  return info;
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
