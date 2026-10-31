import assert from "node:assert/strict";
import { test } from "node:test";

import { parseSiteHealth, siteHealthFindings } from "../sitehealth.js";

// tests/fixtures/site_health.html と同じ内容を、DOM から取り出した形で用意する
const SECTIONS = [
  { id: "wp-core", rows: [["version:", "6.8.2"], ["site_language:", "ja"]] },
  {
    id: "wp-plugins-active",
    rows: [
      ["Akismet Anti-spam: 5.3.1", "自動更新: 有効"],
      ["Contact Form 7: 5.9.8", "自動更新: 無効"],
    ],
  },
  { id: "wp-plugins-inactive", rows: [["Hello Dolly: 1.7.2", "自動更新: 無効"]] },
  {
    id: "wp-server",
    rows: [
      ["httpd_software:", "nginx/1.27.3"],
      ["php_version:", "8.1.31"],
      ["php_sapi:", "fpm-fcgi"],
    ],
  },
  { id: "wp-database", rows: [["extension:", "mysqli"], ["server_version:", "MariaDB 10.6.18"]] },
  { id: "wp-active-theme", rows: [["name:", "Twenty Twenty-Five"], ["version:", "1.2"]] },
];

test("サイトヘルスから PHP・コア・プラグインを読む", () => {
  const info = parseSiteHealth(SECTIONS);
  assert.equal(info.php, "8.1.31");
  assert.equal(info.core, "6.8.2");
  assert.equal(info.httpd, "nginx/1.27.3");
  assert.equal(info.sapi, "fpm-fcgi");
  assert.equal(info.database, "MariaDB 10.6.18");
  assert.deepEqual(
    info.pluginsActive.map((item) => `${item.name}@${item.version}`),
    ["Akismet Anti-spam@5.3.1", "Contact Form 7@5.9.8"],
  );
  assert.deepEqual(
    info.pluginsInactive.map((item) => item.name),
    ["Hello Dolly"],
  );
  assert.deepEqual(
    info.themesActive.map((item) => `${item.name}@${item.version}`),
    ["Twenty Twenty-Five@1.2"],
  );
});

test("日本語の見出しでも同じ結果になる", () => {
  const japanese = [
    { id: "サーバー", rows: [["php_version:", "8.3.6"]] },
    { id: "有効なプラグイン", rows: [["WPForms: 1.9.2", "自動更新: 有効"]] },
  ];
  const info = parseSiteHealth(japanese);
  assert.equal(info.php, "8.3.6");
  assert.deepEqual(
    info.pluginsActive.map((item) => item.name),
    ["WPForms"],
  );
});

test("findings へ変換すると サイトヘルス根拠・確度 1 になる", () => {
  const findings = siteHealthFindings(parseSiteHealth(SECTIONS));
  const php = findings.find((item) => item.kind === "language");
  assert.equal(php.name, "php");
  assert.equal(php.version, "8.1.31");
  assert.equal(php.confidence, 1);
  assert.deepEqual(php.evidence, ["site-health:wp-server"]);

  const core = findings.find((item) => item.kind === "core");
  assert.equal(core.version, "6.8.2");

  const active = findings.filter((item) => item.kind === "plugin" && item.active === true);
  assert.equal(active.length, 2);
  const inactive = findings.filter((item) => item.kind === "plugin" && item.active === false);
  assert.equal(inactive.length, 1);
});

test("空の入力でも落ちない", () => {
  const info = parseSiteHealth([]);
  assert.equal(info.php, null);
  assert.deepEqual(siteHealthFindings(info), []);
});
