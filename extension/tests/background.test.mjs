// background.js のサイトヘルス読み取り（DOM 依存）を、chrome と document の
// 最小スタブで検証する。WordPress 6.x のマークアップ（アコーディオン + 表）を再現する。
import assert from "node:assert/strict";
import { test } from "node:test";

// --- DOM スタブ -----------------------------------------------------------------

function el(tagName, textContent = "", children = []) {
  const node = {
    tagName,
    textContent,
    children,
    parentElement: null,
    previousElementSibling: null,
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  for (const child of children) child.parentElement = node;
  children.forEach((child, index) => {
    child.previousElementSibling = index > 0 ? children[index - 1] : null;
  });
  return node;
}

const cell = (tagName, text) => el(tagName, text);
const row = (label, value) => el("TR", `${label}${value}`, [cell("TD", label), cell("TD", value)]);

function table(rows) {
  const node = el("TABLE", "", rows);
  node.querySelectorAll = (selector) => (selector === "tr" ? rows : []);
  return node;
}

/** WordPress の「情報」タブ: h3（見出し） → div.panel（id でセクションが分かる） → table */
function section(title, key, rows) {
  const heading = el("H3", title, [el("BUTTON", title)]);
  const panel = el("DIV", "", [table(rows)]);
  panel.id = `health-check-accordion-block-${key}`;
  return el("DIV", "", [heading, panel]);
}

function wpInfoDom() {
  // WordPress と同じく、見出しは翻訳済みの表示名・行ラベルは人間向けの文言。
  const root = el("DIV", "", [
    section("WordPress", "wp-core", [row("Version", "6.8.2"), row("Site Language", "ja")]),
    section("Active Plugins (1)", "wp-plugins-active", [
      row("Contact Form 7", "Version 5.9.8 | Auto-updates: Disabled"),
    ]),
    section("Inactive Plugins (1)", "wp-plugins-inactive", [
      row("Hello Dolly", "Version 1.7.2 | Auto-updates: Disabled"),
    ]),
    section("Server", "wp-server", [
      row("Web server", "nginx/1.27.3"),
      row("PHP version", "8.1.31"),
      row("PHP SAPI", "fpm-fcgi"),
    ]),
    section("Database", "wp-database", [row("Database server version", "MariaDB 10.6.18")]),
    section("Active Theme", "wp-active-theme", [
      row("Name", "Twenty Twenty-Five"),
      row("Version", "1.2"),
      row("Author", "the WordPress team"),
    ]),
  ]);

  const tables = [];
  (function walk(node) {
    for (const child of node.children ?? []) {
      if (child.tagName === "TABLE") tables.push(child);
      walk(child);
    }
  })(root);

  return {
    querySelectorAll: (selector) => (selector === "table" ? tables : []),
    documentElement: { outerHTML: '<div class="health-check-body"></div>' },
  };
}

/** 「ステータス」画面: サイトヘルスの表は無い */
function statusDom() {
  const list = table([row("停止中のプラグインを削除してください", "セキュリティ")]);
  return {
    querySelectorAll: (selector) => (selector === "table" ? [list] : []),
    documentElement: { outerHTML: "<html><body>ステータス</body></html>" },
  };
}

// --- chrome スタブ（状態を差し替えて使う）---------------------------------------

const state = {
  url: "",
  empty: false,
  calls: { update: [], head: 0, executeScript: 0 },
  local: {},
  listeners: [],
};

function resetState(url, { empty = false } = {}) {
  state.url = url;
  state.empty = empty;
  state.calls.update = [];
  state.calls.head = 0;
  state.calls.executeScript = 0;
  for (const key of Object.keys(state.local)) delete state.local[key];
}

function storageArea(store) {
  const normalize = (keys) => (keys == null ? null : Array.isArray(keys) ? keys : [keys]);
  return {
    async get(keys) {
      if (keys == null) return { ...store };
      const out = {};
      for (const key of normalize(keys)) if (key in store) out[key] = store[key];
      return out;
    },
    async set(items) {
      Object.assign(store, items);
    },
    async remove(keys) {
      for (const key of normalize(keys)) delete store[key];
    },
  };
}

globalThis.chrome = {
  runtime: {
    getManifest: () => ({ version: "0.4.5" }),
    onInstalled: { addListener() {} },
    onMessage: {
      addListener(fn) {
        state.listeners.push(fn);
      },
    },
  },
  alarms: { create() {}, onAlarm: { addListener() {} } },
  sidePanel: { setPanelBehavior: async () => {} },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
  permissions: { contains: async () => true, request: async () => true },
  storage: { local: storageArea(state.local), session: storageArea({}) },
  tabs: {
    query: async () => [{ id: 1, url: state.url, title: "テスト" }],
    get: async () => ({ id: 1, url: state.url, status: "complete" }),
    update: async (_id, props) => {
      state.calls.update.push(props.url);
      state.url = props.url ?? state.url;
      return { id: 1, url: state.url, status: "complete" };
    },
  },
  scripting: {
    async executeScript({ func }) {
      state.calls.executeScript += 1;
      if (func.name !== "collectSiteHealth") {
        // collectEvidence は location / performance を使うので、ここでは偽の結果を返す
        return [{ result: { url: state.url, html: "<html></html>", resources: [] } }];
      }
      // collectSiteHealth はページの document を読むので、URL に応じて DOM を差し替える
      globalThis.document =
        state.empty || !state.url.includes("tab=debug") ? statusDom() : wpInfoDom();
      return [{ result: func() }];
    },
  },
};

globalThis.fetch = async (_input, options = {}) => {
  if (options.method === "HEAD") state.calls.head += 1;
  return {
    ok: true,
    status: 200,
    headers: { get: () => null, entries: () => new Map().entries() },
    json: async () => ({
      generated_at: "2026-10-29T00:00:00Z",
      advisories: [
        { id: "CVE-TEST-0001", name: "PHP", slug: "php", affected_below: "9.9.9", fixed: "9.9.9" },
      ],
    }),
    text: async () => "",
  };
};

await import("../background.js");

function send(type) {
  return new Promise((resolve) => {
    const handled = state.listeners.some((fn) => fn({ type }, {}, resolve) === true);
    assert.ok(handled, `${type} が処理されない`);
  });
}

// --- テスト（状態を共有するので**順番に**実行する）-----------------------------

test("background: サイトヘルスの読み取り", async (t) => {
  await t.test("WordPress 6.x の「情報」タブ（表がアコーディオンの panel 内）から読める", async () => {
    resetState("https://example.com/wp-admin/site-health.php?tab=debug");

    const report = await send("inspect");
    assert.ok(report.siteHealthRead?.info, "サイトヘルスが読めていない");

    const info = report.siteHealthRead.info;
    assert.equal(info.core, "6.8.2");
    assert.equal(info.php, "8.1.31");
    assert.equal(info.httpd, "nginx/1.27.3");
    assert.deepEqual(
      info.pluginsActive.map((item) => `${item.name}@${item.version}`),
      ["Contact Form 7@5.9.8"],
    );
    assert.deepEqual(
      info.pluginsInactive.map((item) => item.name),
      ["Hello Dolly"],
    );

    // 実測値が判定に使われる
    const php = report.findings.find((item) => item.kind === "language");
    assert.equal(php?.version, "8.1.31");
    assert.ok(php?.evidence?.includes("site-health:wp-server"));
    assert.equal(state.calls.head, 0, "サイトヘルス画面では HEAD を送らない");
  });

  await t.test("「ステータス」画面なら自動で「情報」タブへ移動して読む", async () => {
    resetState("https://example.com/wp-admin/site-health.php");

    const report = await send("inspect");
    assert.equal(state.calls.update.length, 1, "自動で遷移していない");
    assert.match(state.calls.update[0], /tab=debug/, "遷移先が情報タブでない");
    assert.equal(report.siteHealthRead?.info?.php, "8.1.31");
    assert.match(report.url, /tab=debug/, "判定対象が情報タブになっていない");
    assert.ok(state.local.siteHealth?.["https://example.com"], "オリジン単位で保存していない");
    assert.equal(state.calls.head, 0, "サイトヘルス画面では HEAD を送らない");
  });

  await t.test("すでに「情報」タブなら遷移しない", async () => {
    resetState("https://example.com/wp-admin/site-health.php?tab=debug");

    await send("inspect");
    assert.equal(state.calls.update.length, 0, "余計に再読み込みしている");
  });

  await t.test("管理画面のトップからは、自動で情報タブへ移動して読む", async () => {
    resetState("https://example.com/wp-admin/");

    const report = await send("inspect");
    assert.equal(state.calls.update.length, 1, "自動で遷移していない");
    assert.equal(
      state.calls.update[0],
      "https://example.com/wp-admin/site-health.php?tab=debug",
      "遷移先が違う",
    );
    assert.equal(report.siteHealthRead?.info?.php, "8.1.31");
    assert.ok(state.calls.head <= 1, "サイトヘルス以外の HEAD は 1 回まで");
  });

  await t.test("投稿の編集中などは遷移しない（未保存の編集を失わせない）", async () => {
    resetState("https://example.com/wp-admin/post.php?post=1&action=edit");

    const report = await send("inspect");
    assert.equal(state.calls.update.length, 0, "編集画面から勝手に遷移している");
    assert.equal(report.siteHealthRead, null, "サイトヘルスを読もうとしている");
  });

  await t.test("「情報」タブでも表が無ければ、開き直しを案内する", async () => {
    resetState("https://example.com/wp-admin/site-health.php?tab=debug", { empty: true });

    const report = await send("inspect");
    assert.equal(report.siteHealthRead?.info, undefined);
    assert.match(report.siteHealthRead.error, /「情報」タブ/);
  });
});

