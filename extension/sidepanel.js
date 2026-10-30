// サイドパネルの UI。判定は background が行い、ここは結果を描くだけ。
// 値はすべて textContent で入れる（ページ由来の文字列を HTML として解釈しない）。

import { INDEX_CANDIDATES } from "./config.js";
import { originPattern } from "./patterns.js";

const $ = (id) => document.getElementById(id);

const LEVEL_LABEL = {
  red: "🔴 赤",
  yellow: "🟡 黄",
  gray: "⚪ 灰",
  none: "—",
};

const KIND_LABEL = {
  platform: "基盤",
  core: "コア",
  plugin: "プラグイン",
  theme: "テーマ",
  library: "JS",
  language: "言語",
  server: "サーバ",
  database: "DB",
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function advisoryLine(advisory) {
  const parts = [`CVSS ${advisory.cvss ?? "—"}`];
  if (advisory.kev) parts.push("KEV");
  if (advisory.epss !== null && advisory.epss !== undefined) {
    parts.push(`EPSS ${Math.round(advisory.epss * 100)}%`);
  }
  const item = element("li");
  item.append(element("code", "", advisory.id));
  item.append(document.createTextNode(` ・ ${parts.join(" ・ ")}`));
  return item;
}

function renderJudgements(report) {
  const container = $("judgements");
  container.replaceChildren();
  const judgements = report.judgements ?? [];

  if (!judgements.length) {
    const message = report.indexSize
      ? "該当する勧告はありません（検出できた範囲）"
      : "索引が未設定のため、脆弱性の判定はしていません（設定から索引を読み込んでください）";
    container.append(element("p", "empty", message));
    return;
  }

  for (const judgement of judgements) {
    const level = LEVEL_LABEL[judgement.level] ? judgement.level : "none";
    const item = element("div", `item ${level}`);

    const head = element("div", "item-head");
    head.append(
      element("span", `badge ${level}`, LEVEL_LABEL[level]),
      element("span", "name", judgement.component),
      element("span", "version", judgement.version ? `v${judgement.version}` : "版不明"),
    );
    item.append(head);
    item.append(element("p", "action", judgement.action));
    if (judgement.note) item.append(element("p", "empty", judgement.note));

    const advisories = (judgement.advisories ?? []).map(advisoryLine);
    if (advisories.length) {
      const list = element("ul", "advisories");
      list.append(...advisories);
      item.append(list);
    }
    container.append(item);
  }
}

function renderComponents(report) {
  const container = $("components");
  container.replaceChildren();
  const findings = report.findings ?? [];
  if (!findings.length) {
    container.append(element("p", "empty", "検出できませんでした"));
    return;
  }

  const table = element("table");
  const head = element("thead");
  const headRow = element("tr");
  for (const label of ["種別", "名前", "版", "確度"]) headRow.append(element("th", "", label));
  head.append(headRow);

  const body = element("tbody");
  for (const finding of findings) {
    const row = element("tr");
    row.append(
      element("td", "", KIND_LABEL[finding.kind] ?? finding.kind),
      element("td", "", finding.name),
      element("td", "", finding.version ?? "—"),
      element("td", "", Number(finding.confidence ?? 0).toFixed(2)),
    );
    body.append(row);
  }
  table.append(head, body);
  container.append(table);
}

function renderNotes(report) {
  const notes = report.notes ?? [];
  $("unknownSection").hidden = notes.length === 0;
  const list = $("unknown");
  list.replaceChildren(...notes.map((note) => element("li", "", note)));
}

function renderReport(report) {
  if (!report) return;
  $("target").textContent = report.url ?? "";
  $("result").hidden = false;
  renderJudgements(report);
  renderComponents(report);
  renderNotes(report);

  const levels = report.levels ?? {};
  const meta = [
    report.scannedAt ? `判定 ${new Date(report.scannedAt).toLocaleString()}` : null,
    `索引 ${report.indexSize ?? 0} 件`,
    levels.red ? `赤 ${levels.red}` : null,
    levels.yellow ? `黄 ${levels.yellow}` : null,
  ].filter(Boolean);
  $("meta").textContent = meta.join(" ／ ");
}

// --- ヘッダの許可（初回だけ聞く）---------------------------------------------

const DECLINED_KEY = "declinedOrigins";

/**
 * このサイトのヘッダを読む許可を、**初回だけ**求める。
 *
 * Chrome の仕様上、サイトごとの許可は**ユーザー操作からしか**要求できないため、
 * 「このサイトを調べる」のクリック内で聞く（別ボタンは置かない）。
 * 断られたら記録して、次からは黙って判定だけ続ける（何度も聞かない）。
 */
async function askHeaderPermission() {
  const info = await chrome.runtime.sendMessage({ type: "versions" }).catch(() => null);
  if (!info?.origin) return false;
  const pattern = originPattern(info.origin);

  if (await chrome.permissions.contains({ origins: [pattern] }).catch(() => false)) return true;

  const stored = await chrome.storage.local.get(DECLINED_KEY).catch(() => ({}));
  const declined = stored[DECLINED_KEY] ?? {};
  if (declined[info.origin]) {
    // 以前に断られている。しつこく聞かず、必要なら小さなリンクから再要求できるようにする。
    showRetryLink(true);
    return false;
  }

  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: [pattern] });
  } catch {
    // 操作が古くなった等で要求できないことがある。判定は続ける。
    return false;
  }
  if (granted) {
    showRetryLink(false);
    return true;
  }

  declined[info.origin] = true;
  await chrome.storage.local.set({ [DECLINED_KEY]: declined }).catch(() => {});
  showRetryLink(true);
  return false;
}

function showRetryLink(show) {
  const link = $("grantHeaders");
  if (link) link.hidden = !show;
}

/** すでに許可済み／拒否済みの状態を画面に反映する（表示だけ）。 */
async function refreshHeaderHint() {
  const info = await chrome.runtime.sendMessage({ type: "versions" }).catch(() => null);
  if (!info?.origin) return;
  const pattern = originPattern(info.origin);
  if (await chrome.permissions.contains({ origins: [pattern] }).catch(() => false)) {
    showRetryLink(false);
    return;
  }
  const stored = await chrome.storage.local.get(DECLINED_KEY).catch(() => ({}));
  showRetryLink(Boolean(stored[DECLINED_KEY]?.[info.origin]));
}

// --- 索引（URL は打たせない）-------------------------------------------------

/**
 * 索引が未読込なら、候補 URL を順に試して**自動で**読み込む。
 *
 * 許可が要るので、ユーザー操作（「このサイトを調べる」）の流れでだけ呼ぶ。
 */
async function ensureIndexLoaded() {
  const stored = await chrome.storage.local.get(["indexUpdatedAt"]).catch(() => ({}));
  if (stored.indexUpdatedAt) return true;

  for (const url of INDEX_CANDIDATES) {
    const pattern = originPattern(url);
    const granted = await chrome.permissions
      .contains({ origins: [pattern] })
      .catch(() => false);
    const allowed =
      granted || (await chrome.permissions.request({ origins: [pattern] }).catch(() => false));
    if (!allowed) continue;

    $("status").textContent = "索引を読み込んでいます…";
    const result = await chrome.runtime.sendMessage({ type: "loadIndex", url }).catch(() => null);
    if (result?.count) return true;
  }
  return false;
}

async function inspect({ askPermission = false } = {}) {
  const button = $("inspect");
  button.disabled = true;
  $("status").textContent = "調べています…";
  try {
    if (askPermission) {
      const loaded = await ensureIndexLoaded();
      if (!loaded) {
        $("status").textContent =
          "索引を読み込めませんでした（配信が止まっている可能性があります。詳細は設定を確認してください）";
      }
      await askHeaderPermission();
    }
    const report = await chrome.runtime.sendMessage({ type: "inspect" });
    if (report?.error) {
      $("status").textContent = report.error;
      return;
    }
    renderReport(report);
    $("status").textContent = "";
  } catch (error) {
    $("status").textContent = `失敗しました: ${String(error?.message ?? error)}`;
  } finally {
    button.disabled = false;
  }
}

async function restore() {
  const report = await chrome.runtime.sendMessage({ type: "getReport" }).catch(() => null);
  if (report) renderReport(report);
  const stored = await chrome.storage.local.get(["indexUpdatedAt"]).catch(() => ({}));
  if (!stored.indexUpdatedAt) {
    $("status").textContent = "初回のチェック時に、弱点の一覧表を自動で読み込みます。";
  }
}

// --- 入力（PHP とフレームワークのバージョン）----------------------------------

const PRODUCT_LABEL = {
  php: "PHP",
  wordpress: "WordPress",
  laravel: "Laravel",
  symfony: "Symfony",
  codeigniter: "CodeIgniter",
  cakephp: "CakePHP",
  django: "Django",
  rails: "Ruby on Rails",
};

function renderVersions(versions) {
  const list = $("versionList");
  list.replaceChildren();
  const entries = Object.entries(versions || {});
  if (!entries.length) {
    list.append(element("li", "chip empty", "未入力（外から分かる範囲だけで判定します）"));
    return;
  }
  for (const [product, version] of entries) {
    const item = element("li", "chip");
    item.append(element("span", "", `${PRODUCT_LABEL[product] ?? product} ${version}`));
    const remove = element("button", "chip-remove", "×");
    remove.type = "button";
    remove.title = "入力を削除";
    remove.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "setVersion", product, version: "" });
      await loadVersions();
      await inspect();
    });
    item.append(remove);
    list.append(item);
  }
}

async function loadVersions() {
  const result = await chrome.runtime
    .sendMessage({ type: "versions" })
    .catch(() => ({ versions: {} }));
  renderVersions(result?.versions ?? {});
  return result?.versions ?? {};
}

async function addVersion() {
  const product = $("product").value;
  const version = $("version").value.trim();
  if (!version) {
    $("status").textContent = "バージョンを入力してください（例: 8.1.27）";
    return;
  }
  if (!/^\d+(\.\d+)*/i.test(version)) {
    $("status").textContent = "バージョンの形式を確認してください（例: 8.1.27）";
    return;
  }
  const result = await chrome.runtime.sendMessage({ type: "setVersion", product, version });
  if (result?.error) {
    $("status").textContent = result.error;
    return;
  }
  $("version").value = "";
  renderVersions(result?.versions ?? {});
  $("status").textContent = "入力を反映して判定し直しました";
  await inspect();
}

/** 断られたあとに、もう一度だけ許可を求める（リンクから明示的に押したとき）。 */
async function retryHeaderPermission() {
  const info = await chrome.runtime.sendMessage({ type: "versions" }).catch(() => null);
  if (!info?.origin) {
    $("status").textContent = "http / https のページを開いてください";
    return;
  }
  const pattern = originPattern(info.origin);
  const stored = await chrome.storage.local.get(DECLINED_KEY).catch(() => ({}));
  const declined = stored[DECLINED_KEY] ?? {};
  delete declined[info.origin];
  await chrome.storage.local.set({ [DECLINED_KEY]: declined }).catch(() => {});

  const granted = await chrome.permissions.request({ origins: [pattern] }).catch(() => false);
  showRetryLink(!granted);
  $("status").textContent = granted
    ? "このサイトのヘッダを読むようにしました"
    : "許可されませんでした（判定は続けられます）";
  await inspect();
}

$("addVersion").addEventListener("click", () => {
  addVersion().catch((error) => {
    $("status").textContent = `失敗しました: ${String(error?.message ?? error)}`;
  });
});
$("version").addEventListener("keydown", (event) => {
  if (event.key === "Enter") addVersion().catch(() => {});
});
$("grantHeaders").addEventListener("click", () => {
  retryHeaderPermission().catch((error) => {
    $("status").textContent = `失敗しました: ${String(error?.message ?? error)}`;
  });
});

// 「調べる」のクリックで、初回だけヘッダの許可を聞く（ユーザー操作が必要なため）
$("inspect").addEventListener("click", () => {
  inspect({ askPermission: true }).catch(() => {});
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
restore();
loadVersions().catch(() => {});
refreshHeaderHint().catch(() => {});
