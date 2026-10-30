// サイドパネルの UI。判定は background が行い、ここは結果を描くだけ。
// 値はすべて textContent で入れる（ページ由来の文字列を HTML として解釈しない）。

import { INDEX_CANDIDATES, INDEX_ORIGINS } from "./config.js";
import { originPattern } from "./patterns.js";

const $ = (id) => document.getElementById(id);

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

/**
 * 勧告 1 件の「影響する Version」を文章にする。
 *
 * 例: ``1.4.2 以下`` / ``7.3.0 〜 8.2.35 未満`` / ``3.29.11 以下``。
 * 範囲が分からない勧告は ``null``。
 */
function affectedRange(advisory) {
  const lower = advisory.affected_at_or_above;
  if (advisory.affected_below) {
    return lower ? `${lower} 〜 ${advisory.affected_below} 未満` : `${advisory.affected_below} より前`;
  }
  if (advisory.affected_upto) {
    return lower ? `${lower} 〜 ${advisory.affected_upto} 以下` : `${advisory.affected_upto} 以下`;
  }
  if (lower) return `${lower} 以降`;
  return null;
}

function advisoryLine(advisory) {
  // 「どの Version が危ないか」を最初に出す（CVE 番号だけでは確認できない）
  const range = affectedRange(advisory);
  const parts = [range ? `${range}が影響` : "影響する Version は不明"];
  // 修正版が範囲から自明（「X より前が影響」＝X で修正）なときは繰り返さない
  const fixed = advisory.fixed;
  if (fixed && fixed !== advisory.affected_below && fixed !== advisory.affected_upto) {
    parts.push(`${fixed} で修正`);
  }
  if (advisory.cvss !== null && advisory.cvss !== undefined) parts.push(`深刻度 ${advisory.cvss}`);
  if (advisory.kev) parts.push("実際に悪用あり");
  // 0% は情報量が無いので出さない
  if (advisory.epss !== null && advisory.epss !== undefined && advisory.epss >= 0.01) {
    parts.push(`悪用の可能性 ${Math.round(advisory.epss * 100)}%`);
  }

  const item = element("li");
  item.append(element("code", "", advisory.id));
  item.append(document.createTextNode(` ｜ ${parts.join(" ｜ ")}`));
  return item;
}

/** 1 件分のカード（信号の枠の中に入れる。色は枠が持つのでバッジは付けない）。 */
function judgementItem(judgement, level) {
  const item = element("div", "item");

  const head = element("div", "item-head");
  head.append(
    element("span", "name", judgement.component),
    element("span", "version", judgement.version ? `Version ${judgement.version}` : "Version 不明"),
  );
  item.append(head);
  item.append(element("p", "action", judgement.action));
  if (judgement.note) item.append(element("p", "empty", judgement.note));

  const advisories = judgement.advisories ?? [];
  if (advisories.length) {
    const list = element("ul", "advisories");
    list.append(...advisories.map(advisoryLine));

    if (level === "none") {
      // 該当なしのときは、過去の勧告を**畳んで**出す（同じ CVE の山で誤解させない）
      const details = document.createElement("details");
      const summary = element("summary", "", `過去の勧告（${advisories.length}件）を見る`);
      details.append(summary, list);
      item.append(details);
    } else {
      item.append(list);
    }
  }
  return item;
}

//: 信号の並び（赤 → 黄 → 緑 → 灰）。空の枠も出して「全体像」が見えるようにする。
const LEVEL_SECTIONS = ["red", "yellow", "none", "gray"];

function renderJudgements(report) {
  const judgements = report.judgements ?? [];
  const groups = { red: [], yellow: [], none: [], gray: [] };
  for (const judgement of judgements) {
    const level = groups[judgement.level] ? judgement.level : "none";
    groups[level].push(judgement);
  }

  for (const level of LEVEL_SECTIONS) {
    const container = $(`items-${level}`);
    const light = document.querySelector(`.light[data-level="${level}"]`);
    const count = groups[level].length;
    container.replaceChildren();
    light?.classList.toggle("off", count === 0);
    const counter = light?.querySelector("[data-count]");
    if (counter) counter.textContent = count ? String(count) : "";

    if (!count) {
      container.append(element("p", "empty", "なし"));
      continue;
    }
    container.append(...groups[level].map((judgement) => judgementItem(judgement, level)));
  }

  const empty = $("levelsEmpty");
  if (!judgements.length) {
    empty.hidden = false;
    empty.textContent = report.indexSize
      ? "該当する勧告はありません（検出できた範囲）"
      : "索引を取得できていないため、脆弱性の判定はしていません（「調べる」を押すと自動で取得します）";
  } else {
    empty.hidden = true;
    empty.textContent = "";
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
  // 索引の鮮度と取得元も出す（本番を向いているか一目で分かるように）
  const generated = report.indexGeneratedAt ? new Date(report.indexGeneratedAt) : null;
  const staleDays = generated ? Math.floor((Date.now() - generated.getTime()) / 86400000) : null;
  let source = null;
  try {
    source = report.indexUrl ? new URL(report.indexUrl).hostname : null;
  } catch {
    source = null;
  }
  const meta = [
    report.scannedAt ? `判定 ${new Date(report.scannedAt).toLocaleString()}` : null,
    generated
      ? `索引 ${report.indexSize ?? 0} 件（${generated.toLocaleDateString()} 生成）`
      : `索引 ${report.indexSize ?? 0} 件`,
    source ? `取得元 ${source}` : null,
    staleDays !== null && staleDays > 14 ? `⚠ 索引が ${staleDays} 日古い` : null,
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

// --- 索引（URL は打たせない・古ければ取りに行く）------------------------------

/**
 * 索引の取得に必要な許可を、**初回だけ**求める。
 *
 * 2 回目以降は許可が残っているので何も聞かない。取得し直すかどうかの判断は
 * background 側（24 時間ルール）が行う。
 */
async function ensureIndexPermission() {
  const stored = await chrome.storage.local
    .get(["indexUpdatedAt", "indexUrl"])
    .catch(() => ({}));

  // 索引が無い、または取得元が本番と違う（古いローカル配信など）なら許可を取る
  const needsPermission =
    !stored.indexUpdatedAt || stored.indexUrl !== INDEX_CANDIDATES[0];

  const haveAll = await chrome.permissions
    .contains({ origins: INDEX_ORIGINS })
    .catch(() => false);
  if (haveAll) return true;

  if (needsPermission) {
    // github.com と リダイレクト先（*.githubusercontent.com）をまとめて求める
    const granted = await chrome.permissions
      .request({ origins: INDEX_ORIGINS })
      .catch(() => false);
    if (granted) return true;
  }
  return Boolean(stored.indexUpdatedAt);
}

/**
 * 調べる本体。許可が足りなければ取りに行き、**必要な分だけ繰り返す**。
 *
 * 索引の許可とサイトの許可は別オリジンなので、片方を取ったあとにもう片方が
 * 足りないことが分かる場合がある（1 回の再試行では終わらない）。最大 3 回まで回す。
 */
async function inspectWithPermissions() {
  let report = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    report = await chrome.runtime.sendMessage({ type: "inspect" });

    if (report?.indexRefresh?.needsIndexPermission) {
      const granted = await chrome.permissions
        .request({ origins: INDEX_ORIGINS })
        .catch(() => false);
      if (granted) continue;
      return report;
    }

    if (report?.needsSitePermission && report.origin) {
      const granted = await chrome.permissions
        .request({ origins: [originPattern(report.origin)] })
        .catch(() => false);
      if (granted) continue;
      return report;
    }

    return report;
  }
  return report;
}

/**
 * 索引の取得エラーを日本語にする。
 *
 * `fetch` の失敗は英語（``Failed to fetch`` など）で返ってくるため、
 * 画面にそのまま出さず、利用者に意味が伝わる日本語に置き換える。
 */
function describeIndexError(message) {
  const text = String(message ?? "");

  const http = /HTTP\s+(\d{3})/i.exec(text);
  if (http) {
    const code = http[1];
    if (code === "404") return "配信元が見つかりません（HTTP 404）";
    if (code.startsWith("5")) return `配信元で問題が起きています（HTTP ${code}）`;
    return `配信元が HTTP ${code} を返しました`;
  }
  if (/failed to fetch|networkerror|load failed|network request failed/i.test(text)) {
    return "通信できませんでした（許可されていないか、ネットワークに繋がっていません）";
  }
  if (/abort|timeout|timed out/i.test(text)) return "時間切れになりました";
  if (/json|unexpected token/i.test(text)) return "索引の形式が正しくありません";
  if (text.includes("索引が空です")) return "索引が空でした";
  if (text.includes("索引を取得できません")) return text; // もともと日本語
  return "原因を特定できませんでした（詳しくは拡張のコンソールを確認してください）";
}

async function inspect({ askPermission = false } = {}) {
  const button = $("inspect");
  button.disabled = true;
  $("status").textContent = "調べています…";
  try {
    if (askPermission) {
      // 索引 → サイト の順に許可を取る（索引が無いと判定できないため）
      await ensureIndexPermission();
      await askHeaderPermission();
    }

    const report = await inspectWithPermissions();

    if (report?.needsSitePermission) {
      $("status").textContent =
        "このサイトへのアクセスが許可されませんでした。ツールバーのアイコンをクリックしてから、もう一度お試しください。";
      return;
    }
    if (report?.error) {
      $("status").textContent = report.error;
      return;
    }

    renderReport(report);

    // 状態の文言は、今回の結果だけを見て決める（前回の文言を残さない）
    const refresh = report.indexRefresh ?? {};
    if (refresh.needsIndexPermission) {
      $("status").textContent =
        "索引の取得が許可されていません。akiramatsumoto-github.github.io へのアクセスを許可してから、もう一度お試しください。";
    } else if (refresh.error) {
      const cached = refresh.usedCached ? "（前回の索引で判定）" : "";
      $("status").textContent = `索引を更新できませんでした: ${describeIndexError(refresh.error)}${cached}`;
    } else {
      $("status").textContent = "";
    }
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
    $("status").textContent = "「このサイトを調べる」を押すと、索引を自動で用意します。";
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
restore();
loadVersions().catch(() => {});
refreshHeaderHint().catch(() => {});
