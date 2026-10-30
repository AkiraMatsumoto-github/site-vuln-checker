// バックグラウンド（Service Worker）。
//
// 役割:
// 1. アイコンクリックでサイドパネルを開く
// 2. サイドパネルからの依頼で「いま開いているタブ」を調べる
//    - chrome.scripting で証拠（HTML・読み込み済みリソース）を集める
//    - detector で技術構成を推定し、advisor で索引と突き合わせる
//    - 結果は storage.session に置き、サイドパネルへ送る
// 3. 索引（advisories.json）を日次で取り直す
//
// 方針（企画書 12.5）: 秘密（API キー）は持たない。通信は索引の取得だけ。

import { AdvisoryIndex, judge, normalizeSlug, summarizeLevels } from "./advisor.js";
import { INDEX_CANDIDATES, INDEX_ORIGINS, isIndexStale } from "./config.js";
import { analyze, buildNotes } from "./detector.js";
import { originPattern } from "./patterns.js";

const REPORT_KEY = "lastReport";
const INDEX_KEY = "index";
const INDEX_URL_KEY = "indexUrl";
const VERSIONS_KEY = "versions";
const STATE_VERSION_KEY = "stateVersion";
const REFRESH_ALARM = "refresh-index";

//: 保存データの形の版。取得元や保存項目を変えたら上げる（更新時に古い状態を捨てる）
const STATE_VERSION = 2;

//: 入力された製品名 → 検出結果の種別（PHP は言語、WordPress はコア、他はフレームワーク）
const KIND_BY_PRODUCT = { php: "language", wordpress: "core" };

/**
 * 古い版の保存データを捨てる（再インストールしなくても直るように）。
 *
 * - 索引の取得元が今と違う（例: 以前の localhost / Releases）→ 索引を作り直す
 * - 拒否履歴は、取得元が変わったら無効（もう一度だけ聞き直す）
 */
async function migrateStorage(details) {
  const stored = await chrome.storage.local.get([
    INDEX_KEY,
    INDEX_URL_KEY,
    STATE_VERSION_KEY,
    "declinedOrigins",
  ]);

  const expected = INDEX_CANDIDATES[0];
  const staleSource = stored[INDEX_URL_KEY] && stored[INDEX_URL_KEY] !== expected;
  if (staleSource) {
    await chrome.storage.local.remove([INDEX_KEY, INDEX_URL_KEY, "indexUpdatedAt"]);
  }

  const version = Number(stored[STATE_VERSION_KEY] ?? 0);
  if (version < STATE_VERSION) {
    await chrome.storage.local.remove(["declinedOrigins"]);
    await chrome.storage.local.set({ [STATE_VERSION_KEY]: STATE_VERSION });
  }

  // 前回の判定結果（別の版のもの）は出さない
  if (details?.reason === "update" || staleSource) {
    await chrome.storage.session.remove(REPORT_KEY).catch(() => {});
  }
}

chrome.runtime.onInstalled.addListener((details) => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: 1440 });
  migrateStorage(details).catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) refreshIndex().catch(() => {});
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "inspect") {
    inspectActiveTab()
      .then(sendResponse)
      .catch((error) => sendResponse({ error: String(error?.message ?? error) }));
    return true; // 非同期で応答する
  }
  if (message?.type === "getReport") {
    chrome.storage.session
      .get(REPORT_KEY)
      .then((data) => sendResponse(data[REPORT_KEY] ?? null))
      .catch(() => sendResponse(null));
    return true;
  }
  if (message?.type === "refreshIndex") {
    refreshIndex()
      .then(sendResponse)
      .catch((error) => sendResponse({ error: String(error?.message ?? error) }));
    return true;
  }
  if (message?.type === "loadIndex") {
    // 指定 URL から索引を読む（利用者が「調べる」を押した流れで呼ばれる）
    refreshIndex(message.url)
      .then(sendResponse)
      .catch((error) => sendResponse({ error: String(error?.message ?? error) }));
    return true;
  }
  if (message?.type === "versions") {
    readVersions()
      .then(sendResponse)
      .catch((error) => sendResponse({ error: String(error?.message ?? error), versions: {} }));
    return true;
  }
  if (message?.type === "setVersion") {
    writeVersion(message.product, message.version ?? "")
      .then(sendResponse)
      .catch((error) => sendResponse({ error: String(error?.message ?? error) }));
    return true;
  }
  return false;
});

/** ページから証拠を集める（executeScript に渡すので、外部変数は参照しない）。 */
function collectEvidence() {
  const resources = [];
  for (const entry of performance.getEntriesByType("resource")) resources.push(entry.name);
  return {
    url: location.href,
    html: document.documentElement ? document.documentElement.outerHTML : "",
    resources,
    resourcesCount: resources.length,
  };
}

/**
 * レスポンスヘッダを読む（``X-Powered-By`` / ``Server`` から PHP と Web サーバを推定）。
 *
 * PHP の版は**サイトが公開している場合だけ**分かる。実測では 10 サイト中 1 サイトが
 * ``X-Powered-By: PHP/8.3.36`` を返した。公開していないサイトが大半なので、
 * 「取れなくても異常ではない」前提で扱う。
 *
 * 追加リクエストを避けるため、**利用者がそのサイトの許可を与えたときだけ**、
 * **HEAD で 1 回**だけ問い合わせる（本文は取得しない）。
 */
async function readHeaders(url) {
  let pattern;
  try {
    pattern = originPattern(url);
  } catch {
    return {};
  }
  const granted = await chrome.permissions.contains({ origins: [pattern] }).catch(() => false);
  if (!granted) return {};

  try {
    const response = await fetch(url, {
      method: "HEAD",
      credentials: "omit",
      cache: "no-store",
    });
    const headers = {};
    for (const [key, value] of response.headers.entries()) headers[key.toLowerCase()] = value;
    return headers;
  } catch {
    // HEAD を拒否するサーバもある。ヘッダは無くても判定は続けられる。
    return {};
  }
}

async function inspectActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("タブが見つかりません");

  const url = tab.url ?? tab.pendingUrl ?? "";
  if (!/^https?:/i.test(url)) {
    throw new Error("http / https のページを開いてから実行してください");
  }

  // このタブを読む許可があるかを「やってみる」で確かめる。
  // activeTab（アイコンを押したとき）でも、サイトごとの許可でも通る。
  let result;
  try {
    const injected = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectEvidence,
    });
    result = injected?.[0]?.result;
  } catch {
    result = null;
  }
  if (!result) {
    // サイドパネル側で許可を取ってから、もう一度呼んでもらう
    return { needsSitePermission: true, origin: originOf(url) };
  }

  const headers = await readHeaders(result.url);
  const analysis = analyze({
    url: result.url,
    html: result.html,
    resources: result.resources,
    headers,
  });
  const { versions } = await readVersions();
  applyVersions(analysis, versions);
  // 入力を反映したあとで「判定できなかったこと」を作り直す（PHP の版が入ったら注意書きを消す）
  analysis.notes = buildNotes(analysis.findings);
  const indexRefresh = await ensureFreshIndex();
  const index = await loadIndex();
  const judgements = judge(analysis, index);

  // 索引にデータが無いプラットフォームは「構成のみ」であることを伝える
  for (const component of analysis.findings) {
    if (component.kind !== "platform" || !component.version) continue;
    const key = normalizeSlug(component.name);
    if (judgements.some((item) => normalizeSlug(item.component) === key)) continue;
    analysis.notes.push(`${component.name} の弱点・サポート情報は未収録です（構成のみ表示）`);
  }

  const report = {
    url: analysis.url,
    title: tab.title ?? "",
    findings: analysis.findings,
    notes: analysis.notes,
    judgements,
    levels: summarizeLevels(judgements),
    indexSize: index ? index.size : 0,
    indexGeneratedAt: index ? index.generatedAt : null,
    indexUrl: indexRefresh.url ?? null,
    indexRefresh,
    lifecycleSize: index?.lifecycles ? index.lifecycles.size : 0,
    versions,
    scannedAt: new Date().toISOString(),
  };

  await chrome.storage.session.set({ [REPORT_KEY]: report });
  await updateBadge(report);
  return report;
}

/** URL からオリジン（``https://example.com``）を取り出す。 */
function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * いま開いているタブのオリジン。バージョンの入力は**サイトごと**に保存する。
 */
async function activeOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return null;
  try {
    return new URL(tab.url).origin;
  } catch {
    return null;
  }
}

/** このサイトに入力済みのバージョン。 */
async function readVersions() {
  const origin = await activeOrigin();
  if (!origin) return { origin: null, versions: {} };
  const stored = await chrome.storage.local.get(VERSIONS_KEY);
  const all = stored[VERSIONS_KEY] || {};
  return { origin, versions: all[origin] || {} };
}

/** バージョンを保存する（空文字なら削除）。 */
async function writeVersion(product, version) {
  const origin = await activeOrigin();
  if (!origin) {
    throw new Error("対象のサイトを特定できません（http / https のページを開いてください）");
  }
  if (!product) throw new Error("製品を選んでください");

  const stored = await chrome.storage.local.get(VERSIONS_KEY);
  const all = stored[VERSIONS_KEY] || {};
  const forOrigin = { ...(all[origin] || {}) };
  if (version) forOrigin[product] = String(version);
  else delete forOrigin[product];
  all[origin] = forOrigin;
  await chrome.storage.local.set({ [VERSIONS_KEY]: all });
  return { origin, versions: forOrigin };
}

/**
 * 入力されたバージョンを検出結果に反映する。
 *
 * 外からは分からない PHP・フレームワークの版を、利用者自身が入れるための穴埋め。
 * 既に同じ名前の検出結果があれば版を補い、無ければ項目を足す。
 */
function applyVersions(analysis, versions) {
  for (const [product, version] of Object.entries(versions || {})) {
    if (!version) continue;
    const existing = analysis.findings.find((item) => item.name === product);
    if (existing) {
      existing.version = version;
      existing.confidence = 1;
      existing.evidence = [...new Set([...(existing.evidence || []), `input:${product}`])];
      continue;
    }
    analysis.findings.push({
      kind: KIND_BY_PRODUCT[product] ?? "framework",
      name: product,
      version,
      confidence: 1,
      evidence: [`input:${product}`],
      active: null,
      // 利用者が入れた値であることを示す（判定結果が無くても表示するため）
      entered: true,
    });
  }
  return analysis;
}

/**
 * 索引が必要なら取りに行く（「調べる」のたびに呼ばれる）。
 *
 * - 24 時間以内に取れていて、**取得元が本番と一致**していれば何もしない
 * - そうでなければ取得し直す（古いローカル配信などから切り替える）
 * - 取得に失敗しても、保存済みの索引があればそれで判定を続ける
 */
async function ensureFreshIndex() {
  const expected = INDEX_CANDIDATES[0];
  const stored = await chrome.storage.local.get([INDEX_KEY, INDEX_URL_KEY, "indexUpdatedAt"]);
  const hasCached = Boolean(stored[INDEX_KEY]);
  const sameSource = stored[INDEX_URL_KEY] === expected;
  if (hasCached && sameSource && !isIndexStale(stored.indexUpdatedAt)) {
    return { refreshed: false, usedCached: true, url: expected };
  }

  try {
    const result = await refreshIndex(expected);
    return { refreshed: true, count: result.count, usedCached: false, url: result.url };
  } catch (error) {
    // 許可が無い・配信が落ちている等。保存済みがあれば黙ってそれを使う。
    console.warn("索引の更新に失敗しました", error); // 拡張のサービスワーカー画面で確認できる
    const granted = await chrome.permissions
      .contains({ origins: INDEX_ORIGINS })
      .catch(() => false);
    return {
      refreshed: false,
      usedCached: hasCached,
      url: stored[INDEX_URL_KEY] ?? null,
      error: String(error?.message ?? error),
      // 許可が無いのが原因なら、サイドパネル側で許可を取って再試行してもらう
      needsIndexPermission: !granted,
    };
  }
}

async function loadIndex() {
  const stored = await chrome.storage.local.get(INDEX_KEY);
  const raw = stored[INDEX_KEY];
  if (!raw) return null;
  try {
    return AdvisoryIndex.fromJSON(typeof raw === "string" ? JSON.parse(raw) : raw);
  } catch {
    return null;
  }
}

/** 索引を取り直す。取得元は本番（``INDEX_CANDIDATES[0]``）のみ。 */
async function refreshIndex(urlOverride) {
  const url = urlOverride ?? INDEX_CANDIDATES[0];

  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`索引を取得できません（HTTP ${response.status}）`);
  const data = await response.json();
  const index = AdvisoryIndex.fromJSON(data);
  if (!index.size) throw new Error("索引が空です（JSON の形式を確認してください）");

  await chrome.storage.local.set({
    [INDEX_KEY]: data,
    [INDEX_URL_KEY]: url,
    indexUpdatedAt: new Date().toISOString(),
  });
  return { count: index.size, generatedAt: index.generatedAt, url };
}

/** 最も重い判定をバッジに出す（赤 > 黄 > 灰）。 */
async function updateBadge(report) {
  const levels = report.levels ?? {};
  let text = "";
  let color = "#2f855a";
  if (levels.red) {
    text = String(levels.red);
    color = "#c53030";
  } else if (levels.yellow) {
    text = String(levels.yellow);
    color = "#b7791f";
  } else if (levels.gray) {
    text = "?";
    color = "#718096";
  }
  await chrome.action.setBadgeBackgroundColor({ color }).catch(() => {});
  await chrome.action.setBadgeText({ text }).catch(() => {});
}
