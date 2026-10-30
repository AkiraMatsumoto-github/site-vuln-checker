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

import { AdvisoryIndex, judge, summarizeLevels } from "./advisor.js";
import { analyze, buildNotes } from "./detector.js";

const REPORT_KEY = "lastReport";
const INDEX_KEY = "index";
const INDEX_URL_KEY = "indexUrl";
const VERSIONS_KEY = "versions";
const REFRESH_ALARM = "refresh-index";

//: 入力された製品名 → 検出結果の種別（PHP は言語、WordPress はコア、他はフレームワーク）
const KIND_BY_PRODUCT = { php: "language", wordpress: "core" };

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: 1440 });
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

async function inspectActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !/^https?:/i.test(tab.url ?? "")) {
    throw new Error("http / https のページで実行してください");
  }

  const [{ result } = {}] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: collectEvidence,
  });
  if (!result) throw new Error("ページから情報を取得できませんでした");

  const analysis = analyze({
    url: result.url,
    html: result.html,
    resources: result.resources,
  });
  const { versions } = await readVersions();
  applyVersions(analysis, versions);
  // 入力を反映したあとで「判定できなかったこと」を作り直す（PHP の版が入ったら注意書きを消す）
  analysis.notes = buildNotes(analysis.findings);
  const index = await loadIndex();
  const judgements = judge(analysis, index);

  const report = {
    url: analysis.url,
    title: tab.title ?? "",
    findings: analysis.findings,
    notes: analysis.notes,
    judgements,
    levels: summarizeLevels(judgements),
    indexSize: index ? index.size : 0,
    indexGeneratedAt: index ? index.generatedAt : null,
    lifecycleSize: index?.lifecycles ? index.lifecycles.size : 0,
    versions,
    scannedAt: new Date().toISOString(),
  };

  await chrome.storage.session.set({ [REPORT_KEY]: report });
  await updateBadge(report);
  return report;
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
    });
  }
  return analysis;
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

/** 索引を取り直す。URL は設定画面で指定する。 */
async function refreshIndex() {
  const stored = await chrome.storage.local.get(INDEX_URL_KEY);
  const url = stored[INDEX_URL_KEY];
  if (!url) return { error: "索引の URL が未設定です（設定画面で指定してください）" };

  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`索引を取得できません（HTTP ${response.status}）`);
  const data = await response.json();
  const index = AdvisoryIndex.fromJSON(data);
  if (!index.size) throw new Error("索引が空です（JSON の形式を確認してください）");

  await chrome.storage.local.set({
    [INDEX_KEY]: data,
    indexUpdatedAt: new Date().toISOString(),
  });
  return { count: index.size, generatedAt: index.generatedAt };
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
