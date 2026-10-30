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
import { analyze } from "./detector.js";

const REPORT_KEY = "lastReport";
const INDEX_KEY = "index";
const INDEX_URL_KEY = "indexUrl";
const REFRESH_ALARM = "refresh-index";

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
    scannedAt: new Date().toISOString(),
  };

  await chrome.storage.session.set({ [REPORT_KEY]: report });
  await updateBadge(report);
  return report;
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
