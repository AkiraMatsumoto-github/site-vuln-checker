// 設定画面。索引の URL を保存し、そのオリジンへのアクセス許可を取ってから読み込む。
// `chrome.permissions.request` はユーザー操作（クリック）から呼ぶ必要がある。

import { originPattern } from "./patterns.js";

const $ = (id) => document.getElementById(id);

async function showStatus() {
  const stored = await chrome.storage.local.get(["indexUpdatedAt", "index"]);
  const size = stored.index?.advisories?.length ?? 0;
  if (!stored.indexUpdatedAt) {
    $("status").textContent = "索引はまだ読み込んでいません。";
    return;
  }
  $("status").textContent = `読み込み済み: ${size} 件（更新 ${new Date(
    stored.indexUpdatedAt,
  ).toLocaleString()}）`;
}

async function loadUrl() {
  const stored = await chrome.storage.local.get(["indexUrl"]);
  $("url").value = stored.indexUrl ?? "";
}

async function save() {
  const url = $("url").value.trim();
  if (!url) {
    $("status").textContent = "URL を入力してください。";
    return;
  }

  let origin;
  try {
    origin = originPattern(url);
  } catch {
    $("status").textContent = "URL の形式が正しくありません。";
    return;
  }

  const granted = await chrome.permissions.request({ origins: [origin] });
  if (!granted) {
    $("status").textContent = "アクセスが許可されなかったため、索引を取得できません。";
    return;
  }

  await chrome.storage.local.set({ indexUrl: url });
  await refresh();
}

async function refresh() {
  $("status").textContent = "読み込んでいます…";
  try {
    const result = await chrome.runtime.sendMessage({ type: "refreshIndex" });
    if (result?.error) {
      $("status").textContent = result.error;
      return;
    }
    const generated = result.generatedAt
      ? `（索引の生成 ${new Date(result.generatedAt).toLocaleString()}）`
      : "";
    $("status").textContent = `読み込みました: ${result.count} 件${generated}`;
  } catch (error) {
    $("status").textContent = `失敗しました: ${String(error?.message ?? error)}`;
  }
}

$("save").addEventListener("click", save);
$("refresh").addEventListener("click", refresh);
loadUrl().then(showStatus);
