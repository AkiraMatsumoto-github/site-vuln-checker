import assert from "node:assert/strict";
import { test } from "node:test";

import { INDEX_CANDIDATES, INDEX_ORIGINS, INDEX_TTL_MS, INDEX_URL, isIndexStale } from "../config.js";
import {
  isAdminHomeUrl,
  isAdminUrl,
  isSiteHealthInfoTab,
  isSiteHealthUrl,
  originPattern,
} from "../patterns.js";

// Chrome のマッチパターンはポートを含められない（含めると一致しない）。
test("ポートを落としてマッチパターンを作る", () => {
  assert.equal(originPattern("https://example.com/a/b"), "https://example.com/*");
  assert.equal(originPattern("https://example.com:8443/"), "https://example.com/*");
  assert.equal(originPattern("https://example.com/x/y.json"), "https://example.com/*");
});

test("索引の取得元は GitHub Pages（直配信）だけ", () => {
  assert.equal(INDEX_CANDIDATES.length, 1, "localhost などの代替を含めない");
  assert.equal(INDEX_CANDIDATES[0], INDEX_URL);
  const parsed = new URL(INDEX_CANDIDATES[0]);
  assert.equal(parsed.protocol, "https:");
  assert.equal(parsed.hostname, "akiramatsumoto-github.github.io");
  assert.match(parsed.pathname, /\/advisories\.json$/);
});

test("索引の URL は JSON を指している", () => {
  for (const url of INDEX_CANDIDATES) {
    assert.match(url, /\.json($|\?)/);
  }
});

test("索引の許可は Pages の 1 オリジンだけ（リダイレクトが無い）", () => {
  assert.equal(INDEX_ORIGINS.length, 1);
  assert.equal(INDEX_ORIGINS[0], "https://akiramatsumoto-github.github.io/*");
  for (const origin of INDEX_ORIGINS) {
    assert.match(origin, /^https:\/\//, `https 以外は許可しない: ${origin}`);
  }
});

// --- 索引の鮮度（「調べる」のたびに取りに行くかの判断）-------------------------

test("24 時間を超えたら古い（取りに行く）", () => {
  const now = Date.parse("2026-10-30T12:00:00Z");
  assert.equal(isIndexStale("2026-10-30T11:00:00Z", now), false);
  assert.equal(isIndexStale(new Date(now - INDEX_TTL_MS - 1000).toISOString(), now), true);
});

test("索引が無い・日時が壊れている場合は古いとみなす", () => {
  assert.equal(isIndexStale(undefined), true);
  assert.equal(isIndexStale(null), true);
  assert.equal(isIndexStale("not-a-date"), true);
});

// --- サイトヘルス（URL と中身で自動的に振り分ける）----------------------------

test("サイトヘルスの画面は「情報」タブでなくても対象にする", () => {
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/site-health.php"), true);
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/site-health.php?tab=status"), true);
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/site-health.php?tab=debug"), true);
  assert.equal(isSiteHealthUrl("https://example.com:8443/wp-admin/site-health.php"), true);
});

test("管理画面のディレクトリ名を変えていても対象にする", () => {
  // /wp-admin/ を /admin/ や /wp/wp-admin/ に変えているサイト
  assert.equal(isSiteHealthUrl("https://example.com/admin/site-health.php"), true);
  assert.equal(isSiteHealthUrl("https://example.com/wp/wp-admin/site-health.php"), true);
  assert.equal(isSiteHealthUrl("https://example.com/manage/site-health.php?tab=debug"), true);
  // プラグイン形式（admin.php?page=site-health）
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/admin.php?page=site-health"), true);
});

test("サイトヘルス以外の管理画面は対象にしない", () => {
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/"), false);
  assert.equal(isSiteHealthUrl("https://example.com/admin/"), false);
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/options-general.php"), false);
  assert.equal(isSiteHealthUrl("https://example.com/"), false);
  assert.equal(isSiteHealthUrl("https://example.com/blog/site-health.php"), true, "任意の場所の site-health.php");
  assert.equal(isSiteHealthUrl("https://example.com/wp-admin/site-health.php.bak"), false);
  assert.equal(isSiteHealthUrl("not a url"), false);
});

test("管理画面のトップだけを自動遷移の対象にする", () => {
  // /wp-admin/ と /wp-admin/index.php だけ（投稿の編集中などは遷移しない）
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/"), true);
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/index.php"), true);
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/index.php?foo=1"), true);
  assert.equal(isAdminHomeUrl("https://example.com/wp/wp-admin/"), true, "サブディレクトリ設置");
  assert.equal(isAdminHomeUrl("https://example.com:8443/wp-admin/"), true);
  // 対象外（未保存の編集を失わせないため）
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/post.php?post=1&action=edit"), false);
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/plugins.php"), false);
  assert.equal(isAdminHomeUrl("https://example.com/wp-admin/site-health.php"), false);
  assert.equal(isAdminHomeUrl("https://example.com/"), false);
  assert.equal(isAdminHomeUrl("not a url"), false);
});

// --- サイトヘルスの「情報」タブ判定 ------------------------------------------

test("「情報」タブ（?tab=debug）だけを情報タブとみなす", () => {
  assert.equal(isSiteHealthInfoTab("https://example.com/wp-admin/site-health.php?tab=debug"), true);
  assert.equal(
    isSiteHealthInfoTab("https://example.com/admin/site-health.php?tab=debug&foo=1"),
    true,
  );
  // ステータス画面（表が無い）は情報タブではない
  assert.equal(isSiteHealthInfoTab("https://example.com/wp-admin/site-health.php"), false);
  assert.equal(isSiteHealthInfoTab("https://example.com/wp-admin/site-health.php?tab=status"), false);
  assert.equal(isSiteHealthInfoTab("not a url"), false);
});


test("管理画面は HEAD を送らない対象とみなす", () => {
  assert.equal(isAdminUrl("https://example.com/wp-admin/"), true);
  assert.equal(isAdminUrl("https://example.com/wp-admin/options-general.php"), true);
  assert.equal(isAdminUrl("https://example.com/wp-admin"), true);
  assert.equal(isAdminUrl("https://example.com/wp-login.php"), true);
  assert.equal(isAdminUrl("https://example.com:8443/wp-admin/site-health.php?tab=debug"), true);
});

test("公開ページは今までどおり HEAD を送る", () => {
  assert.equal(isAdminUrl("https://example.com/"), false);
  assert.equal(isAdminUrl("https://example.com/blog/wp-admin-guide/"), false);
  assert.equal(isAdminUrl("https://example.com/?p=1"), false);
  assert.equal(isAdminUrl("not a url"), false);
});

