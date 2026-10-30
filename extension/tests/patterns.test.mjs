import assert from "node:assert/strict";
import { test } from "node:test";

import { INDEX_CANDIDATES, INDEX_ORIGINS, INDEX_TTL_MS, RELEASE_INDEX_URL, isIndexStale } from "../config.js";
import { originPattern } from "../patterns.js";

// Chrome のマッチパターンはポートを含められない（含めると一致しない）。
test("ポートを落としてマッチパターンを作る", () => {
  assert.equal(originPattern("https://example.com/a/b"), "https://example.com/*");
  assert.equal(originPattern("https://example.com:8443/"), "https://example.com/*");
  assert.equal(originPattern("https://github.com/x/y.json"), "https://github.com/*");
});

test("索引の取得元は本番（GitHub Releases）だけ", () => {
  assert.equal(INDEX_CANDIDATES.length, 1, "localhost などの代替を含めない");
  assert.equal(INDEX_CANDIDATES[0], RELEASE_INDEX_URL);
  const parsed = new URL(INDEX_CANDIDATES[0]);
  assert.equal(parsed.protocol, "https:");
  assert.equal(parsed.hostname, "github.com");
  assert.match(parsed.pathname, /\/releases\/latest\/download\/advisories\.json$/);
});

test("索引の URL は JSON を指している", () => {
  for (const url of INDEX_CANDIDATES) {
    assert.match(url, /\.json($|\?)/);
  }
});

test("索引の取得には github.com とリダイレクト先の許可が要る", () => {
  // Releases は署名付き URL（*.githubusercontent.com）へ 302 するため、両方必要
  assert.ok(INDEX_ORIGINS.some((origin) => /^https:\/\/github\.com\/\*$/.test(origin)));
  assert.ok(INDEX_ORIGINS.some((origin) => origin.includes("*.githubusercontent.com")));
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

