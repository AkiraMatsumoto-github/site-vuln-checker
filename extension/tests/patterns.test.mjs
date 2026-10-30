import assert from "node:assert/strict";
import { test } from "node:test";

import {
  INDEX_CANDIDATES,
  INDEX_TTL_MS,
  indexCandidates,
  isDevelopment,
  isIndexStale,
} from "../config.js";
import { originPattern } from "../patterns.js";

// Chrome のマッチパターンはポートを含められない（含めると一致しない）。
test("ポートを落としてマッチパターンを作る", () => {
  assert.equal(originPattern("http://localhost:8000/out/advisories.json"), "http://localhost/*");
  assert.equal(originPattern("https://example.com/a/b"), "https://example.com/*");
  assert.equal(originPattern("https://example.com:8443/"), "https://example.com/*");
});

test("索引の候補は https か localhost のみ", () => {
  assert.ok(INDEX_CANDIDATES.length > 0, "候補が空だと自動で読み込めない");
  for (const url of INDEX_CANDIDATES) {
    const parsed = new URL(url);
    assert.ok(
      parsed.protocol === "https:" || parsed.hostname === "localhost",
      `想定外の配信元: ${url}`,
    );
  }
});

test("索引の URL は JSON を指している", () => {
  for (const url of INDEX_CANDIDATES) {
    assert.match(url, /\.json($|\?)/);
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

test("本番（ストア版）は Releases だけ、開発はローカルを優先", () => {
  const production = indexCandidates({ development: false });
  const development = indexCandidates({ development: true });
  assert.equal(production.length, 1);
  assert.match(production[0], /^https:\/\/github\.com\//);
  assert.match(development[0], /^http:\/\/localhost:/);
  assert.equal(development.length, 2);
});

test("update_url の有無で開発かどうかを判別する", () => {
  assert.equal(isDevelopment({}), true);
  assert.equal(
    isDevelopment({ update_url: "https://clients2.google.com/service/update2/crx" }),
    false,
  );
  assert.equal(isDevelopment(null), true);
});
