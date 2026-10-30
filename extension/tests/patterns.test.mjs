import assert from "node:assert/strict";
import { test } from "node:test";

import { INDEX_CANDIDATES } from "../config.js";
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
