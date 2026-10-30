import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AdvisoryIndex,
  LEVEL,
  compareVersions,
  isAffected,
  judge,
  normalizeSlug,
  summarizeLevels,
} from "../advisor.js";

const INDEX = {
  generated_at: "2026-10-29T00:00:00Z",
  advisories: [
    {
      id: "CVE-2025-90001",
      name: "Contact Form 7",
      slug: "contact-form-7",
      affected_below: "5.9.9",
      fixed: "5.9.9",
      cvss: 9.8,
      kev: true,
    },
    {
      id: "CVE-2025-90002",
      name: "Elementor",
      slug: "elementor",
      affected_below: "3.20.0",
      fixed: "3.20.0",
      cvss: 6.1,
      kev: false,
    },
    {
      id: "CVE-2026-90004",
      name: "WPLP Cookie Consent - Cookie Banner & Consent Management",
      affected_upto: "1.4.2",
      cvss: 9.8,
      kept: false,
    },
  ],
};

const plugin = (name, version, active = true) => ({
  kind: "plugin",
  name,
  version,
  confidence: 0.85,
  evidence: [],
  active,
});
const analysis = (findings) => ({ findings });

test("バージョン比較", () => {
  assert.equal(compareVersions("1.2", "1.2.0"), 0);
  assert.equal(compareVersions("5.9.8", "5.9.9"), -1);
  assert.equal(compareVersions("5.9.10", "5.9.9"), 1);
  assert.equal(compareVersions("10.0", "9.9.9"), 1);
  assert.equal(compareVersions("v5.9.9", "5.9.9"), 0);
  assert.equal(compareVersions("1.0", "1.0-beta"), -1);
});

test("slug の正規化", () => {
  assert.equal(normalizeSlug("Contact Form 7"), "contact-form-7");
  assert.equal(normalizeSlug("WooCommerce / Extra"), "woocommerce-extra");
});

test("affected_upto は境界を含む", () => {
  const advisory = { affected_upto: "1.4.2" };
  assert.equal(isAffected("1.4.1", advisory), true);
  assert.equal(isAffected("1.4.2", advisory), true);
  assert.equal(isAffected("1.4.3", advisory), false);
});

test("前方一致でマーケティング名を拾う", () => {
  const index = AdvisoryIndex.fromJSON(INDEX);
  const found = index.advisoriesFor({ name: "wplp-cookie-consent" });
  assert.deepEqual(
    found.map((item) => item.id),
    ["CVE-2026-90004"],
  );
  // 短すぎる slug は前方一致させない
  assert.deepEqual(index.advisoriesFor({ name: "seo" }), []);
});

test("KEV 該当は赤で、更新先を出す", () => {
  const judgements = judge(analysis([plugin("contact-form-7", "5.9.8")]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements.length, 1);
  assert.equal(judgements[0].level, LEVEL.RED);
  assert.equal(judgements[0].action, "→ 5.9.9 へ更新");
  assert.equal(judgements[0].advisories[0].id, "CVE-2025-90001");
});

test("CVSS が低ければ黄", () => {
  const judgements = judge(analysis([plugin("elementor", "3.19.0")]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements[0].level, LEVEL.YELLOW);
  assert.equal(judgements[0].action, "→ 3.20.0 へ更新");
});

test("修正版以降なら該当なし", () => {
  const judgements = judge(analysis([plugin("elementor", "3.21.0")]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements[0].level, LEVEL.NONE);
});

test("版が不明なら灰（緑にしない）", () => {
  const judgements = judge(analysis([plugin("elementor", null)]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements[0].level, LEVEL.GRAY);
  assert.match(judgements[0].note, /1 件の勧告/);
});

test("勧告が無いプラグインは判定を出さない", () => {
  const judgements = judge(analysis([plugin("no-such-plugin", null)]), AdvisoryIndex.fromJSON(INDEX));
  assert.deepEqual(judgements, []);
});

test("索引が無ければ判定しない", () => {
  const judgements = judge(analysis([plugin("contact-form-7", "5.9.8")]), null);
  assert.deepEqual(judgements, []);
});

test("EPSS 0.5 以上は赤", () => {
  const index = AdvisoryIndex.fromJSON({
    advisories: [
      {
        id: "CVE-X",
        name: "Epss Only",
        affected_below: "9.9.9",
        fixed: "9.9.9",
        cvss: 5.0,
        epss: 0.8,
      },
    ],
  });
  const judgements = judge(analysis([plugin("epss-only", "1.0")]), index);
  assert.equal(judgements[0].level, LEVEL.RED);
});

test("内訳の集計", () => {
  const index = AdvisoryIndex.fromJSON(INDEX);
  const judgements = judge(
    analysis([
      plugin("contact-form-7", "5.9.8"),
      plugin("elementor", "3.19.0"),
      plugin("elementor", null),
    ]),
    index,
  );
  assert.deepEqual(summarizeLevels(judgements), { red: 1, yellow: 1, gray: 1, none: 0 });
});
