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
  const found = index.advisoriesFor({ kind: "plugin", name: "wplp-cookie-consent" });
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
  assert.equal(judgements[0].action, "修正版 5.9.9 に更新してください");
  assert.equal(judgements[0].advisories[0].id, "CVE-2025-90001");
});

test("CVSS が低ければ黄", () => {
  const judgements = judge(analysis([plugin("elementor", "3.19.0")]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements[0].level, LEVEL.YELLOW);
  assert.equal(judgements[0].action, "修正版 3.20.0 に更新してください");
});

test("修正版以降なら該当なし（重複 CVE は 1 件にまとめる）", () => {
  // WordPress コアの勧告は系統ごとに別レコードになる。画面に同じ CVE を並べない。
  const index = AdvisoryIndex.fromJSON({
    advisories: ["6.0.9", "6.1.9", "6.2.9", "6.3.9", "7.0.5"].map((fixed, i) => ({
      id: "CVE-2026-87902",
      name: "WordPress",
      slug: "wordpress",
      affected_below: fixed,
      fixed,
      cvss: 8.1,
      kev: true,
      epss: 0.96,
      range: i,
    })),
  });
  const component = { kind: "core", name: "wordpress", version: "7.1.4" };
  const judgements = judge(analysis([component]), index);
  assert.equal(judgements.length, 1);
  assert.equal(judgements[0].level, LEVEL.NONE);
  assert.match(judgements[0].action, /該当しません/);
  assert.match(judgements[0].note, /すべて修正済み/);
  assert.equal(judgements[0].advisories.length, 1, "同じ CVE を 1 行にまとめる");
});

test("該当する勧告も CVE 単位で 1 行（系統が複数当たっても）", () => {
  const index = AdvisoryIndex.fromJSON({
    advisories: ["8.2.35", "8.3.36"].map((fixed) => ({
      id: "CVE-2026-109618",
      name: "PHP",
      slug: "php",
      affected_below: fixed,
      fixed,
      cvss: 9.8,
      kev: true,
    })),
  });
  const judgements = judge(analysis([language("php", "8.1.27")]), index);
  assert.equal(judgements[0].advisories.length, 1);
  assert.equal(judgements[0].level, LEVEL.RED);
});

test("版が不明なら灰（緑にしない）", () => {
  const judgements = judge(analysis([plugin("elementor", null)]), AdvisoryIndex.fromJSON(INDEX));
  assert.equal(judgements[0].level, LEVEL.GRAY);
  assert.match(judgements[0].note, /過去の勧告 1 件/);
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

test("同じコンポーネントが 2 回出ても 1 行にまとめる", () => {
  const index = AdvisoryIndex.fromJSON(INDEX);
  const judgements = judge(
    analysis([plugin("elementor", "3.19.0"), plugin("elementor", null)]),
    index,
  );
  assert.equal(judgements.length, 1);
  assert.equal(judgements[0].level, LEVEL.YELLOW);
});

test("内訳の集計", () => {
  const index = AdvisoryIndex.fromJSON(INDEX);
  const judgements = judge(
    analysis([
      plugin("contact-form-7", "5.9.8"),
      plugin("elementor", "3.19.0"),
      plugin("wplp-cookie-consent", null),
    ]),
    index,
  );
  assert.deepEqual(summarizeLevels(judgements), { red: 1, yellow: 1, gray: 1, none: 0 });
});

// --- CPE の下限つき範囲とライフサイクル（EOL）---------------------------------

test("CPE の下限より下は影響なし", () => {
  const advisory = {
    id: "CVE-2026-109618",
    name: "PHP",
    slug: "php",
    affected_at_or_above: "7.3.0",
    affected_below: "8.2.35",
  };
  assert.equal(isAffected("8.1.27", advisory), true);
  assert.equal(isAffected("8.2.35", advisory), false);
  assert.equal(isAffected("7.2.34", advisory), false);
});

const TODAY = new Date(Date.UTC(2026, 9, 29));

const LIFECYCLE_INDEX = {
  generated_at: "2026-10-29T00:00:00Z",
  advisories: [
    {
      id: "CVE-2026-109618",
      name: "PHP",
      slug: "php",
      affected_at_or_above: "7.3.0",
      affected_below: "8.2.35",
      fixed: "8.2.35",
      cvss: 9.8,
    },
  ],
  lifecycles: {
    products: {
      php: {
        name: "PHP",
        cycles: [
          { cycle: "8.5", eol: "2029-12-31", latest: "8.5.12" },
          { cycle: "8.4", eol: "2028-12-31", latest: "8.4.27" },
          { cycle: "8.3", eol: "2027-12-31", latest: "8.3.36" },
          { cycle: "8.2", eol: "2026-12-31", latest: "8.2.35" },
          { cycle: "8.1", eol: "2025-12-31", latest: "8.1.34" },
        ],
      },
    },
  },
};

function language(name, version) {
  return { kind: "language", name, version, confidence: 1, evidence: [`input:${name}`], active: null };
}

test("ライフサイクルを索引から読む（製品名でも引ける）", () => {
  const index = AdvisoryIndex.fromJSON(LIFECYCLE_INDEX);
  assert.equal(index.lifecycles.size, 1);
  assert.equal(index.lifecycles.check("PHP", "8.1.27", TODAY).state, "eol");
  assert.equal(index.lifecycles.check("php", "8.5.12", TODAY).state, "supported");
});

test("PHP 8.1 は EOL で黄（PHP2Shell の CVE と合わさって赤）", () => {
  const index = AdvisoryIndex.fromJSON(LIFECYCLE_INDEX);

  // 脆弱性だけを見れば赤、EOL だけを見れば黄。合わさったら赤で 1 行。
  const judgements = judge(analysis([language("php", "8.1.27")]), index, TODAY);
  assert.equal(judgements.length, 1);
  const only = judgements[0];
  assert.equal(only.level, LEVEL.RED);
  assert.match(only.action, /8\.2\.35/); // 修正版（脆弱性）
  assert.match(only.action, /8\.5\.12/); // 移行先（EOL）
  assert.match(only.note, /2025-12-31 にサポート終了/);
});

test("EOL だけなら黄、同一系統のパッチ遅れは「—」", () => {
  const index = AdvisoryIndex.fromJSON({ lifecycles: LIFECYCLE_INDEX.lifecycles });

  const eol = judge(analysis([language("php", "8.1.27")]), index, TODAY);
  assert.deepEqual(
    eol.map((item) => item.level),
    [LEVEL.YELLOW],
  );
  assert.match(eol[0].action, /8\.5\.12 以降に移行/);

  const outdated = judge(analysis([language("php", "8.4.20")]), index, TODAY);
  assert.deepEqual(
    outdated.map((item) => item.level),
    [LEVEL.NONE],
  );
  assert.match(outdated[0].action, /8\.4\.27/);

  assert.deepEqual(judge(analysis([language("php", "8.5.12")]), index, TODAY), []);
});

test("プラグインは EOL 判定の対象外", () => {
  const index = AdvisoryIndex.fromJSON({ lifecycles: LIFECYCLE_INDEX.lifecycles });
  assert.deepEqual(judge(analysis([plugin("php", "8.1.27")]), index, TODAY), []);
});

