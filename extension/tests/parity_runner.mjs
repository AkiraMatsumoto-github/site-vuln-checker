// Python 版（advisories.py）と判定が一致するかを確かめるための入口。
//
// 標準入力の JSON（{index, today, cases}）を受け取り、各ケースの判定を
// JSON で返す。tests/test_parity.py が Python の結果と突き合わせる。

import { readFileSync } from "node:fs";

import { AdvisoryIndex, judge } from "../advisor.js";
import {
  ANALYTICS_TAG_HOSTS,
  CDN_SERVER_NAMES,
  CDN_SIGNATURES,
  IMAGE_CDN_HOSTS,
  SECURITY_HEADERS,
  SHOPIFY_APP_DOMAINS,
  analyze,
} from "../detector.js";

const input = JSON.parse(readFileSync(0, "utf8"));
const index = AdvisoryIndex.fromJSON(input.index);
const today = new Date(input.today);

const results = (input.cases ?? []).map((findings) =>
  judge({ findings }, index, today).map((judgement) => ({
    component: judgement.component,
    version: judgement.version ?? null,
    level: judgement.level,
    action: judgement.action,
    note: judgement.note ?? "",
    advisories: (judgement.advisories ?? []).map((advisory) => ({
      id: advisory.id,
      ranges: advisory.ranges ?? [],
    })),
  })),
);

// 1.1.0 で追加した検出（CDN / セキュリティ / タグ / 画像配信）も Python と突き合わせる
const NEW_KINDS = new Set(["cdn", "security", "tag", "image"]);
const detectInput = input.detect;
const detected = detectInput
  ? analyze({
      url: detectInput.url,
      html: detectInput.html ?? "",
      resources: detectInput.resources ?? [],
      headers: detectInput.headers ?? {},
    })
      .findings.filter((item) => NEW_KINDS.has(item.kind))
      .map((item) => ({
        kind: item.kind,
        name: item.name,
        version: item.version,
        evidence: item.evidence,
      }))
  : [];

process.stdout.write(
  JSON.stringify({
    cases: results,
    // アプリ辞書が Python と食い違わないように、辞書そのものも返す（レビュー #14）
    shopifyDomains: SHOPIFY_APP_DOMAINS,
    // 1.1.0 の辞書も同じ理由で突き合わせる
    dictionaries: {
      cdnSignatures: CDN_SIGNATURES,
      cdnServerNames: CDN_SERVER_NAMES,
      securityHeaders: SECURITY_HEADERS,
      analyticsTagHosts: ANALYTICS_TAG_HOSTS,
      imageCdnHosts: IMAGE_CDN_HOSTS,
    },
    detected,
  }),
);
