// Python 版（advisories.py）と判定が一致するかを確かめるための入口。
//
// 標準入力の JSON（{index, today, cases}）を受け取り、各ケースの判定を
// JSON で返す。tests/test_parity.py が Python の結果と突き合わせる。

import { readFileSync } from "node:fs";

import { AdvisoryIndex, judge } from "../advisor.js";

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
    advisories: (judgement.advisories ?? []).map((advisory) => advisory.id),
  })),
);

process.stdout.write(JSON.stringify(results));
