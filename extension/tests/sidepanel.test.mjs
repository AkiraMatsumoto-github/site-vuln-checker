import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const extension = join(here, "..");

const html = readFileSync(join(extension, "sidepanel.html"), "utf8");
const sidepanel = readFileSync(join(extension, "sidepanel.js"), "utf8");
const background = readFileSync(join(extension, "background.js"), "utf8");

test("操作ボタンは「調べる」1 つだけ（画面ごとに分けない）", () => {
  const actions = /<div class="actions">([\s\S]*?)<\/div>/.exec(html);
  assert.ok(actions, ".actions が無い");

  const buttons = [...actions[1].matchAll(/<button\b[^>]*>/g)].map((match) => match[0]);
  assert.equal(buttons.length, 1, "ボタンは 1 つに統一する");
  assert.match(buttons[0], /id="inspect"/);
  assert.doesNotMatch(html, /id="sitehealth"/, "サイトヘルス専用のボタンは置かない");
});

test("サイトヘルスは「調べる」の中で URL により振り分ける", () => {
  // 判定の入口（inspectActiveTab）が URL を見て読み取りを呼ぶ
  assert.match(background, /if \(isSiteHealthUrl\(/, "URL による振り分けが無い");

  // ボタン側からサイトヘルス専用のメッセージを送らない（入口は 1 つ）
  assert.doesNotMatch(sidepanel, /type: "readSiteHealth"/);
  assert.doesNotMatch(sidepanel, /id="sitehealth"/);
});
