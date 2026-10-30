// サイドパネルの UI。判定は background が行い、ここは結果を描くだけ。
// 値はすべて textContent で入れる（ページ由来の文字列を HTML として解釈しない）。

const $ = (id) => document.getElementById(id);

const LEVEL_LABEL = {
  red: "🔴 赤",
  yellow: "🟡 黄",
  gray: "⚪ 灰",
  none: "—",
};

const KIND_LABEL = {
  platform: "基盤",
  core: "コア",
  plugin: "プラグイン",
  theme: "テーマ",
  library: "JS",
  language: "言語",
  server: "サーバ",
  database: "DB",
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function advisoryLine(advisory) {
  const parts = [`CVSS ${advisory.cvss ?? "—"}`];
  if (advisory.kev) parts.push("KEV");
  if (advisory.epss !== null && advisory.epss !== undefined) {
    parts.push(`EPSS ${Math.round(advisory.epss * 100)}%`);
  }
  const item = element("li");
  item.append(element("code", "", advisory.id));
  item.append(document.createTextNode(` ・ ${parts.join(" ・ ")}`));
  return item;
}

function renderJudgements(report) {
  const container = $("judgements");
  container.replaceChildren();
  const judgements = report.judgements ?? [];

  if (!judgements.length) {
    const message = report.indexSize
      ? "該当する勧告はありません（検出できた範囲）"
      : "索引が未設定のため、脆弱性の判定はしていません（設定から索引を読み込んでください）";
    container.append(element("p", "empty", message));
    return;
  }

  for (const judgement of judgements) {
    const level = LEVEL_LABEL[judgement.level] ? judgement.level : "none";
    const item = element("div", `item ${level}`);

    const head = element("div", "item-head");
    head.append(
      element("span", `badge ${level}`, LEVEL_LABEL[level]),
      element("span", "name", judgement.component),
      element("span", "version", judgement.version ? `v${judgement.version}` : "版不明"),
    );
    item.append(head);
    item.append(element("p", "action", judgement.action));
    if (judgement.note) item.append(element("p", "empty", judgement.note));

    const advisories = (judgement.advisories ?? []).map(advisoryLine);
    if (advisories.length) {
      const list = element("ul", "advisories");
      list.append(...advisories);
      item.append(list);
    }
    container.append(item);
  }
}

function renderComponents(report) {
  const container = $("components");
  container.replaceChildren();
  const findings = report.findings ?? [];
  if (!findings.length) {
    container.append(element("p", "empty", "検出できませんでした"));
    return;
  }

  const table = element("table");
  const head = element("thead");
  const headRow = element("tr");
  for (const label of ["種別", "名前", "版", "確度"]) headRow.append(element("th", "", label));
  head.append(headRow);

  const body = element("tbody");
  for (const finding of findings) {
    const row = element("tr");
    row.append(
      element("td", "", KIND_LABEL[finding.kind] ?? finding.kind),
      element("td", "", finding.name),
      element("td", "", finding.version ?? "—"),
      element("td", "", Number(finding.confidence ?? 0).toFixed(2)),
    );
    body.append(row);
  }
  table.append(head, body);
  container.append(table);
}

function renderNotes(report) {
  const notes = report.notes ?? [];
  $("unknownSection").hidden = notes.length === 0;
  const list = $("unknown");
  list.replaceChildren(...notes.map((note) => element("li", "", note)));
}

function renderReport(report) {
  if (!report) return;
  $("target").textContent = report.url ?? "";
  $("result").hidden = false;
  renderJudgements(report);
  renderComponents(report);
  renderNotes(report);

  const levels = report.levels ?? {};
  const meta = [
    report.scannedAt ? `判定 ${new Date(report.scannedAt).toLocaleString()}` : null,
    `索引 ${report.indexSize ?? 0} 件`,
    levels.red ? `赤 ${levels.red}` : null,
    levels.yellow ? `黄 ${levels.yellow}` : null,
  ].filter(Boolean);
  $("meta").textContent = meta.join(" ／ ");
}

async function inspect() {
  const button = $("inspect");
  button.disabled = true;
  $("status").textContent = "調べています…";
  try {
    const report = await chrome.runtime.sendMessage({ type: "inspect" });
    if (report?.error) {
      $("status").textContent = report.error;
      return;
    }
    renderReport(report);
    $("status").textContent = "";
  } catch (error) {
    $("status").textContent = `失敗しました: ${String(error?.message ?? error)}`;
  } finally {
    button.disabled = false;
  }
}

async function restore() {
  const report = await chrome.runtime.sendMessage({ type: "getReport" }).catch(() => null);
  if (report) renderReport(report);
  const stored = await chrome.storage.local.get(["indexUpdatedAt"]).catch(() => ({}));
  if (!stored.indexUpdatedAt) {
    $("status").textContent = "索引が未設定です。設定から索引の URL を読み込んでください。";
  }
}

$("inspect").addEventListener("click", inspect);
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
restore();
