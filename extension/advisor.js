// 勧告索引（advisories.json）との照合と判定。
//
// Python 版（src/site_vuln_checker/advisories.py）の移植。索引は拡張のローカルに持つ
// （閲覧 URL をサーバへ送らない）。判定は 2 段階:
//   1. 影響範囲に入るか（affected_below / affected_upto）
//   2. 入っていれば KEV / CVSS / EPSS で赤・黄を決める

export const LEVEL = { RED: "red", YELLOW: "yellow", GRAY: "gray", NONE: "none" };
export const RED_CVSS = 9.0;
export const RED_EPSS = 0.5;
/** 前方一致で拾うための最小長（短すぎる slug は誤爆する）。 */
export const MIN_PREFIX_MATCH = 6;

const SEGMENT_RE = /\d+|[A-Za-z]+/g;
const SLUG_RE = /[^a-z0-9]+/g;

export function normalizeSlug(text) {
  return String(text)
    .trim()
    .toLowerCase()
    .replace(SLUG_RE, "-")
    .replace(/^-+|-+$/g, "");
}

/** 比較用のキー。`1.2` / `1.2.0` / `5.9.9.1` を数値で比べる。 */
export function versionKey(version) {
  const parts = String(version).trim().replace(/^[vV]/, "").match(SEGMENT_RE) || [];
  return parts.map((part) => (/^\d+$/.test(part) ? [0, Number(part)] : [1, part]));
}

export function compareVersions(left, right) {
  const a = versionKey(left);
  const b = versionKey(right);
  const width = Math.max(a.length, b.length);
  for (let index = 0; index < width; index += 1) {
    const [tagA, valueA] = a[index] || [0, 0];
    const [tagB, valueB] = b[index] || [0, 0];
    if (tagA !== tagB) return tagA < tagB ? -1 : 1;
    if (valueA === valueB) continue;
    return valueA < valueB ? -1 : 1;
  }
  return 0;
}

/**
 * バージョンが勧告の影響範囲に入るか。
 *
 * CPE（NVD の構造化データ）に由来する勧告は**下限**を持つ
 * （例: PHP は「7.3.0 以上 8.2.35 未満」）。下限より下を影響ありとしない。
 */
export function isAffected(version, advisory) {
  if (
    advisory.affected_at_or_above &&
    compareVersions(version, advisory.affected_at_or_above) < 0
  ) {
    return false;
  }
  if (advisory.affected_below && compareVersions(version, advisory.affected_below) < 0) return true;
  return Boolean(advisory.affected_upto && compareVersions(version, advisory.affected_upto) <= 0);
}

function lowerBound(sorted, value) {
  let low = 0;
  let high = sorted.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (sorted[mid] < value) low = mid + 1;
    else high = mid;
  }
  return low;
}

const LEVEL_ORDER = { red: 0, yellow: 1, gray: 2, none: 3 };

function levelFor(affected) {
  if (affected.some((advisory) => advisory.kev)) return LEVEL.RED;
  if (affected.some((advisory) => (advisory.cvss ?? 0) >= RED_CVSS)) return LEVEL.RED;
  if (affected.some((advisory) => (advisory.epss ?? 0) >= RED_EPSS)) return LEVEL.RED;
  return LEVEL.YELLOW;
}

/** サポート終了が「近い」とみなす日数（Python 版と同じ）。 */
export const EOL_SOON_DAYS = 90;
/** ライフサイクル（EOL）を判定する種別。プラグインは系統を持たないので対象外。 */
export const LIFECYCLE_KINDS = ["core", "language", "framework", "library"];
/** 勧告（CVE）で判定する種別。 */
export const ADVISORY_KINDS = ["plugin", "theme", "core", "language", "framework"];

/** ``2025-12-31`` を UTC のミリ秒に（読めなければ null）。 */
function parseDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value ?? ""));
  if (!match) return null;
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
}

/** EOL 判定の説明文（画面と CLI で同じ言い方にする）。 */
export function lifecycleNote(status) {
  if (status.state === "eol") {
    return `${status.eol} にサポート終了（${status.cycle} 系の修正版は出ません）`;
  }
  if (status.state === "eol_soon") {
    return `${status.eol} にサポート終了予定です`;
  }
  if (status.state === "outdated") {
    return "セキュリティ修正を含むかは分かりません（更新を検討してください）";
  }
  return "";
}

/** 同じ CVE を 1 つにまとめる（CPE 由来の勧告は系統ごとに別レコードになるため）。 */
function uniqueById(advisories) {
  const seen = new Map();
  for (const advisory of advisories) {
    if (!seen.has(advisory.id)) seen.set(advisory.id, advisory);
  }
  return [...seen.values()];
}

/** 「どれくらい危ないか」を 1 文で表す（CVE の羅列ではなく理由を伝える）。 */
function riskReason(affected) {
  if (affected.some((advisory) => advisory.kev)) return "実際に悪用が確認されています";
  const maxCvss = Math.max(...affected.map((advisory) => advisory.cvss ?? 0));
  if (maxCvss >= RED_CVSS) return `深刻度が非常に高い弱点があります（${maxCvss.toFixed(1)}）`;
  const maxEpss = Math.max(...affected.map((advisory) => advisory.epss ?? 0));
  if (maxEpss >= RED_EPSS) {
    return `30 日以内に悪用される確率が高い弱点があります（${Math.round(maxEpss * 100)}%）`;
  }
  if (maxCvss) return `弱点の影響を受けます（深刻度 ${maxCvss.toFixed(1)}）`;
  return "弱点の影響を受けます";
}

/** 1 コンポーネントを勧告（CVE）と突き合わせる。 */
function judgeAdvisories(component, index) {
  const advisories = index ? index.advisoriesFor(component) : [];

  if (!component.version) {
    // 版が分からない = 判定不能。勧告の履歴があるものだけ灰で知らせる。
    if (!advisories.length) return null;
    const unique = uniqueById(advisories);
    return {
      component: component.name,
      version: null,
      level: LEVEL.GRAY,
      action: "Version を確認してください",
      advisories: unique,
      note: `Version が不明なため判定できません（過去の勧告 ${unique.length} 件）`,
    };
  }

  const affected = advisories.filter((advisory) => isAffected(component.version, advisory));
  if (!affected.length) {
    if (!advisories.length) return null;
    const unique = uniqueById(advisories);
    return {
      component: component.name,
      version: component.version,
      level: LEVEL.NONE,
      action: "この Version は該当しません",
      advisories: unique,
      note: `過去の勧告 ${unique.length} 件はすべて修正済みです`,
    };
  }

  const fixed = [...new Set(affected.map((advisory) => advisory.fixed).filter(Boolean))].sort(
    compareVersions,
  );
  return {
    component: component.name,
    version: component.version,
    level: levelFor(affected),
    action: fixed.length
      ? `修正版 ${fixed[fixed.length - 1]} に更新してください`
      : "修正版は公開されていません（ベンダに確認してください）",
    advisories: uniqueById(
      [...affected].sort((a, b) => Number(!a.kev) - Number(!b.kev) || (b.cvss ?? 0) - (a.cvss ?? 0)),
    ),
    note: riskReason(affected),
  };
}

/** サポート終了（軸B）の判定。脆弱性が 0 件でも「移行が必要」を出す。 */
function judgeLifecycle(component, lifecycles, today) {
  if (!lifecycles || !component.version) return null;
  if (!LIFECYCLE_KINDS.includes(component.kind)) return null;

  const status = lifecycles.check(component.name, component.version, today);
  if (!status || status.state === "supported" || status.state === "unknown") return null;

  let level = LEVEL.NONE;
  let action;
  if (status.state === "eol") {
    action = status.moveTo
      ? `サポートが終了しています。${status.moveTo} 以降に移行してください`
      : "サポートが終了しています。サポート中の系統へ移行してください";
    level = LEVEL.YELLOW;
  } else if (status.state === "eol_soon") {
    action = status.moveTo
      ? `サポート終了が近づいています。${status.moveTo} 以降に更新してください`
      : "サポート終了が近づいています。サポート中の系統へ更新してください";
    level = LEVEL.YELLOW;
  } else {
    action = `同じ ${status.cycle} 系の最新は ${status.latest} です`;
  }

  return {
    component: component.name,
    version: component.version,
    level,
    action,
    advisories: [],
    note: lifecycleNote(status),
  };
}

/** 同じコンポーネントの 2 つの判定（脆弱性・EOL）を 1 行にまとめる。
 *
 * ``right`` はライフサイクル（EOL）の判定。**移行の提案を先に**出す
 * （サポートが終わった枝にパッチを当てても長くはもたないため）。
 */
function mergeJudgements(left, right) {
  const level = LEVEL_ORDER[left.level] <= LEVEL_ORDER[right.level] ? left.level : right.level;
  const actions = [...new Set([right.action, left.action].filter(Boolean))];
  const notes = [...new Set([left.note, right.note].filter(Boolean))];
  const advisories = new Map();
  for (const advisory of [...(left.advisories || []), ...(right.advisories || [])]) {
    advisories.set(advisory.id, advisory);
  }
  return {
    component: left.component,
    version: left.version ?? right.version,
    level,
    action: actions.join(" / "),
    advisories: [...advisories.values()],
    note: notes.join("。"),
  };
}

/**
 * 検出結果と索引を突き合わせて、コンポーネントごとの判定を返す。
 *
 * 2 軸で見る: 軸A=既知の脆弱性、軸B=サポート終了（EOL）。
 * 同じコンポーネントに両方が当たったら 1 行にまとめ、重い方を採用する。
 *
 * @param {{findings: Array}} analysis
 * @param {AdvisoryIndex|null} index
 * @param {Date} [today] テスト用に日付を固定できる
 */
export function judge(analysis, index, today = new Date()) {
  const findings = analysis?.findings || [];
  const judgements = [];

  for (const component of findings) {
    if (!ADVISORY_KINDS.includes(component.kind)) continue;
    const judgement = judgeAdvisories(component, index);
    if (judgement) judgements.push(judgement);
  }
  for (const component of findings) {
    const judgement = judgeLifecycle(component, index?.lifecycles ?? null, today);
    if (judgement) judgements.push(judgement);
  }

  const merged = new Map();
  for (const judgement of judgements) {
    const key = normalizeSlug(judgement.component);
    const existing = merged.get(key);
    merged.set(key, existing ? mergeJudgements(existing, judgement) : judgement);
  }

  return [...merged.values()].sort(
    (a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || a.component.localeCompare(b.component),
  );
}


export function summarizeLevels(judgements) {
  const counts = { red: 0, yellow: 0, gray: 0, none: 0 };
  for (const judgement of judgements) {
    counts[judgement.level] = (counts[judgement.level] || 0) + 1;
  }
  return counts;
}

export class AdvisoryIndex {
  constructor(advisories = [], generatedAt = null) {
    this.advisories = advisories;
    this.generatedAt = generatedAt;
    /** サポート終了（EOL）情報。索引 JSON の ``lifecycles`` から読む。 */
    this.lifecycles = null;
    this._byKey = new Map();
    this._byName = new Map();
    for (const advisory of advisories) {
      const key = normalizeSlug(advisory.slug || advisory.name);
      if (!this._byKey.has(key)) this._byKey.set(key, []);
      this._byKey.get(key).push(advisory);

      const nameKey = normalizeSlug(advisory.name);
      if (!this._byName.has(nameKey)) this._byName.set(nameKey, []);
      this._byName.get(nameKey).push(advisory);
    }
    // 前方一致を O(log n) で引くため、正規化した名前を並べておく
    this._sortedNames = [...this._byName.keys()].sort();
  }

  static fromJSON(data) {
    const isArray = Array.isArray(data);
    const advisories = isArray ? data : data?.advisories || [];
    const index = new AdvisoryIndex(advisories, isArray ? null : (data?.generated_at ?? null));
    index.lifecycles = isArray ? null : LifecycleIndex.fromJSON(data?.lifecycles);
    return index;
  }

  get size() {
    return this.advisories.length;
  }

  lookup(nameOrSlug) {
    return [...(this._byKey.get(normalizeSlug(nameOrSlug)) || [])];
  }

  /**
   * 検出結果に該当しうる勧告を探す（slug 完全一致 → 表示名完全一致 → 前方一致）。
   *
   * 前方一致は**プラグインとテーマだけ**。``wordpress``（コア）に許すと
   * 「WordPress User Extra Fields」のようなプラグイン名を拾って誤検知になる。
   */
  advisoriesFor(component) {
    const slug = normalizeSlug(component.name || "");
    const byKey = this._byKey.get(slug);
    if (byKey) return [...byKey];

    const byName = this._byName.get(slug);
    if (byName) return [...byName];

    if (component.kind !== "plugin" && component.kind !== "theme") return [];
    if (slug.length < MIN_PREFIX_MATCH) return [];

    const prefix = `${slug}-`;
    const matched = [];
    let index = lowerBound(this._sortedNames, prefix);
    while (index < this._sortedNames.length && this._sortedNames[index].startsWith(prefix)) {
      matched.push(...this._byName.get(this._sortedNames[index]));
      index += 1;
    }
    return matched;
  }
}

/**
 * サポート終了（EOL）情報。索引 JSON の ``lifecycles`` をそのまま使う。
 *
 * 形式: ``{products: {php: {name: "PHP", cycles: [{cycle, eol, latest}]}}}``
 */
export class LifecycleIndex {
  constructor(products = {}) {
    this.products = products;
    this._byAlias = new Map();
    for (const [key, value] of Object.entries(products)) {
      const entry = { key, ...value };
      this._byAlias.set(key.toLowerCase(), entry);
      if (value?.name) this._byAlias.set(String(value.name).toLowerCase(), entry);
    }
  }

  static fromJSON(data) {
    if (!data || typeof data !== "object") return null;
    const products = data.products && typeof data.products === "object" ? data.products : data;
    const entries = Object.entries(products).filter(
      ([, value]) => value && typeof value === "object" && Array.isArray(value.cycles),
    );
    return entries.length ? new LifecycleIndex(Object.fromEntries(entries)) : null;
  }

  get size() {
    return Object.keys(this.products).length;
  }

  /**
   * ``version`` の状態を返す（``eol`` / ``eol_soon`` / ``outdated`` / ``supported`` / ``unknown``）。
   * 対象外の製品は ``null``。
   */
  check(product, version, today = new Date()) {
    const lifecycle = this._byAlias.get(String(product ?? "").trim().toLowerCase());
    if (!lifecycle) return null;

    const name = lifecycle.name || product;
    const cycles = [...(lifecycle.cycles || [])].sort(
      (a, b) => String(b.cycle).split(".").length - String(a.cycle).split(".").length,
    );
    const digits = String(version ?? "")
      .trim()
      .replace(/^[vV]/, "")
      .replace(/-/g, ".")
      .split(".")
      .filter(Boolean)
      .map((part) => (/^\d+$/.test(part) ? String(Number(part)) : part));

    const cycle = cycles.find((candidate) => {
      const width = String(candidate.cycle).split(".").length;
      return digits.length >= width && digits.slice(0, width).join(".") === String(candidate.cycle);
    });
    if (!cycle) return { product, name, version, state: "unknown" };

    const todayTs = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
    const eolTs = parseDate(cycle.eol);
    const behind = Boolean(cycle.latest && compareVersions(version, cycle.latest) < 0);

    let state = "supported";
    if (eolTs !== null) {
      if (eolTs < todayTs) state = "eol";
      else if ((eolTs - todayTs) / 86400000 <= EOL_SOON_DAYS) state = "eol_soon";
      else if (behind) state = "outdated";
    } else if (behind) {
      state = "outdated";
    }

    let moveTo = null;
    if (state === "eol" || state === "eol_soon") {
      const alive = cycles
        .filter((candidate) => {
          const ts = parseDate(candidate.eol);
          return (ts === null || ts >= todayTs) && candidate.latest;
        })
        .sort((a, b) => compareVersions(b.cycle, a.cycle));
      if (alive.length) moveTo = alive[0].latest;
    }

    return {
      product,
      name,
      version,
      state,
      cycle: cycle.cycle,
      eol: cycle.eol ?? null,
      latest: cycle.latest ?? null,
      moveTo,
    };
  }
}

