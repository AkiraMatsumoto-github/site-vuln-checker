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

/** バージョンが勧告の影響範囲に入るか。 */
export function isAffected(version, advisory) {
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

/**
 * 検出結果と索引を突き合わせて、コンポーネントごとの判定を返す。
 *
 * @param {{findings: Array}} analysis
 * @param {AdvisoryIndex|null} index
 */
export function judge(analysis, index) {
  const judgements = [];
  const components = (analysis?.findings || []).filter(
    (item) => item.kind === "plugin" || item.kind === "theme",
  );

  for (const component of components) {
    const advisories = index ? index.advisoriesFor(component) : [];

    if (!component.version) {
      // 版が分からない = 判定不能。勧告の履歴があるものだけ灰で知らせる。
      if (advisories.length) {
        judgements.push({
          component: component.name,
          version: null,
          level: LEVEL.GRAY,
          action: "バージョンを確認する",
          advisories,
          note: `過去に ${advisories.length} 件の勧告あり。版が不明なため判定できません`,
        });
      }
      continue;
    }

    const affected = advisories.filter((advisory) => isAffected(component.version, advisory));
    if (!affected.length) {
      if (advisories.length) {
        judgements.push({
          component: component.name,
          version: component.version,
          level: LEVEL.NONE,
          action: "該当なし（勧告は修正版以降）",
          advisories,
          note: "",
        });
      }
      continue;
    }

    const fixed = [...new Set(affected.map((advisory) => advisory.fixed).filter(Boolean))].sort(
      compareVersions,
    );
    judgements.push({
      component: component.name,
      version: component.version,
      level: levelFor(affected),
      action: fixed.length ? `→ ${fixed[fixed.length - 1]} へ更新` : "修正版不明（ベンダに確認）",
      advisories: [...affected].sort(
        (a, b) => Number(!a.kev) - Number(!b.kev) || (b.cvss ?? 0) - (a.cvss ?? 0),
      ),
      note: "",
    });
  }

  judgements.sort(
    (a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || a.component.localeCompare(b.component),
  );
  return judgements;
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
    const advisories = Array.isArray(data) ? data : data?.advisories || [];
    return new AdvisoryIndex(advisories, Array.isArray(data) ? null : data?.generated_at ?? null);
  }

  get size() {
    return this.advisories.length;
  }

  lookup(nameOrSlug) {
    return [...(this._byKey.get(normalizeSlug(nameOrSlug)) || [])];
  }

  /** 検出結果に該当しうる勧告を探す（slug 完全一致 → 表示名完全一致 → 前方一致）。 */
  advisoriesFor(component) {
    const slug = normalizeSlug(component.name || "");
    const byKey = this._byKey.get(slug);
    if (byKey) return [...byKey];

    const byName = this._byName.get(slug);
    if (byName) return [...byName];

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
