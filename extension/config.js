// 拡張の設定値（URL など）を 1 か所にまとめる。
//
// 索引（advisories.json）の場所は**利用者に打たせない**。候補を順に試して、
// 最初に取得できたものを使う。取得には各オリジンの許可が要るので、
// 許可を求めるのは「このサイトを調べる」を押したとき（ユーザー操作）に行う。
//
// 本番（Chrome Web Store から入れたもの）は **GitHub Releases の索引だけ**を試す。
// 開発（unpacked）は手元の配信を優先する。ストアから入れた拡張には
// manifest の ``update_url`` が入るため、それで判別できる。

/** 配布用の索引（GitHub Actions が日次で更新する）。 */
export const RELEASE_INDEX_URL =
  "https://github.com/AkiraMatsumoto-github/site-vuln-checker/releases/latest/download/advisories.json";

/** 開発用（ローカル配信）。本番では使わない。 */
export const LOCAL_INDEX_URL = "http://localhost:8000/out/advisories.json";

/** 開発（unpacked）かどうか。Node のテストでは chrome が無いので開発扱い。 */
export function isDevelopment(manifest) {
  const resolved =
    manifest ?? (typeof chrome !== "undefined" ? chrome.runtime?.getManifest?.() : null);
  if (!resolved) return true;
  return !resolved.update_url;
}

/**
 * 索引の候補（上から順に試す）。
 *
 * @param {{development?: boolean}} [options]
 */
export function indexCandidates(options = {}) {
  const development = options.development ?? isDevelopment();
  return development ? [LOCAL_INDEX_URL, RELEASE_INDEX_URL] : [RELEASE_INDEX_URL];
}

/** 実行環境に応じた候補（拡張の各画面はこれを使う）。 */
export const INDEX_CANDIDATES = indexCandidates();

/** 索引を「新しい」とみなす期間。Actions が毎日更新するので 24 時間。 */
export const INDEX_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * 索引が古いか（取得し直すべきか）。
 *
 * @param {string|null|undefined} updatedAt 最後に取得した日時（ISO 文字列）
 * @param {number} [now] 現在時刻（テスト用）
 * @param {number} [ttl] 新しいとみなす期間
 */
export function isIndexStale(updatedAt, now = Date.now(), ttl = INDEX_TTL_MS) {
  if (!updatedAt) return true;
  const at = Date.parse(updatedAt);
  if (Number.isNaN(at)) return true;
  return now - at >= ttl;
}


