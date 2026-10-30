// 拡張の設定値（URL など）を 1 か所にまとめる。
//
// 索引（advisories.json）は **GitHub Releases から取得する**（本番のみ）。
// URL は利用者に打たせない。取得にはオリジンの許可が要るので、
// 許可を求めるのは「このサイトを調べる」を押したとき（ユーザー操作）に行う。

/** 索引の配信元（GitHub Actions が毎日更新する）。 */
export const RELEASE_INDEX_URL =
  "https://github.com/AkiraMatsumoto-github/site-vuln-checker/releases/latest/download/advisories.json";

/** 取得を試す URL（本番のみ）。 */
export const INDEX_CANDIDATES = [RELEASE_INDEX_URL];


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


