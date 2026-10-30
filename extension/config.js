// 拡張の設定値（URL など）を 1 か所にまとめる。
//
// 索引（advisories.json）は **GitHub Pages から取得する**（本番のみ）。
// Releases はリダイレクト（302 → 署名付き URL）になるため、拡張の fetch では
// リダイレクト先の許可も必要になり、CORS で失敗しやすかった。
// Pages は直配信なので **1 オリジンの許可**だけで済む。
// URL は利用者に打たせない。許可を求めるのは「このサイトを調べる」を押したとき。

/** 索引の配信元（GitHub Actions が毎日更新する）。 */
export const INDEX_URL =
  "https://akiramatsumoto-github.github.io/site-vuln-checker/advisories.json";

/** 取得を試す URL（本番のみ）。 */
export const INDEX_CANDIDATES = [INDEX_URL];

/** 索引の取得に必要なオリジン（Pages は直配信なので 1 つでよい）。 */
export const INDEX_ORIGINS = ["https://akiramatsumoto-github.github.io/*"];




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


