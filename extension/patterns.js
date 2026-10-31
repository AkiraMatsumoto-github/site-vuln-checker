// URL から Chrome のマッチパターンを作る小さな共通関数。
//
// Chrome のマッチパターンは**ポートを含められない**（`https://example.com:8443/*` は
// そのままでは通らない）ため、ホスト名だけを使う。索引の配信元と
// 「サイトのヘッダを読む」許可の両方で使う。

export function originPattern(url) {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.hostname}/*`;
}

//: 管理画面（HEAD を送っても意味が無い）のパス。
const ADMIN_PATH = /^\/wp-(?:admin|login)/i;

/**
 * 管理画面かどうか。
 *
 * `wp-admin` への HEAD はログイン画面へのリダイレクトが返るだけで、
 * 得られる情報が無いのに**サーバへ余計な負荷**をかける（レビュー #10）。
 */
export function isAdminUrl(url) {
  try {
    return ADMIN_PATH.test(new URL(url).pathname);
  } catch {
    return false;
  }
}
