// URL から Chrome のマッチパターンを作る小さな共通関数。
//
// Chrome のマッチパターンは**ポートを含められない**（`https://example.com:8443/*` は
// そのままでは通らない）ため、ホスト名だけを使う。索引の配信元と
// 「サイトのヘッダを読む」許可の両方で使う。

export function originPattern(url) {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.hostname}/*`;
}
