// 拡張の設定値（URL など）を 1 か所にまとめる。
//
// 索引（advisories.json）の場所は**利用者に打たせない**。上から順に試して、
// 最初に取得できたものを使う。取得には各オリジンの許可が要るので、
// 許可を求めるのは「このサイトを調べる」を押したとき（ユーザー操作）に行う。

/** 索引の候補（上から順に試す）。 */
export const INDEX_CANDIDATES = [
  // ローカルで配信している場合（開発・自分で更新する人向け）
  "http://localhost:8000/out/advisories.json",
  // 配布用（GitHub Actions が日次で更新する想定）
  "https://github.com/AkiraMatsumoto-github/site-vuln-checker/releases/latest/download/advisories.json",
];
