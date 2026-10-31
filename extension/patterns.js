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

//: サイトヘルスの画面。**ディレクトリ名は問わない**（`/wp-admin/` を `/admin/` などに
//: 変えているサイトがあるため）。`admin.php?page=site-health` 形式の実装も拾う。
const SITE_HEALTH_PATH = /\/site-health\.php\/?$/i;
const SITE_HEALTH_PAGE_SLUG = /^site-health$/i;

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

/**
 * サイトヘルスの「情報」タブか（``?tab=debug``）。
 *
 * WordPress は**情報タブのときだけ** PHP・プラグインの表を HTML に出力する。
 * 「ステータス」タブ（``?tab`` なし）には表が無いので、自動で切り替える必要がある。
 */
export function isSiteHealthInfoTab(url) {
  try {
    return new URL(url).searchParams.get("tab") === "debug";
  } catch {
    return false;
  }
}

/**
 * WordPress の**管理画面のトップ**か（``/wp-admin/`` または ``/wp-admin/index.php``）。
 *
 * ここからだけサイトヘルスへ自動で移動する（投稿の編集中などに遷移して
 * 未保存の内容を失わせないため、対象を絞っている）。
 */
export function isAdminHomeUrl(url) {
  try {
    return /\/wp-admin\/(?:index\.php)?$/i.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

/**
 * WordPress の「サイトヘルス」の画面か（「情報」タブでなくてもよい）。
 *
 * サイトヘルスの情報は**同じページに全部入っている**（タブは表示の切り替えだけ）ので、
 * `?tab=debug` かどうかは見ない。ディレクトリ名の変更（`/admin/site-health.php`）や
 * サブディレクトリ設置（`/wp/site-health.php`）でも一致させる。
 */
export function isSiteHealthUrl(url) {
  try {
    const parsed = new URL(url);
    if (SITE_HEALTH_PATH.test(parsed.pathname)) return true;
    return SITE_HEALTH_PAGE_SLUG.test(parsed.searchParams.get("page") ?? "");
  } catch {
    return false;
  }
}
