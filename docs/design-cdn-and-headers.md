# 設計: CDN・セキュリティヘッダ・タグ・画像配信の検出（1.1.0）

## 目的

「構成（検出できたもの）」で出している情報を増やす。**追加の通信は行わない**（L1 パッシブのまま）。

- いま出している種別: 基盤 / コア / プラグイン / アプリ / テーマ / JS / フレームワーク / 言語 / サーバ
- 追加する種別: **CDN / セキュリティ / タグ / 画像配信**

根拠に使うのは、すでに取得済みの **レスポンスヘッダ**（`background.js` の `readHeaders()` が全部集めている）と、
すでに取得済みの **HTML・読み込み済みリソース URL** だけ。

## 追加する種別と判定

### 1. CDN（`kind: "cdn"`）

**ヘッダ**で判定する（`server` だけに頼らない）。

| 名前 | 目印 |
| --- | --- |
| `cloudflare` | `cf-ray` / `cf-cache-status` / `server: cloudflare` |
| `cloudfront` | `x-amz-cf-id` / `x-amz-cf-pop` / `via: …cloudfront.net` |
| `fastly` | `x-fastly-request-id` / `x-served-by` |
| `akamai` | `x-akamai-transformed` / `akamai-grn` / `x-akamai-request-id` / `server: AkamaiGHost` |
| `vercel` | `x-vercel-id` / `x-vercel-cache` / `server: Vercel` |
| `netlify` | `x-nf-request-id` / `server: Netlify` |
| `azure` | `x-azure-ref` / `server: Windows-Azure…` |
| `google-cloud` | `x-cloud-trace-context` / `server: Google Frontend` `gws` |
| `sucuri` | `x-sucuri-id` / `x-sucuri-cache` |
| `imperva` | `x-iinfo` |
| `bunny` / `keycdn` / `github-pages` | `server: BunnyCDN` / `server: keycdn` / `server: GitHub.com` |

- **`server` に CDN 名が出たときは「サーバ」行を出さない**（実体は CDN なので二重表示を避ける）。
  1.0.1 までは `server: cloudflare` を「サーバ cloudflare」と表示していたが、1.1.0 からは「CDN cloudflare」。
- 版は取れないので `version = null`（精度は `—`）。

### 2. セキュリティヘッダ（`kind: "security"`）

**設定されているものだけ**行にする（`version = null`）。未設定は**注記**にまとめる（行にしない）。

| 行の名前 | ヘッダ |
| --- | --- |
| `hsts` | `strict-transport-security` |
| `csp` | `content-security-policy` |
| `x-frame-options` | `x-frame-options` |
| `x-content-type-options` | `x-content-type-options` |
| `referrer-policy` | `referrer-policy` |
| `permissions-policy` | `permissions-policy` |

- 注記: 「未設定のセキュリティヘッダ: x-frame-options, csp（脆弱性ではありません）」
- **赤・黄（脆弱性）には入れない**。ヘッダの有無は攻撃の可能性の判定材料ではない
- ヘッダを 1 つも取得できていない場合は、未設定の注記を出さない（誤解を避ける）

### 3. タグ（`kind: "tag"`）

読み込み済みリソースの**ホスト名**で判定（`hostMatches` を使い、`notexample.com` は一致させない）。

`googletagmanager.com`（`/gtag/js` は `ga4`、それ以外は `gtm`） / `google-analytics.com`→`ga4` /
`clarity.ms`→`clarity` / `hotjar.com`→`hotjar` / `connect.facebook.net`→`meta-pixel` /
`analytics.tiktok.com`→`tiktok-pixel` / `static.ads-twitter.com`→`x-pixel` / `yjtag.jp`→`yahoo-tag` /
`line-scdn.net`→`line-tag` / `bat.bing.com`→`microsoft-uet` / `js.hs-scripts.com`→`hubspot` /
`assets.adobedtm.com`→`adobe-analytics` / `cdn.segment.com`→`segment` /
`doubleclick.net`→`google-ads` / `googlesyndication.com`→`google-adsense` /
`smartnews-ads.com`→`smartnews-ads` / `microad.jp`→`microad` / `d2c.ne.jp`→`d2c` / `yjmg.jp`→`yahoo-ads`

- Shopify のアプリ（`kind: "app"`）とは別扱い（サイト種類を問わず出す）
- 版は取れないので `version = null`

### 4. 画像配信（`kind: "image"`）

| 名前 | 目印 |
| --- | --- |
| `jetpack-photon` | `i0.wp.com` 〜 `i9.wp.com` |
| `cloudinary` | `*.cloudinary.com` |
| `imgix` | `*.imgix.net` |
| `contentful` | `*.ctfassets.net` |
| `sanity` | `*.sanity.io` |

### 5. 言語・サーバの精度向上

- `x-powered-by: ASP.NET` → 言語 `aspnet`、版は `x-aspnet-version` から
- `x-aspnetmvc-version` → フレームワーク `asp.net-mvc`
- `x-powered-by: Express` → フレームワーク `express`
- `x-powered-by: Servlet/3.1` → 言語 `java`（版 3.1）
- `x-litespeed-cache` → サーバ `litespeed`

### 6. フレームワーク（版が取れるもの）

- **Angular**: `<app-root ng-version="17.3.1">` → `framework/angular` 版あり（`versionConfidence = 1.0`）
  - 同じページで `angular.min.js` を読んでいる場合は **JS ライブラリの `angular` 行を出さない**（二重表示を避ける）
- **SvelteKit**: `data-sveltekit-preload-data` / `__sveltekit`
- **htmx / Alpine.js**: 読み込んでいるファイル名（`htmx.min.js`, `alpine.min.js`）から JS ライブラリとして判定

## 表示（サイドパネル）

`種別` のラベルを追加する（`sidepanel.js` の `KIND_LABEL`、`report.py` の `KIND_LABELS`）。

```
CDN / セキュリティ / タグ / 画像配信
```

並び順は `analyze()` が返す順のまま:
基盤 → コア → プラグイン → アプリ → テーマ → JS → フレームワーク → 言語 → サーバ → **CDN → セキュリティ → タグ → 画像配信**

## 判定に使わないもの（意図的にやらない）

- `/wp-json/`、`/readme.html`、`readme.txt`、`robots.txt`、favicon ハッシュなどの**追加リクエスト**
  → 「能動的なスキャンはしない」という前提（掲載文・プライバシーポリシー）が崩れるため
- セキュリティヘッダの**値の評価**（CSP の中身が妥当か等）→ 誤判定しやすいので「設定の有無」まで

## 実装（両方そろえる）

| ファイル | 変更 |
| --- | --- |
| `extension/detector.js` | 定数・判定関数・`analyze()` / `buildNotes()` |
| `src/site_vuln_checker/detect.py` | 同じ内容（`ANALYTICS_TAG_HOSTS` などは**同じ順**で持つ） |
| `extension/sidepanel.js` | `KIND_LABEL` |
| `src/site_vuln_checker/report.py` | `KIND_LABELS` |
| `extension/background.js` | `buildNotes(findings, headers)` にヘッダを渡す |
| `tests/test_parity.py`, `extension/tests/parity_runner.mjs` | 辞書（タグ・画像・CDN・セキュリティ）の一致を検査 |
| `tests/test_detect.py`, `extension/tests/detector.test.mjs` | 判定のテスト |

## 版

- `extension/manifest.json`: 1.0.1 → **1.1.0**（ストア更新は審査が必要）
- 掲載文の「わかること」に CDN・セキュリティヘッダ・タグの 1 行を足す
