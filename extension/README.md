# Chrome 拡張（サイト脆弱性チェッカー）

開いているサイトの技術構成を推定し、**既知の脆弱性とサポート終了**を「更新すべきもの」として表示します。
判定は拡張の**端末内**で行い、閲覧 URL をサーバへ送りません。

## 読み込み方（開発中は unpacked）

1. `chrome://extensions` を開く
2. 右上の **デベロッパー モード** を ON
3. **パッケージ化されていない拡張機能を読み込む** → この `extension` フォルダを選ぶ
4. ツールバーのアイコンをクリック → サイドパネルが開く

## 索引（advisories.json）を用意する

拡張は**索引をローカルに持って**照合します。まず Python 側で索引を作ります。

```powershell
cd C:\Users\yahoo\dev\site-vuln-checker

# NVD から索引を作り、KEV / EPSS を付ける
uv run svc-ingest --days 14 --limit 200 --out out/advisories.json
uv run svc-enrich --index out/advisories.json

# ローカルで配信する（別のターミナルで）
python -m http.server 8000
```

拡張の**設定**（サイドパネルの「設定」ボタン）で、索引の URL を入れて「保存して読み込む」：

```
http://localhost:8000/out/advisories.json
```

> オリジンへのアクセス許可を求められます（`optional_host_permissions`）。
> 許可しないと索引を取得できません。**閲覧 URL はどこにも送りません**（通信は索引の取得だけ）。

## 使い方

1. 調べたいサイトを開く
2. アイコンをクリック → サイドパネルで **「このサイトを調べる」**
3. 結果が出る
   - **更新すべきもの**: 🔴 赤 / 🟡 黄 / ⚪ 灰（判定不能）/ — 該当なし
   - **構成**: 基盤・コア・プラグイン・テーマ・JS ライブラリ・言語・サーバ
   - **判定できなかったこと**: 版が不明、PHP 不明 など
4. アイコンのバッジに、赤（または黄・灰）の件数が出る

## 制約（正直な限界）

| 制約 | 理由 |
| --- | --- |
| **PHP のバージョンは取れない** | ヘッダを読む権限（`webRequest`）を要求していないため。`X-Powered-By` は MV3 の案 A では見えない |
| 管理画面専用プラグインは検出できない | フロントにアセットを出さないため |
| 有効/無効の断定はしない | 本文中の文字列だけで見つけたものは「有効」と表示しない（`active=null`） |
| 「緑」は安全を意味しない | 判定は**推定**。検出できた範囲の話でしかない |

## テスト

```powershell
# 構文チェック
node --check extension/background.js
node --check extension/detector.js
node --check extension/advisor.js
node --check extension/sidepanel.js
node --check extension/options.js

# 単体テスト（Python 版と同じフィクスチャを使う）
node --test extension/tests/detector.test.mjs extension/tests/advisor.test.mjs
```

CI（GitHub Actions）でも同じコマンドを実行しています。

## Chrome Web Store に出すときの注意（企画書 20 章）

- **単一目的**: 「閲覧中サイトの技術構成と既知脆弱性の表示」に限定する（一覧ダッシュボードは拡張に入れない）
- **最小権限**: `activeTab` / `scripting` / `storage` / `sidePanel` / `alarms` のみ。`<all_urls>` と `webRequest` は要求しない
- **プライバシー**: 閲覧 URL を送らない・テレメトリなしを説明文とポリシーに明記
- 名前・説明文に **「WordPress」を入れない**（商標ポリシー。説明文での言及に留める）
