# Chrome 拡張（サイト脆弱性チェッカー）

開いているサイトの技術構成を推定し、**既知の脆弱性とサポート終了**を「更新すべきもの」として表示します。
判定は拡張の**端末内**で行い、閲覧 URL をサーバへ送りません。

## 読み込み方（開発中は unpacked）

1. `chrome://extensions` を開く
2. 右上の **デベロッパー モード** を ON
3. **パッケージ化されていない拡張機能を読み込む** → この `extension` フォルダを選ぶ
4. ツールバーのアイコンをクリック → サイドパネルが開く

## 索引（advisories.json）

拡張は**索引をローカルに持って**照合します。取得元は **GitHub Releases のみ**（`config.js`）で、
**設定画面はありません**。**「このサイトを調べる」を押すたびに、（最短 5 分間隔で）索引が最新かを ETag で確認し、変わっていれば
自動で取りに行きます**（初回だけ Chrome がアクセス許可を確認します）。

```
https://akiramatsumoto-github.github.io/site-vuln-checker/advisories.json
```

索引は `.github/workflows/publish-index.yml` が毎日 03:00 JST に作り直します
（手元で配信する必要はありません）。画面下に `取得元 akiramatsumoto-github.github.io` と表示されます。

> 取得には **`akiramatsumoto-github.github.io`** への許可が必要です（Pages は直配信なので 1 オリジンだけ）。
> 初回のクリック時に求められます。Releases にも同じファイルを置いていますが、拡張は使いません
> （Releases は署名付き URL へ 302 するため、リダイレクト先の許可も必要になり CORS で失敗しやすい）。

> 許可しないと索引を取得できません。**閲覧 URL はどこにも送りません**（通信は索引の取得だけ）。

## 使い方

1. 調べたいサイトを開く
2. アイコンをクリック → サイドパネルで **「このサイトを調べる」**
3. 結果が出る
   - **更新すべきもの**: 🔴 赤 / 🟡 黄 / ⚪ 不明（判定不能）/ — 該当なし
   - **構成**: 基盤・コア・プラグイン・テーマ・JS ライブラリ・言語・サーバ
   - **判定できなかったこと**: 版が不明、PHP 不明 など
4. アイコンに、赤（または黄・不明）の件数が出る
5. **PHP やフレームワークの版が分かる場合**は「バージョンを入力」に入れて **追加**。
   そのサイトのぶんだけ保存され、サポート終了（EOL）と本体の脆弱性を判定する

## 制約（正直な限界）

| 制約 | 理由 |
| --- | --- |
| **PHP のバージョンは大半のサイトで取れない** | 公開しているサイトだけ分かる（実測 10 サイト中 1 サイト）。**初回のチェック時にそのサイトの許可を求める**（許可すれば `X-Powered-By` を読み、拒否・非公開なら入力で代替） |
| フレームワークの版も外から取れない | 目印（`csrfmiddlewaretoken` など）から名前だけ推定する。版は入力式 |
| 管理画面専用プラグインは検出できない | フロントにアセットを出さないため |
| 有効/無効の断定はしない | 本文中の文字列だけで見つけたものは「有効」と表示しない（`active=null`） |
| 「緑」は安全を意味しない | 判定は**推定**。検出できた範囲の話でしかない |
| CodeIgniter の EOL は出せない | endoflife.date にデータが無い（CVE の判定は可能） |

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
- **最小権限**: `activeTab` / `tabs` / `scripting` / `storage` / `sidePanel` / `alarms` のみ。`<all_urls>` と `webRequest` は要求しない
  - `tabs` は「いま開いているサイトの URL を知る」ために必要（履歴は読みません）
  - サイトの読み取りは、アイコンを押したとき（`activeTab`）または**サイトごとの許可**で行う
- **プライバシー**: 閲覧 URL を送らない・テレメトリなしを説明文とポリシーに明記
- 名前・説明文に **「WordPress」を入れない**（商標ポリシー。説明文での言及に留める）
