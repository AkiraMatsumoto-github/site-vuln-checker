# サイト脆弱性チェッカー（Site Vulnerability Checker）

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/AkiraMatsumoto-github/site-vuln-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/AkiraMatsumoto-github/site-vuln-checker/actions/workflows/ci.yml)
![Chrome: Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-4285f4.svg)
![判定は端末内](https://img.shields.io/badge/%E5%88%A4%E5%AE%9A-%E7%AB%AF%E6%9C%AB%E5%86%85-2ea44f.svg)
![無料](https://img.shields.io/badge/%E6%96%99%E9%87%91-%E7%84%A1%E6%96%99-brightgreen.svg)

**開いているサイトが、何で動いていて、どこが古いか。ひと目で。**

サイトの技術構成（WordPress・プラグイン・JS ライブラリ）を推定し、**既知の脆弱性**と
突き合わせて、**「更新すべきもの」**だけを表示する Chrome 拡張です。
判定は端末の中で行い、**見ているサイトの URL をどこにも送りません**。

| 🔍 その場で判定 | ⚠️ 更新すべきものだけ | 🔒 端末内で判定 | 💸 完全無料 |
| :---: | :---: | :---: | :---: |
| 開いているタブを 1 クリックで調べる | 赤 / 黄 / 灰で優先順位を出す | URL を送らない・テレメトリなし | 公開データだけで動く |

## なぜ作ったか

- **そのサイトが何で動いているか、外からは分からない。** 問い合わせるしかない現場が多く、古いプラグインが残っていても気づけません。
- **「プラグインだけ更新すれば安心」ではない。** PHP 8.1 のように**土台のサポートが終わっている**のに、WordPress だけ最新にして安心しているサイトがあります。
- **脆弱性情報が英語で、あちこちに散っている。** NVD・JVN・ベンダの DB を 1 つずつ見るのは現実的ではありません。
- **既存ツールは片手落ち。** WPScan は CLI で WordPress 専用、Retire.js は JS だけ、OSV-Scanner は手元のコードだけ。**「いま見ているサイト」を横断的に見る道具**がありませんでした。

この 4 つを 1 つにまとめるために作りました。

## できること / できないこと

**先に「できないこと」を書きます。** ここを曖昧にすると、いちばん危ない誤解（＝「緑だから安全」）を生むためです。

| | 内容 |
| --- | --- |
| ✅ できる | サイトのプラットフォーム判定（WordPress など）／**コアのバージョン**／プラグイン・テーマの検出と版の推定／JS ライブラリの検出／**既知の脆弱性との照合**／**更新先のバージョン提示**／**悪用実績（KEV）・悪用予測（EPSS）での優先順位** |
| ⚠️ 一部だけ | プラグインは**フロントに出ているものだけ**（有効化されていて画面に読み込まれるもの）。版が取れないものは「灰」 |
| ❌ できない | **PHP のバージョン**（サーバが公開していないことが多い）／管理画面専用プラグイン／テーマの脆弱性（公開 DB がない）／SaaS（Shopify など）のサーバ側／**「安全である」ことの保証** |
| 🚧 これから | **サポート終了（EOL）の判定**（PHP・WordPress コア）／自サイトの Site Health 読み取り／Chrome Web Store での公開／JS ライブラリのシグネチャ拡充 |

## かんたん 3 ステップ

1. **索引を読み込む**（初回だけ）— 設定画面で索引の URL を指定します。
2. 調べたいサイトを開いて、**ツールバーのアイコン**をクリック。
3. サイドパネルの **「このサイトを調べる」** を押すと、**更新すべきもの**が出ます。

## 判定のしかた（赤 / 黄 / 灰）

| 判定 | 条件 | 意味 |
| --- | --- | --- |
| 🔴 赤 | 影響する勧告に **KEV**（実際に悪用された）／**CVSS 9.0 以上**／**EPSS 0.5 以上**がある | 早めに対応したい |
| 🟡 黄 | 影響する勧告がある（上記以外） | 修正版が出ています。更新を検討 |
| ⚪ 灰 | **バージョンが分からない**（勧告の履歴があるものだけ表示） | 判定できません |
| — | 勧告はあるが修正版以降 | 該当なし（**検出できた範囲で**） |

> **「緑」は「安全」ではありません。** バージョンが取れないものを緑にしない、根拠を必ず出す、
> 判定した時刻とデータの日付を出す——という原則で作っています。

## 外部から、どこまで分かるのか（実測）

「結局どれくらい分かるのか」を先に出します（2026-10-29〜30 に実測）。

**サイトを見たとき**（`wordpress.org` / `ja.wordpress.org` / `php.net` / `example.com` を各 1 リクエスト）

| 項目 | 結果 |
| --- | --- |
| WordPress の判定 | 2/4（残り 2 件は WordPress ではないサイト） |
| **コアのバージョン** | **2/2（100%）**（`meta generator` から。片方は `7.2-beta3-…`） |
| プラグイン | 各 1 件（`gutenberg` 24.3.0）／**版も取得** |
| **PHP のバージョン** | **0/4（0%）** |
| サーバのバージョン | 0/4（0%）（`Server: nginx` のみで、版は非公開） |

→ **コアはほぼ確実に取れる。PHP は外からはほぼ取れない。** そのため PHP のサポート終了は
「取れたときだけ警告する」扱いで、自サイト向けの正確な読み取りは今後の対応にしています。

**索引（脆弱性データ）を作ったとき**（NVD・直近 14 日・200 件）

| 項目 | 結果 |
| --- | --- |
| 索引に載った | **175 件（88%）**（除外 25 件：プラグイン名が特定できない 22・影響バージョンが特定できない 3） |
| 影響範囲の書き方 | 「X 以下」52 件 ／ 「before X」123 件 |
| KEV に該当 | **0 件**（直近の WordPress プラグイン CVE は KEV に載っていない） |
| EPSS | 全件に付与。**中央値 0.24%**・最大 2.5% |
| 索引全体の判定 | 赤 4 件（すべて CVSS 9.0 以上）／黄 171 件 |

→ WordPress プラグインの新しい CVE は **KEV に載らず、EPSS も低い**。つまり WP プラグインの「赤」は
**CVSS と修正版の有無**で決まります。KEV / EPSS は PHP コアや、広く使われている古い CVE で効きます。

## 何でできているか

```
extension/                     Chrome 拡張（Manifest V3・ビルド不要）
  detector.js                  技術構成の推定（プラグイン・版・確度・根拠）
  advisor.js                   索引との照合と赤 / 黄 / 灰
  background.js                タブの証拠収集 → 判定 → バッジ
  sidepanel.html / .js         結果の表示
  options.html / .js           索引 URL の設定
src/site_vuln_checker/         索引を作る側（Python 3.14 / uv）
  ingest.py                    NVD → 索引（「before X」「X 以下」を抽出）
  enrich.py                    KEV / EPSS の結合
  detect.py / advisories.py    判定ロジック（拡張の JS と同じ仕様）
  survey.py / report.py        外部判定の実測と HTML レポート
tests/                         フィクスチャ（**Python と JS で共用**）
```

判定ロジックは **Python と JavaScript の二重実装**ですが、**同じフィクスチャで同じ結果**になることを
テストで固定しています（Python 95 件 / JS 20 件）。

## 使い方（インストール）

**いまは Chrome Web Store で公開していません。** 開発版（unpacked）として読み込みます。

### 1. 索引を作る

```powershell
git clone https://github.com/AkiraMatsumoto-github/site-vuln-checker.git
cd site-vuln-checker
uv sync

# NVD から索引を作り、悪用実績（KEV）と悪用予測（EPSS）を付ける
uv run svc-ingest --days 14 --limit 200 --out out/advisories.json
uv run svc-enrich --index out/advisories.json
```

### 2. 索引を配信する（別のターミナル）

```powershell
python -m http.server 8000
```

### 3. 拡張を読み込む

1. `chrome://extensions` を開く
2. 右上の **デベロッパー モード** を ON
3. **パッケージ化されていない拡張機能を読み込む** → `extension` フォルダを選ぶ
4. ツールバーのアイコン → サイドパネルの **設定** で、索引の URL を入れて「保存して読み込む」

```
http://localhost:8000/out/advisories.json
```

> 索引の配信元へのアクセス許可を求められます。**閲覧したサイトの URL はどこにも送りません**
> （通信は索引の取得だけです）。

## 設定: NVD API キー（任意）

NVD の CVE API はキー無しでも使えますが、**キーがあると 10 倍速く**なります
（キー無し 5 リクエスト/30 秒 → キーあり 50 リクエスト/30 秒）。取得は無料です
（[NVD の申請ページ](https://nvd.nist.gov/developers/request-an-api-key)）。

```powershell
$env:NVD_API_KEY = "取得したキー"   # そのセッションだけ
setx NVD_API_KEY "取得したキー"     # 以後ずっと（新しいターミナルから有効）
```

リポジトリ直下の `.env` に書くこともできます（`.gitignore` 済み。`.env.example` をコピー）。
優先順位は **環境変数 → `.env`** です。**拡張にはキーを持たせません。**

## プライバシー

- 判定は**端末の中**で行います。**見ているサイトの URL をサーバへ送りません**。
- 通信は**索引の取得だけ**です（どのサイトを見たかの情報は含まれません）。
- 拡張に **API キーなどの秘密情報を持たせていません**。
- 索引の生成（Python 側）は公開データ（NVD / CISA KEV / FIRST EPSS）だけを使います。
- アクセス解析・テレメトリはありません。

## 制約と注意（正直に）

| 制約 | 理由 |
| --- | --- |
| **PHP のバージョンは取れません** | ヘッダを読む権限（`webRequest`）を要求していないため。`X-Powered-By` を公開しているサイトは限られます（実測 0/4） |
| **サポート終了（EOL）の判定はまだありません** | 今は「既知の脆弱性」だけを見ています。EOL は PHP のバージョンが取れてから意味を持つため、Site Health 読み取りとセットで追加します |
| 管理画面専用プラグインは対象外 | フロントにアセットを出さないため |
| 有効 / 無効は断定しません | 本文中の文字列だけで見つけたものは「有効」と表示しません |
| **誤検知・未検出はあります** | `?ver=` は書き換えられ得る、WAF がバージョンを隠す、など |
| 第三者のサイトを調べる範囲 | **公開ページの閲覧の範囲**に限ります（追加のスキャンはしません） |
| 判定は**推定**です | 安全性を保証しません。「緑」は「安全」ではありません |
| **異議申立て窓口は未設置** | 公開（Chrome Web Store）までに用意します |

## よくある質問

<details>
<summary>製品名に「WordPress」が入っていないのはなぜ？</summary>

WordPress Foundation の商標ポリシーで、**製品名・サービス名・ドメイン名に「WordPress」を使うのは許可制**です
（"Hosting for WordPress" のように、説明で言及する形が推奨されています）。このため製品名には入れず、
説明文で言及しています。詳しくは[企画書 20.3](docs/proposal.md)。
</details>

<details>
<summary>PHP のバージョンが「不明」になる</summary>

外部からは分からないことが多いためです。`X-Powered-By` を公開しているサイトは限られ、
実測では 4 サイト中 0 サイトでした。**「不明」は「安全」ではありません。**
自サイトであれば、WordPress の「ツール → サイトヘルス → 情報」から正確に読めるようにする予定です。
</details>

<details>
<summary>プラグインが「灰」になる</summary>

バージョンが取れないためです。`?ver=` が付いていない、CSS / JS が結合・遅延読み込みされている、
といった理由があります。**推測で埋めずに灰**にしています。
</details>

<details>
<summary>「赤」が出たけど、たぶん誤検知です</summary>

「根拠」に、どのシグナル（`meta:generator`、`asset:?ver=5.9.8` など）で判定したかを出しています。
改善に使うので、[Issues](https://github.com/AkiraMatsumoto-github/site-vuln-checker/issues) で教えてください。
</details>

<details>
<summary>無料ですか？</summary>

無料です（MIT ライセンス）。データは NVD / CISA KEV / FIRST EPSS など**公開データだけ**を使っています。
</details>

<details>
<summary>Chrome Web Store ではいつ公開されますか？</summary>

説明文・プライバシーポリシー・異議申立て窓口を用意してからです。それまでは unpacked で使えます。
</details>

<details>
<summary>WordPress 以外（Shopify など）は対応しますか？</summary>

Shopify は「読み込まれている JS ライブラリの脆弱性」までを v1 以降で対応予定です。
SaaS のサーバ側（アプリのバージョンなど）は外部から見えないため対象外です。
</details>

## 開発

```powershell
uv sync
uv run pytest -q            # Python 95 tests
uv run ruff check .

node --check extension/background.js
node --test extension/tests/detector.test.mjs extension/tests/advisor.test.mjs   # JS 20 tests
```

CI（GitHub Actions）は **Python と Node の両方**を回します。
設計の背景と判断の記録は[企画書](docs/proposal.md)、実装のレビューは[レビュー](docs/review-v0.10.md)にあります。

## ライセンス

このリポジトリは [MIT ライセンス](LICENSE) で公開しています。
Copyright (c) 2026 AkiraMatsumoto-github

使っているデータとソフトウェアは、それぞれのライセンスに従います。

| 名前 | 用途 | ライセンス |
| --- | --- | --- |
| [NVD](https://nvd.nist.gov/)（NIST） | CVE・CVSS・CPE | 米国政府の著作物（パブリックドメイン相当） |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 悪用実績 | 米国政府（公開） |
| [EPSS](https://www.first.org/epss/)（FIRST） | 悪用予測 | 公開データ（無償） |
| [GitHub Advisory Database](https://github.com/advisories) | OSS の勧告（**予定**） | **CC-BY-4.0**（出典表示） |
| [retire.js](https://github.com/RetireJS/retire.js) のシグネチャ | JS ライブラリの判定（予定） | Apache-2.0 |
| [httpx](https://www.python-httpx.org/) / [beautifulsoup4](https://www.crummy.com/software/BeautifulSoup/) | HTTP・HTML 解析 | BSD-3-Clause / MIT |

> データは各提供元のものです。本ツールはそれを再配布しています。

## 参考

- 企画書（設計・判断の記録・実測）: [docs/proposal.md](docs/proposal.md)
- 実装レビュー（指摘と対応）: [docs/review-v0.10.md](docs/review-v0.10.md)
- 拡張の詳細（権限・制約・確認手順）: [extension/README.md](extension/README.md)
