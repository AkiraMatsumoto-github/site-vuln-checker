# サイト脆弱性チェッカー（Site Vulnerability Checker）

[![CI](https://github.com/AkiraMatsumoto-github/site-vuln-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/AkiraMatsumoto-github/site-vuln-checker/actions/workflows/ci.yml)

いま開いているサイトの技術構成（WordPress / PHP / プラグイン / JS ライブラリ）を推定し、
**「既知の脆弱性（軸A）」と「サポート終了・更新遅れ（軸B）」**の 2 軸で「更新すべきもの」を示す企画。
企画書は [`docs/proposal.md`](docs/proposal.md)。

> **名称について**: 製品名に「WordPress」は入れません（WordPress Foundation の商標ポリシーで、
> 製品名・サービス名・ドメイン名への使用は許可制のため）。WordPress には**説明文で言及**します。
> 詳細: 企画書 [20.3 名称と商標](docs/proposal.md#203-名称と商標v08-追加)。
>
> **内部名**: リポジトリ `site-vuln-checker` / Python パッケージ `site_vuln_checker` / CLI `svc-*`（SVC = Site Vulnerability Checker）。

このリポジトリには、企画の成立可否を確かめる **PoC（Phase 0）** を置く。

## PoC の内容

| ID | 内容 | 実装 |
| --- | --- | --- |
| **P0-21** | 外部からどれだけ判定できるかの実測（対応サイトを巡回し、検出率を集計） | `site_vuln_checker/survey.py` |
| **P0-18** | WordPress「サイトヘルス → 情報」の DOM 解析（PHP 版数・全プラグイン・DB の取得） | `site_vuln_checker/sitehealth.py` |
| 可視化 | 検出したプラグイン・版・確度・根拠を HTML レポートにする | `site_vuln_checker/report.py` |
| **判定（軸A）** | 勧告索引（JSON）と突き合わせて **赤 / 黄 / 灰** を決める | `site_vuln_checker/advisories.py` |
| **索引の生成** | NVD の CVE から「before X」「X 以下」を抽出して索引を作る | `site_vuln_checker/ingest.py` |
| **悪用実績・予測** | KEV / EPSS を索引に付ける | `site_vuln_checker/enrich.py` |
| **Chrome 拡張** | サイドパネルで判定を表示（MV3・ビルド不要・Node はテストのみ） | `extension/` |

> **JS は未検証**: この環境には Node が入っていないため、まず判定ロジックを Python で固め、
> `tests/fixtures/` を**正解データ**として拡張（Manifest V3 / JS）へ移植する。
> 移植先では同じフィクスチャで同じ結果になることを受け入れ条件にする。

## 使い方

```powershell
# 依存の同期
uv sync

# テスト
uv run pytest -q
uv run ruff check .

# 外部判定の実測（robots.txt を尊重し、1 サイト 1 リクエスト・既定 1 秒間隔）
uv run svc-survey --urls sites.sample.txt --limit 5 --delay 1.0

# 勧告索引を NVD から作る（直近 14 日・最大 200 件。キーがあると速い）
uv run svc-ingest --days 14 --limit 200 --out out/advisories.json

# 索引を渡すと、赤 / 黄 / 灰 の判定まで行う
uv run svc-survey --urls sites.sample.txt --limit 5 --delay 1.0 `
  --advisories out/advisories.json

# 結果を HTML に可視化する
uv run svc-report
```

出力は `out/` に置く（`survey.json` / `summary.json` / `report.html`）。

## 設定: NVD API キー（任意）

NVD の CVE API はキー無しでも使えますが、**キーがあると 10 倍速く**なります
（キー無し 5 req/30 秒 → キーあり 50 req/30 秒）。取得は無料（メールアドレスのみ）:
https://nvd.nist.gov/developers/request-an-api-key

**置き場所は 2 か所だけ。拡張（Chrome 側）には絶対に入れません。**

### 1. ローカル実行（この PC）

```powershell
# そのセッションだけ
$env:NVD_API_KEY = "取得したキー"

# 以後ずっと（新しいターミナルから有効）
setx NVD_API_KEY "取得したキー"
```

または、リポジトリ直下に `.env` を作って書く（`.gitignore` 済み・`.env.example` をコピー）:

```
NVD_API_KEY=取得したキー
```

優先順位は **環境変数 → `.env`** です。

### 2. GitHub Actions（将来の日次更新）

```powershell
gh secret set NVD_API_KEY    # 値を聞かれるので貼り付け（シェル履歴に残らない）
gh secret list               # 登録の確認
```

Workflow からは次のように渡します。

```yaml
env:
  NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
```

### 確認

```powershell
uv run python -c "from site_vuln_checker.nvd import api_key_from_env, min_interval; k=api_key_from_env(); print('キー:', 'あり' if k else 'なし', '/ 間隔:', min_interval(k), '秒')"
```

## 判定（赤 / 黄 / 灰）

`--advisories` に**勧告索引の JSON** を渡すと、検出したプラグイン・テーマと突き合わせて判定します。

```json
{
  "generated_at": "2026-10-29T00:00:00Z",
  "advisories": [
    {
      "id": "CVE-2025-90001",
      "name": "Contact Form 7",
      "slug": "contact-form-7",
      "affected_below": "5.9.9",
      "fixed": "5.9.9",
      "cvss": 9.8,
      "kev": true,
      "source": "nvd"
    }
  ]
}
```

| 判定 | 条件 |
| --- | --- |
| 🔴 赤 | 影響する勧告に **KEV** / **CVSS 9.0 以上** / **EPSS 0.5 以上** のいずれかがある |
| 🟡 黄 | 影響する勧告がある（上記以外） |
| ⚪ 灰 | **バージョンが不明**（勧告の履歴があるものだけ表示） |
| — | 勧告はあるが修正版以降（該当なし） |

- `affected_below` は NVD の説明文にある「before 5.9.9」をそのまま使う想定です（企画書 4.3）
- **バージョンが分からないものを緑にはしません**（企画書 7.6 の鉄則）
- 索引は `tests/fixtures/advisories.json`（**合成データ**）で試せます

### KEV / EPSS を付ける

```powershell
# 索引に KEV（悪用実績）と EPSS（悪用予測）を後付けする
uv run svc-enrich --index out/advisories.json

# ネットワークを使わずに片方だけ飛ばすこともできる
uv run svc-enrich --index out/advisories.json --skip-epss
```

- **KEV**: CISA のカタログ（約 1,700 件）に載っていれば `kev=true`。載っている勧告は**赤**
- **EPSS**: FIRST の日次 CSV（約 25 万件 → 実測 39.7 万件）から確率とパーセンタイルを付与。**0.5 以上は赤**
- 取り込みに失敗しても**索引は壊れません**（付加情報なので、無いまま進む）


## 初回の実測結果（n=4 / 2026-10-29）

`wordpress.org` / `ja.wordpress.org` / `php.net` / `example.com` を各 1 リクエストで巡回した結果。

| 指標 | 結果 |
| --- | --- |
| 取得 | 4/4 サイト |
| WordPress 判定 | 2/4（50%）※残り 2 件は WordPress ではないサイト |
| **コア版の特定** | **2/2（100%）**（`meta generator` から。片方は `7.2-beta3-64914`） |
| **プラグイン検出** | WordPress サイトで各 1 件（`gutenberg` 24.3.0）／**版も取得** |
| **PHP 版の特定** | **0/4（0%）** |
| サーバ版の特定 | 0/4（0%）（`Server: nginx` のみ） |

**わかったこと**: コアはほぼ確実に取れる。**PHP とサーバのバージョンは外からは取れない**（企画書 8.1 の見込みより厳しい）。
→ PHP の EOL 判定は **Site Health 読み取り（自サイト）が本命**という設計判断を、実測が裏付けた。

`out/report.html` を開くと、サイトごとに「プラグイン名 / 推定バージョン / 確度 / 根拠」が表で見える。

## Chrome 拡張（サイドパネル）

```powershell
# 1. 索引を作る
uv run svc-ingest --days 14 --limit 200 --out out/advisories.json
uv run svc-enrich --index out/advisories.json

# 2. 索引をローカルで配信する（別ターミナル）
python -m http.server 8000

# 3. chrome://extensions → デベロッパーモード → 「パッケージ化されていない拡張機能を読み込む」
#    → extension フォルダを選ぶ → 設定で http://localhost:8000/out/advisories.json を読み込む
```

詳しくは [extension/README.md](extension/README.md)（権限・制約・確認手順）を参照。
JS のテストは CI で実行しています（`node --check` + `node --test`）。

## 安全な使い方（重要）

- 取得するのは **トップページ 1 枚だけ**。追加リクエストはしない（L1 パッシブのみ）。
- `robots.txt` で `Disallow` されているサイトは取得しない。
- 同一ホストへは既定 1 秒間隔。`--delay` を下げない。
- 対象は**自分が許諾を持つサイト、または公開情報の閲覧の範囲**に限る。
- 判定は**推定**。`confidence` を必ず併記し、断定しない。

## ディレクトリ

```
docs/proposal.md          企画書（v0.9）
src/site_vuln_checker/
  detect.py               外部検出（HTML・ヘッダ・読み込みリソース → コンポーネント）
  fetch.py                robots 尊重・レート制限つきの取得
  survey.py               巡回して JSON/CSV と集計を出す CLI（svc-survey）
  report.py               検出結果の HTML 可視化（svc-report）
  sitehealth.py           WordPress「サイトヘルス → 情報」の解析
tests/                    フィクスチャと単体テスト（= 拡張の正解データ）
```
