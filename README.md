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

# 勧告索引を渡すと、赤 / 黄 / 灰 の判定まで行う
uv run svc-survey --urls sites.sample.txt --limit 5 --delay 1.0 `
  --advisories tests/fixtures/advisories.json

# 結果を HTML に可視化する
uv run svc-report
```

出力は `out/` に置く（`survey.json` / `summary.json` / `report.html`）。

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
| 🔴 赤 | 影響する勧告に **KEV** がある、または **CVSS 9.0 以上** |
| 🟡 黄 | 影響する勧告がある（上記以外） |
| ⚪ 灰 | **バージョンが不明**（勧告の履歴があるものだけ表示） |
| — | 勧告はあるが修正版以降（該当なし） |

- `affected_below` は NVD の説明文にある「before 5.9.9」をそのまま使う想定です（企画書 4.3）
- **バージョンが分からないものを緑にはしません**（企画書 7.6 の鉄則）
- 索引は `tests/fixtures/advisories.json`（**合成データ**）で試せます

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
