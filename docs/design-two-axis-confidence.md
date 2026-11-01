# 設計: 確度は「版」だけに持たせる（技術は二値＋根拠）

状態: **承認済み・実装済み（未コミット）** ／ 2026-10-31
対象: `detect.py` / `detector.js` の `Finding`、サイドパネルの構成表、HTML レポート

## 0. 決定（2026-10-31）

- **技術（使われているか）は二値**。`confidence`（技術の確度）は**廃止**
- 確度は **`versionConfidence`（版の確かさ）だけ**に持たせる
- 構成表は **「検出」列を削除**し、**「精度」列**に `versionConfidence` を **高 / 中 / 低**で表示
  （Version が取れていなければ「—」）
- 「未確認」マークは**今回は入れない**（`active` の「有効 / 無効」タグは従来どおり）

## 1. 課題（ご指摘）

いまの `confidence` は「技術の確度」と「版の確度」が混ざっている。

| 例 | 現在 | 問題 |
| --- | --- | --- |
| テーマ（`style.css?ver` あり） | 0.5 | 名前は確実。**版が推測なだけ**なのに技術まで半信半疑に見える |
| プラグイン（版なし） | 0.6 | 名前は確実。版が無いだけで下がる |
| `report.py` の注記 | 「検出の確かさ（Version の正しさではない）」 | **実装の値と矛盾** |

## 2. 方針（ご提案のとおり）

**技術には確度を持たせない。確度は「版」にだけ持たせる。**

| 項目 | 扱い |
| --- | --- |
| 技術（使われているか） | **二値**（検出した / しない）。根拠（`evidence`）で示す |
| 版（その版が正しいか） | **`versionConfidence`（0〜1）** を新設。版が無ければ 0 |
| `confidence` | **廃止**（技術の確度という概念をなくす） |

### 技術の「弱い証拠」はどう表すか

二値にすると、**本文に名前が出ているだけ**のもの（プラグインを無効化している、記事で言及している）と、
**実際に読み込まれている**ものが同じ見た目になります。これは既存の `active` で区別できます。

| `active` | 意味 | 表示 |
| --- | --- | --- |
| `true` | リソース（`/wp-content/...`）に現れた＝**読み込まれている** | そのまま |
| `false` | 停止中（サイトヘルスから） | 「停止中」 |
| `null` | **本文に文字列があるだけ**（読み込まれていない可能性） | **「未確認」** |

`confidence` の代わりに、この **「未確認」マーク**（＝確度ではなく状態）で弱い証拠を示します。
フレームワーク（`csrfmiddlewaretoken` など）は `active` が無いので、根拠列に「本文」と出し、
名前に「未確認」を付けます。

## 3. 版の確度（新設）

**「その版を誰が言ったか」** で決める。

| 版の出どころ | `versionConfidence` | 例 |
| --- | --- | --- |
| 実測（サイトヘルス） | **1.0** | PHP 8.1.31（画面の値） |
| 利用者の入力（開発者向け） | **1.0** | 手入力 `8.1.27` |
| 製品の自己申告 | **1.0** | `<meta generator="WordPress 6.8.2">` |
| ファイル名に版が入っている | **0.9** | `jquery-3.7.1.min.js` |
| 間接的な証拠（`?ver=`） | **0.6** | プラグイン `style.css?ver=5.9.8` |
| テーマの `?ver=` | **0.4** | 子テーマ・キャッシュバスターの可能性 |
| ヘッダ（`X-Powered-By`） | **0.6** | プロキシで書き換わり得る |
| 版が取れない | **0** | 不明 |

## 4. 画面（案）: 構成表

```
| 種別   | 名前             | Version     | 精度 | 根拠   |
| コア   | wordpress        | 6.8.2       | 高   | メタ   |
| テーマ | twentytwentyfive | 1.2         | 低   | リンク |
| プラグイン | hello-dolly  | —           | —    | 本文   |
```

- 「検出」列は**廃止**
- 「**精度**」列＝`versionConfidence`（高 ≥0.8 / 中 ≥0.5 / 低 / — 版なし）
- 本文だけのものは `active` の「有効 / 無効」タグで区別（今回は新しいマークを足さない）

## 5. 判定（赤/黄/緑）への影響

- 判定ロジックは変更なし（版の値と索引の範囲だけで決まる）。
- **緑の言い方**：版が推定のときは `この Version に脆弱性の報告はありません（推定した版で照合）`
- 版が不明（`None`）は現状どおり「不明」または「構成のみ」。

## 6. 互換・移行

- `confidence` を**削除**（Python / JS / レポート / テストの期待値を更新）
- 保存済みレポートに `confidence` が残っていても無視するだけ（壊れない）
- `versionConfidence` が無い古いデータは **0**（＝版は不明扱い）として安全側に倒す
- 索引（`advisories.json`）は**影響なし**
- `test_parity` に「版の確度が JS / Python で一致」を追加

## 7. 変更するファイル

| ファイル | 変更 |
| --- | --- |
| `src/site_vuln_checker/detect.py` | `Finding.confidence` を削除、`version_confidence` を追加、各検出の値を上表に |
| `extension/detector.js` | 同上（`finding()` の引数も変更） |
| `extension/sitehealth.js` / `background.js` | サイトヘルス・手入力は `1.0`、`confidence` を外す |
| `extension/sidepanel.js` | 「検出」列を削除 → 「版の確かさ」列、`（推定）`・`未確認` 表示 |
| `src/site_vuln_checker/report.py` | HTML レポートも同じ列・言い方 |
| `tests/test_detect.py` / `extension/tests/*` | 期待値を全面更新（`confidence` → `version_confidence`） |
| `README.md` / `docs/proposal.md` | 確度の説明を「版だけ」に |

## 8. 実装結果（この変更で入れたもの）

| ファイル | 変更 |
| --- | --- |
| `src/site_vuln_checker/detect.py` | `Finding.confidence` を削除 → `version_confidence`。各検出の値を上表に |
| `extension/detector.js` | `finding()` の 4 番目を `versionConfidence` に。値は Python と同じ |
| `src/site_vuln_checker/sitehealth.py` / `extension/sitehealth.js` / `background.js` | 実測値・手入力は `1.0` |
| `extension/sidepanel.js` | 「検出」列 → **「精度」列**（高/中/低、版なしは「—」） |
| `src/site_vuln_checker/report.py` | HTML レポートも「精度」列・ツールチップは「版の確かさ」 |
| `survey.py` | 集計キーを `core_version_confidence_avg`、CSV 列を `version_confidence` |
| テスト | 期待値を更新（Python 134 / JS 72 が通過） |

