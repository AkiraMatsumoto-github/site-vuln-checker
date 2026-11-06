# Chrome ウェブストア提出の手順（v1.0.0）

対象: `extension/`（**v1.0.0**）／初回の所要: **60〜90 分**（審査は数日〜2 週間）
掲載文の実値は [`listing.md`](listing.md) にまとまっています（この手順から貼るだけ）。

---

## 0. 前提（一度だけ）

- [ ] **デベロッパー登録**（初回 5 USD）
- [ ] 連絡先メールの確認と **2 段階認証**（公開に必須）
- [ ] 公開者の属性（Trader / Non-trader）を申告（EU DSA）
- [ ] **プライバシーポリシーが公開されている**（HTTP 200 を確認）
      `https://akiramatsumoto-github.github.io/site-vuln-checker/privacy.html`
- [ ] **サポート URL** が生きている
      `https://github.com/AkiraMatsumoto-github/site-vuln-checker/issues`

---

## 1. パッケージ（ZIP）を作る

```powershell
# リポジトリのルートで実行（tests と README を除く）
$stage = Join-Path $env:TEMP 'svc-stage'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item extension\* $stage -Recurse
Remove-Item "$stage\tests", "$stage\README.md" -Recurse -Force
Compress-Archive -Path "$stage\*" -DestinationPath svc-1.0.0.zip -Force
```

- [ ] `extension/manifest.json` の `version` が **1.0.0**
- [ ] **ZIP の直下に `manifest.json`**（`extension/` フォルダごと入れない）
- [ ] サイズが小さいこと（約 45 KB。アイコン 4 枚を含む）
- [ ] 読み込んで動作確認（下記 5）

> `svc-1.0.0.zip` は `.gitignore` 済み（ビルド成果物なのでリポジトリには入れません）。

---

## 2. ストア掲載情報（Store listing）

| 項目 | 値（[`listing.md`](listing.md) から貼る） |
| --- | --- |
| 名前 | サイト脆弱性チェッカー |
| 短い説明 | listing.md §2（**103 文字**） |
| 詳細説明 | listing.md §3 |
| カテゴリ | 開発者ツール |
| 言語 | 日本語 |
| ストアアイコン（128×128） | `store/icon-128x128.png` |
| スクリーンショット（1〜5 枚） | `store/screenshots/01〜04-1280x800.png`（4 枚・1 枚目がサムネイル） |
| 小さいプロモ画像（440×280） | `store/promo-440x280.png` |
| マーキー画像（1400×560・任意） | 未作成（横長で別途デザインが必要） |
| ホームページ URL（任意） | `https://github.com/AkiraMatsumoto-github/site-vuln-checker` |
| サポート URL | `https://github.com/AkiraMatsumoto-github/site-vuln-checker/issues` |

---

## 3. プライバシー（Privacy practices）

- [ ] **単一目的**: listing.md §5 の文案
- [ ] **権限の用途**: `sidePanel` / `activeTab` / `scripting` / `tabs` / `storage` / `alarms` /
      `optional_host_permissions` の 7 つを、listing.md §5 の表のとおり入力
- [ ] **データ使用**: 「ユーザーデータを収集しません」＋端末内のみ・第三者提供なし・Limited Use に準拠
- [ ] **プライバシーポリシー URL**: `https://akiramatsumoto-github.github.io/site-vuln-checker/privacy.html`
- [ ] **リモートコード**: 使用しない（索引 JSON はデータのみ）
- [ ] データ使用のチェック項目（収集しない／販売しない／目的外利用しない）にチェック

---

## 4. 審査用メモ（Reviewer notes）※英語のまま貼る

```
Thank you for reviewing.

What it does: it reads only what the currently open page has already loaded, estimates the
site's tech stack (WordPress / plugins / themes / PHP / JS libraries) and compares it with a
vulnerability index the extension downloads. Results are shown in the side panel in five
groups: red / yellow / green / info / unknown.

How to test (no account required):
1. Open any public website, e.g. https://wordpress.org/
2. Click the toolbar icon to open the side panel, then click the button
   "このサイトを調べる" (Inspect this site).
3. On first use Chrome asks for permission to download the index from
   https://akiramatsumoto-github.github.io/site-vuln-checker/advisories.json — please allow it.
   If declined, the extension shows a message that it cannot judge.
4. The result appears in five sections. Expand "影響する勧告 N 件… を見る" to see CVE details
   (affected version ranges, exploitation likelihood, impact).

Optional (your own site only): in a WordPress admin you control, open /wp-admin/ (dashboard)
or /wp-admin/site-health.php and click the same button. The extension switches to the "Info"
tab of Site Health and reads the values already displayed on that page (PHP version,
database, plugins). It never bypasses authentication and never reads other users' data.

Network requests:
- GET https://akiramatsumoto-github.github.io/site-vuln-checker/advisories.json
  (vulnerability index; ETag revalidation, at most every 5 minutes and once per day)
- Optionally, only if the user grants access to the inspected site: one HEAD request to that
  site to read public response headers (no cookies; not sent on wp-admin/site-health pages).
  The optional host permission (https://*/*) is requested per origin at runtime for this
  purpose and for reading Site Health. Declining still allows the basic analysis.

No page content, URLs or Site Health data are sent to any server. No remote code is executed
(eval / new Function / CDN scripts are not used). The extension is not affiliated with
WordPress or Automattic.
```

- [ ] 上記をそのまま貼る（英語で書くのが無難）

---

## 5. 提出前の動作確認（クリーンなプロファイル）

- [ ] Chrome **116 以上**、他の拡張を無効にしたプロファイルで unpacked 読み込み
- [ ] 任意のサイトで「調べる」→ **5 つの枠**が出る（0 件の枠はランプ消灯）
- [ ] 初回に索引の許可ダイアログ → 許可（拒否しても判定が続くことも確認）
- [ ] DevTools の Network で、通信先が **`akiramatsumoto-github.github.io` だけ**
- [ ] 自分の WordPress の **`/wp-admin/`** から押す → 自動で「情報」タブへ移動し、PHP などが入る
- [ ] パネル左下が **v1.0.0**
- [ ] アイコンのバッジに赤（または黄）の件数が出る

---

## 6. 提出〜公開

- [ ] 「審査のために送信」を押す
- [ ] 審査中の質問には 2〜3 日以内に返信
- [ ] 公開後、ストアのページで **説明・スクショ・権限の表示**を確認
- [ ] ストアの URL を README に追記（公開後に）

---

## 7. 却下されたときの対応（2026-10-31 の実例）

**参照 ID: Yellow Argon** / 違反: **キーワード スパム**（説明に過剰・無関係なキーワード）

| 項目 | 内容 |
| --- | --- |
| 対象 | 詳細説明の**データ出典リスト**（`NVD / GitHub Advisory Database / CISA KEV / FIRST EPSS / JVN iPedia / endoflife.date / WordPress.org Plugin API`） |
| 原因 | 第三者サービスの名前を並べた部分が「キーワードの詰め込み」と判定された |

### 直し方（パッケージの再作成は不要）

- [ ] `store/listing.md` §3 の**出典リストを削除**（現在の文面は削除済み）
- [ ] 管理画面の「詳細説明」を、修正後の文に差し替える
- [ ] 「保存」→ **「審査のために送信」**をもう一度押す
- [ ] **ZIP の再アップロードは不要**（コードは変わっていないため。バージョンも 1.0.0 のままでよい）

> 出典・ライセンス（CC-BY-4.0 など）の表示義務は、**プライバシーポリシー §7** に記載して担保する
> （掲載文には書かない）。今後、説明文に**第三者サービスの名前を羅列しない**こと。

### 再提出時に見直すポイント

| 見る場所 | チェック |
| --- | --- |
| 短い説明 | 1 文で機能を説明している（キーワードの羅列がない） |
| 詳細説明 | 製品名の羅列・無関係な語（他社データベース名など）がない |
| スクリーンショット | 第三者の実サイト名が写っていない |
| 権限の用途 | 7 つすべてに理由が書かれている |

---

## 8. 公開後の運用

| 項目 | やること |
| --- | --- |
| 索引の更新 | `.github/workflows/publish-index.yml` が毎日 03:00 JST に更新（**拡張の再審査は不要**） |
| 差分の窓 | 3 日（`--days 3`）。NVD の公開が遅れた場合は手動で `full: true` 実行 |
| 問い合わせ | GitHub Issues に **3 営業日以内**の初回応答 |
| 誤検知の報告 | 索引の元データ（NVD / OSV）を確認し、必要なら取り込み側で除外 |
| プライバシーポリシー | 変更したら `docs/privacy.html` を更新（Pages へは publish-index が配信） |

### 既知の表示：「セーフ ブラウジング保護強化機能で信頼されていません」

`chrome://extensions` に「この拡張機能は、セーフ ブラウジング保護強化機能で信頼されていません」と出ることがある。
**壊れている・危険という意味ではなく**、Google の信頼リストに入っていないという表示。

| 状況 | 消し方 |
| --- | --- |
| デベロッパーモードで読み込んだ（unpacked） | **必ず出る**。ストア版に切り替えるか、設定 →「プライバシーとセキュリティ」→「セキュリティ」→ **標準保護機能**に下げる |
| ストアからインストール（1.0.1 は 2026-11-03 公開） | 開発者側で消す操作はない。Google が基準（ストア掲載・開発者の検証・違反履歴なし・利用実績など）で判定し、満たすと外れる。**時期は非公開** |

- 効くのは「違反ゼロのまま更新を続ける」「プライバシー申告と実装を一致させる」「権限を増やさない」の積み上げだけ。
  マニフェストやコードの変更で消せるものではない
- 個別の解除申請フォームはない（Chrome ウェブストアの One Stop Support で相談は可能）
- 警告が出るのは **保護強化機能を ON にしている人だけ**（標準保護機能のユーザーには出ない）

---

## 9. 更新（1.0.1）

公開済み（1.0.0）から更新するときの手順。**パッケージの差し替え＋審査依頼**が必要。

### 1) ZIP を作る

```powershell
$stage = Join-Path $env:TEMP "svc-stage-101"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item extension\* $stage -Recurse
Remove-Item "$stage\tests", "$stage\README.md" -Recurse -Force
Compress-Archive -Path "$stage\*" -DestinationPath svc-1.0.1.zip -Force
```

- [ ] `extension/manifest.json` の `version` が **1.0.1**
- [ ] ZIP の直下に `manifest.json`／`tests` と `README.md` を含まない
- [ ] 約 45 KB・14 ファイル（JS 9・CSS 1・HTML 1・アイコン 4）

### 2) アップロードして審査依頼

- [ ] 管理画面 → アイテム → **「パッケージ」タブ** → 新しい ZIP をアップロード
- [ ] 「What's new」に下の文案を貼る
- [ ] **「審査のために送信」**
- [ ] 掲載情報（プロモ画像など）も同時に変えるなら、このタイミングで保存しておく

### 2-2) ストア掲載情報を差し替える（スクリーンショット）

- [ ] 「ストア掲載情報」→ スクリーンショットに `store/screenshots/01〜04-1280x800.png` の **4 枚**を順番にアップ（1.0.1 の UI。`tools/make_store_screenshots.ps1` で再生成できる）
- [ ] 既存の 3 枚（旧 UI・`検出` 列）は**削除**する
- [ ] 小さいプロモ画像（440×280）を `store/promo-440x280.png` に差し替え
- [ ] 保存 → パッケージと同時に審査へ（掲載情報だけの変更でも審査の対象になる）

### 3) What's new（文案）

```
・構成表の「検出」を「精度」に変え、Version が正しい確かさ（高 / 中 / 低）を示すようにしました。
・アプリの説明文を分かりやすい表現に調整しました。
```
