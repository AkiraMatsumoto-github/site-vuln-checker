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
| ストアアイコン（128×128） | `store/icon-128x128.png`（= `extension/icons/icon128.png` のコピー） |
| スクリーンショット（1〜5 枚） | `store/screenshots/01-red-1280x800.png` ほか 2 枚 |
| 小さいプロモ画像（440×280・任意） | 未作成（任意） |
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

## 7. 公開後の運用

| 項目 | やること |
| --- | --- |
| 索引の更新 | `.github/workflows/publish-index.yml` が毎日 03:00 JST に更新（**拡張の再審査は不要**） |
| 差分の窓 | 3 日（`--days 3`）。NVD の公開が遅れた場合は手動で `full: true` 実行 |
| 問い合わせ | GitHub Issues に **3 営業日以内**の初回応答 |
| 誤検知の報告 | 索引の元データ（NVD / OSV）を確認し、必要なら取り込み側で除外 |
| プライバシーポリシー | 変更したら `docs/privacy.html` を更新（Pages へは publish-index が配信） |
