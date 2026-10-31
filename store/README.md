# ストア公開用の素材

Chrome ウェブストアに提出する画像・文章をここに置きます（**`extension/` の外**なので、拡張の ZIP には入りません）。

```
store/
  README.md             ← このファイル（撮り方と提出先）
  screenshots/          ← 1280×800 か 640×400 の PNG（1〜5 枚）
    01-red.png
    02-green-info-gray.png
    03-site-health.png
  listing.md            ← 短い説明・詳細説明の最終稿（作成中）
```

## スクリーンショット 3 枚（推奨）

| ファイル | 撮る画面 | 伝えたいこと |
| --- | --- | --- |
| `01-red.png` | 判定結果の**上から赤枠の見出しまで**（赤・黄が並ぶ） | 「押すと、更新すべきものが重要度順に出る」 |
| `02-green-info-gray.png` | **緑・情報・不明**の枠と「構成（検出できたもの）」の表 | 「安全そうなもの・分からないものも、正直に分けて出す」 |
| `03-site-health.png` | サイトヘルスを開いた状態で押した結果（実測値の注記＋停止中プラグインまで出る構成表） | 「自分のサイトなら PHP まで正確に見える」 |

- **サイズ**: 1280×800 または 640×400（この 2 つ以外は受け付けられません）
- **形式**: PNG（24-bit、アルファ無し）または JPEG。**1 枚目がストア一覧のサムネイル**になります
- **被写体**: 自分のサイトか `example.com` 系の検証用サイト。**第三者の実サイト名は写さない**（誤検知で相手に不利益を与えないため）

## 撮り方（いちばん簡単な手順）

1. Chrome のウィンドウを **1280×800** にする（DevTools のデバイスツールバーで 1280×800 を選んでもよい）
2. 対象のページを開く → ツールバーのアイコン → サイドパネルを開く
3. 赤を出したい場合は「バージョンを入力」に `8.1.27`（PHP）を入れて **追加**（サンプルサイトなら何でも可）
4. **ウィンドウ全体**を撮る（`Win + Shift + S`）。サイドパネルだけを撮って拡大すると粗くなるため、全体を撮って余白を整える
5. 画像編集で 1280×800（または 640×400）に整える。**拡大はしない**（ぼやけます）。余白を足すのは可
6. `store/screenshots/01-red.png` などに保存する

## 提出先（Chrome ウェブストア管理画面）

| 項目 | 場所 | 使うファイル・値 |
| --- | --- | --- |
| スクリーンショット | 「ストア掲載情報」→ スクリーンショット | `store/screenshots/01〜03.png`（1〜5 枚） |
| ストアアイコン | 同上（128×128） | `extension/icons/icon128.png` |
| 小さいプロモ画像（任意） | 同上（440×280） | 未作成（任意） |
| プライバシーポリシー URL | 「プライバシー」タブ | `https://akiramatsumoto-github.github.io/site-vuln-checker/privacy.html` |
| サポート URL | 「ストア掲載情報」 | `https://github.com/AkiraMatsumoto-github/site-vuln-checker/issues` |
| ホームページ URL（任意） | 同上 | `https://github.com/AkiraMatsumoto-github/site-vuln-checker` |
| パッケージ | 「パッケージ」タブ | `extension/` を ZIP 化（下記） |

### ZIP の作り方（リポジトリのルートで実行）

```powershell
# tests と README を除いて ZIP 化する（ZIP の直下に manifest.json が来る形）
$stage = Join-Path $env:TEMP 'svc-stage'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item extension\* $stage -Recurse
Remove-Item "$stage\tests", "$stage\README.md" -Recurse -Force
Compress-Archive -Path "$stage\*" -DestinationPath svc-0.4.3.zip -Force
```

- `extension\tests\` と `extension\README.md` は動かないので外しています（入れても審査は通ります）
- ZIP の直下に `manifest.json` が来ていることを確認してください（`extension/` フォルダごと入れない）
- 版を上げたらファイル名も合わせる（`svc-1.0.0.zip` など）


## 説明文の骨子

`docs/proposal.md` の 20.1 に下書きがあります（短い説明 132 文字以内＋詳細）。最終稿は `store/listing.md` に置きます。
