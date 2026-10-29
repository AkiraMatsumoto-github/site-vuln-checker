# 実装レビュー（v0.10 時点）

- 対象: `site_vuln_checker` の全モジュール（detect / fetch / survey / report / sitehealth / advisories / ingest / nvd）とテスト
- 方法: 全コードを読み、**疑わしい挙動を実際に実行して確認**（下記の再現ログ）。企画書（v0.10）との整合も確認
- テスト/CI: `pytest` **54 passed** / `ruff` クリーン / GitHub Actions 緑（レビュー時点）
- 結論: **骨格と「推測しない」方針は良い。ただし誤検知につながる欠陥が 4 件（High）**

## 0. 対応状況（2026-10-29 修正済み）

| ID | 状態 | 対応内容 |
| --- | --- | --- |
| **H1** | ✅ 修正 | 影響範囲の抽出を**プラグイン名より後ろ**に限定（`_scope`）。回帰テスト 2 件を追加。**再測でも取り込み 188 件のまま**（誤検知だけを除去） |
| **H2** | ✅ 修正 | `survey.json` に `advisories_applied` を追加。未適用なら KPI を「—（未判定）」にし、**「赤 0 は問題なしではありません」**を明示 |
| **H3** | ✅ 修正 | 本文中の文字列だけで見つけたプラグインは `active=None`（「有効」と断定しない） |
| **H4** | ✅ 修正 | 日本語名は slug が空になるため**元の名前**を使う |
| M1 | ✅ 修正 | 403 は再試行せず、**キー無効の案内**で即失敗（429 のみ再試行、`Retry-After` を尊重） |
| M2 | ✅ 修正 | `Content-Type` が HTML 系以外なら `FetchError`（fetch のテスト 7 件を追加） |
| M3 | ✅ 修正 | `robots.txt` の docstring を実装に合わせた（取得できない場合は許可） |
| M7 | ✅ 修正 | 壊れた索引は `ValueError`（案内つき）。CLI は exit 1 |
| M4・M5・M6・M8 | 未対応 | 性能（前計算）とカバレッジ改善。次フェーズ |
| L1〜L8 | 未対応 | 整理・テスト追加・拡張の実装 |

> 修正後のテストは **68 passed**（新規 14 件）。`ruff` クリーン。

---

## 1. 指摘一覧

| ID | 重大度 | 場所 | 内容 | 工数 |
| --- | --- | --- | --- | --- |
| **H1** | **高** | `ingest.extract_range` | 本文の `before X` が**別製品（WordPress コア）**を指していても、プラグインの影響範囲として採用してしまう | 2〜3h |
| **H2** | **高** | `report.render` / `survey` | **索引を渡していなくても「赤 0」**と表示され、安全に見える（企画書の鉄則に反する） | 1h |
| **H3** | **高** | `detect._detect_plugins` | 本文中の文字列だけで見つけたプラグインも **`active=True`（有効）** と表示する | 1h |
| **H4** | **高** | `sitehealth.Component.slug` | **日本語名のプラグインは slug が空文字**になる（日本語サイトで多用） | 30m |
| M1 | 中 | `nvd.search` | **403（キー無効）をレート制限と同じ扱いで再試行**し、誤った案内を出す | 30m |
| M2 | 中 | `fetch.fetch` | **Content-Type を見ていない**（PDF/画像/JSON も HTML として解析） | 1h |
| M3 | 中 | `fetch.allowed` | docstring（「判定できないときは許可しない」）と実装（許可する）が**矛盾** | 15m |
| M4 | 中 | `advisories.advisories_for` | 前方一致で**全件を毎回正規化**（索引 2 万件 × プラグイン 10 件 = 20 万回） | 1h |
| M5 | 中 | `ingest.extract_range` | `fixed in 2.0.0` 形式を**取りこぼす**（範囲不明として捨てる） | 1h |
| M6 | 中 | `ingest.extract_name` | 1 つの CVE が**複数プラグインを列挙**しても 1 つしか拾わない | 2h |
| M7 | 中 | `survey`/`report` CLI | `--advisories` に壊れた JSON を渡すと**トレースバック**で落ちる | 30m |
| M8 | 中 | `detect._detect_plugins` | 同じ slug の `?ver=` が複数あるとき**最初の 1 つ**を採用（無関係なアセットの版の可能性） | 1h |
| L1 | 低 | `detect._detect_platforms` | 引数 `meta` が未使用 | 5m |
| L2 | 低 | `fetch.fetch` | `_last_hit` を `except` と `finally` で二重更新 | 5m |
| L3 | 低 | `survey.run` | `"red"` を直書き（`LEVEL_RED` を使っていない） | 5m |
| L4 | 低 | `ingest` | `parse_cve` を `build_index` と `summarize` で二度呼ぶ | 30m |
| L5 | 低 | `fetch` | `MAX_BYTES` をダウンロード**後**に判定（ストリーミングで上限を掛けるべき） | 1h |
| L6 | 低 | `nvd.api_key_from_env` | `.env` を **CWD 相対**で読むため実行場所に依存 | 15m |
| L7 | 低 | tests | `fetch`（robots・レート）と `survey.run` のテストが無い | 2h |
| L8 | 低 | リポジトリ全体 | **Chrome 拡張が未実装**（Python の PoC のみ） | （別項目） |

---

## 2. High の詳細（再現つき）

### H1. `before X` が別製品を指すケースで誤判定する

**再現**

```python
from site_vuln_checker.ingest import extract_name, extract_range
c = "WordPress before 6.0.1 allows X, and the Foo Bar plugin for WordPress 1.2 and earlier is also affected."
extract_name(c)   # -> 'Foo Bar'
extract_range(c)  # -> ('6.0.1', None)   ← 本当は 1.2 以下
```

**なぜ危険か**: 生成される勧告が「Foo Bar は 6.0.1 未満が影響」になる。実際のプラグインの版は 1.x なので **ほぼ全部が「影響あり」→ 赤**。誤検知が大量に出ると、企画の信頼（誤検知 5% 未満）を一撃で壊す。

**原因**: `_BEFORE_RE` を**説明文全体**に最優先で当てている（`extract_range` の順序）。

**対策案**
1. 抽出範囲を**プラグイン名の出現位置より後ろ**に限定する
2. `WordPress before X` のように**製品名＋before** の形は除外する（`(?<!WordPress )before` では不足。名詞句の直後判定が必要）
3. 同一文に限定する（`.` や `;` で区切る）
4. 上記の文章を**回帰テスト**に追加

### H2. 索引なしでも「赤 0」＝安全に見える

**再現**

```
索引なしでレポートを出すと… 赤のKPI: 0 / 「索引」の注意書き: False
```

**なぜ危険か**: 「赤 0」は「調べて問題なし」と読める。企画書 7.6 の鉄則（見えていないものを緑で塗りつぶさない）に**コードが違反**している。

**対策案**: `survey.json` に `advisories_applied: true/false` を記録し、レポートでは
`索引が未適用のため、脆弱性の判定はしていません（赤 0 は「問題なし」ではありません）` を明示。KPI は `—` 表示にする。

### H3. 本文中の文字列だけで「有効」と表示する

**再現**

```python
html = "<html><body><pre>/wp-content/plugins/y/lib.js</pre></body></html>"
analyze("https://e/", html, {}).of_kind("plugin")  # -> [(name='y', active=True)]
```

**なぜ危険か**: 「有効化されている」という**確認していない事実**を表示する。企画書 8.2 の「推定である」方針と矛盾。

**対策案**: リソース URL で見つかったものだけ `active=True`。HTML 内の文字列だけの検出は `active=None`（不明）とし、UI では「有効（推定）」ではなく「検出」と表示する。

### H4. 日本語名のプラグインで slug が空になる

**再現**

```python
Component(name="アドバンスドカスタムフィールド", version="1.0").slug  # -> ''
```

**なぜ危険か**: Site Health は日本語サイトで**日本語のプラグイン名**を返す。slug が空だとレポートの名前が空になり、照合もできない（`len(slug) >= 6` の条件で常に不一致）。

---

## 3. 中程度の詳細

### M1. 403 をレート制限として再試行する

```python
if response.status_code in (403, 429):   # ← 403 は「キーが無効／権限なし」
    time.sleep(min(60.0, 6.0 * attempt))
    continue
```

実測では 403 が「不正なキー」で返る。**最大 18 秒 × 3 回待ってから**「間隔を空けて再実行してください」と誤案内する。403 は即座に失敗し、`API キーが無効か権限がありません（.env を確認）` と出すべき。

### M2. Content-Type を見ていない

`fetch.fetch` はステータスとサイズしか見ない。`application/pdf` や `image/png` を HTML として BeautifulSoup に渡すと、無意味な検出結果になる（例外にならないので気づきにくい）。`text/html` / `application/xhtml+xml` 以外は `FetchError("HTML ではありません")` にすべき。

### M3. robots.txt の docstring と実装が矛盾

```python
def allowed(self, url: str) -> bool:
    """robots.txt で許可されているか。判定できないときは許可しない（安全側）。"""
    ...
    if parser is None:
        return True     # ← 許可している
```

実装（404 や通信失敗は許可）は妥当。**docstring を実装に合わせる**。あわせて「robots.txt 自体もレート制限の対象外になっている」点をコメントで明示したい。

### M4. 前方一致が O(索引 × コンポーネント)

`advisories_for()` は毎回 `self.advisories` 全件を `normalize_slug()` する。索引 2 万件（`--days 180` 相当）で 1 サイト 10 プラグインなら 20 万回。`__post_init__` で `_by_normalized_name: dict[str, list[Advisory]]` を作れば O(1)。

### M5. `fixed in X` を取りこぼす

```
"The Foo plugin for WordPress is vulnerable to X. This is fixed in 2.0.0."
→ extract_range = (None, None) → 索引に入れない
```

`fixed in (version )?X` を `affected_below = X` として拾えば 5〜10% 拾える見込み（要実測）。

### M6. 複数プラグイン列挙に未対応

```
"The A plugin for WordPress, the B plugin for WordPress and the C plugin are vulnerable before 3.1."
→ name = 'A' のみ（B, C は落ちる）
```

PoC の制約として **README と 4.3 に明記**するのが最低線。将来は `findall` で全件＋同一範囲を割り当てる。

### M7. 壊れた索引でトレースバック

`svc-survey --advisories broken.json` → `json.JSONDecodeError` がそのまま出る。`AdvisoryIndex.load` で捕捉し、`索引を読めません: <path>（JSON を確認してください）` と exit 1。

### M8. `?ver=` が複数あるときの選び方

`_detect_plugins` は slug ごとに**最初の** `?ver=` を採用する。`assets/css/admin.css?ver=1.0` と `assets/js/app.js?ver=5.9.8` が混在すると 1.0 を採る可能性。**最頻値**（コアと同じ方式）に統一すべき。

---

## 4. 良い点（維持したい設計）

| 項目 | 理由 |
| --- | --- |
| **版が不明なら灰**（`judge`） | 企画の鉄則がコードに落ちている。`LEVEL_NONE` と `LEVEL_GRAY` を分けているのも良い |
| **除外理由の集計**（`summarize`） | 「なぜ取り込めなかったか」が数字で残る。改善の判断材料になる |
| **秘密をリポジトリに入れない** | `.env` を gitignore、CI に秘密なし、拡張にキーを持たせない方針（12.5）と一致 |
| **テストが仕様になっている** | `tests/fixtures/` が拡張移植時の正解データ。実際に NVD の 3 形態を固定している |
| **`Advisory`/`Judgement` の分離** | 判定ロジックが純粋関数で、ネットワーク無しで検証できる |
| CI（ruff + pytest） | 変更のたびに 15 秒で検証できる |

---

## 5. 推奨する修正順序

| 順 | 対象 | 理由 |
| --- | --- | --- |
| 1 | **H1**（誤検知の源） | 赤の大量誤検知は企画の信頼を壊す。回帰テスト込みで直す |
| 2 | **H2 + H3**（表示の誠実さ） | 「赤 0」「有効」は**誤解を招く表示**。企画の差別化（誠実さ）に直結 |
| 3 | **H4**（日本語 slug） | 日本語サイトでは常用パス。1 行で直る |
| 4 | M1・M2・M7（失敗時の挙動） | 運用時に詰まる。実装は軽い |
| 5 | M4・M8（性能・精度） | 索引を大きくする前に |
| 6 | M5・M6（取りこぼし） | カバレッジ改善。実測してから |
| 7 | L1〜L6（整理） | まとめて 1 コミットで |
| 8 | L7（テストの穴） | `fetch` をモックして 4 件程度 |
| 9 | L8（拡張の実装） | 製品の本丸。別フェーズ |

---

## 6. 再現手順

```powershell
cd C:\Users\yahoo\dev\site-vuln-checker
uv run pytest -q          # 54 passed
uv run ruff check .       # All checks passed

# H1
uv run python -c "from site_vuln_checker.ingest import extract_range; print(extract_range('WordPress before 6.0.1 allows X, and the Foo Bar plugin for WordPress 1.2 and earlier is also affected.'))"

# H2
uv run svc-report   # 索引なしで実行 → 「赤 0」が出る

# H3
uv run python -c "from site_vuln_checker.detect import analyze; print([(f.name, f.active) for f in analyze('https://e/', '<html><body><pre>/wp-content/plugins/y/lib.js</pre></body></html>', {}).of_kind('plugin')])"

# H4
uv run python -c "from site_vuln_checker.sitehealth import Component; print(repr(Component(name='アドバンスドカスタムフィールド', version='1.0').slug))"
```
