"""検出結果の可視化（PoC）。

``out/survey.json`` を読み、``out/report.html`` を書き出す。
**どのプラグインが、どのバージョンで、どの根拠で検出されたか**を一覧できるようにする。

まだ脆弱性 DB とは突き合わせていない（次の段階）。ここで見せるのは「構成の可視化」まで。
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path

DEFAULT_OUT = Path("out")

KIND_LABELS = {
    "platform": "プラットフォーム",
    "core": "コア",
    "plugin": "プラグイン",
    "theme": "テーマ",
    "library": "JS ライブラリ",
    "language": "言語",
    "server": "サーバ",
    "database": "DB",
}

_CSS = """
:root { color-scheme: light dark; }
body { font-family: system-ui, "Segoe UI", "Hiragino Sans", sans-serif; margin: 0;
       padding: 24px; line-height: 1.6; background: #fafafa; color: #1a1a1a; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 0 0 8px; }
.sub { color: #666; font-size: 0.85rem; margin-bottom: 20px; }
.summary { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }
.kpi { background: #fff; border: 1px solid #e3e3e3; border-radius: 8px; padding: 10px 14px;
       min-width: 140px; }
.kpi b { display: block; font-size: 1.3rem; }
.kpi span { color: #666; font-size: 0.8rem; }
.card { background: #fff; border: 1px solid #e3e3e3; border-radius: 10px; padding: 16px 18px;
        margin-bottom: 18px; }
.card.failed { border-color: #e0b4b4; background: #fff7f7; }
.url { font-family: ui-monospace, Consolas, monospace; font-size: 0.9rem; word-break: break-all; }
.meta { color: #666; font-size: 0.8rem; margin-bottom: 10px; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; margin: 6px 0 14px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
th { color: #555; font-weight: 600; background: #fafafa; }
code { font-family: ui-monospace, Consolas, monospace; font-size: 0.82rem; color: #444; }
.tag { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.75rem;
       border: 1px solid #ddd; background: #f5f5f5; }
.bar { height: 6px; background: #eee; border-radius: 3px; width: 80px; display: inline-block;
       vertical-align: middle; }
.bar > i { display: block; height: 6px; border-radius: 3px; }
.hi { background: #2f855a; } .mid { background: #b7791f; } .lo { background: #a0aec0; }
.notes { background: #fdf9e7; border: 1px solid #f0e0a8; border-radius: 8px; padding: 8px 12px;
         font-size: 0.85rem; margin-top: 8px; }
.empty { color: #888; font-size: 0.85rem; }
footer { color: #777; font-size: 0.78rem; margin-top: 28px; border-top: 1px solid #e3e3e3;
         padding-top: 12px; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _confidence(conf: float) -> str:
    """**検出の確かさ**を 高 / 中 / 低 で表す（Version の正しさではない）。

    数値そのものは利用者の判断に使えないため、ツールチップに残す。
    """
    label = "高" if conf >= 0.8 else "中" if conf >= 0.5 else "低"
    return f'<span title="検出の確かさ {conf:.2f}">{label}</span>'


def _rows(findings: list[dict]) -> str:
    if not findings:
        return '<tr><td colspan="4" class="empty">検出なし</td></tr>'
    out = []
    for f in findings:
        version = f.get("version")
        if f.get("kind") == "platform":
            version_cell = "—"
        elif version:
            version_cell = _esc(version)
        else:
            version_cell = '<span class="empty">版不明（灰）</span>'
        evidence = "<br>".join(f"<code>{_esc(e)}</code>" for e in f.get("evidence", []))
        active = f.get("active")
        badge = ""
        if active is True:
            badge = ' <span class="tag">有効</span>'
        elif active is False:
            badge = ' <span class="tag">無効</span>'
        out.append(
            "<tr>"
            f"<td><b>{_esc(f.get('name'))}</b>{badge}</td>"
            f"<td>{version_cell}</td>"
            f"<td>{_confidence(float(f.get('confidence') or 0))}</td>"
            f"<td>{evidence}</td>"
            "</tr>"
        )
    return "".join(out)


def _section(title: str, findings: list[dict]) -> str:
    if not findings:
        return ""
    return (
        f"<h3>{_esc(title)}</h3>"
        "<table><thead><tr><th>名前</th><th>Version</th><th>検出</th>"
        f"<th>根拠</th></tr></thead><tbody>{_rows(findings)}</tbody></table>"
        '<p class="note">'
        "Version が「—」のものは、製品は判定できたが Version が取れなかったものです。"
        "「検出」は<b>その製品だと判定できた確かさ</b>（高 / 中 / 低）です。"
        "</p>"
    )


_LEVEL_LABELS = {
    "red": ("🔴 赤", "#c53030"),
    "yellow": ("🟡 黄", "#b7791f"),
    "gray": ("⚪ 灰", "#718096"),
    "none": ("—", "#2f855a"),
}


def _range_text(advisory: dict) -> str | None:
    """「影響する Version」を文章にする（1.4.2 以下 / 7.3.0 〜 8.2.35 未満 など）。"""
    lower = advisory.get("affected_at_or_above")
    below = advisory.get("affected_below")
    upto = advisory.get("affected_upto")
    if below:
        return f"{lower} 〜 {below} 未満" if lower else f"{below} より前"
    if upto:
        return f"{lower} 〜 {upto} 以下" if lower else f"{upto} 以下"
    if lower:
        return f"{lower} 以降"
    return None


def _advisory_line(advisory: dict) -> str:
    """`CVE-xxxx ｜ 1.4.2 以下が影響 ｜ 1.4.3 で修正 ｜ 深刻度 9.8` のような 1 行。"""
    parts = []
    range_text = _range_text(advisory)
    parts.append(f"{_esc(range_text)}が影響" if range_text else "影響する Version は不明")
    fixed = advisory.get("fixed")
    # 修正版が範囲から自明（「X より前が影響」なら X が修正版）なときは繰り返さない
    if fixed and fixed not in (advisory.get("affected_below"), advisory.get("affected_upto")):
        parts.append(f"{_esc(fixed)} で修正")
    if advisory.get("cvss") is not None:
        parts.append(f"深刻度 {_esc(advisory['cvss'])}")
    if advisory.get("kev"):
        parts.append("<b>実際に悪用あり</b>")
    epss = advisory.get("epss")
    if epss is not None and float(epss) >= 0.01:
        parts.append(f"悪用の可能性 {float(epss) * 100:.0f}%")
    detail = " ｜ " + " ｜ ".join(parts) if parts else ""
    return f"<code>{_esc(advisory.get('id'))}</code>{detail}"


def _judgement_rows(judgements: list[dict]) -> str:
    """赤/黄/灰の判定を表にする。"""
    rows = []
    for judgement in judgements:
        label, color = _LEVEL_LABELS.get(str(judgement.get("level")), ("?", "#555"))
        advisories = judgement.get("advisories") or []
        details = (
            "<br>".join(_advisory_line(a) for a in advisories)
            or '<span class="empty">該当なし</span>'
        )
        note = judgement.get("note")
        note_html = f'<br><span class="empty">{_esc(note)}</span>' if note else ""
        rows.append(
            "<tr>"
            f'<td><span class="tag" style="color:{color};border-color:{color}">{label}</span></td>'
            f"<td><b>{_esc(judgement.get('component'))}</b></td>"
            f"<td>{_esc(judgement.get('version') or '版不明')}</td>"
            f"<td>{_esc(judgement.get('action'))}{note_html}<br>{details}</td>"
            "</tr>"
        )
    return "".join(rows)


def _judgement_section(judgements: list[dict]) -> str:
    if not judgements:
        return ""
    return (
        "<h3>更新すべきもの（判定）</h3>"
        "<table><thead><tr><th>判定</th><th>コンポーネント</th><th>版</th>"
        "<th>該当する勧告 / 次の行動</th></tr></thead><tbody>"
        f"{_judgement_rows(judgements)}</tbody></table>"
    )


def _site_card(site: dict) -> str:
    url = site.get("url")
    analysis = site.get("analysis")
    if not site.get("ok") or not analysis:
        return (
            '<div class="card failed">'
            f'<div class="url">{_esc(url)}</div>'
            f'<div class="meta">取得できませんでした: {_esc(site.get("error") or "不明")}</div>'
            "</div>"
        )

    findings: list[dict] = analysis.get("findings", [])
    by_kind: dict[str, list[dict]] = {}
    for finding in findings:
        by_kind.setdefault(str(finding.get("kind")), []).append(finding)

    meta = " ・ ".join(
        [
            f"HTTP {site.get('status')}",
            f"{site.get('elapsed_ms')} ms",
            f"検出 {len(findings)} 件",
        ]
    )
    notes = analysis.get("notes", [])
    notes_html = ""
    if notes:
        items = "".join(f"<li>{_esc(n)}</li>" for n in notes)
        notes_html = f'<div class="notes"><b>判定できなかったこと</b><ul>{items}</ul></div>'

    server_kinds = by_kind.get("language", []) + by_kind.get("server", []) + by_kind.get(
        "database", []
    )

    return (
        '<div class="card">'
        f'<div class="url">{_esc(url)}</div>'
        f'<div class="meta">{_esc(meta)}</div>'
        + _judgement_section(site.get("judgements") or [])
        + _section("プラットフォーム", by_kind.get("platform", []))
        + _section("コア", by_kind.get("core", []))
        + _section("プラグイン", by_kind.get("plugin", []))
        + _section("テーマ", by_kind.get("theme", []))
        + _section("JS ライブラリ", by_kind.get("library", []))
        + _section("言語・サーバ・DB", server_kinds)
        + notes_html
        + "</div>"
    )


def _kpi(value: str, label: str) -> str:
    return f'<div class="kpi"><b>{_esc(value)}</b><span>{_esc(label)}</span></div>'


def _percent(value: object) -> str:
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return "—"


def render(payload: dict) -> str:
    summary: dict = payload.get("summary", {})
    sites: list[dict] = payload.get("sites", [])
    levels: dict = summary.get("levels") or {}
    applied = bool(summary.get("advisories_applied"))

    if applied:
        level_kpis = [
            _kpi(str(levels.get("red", 0)), "赤（要対応）"),
            _kpi(str(levels.get("yellow", 0)), "黄（更新推奨）"),
            _kpi(str(levels.get("gray", 0)), "灰（判定不能）"),
        ]
        notice = ""
    else:
        # 索引が無いのに「赤 0」を出すと「問題なし」と誤解される（レビュー H2）
        level_kpis = [
            _kpi("—", "赤（未判定）"),
            _kpi("—", "黄（未判定）"),
            _kpi("—", "灰（未判定）"),
        ]
        notice = (
            '<div class="notes"><b>脆弱性の判定はしていません</b>（勧告索引が未適用）。'
            "<b>赤 0 は「問題なし」ではありません。</b> "
            "<code>svc-survey --advisories &lt;index.json&gt;</code> で索引を渡してください。</div>"
        )

    kpis = "".join(
        [
            _kpi(
                f"{summary.get('sites_fetched', 0)}/{summary.get('sites_tried', 0)}",
                "取得できたサイト",
            ),
            _kpi(_percent(summary.get("wordpress_rate")), "WordPress 判定率"),
            _kpi(_percent(summary.get("core_version_rate")), "コア版の特定率"),
            _kpi(_percent(summary.get("php_version_rate")), "PHP 版の特定率"),
            _kpi(_percent(summary.get("plugin_version_rate")), "プラグイン版の特定率"),
            _kpi(str(summary.get("plugins_per_site", 0)), "プラグイン数/サイト"),
            *level_kpis,
        ]
    )
    cards = "".join(_site_card(site) for site in sites)

    return f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>サイト脆弱性チェッカー PoC レポート</title>
<style>{_CSS}</style>
</head>
<body>
<h1>サイト脆弱性チェッカー PoC レポート（外部モード）</h1>
<div class="sub">
  公開ページに<b>すでに表示・読み込みされている情報</b>だけから推定した技術構成です（L1 パッシブ）。
  追加のリクエストはしていません。判定は<b>推定</b>であり、脆弱性の有無はまだ判定していません。
</div>
{notice}
<div class="summary">{kpis}</div>
{cards}
<footer>
  生成: site-vuln-checker（サイト脆弱性チェッカー PoC） /
  この PoC は外部から何が分かるかの実測用です。
  「版不明（灰）」は判定不能を意味し、安全を意味しません。
</footer>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="検出結果の HTML 可視化")
    parser.add_argument("--in", dest="src", type=Path, default=DEFAULT_OUT / "survey.json")
    parser.add_argument("--out", dest="dst", type=Path, default=DEFAULT_OUT / "report.html")
    args = parser.parse_args(argv)

    if not args.src.exists():
        print(f"入力がありません: {args.src}（先に svc-survey を実行してください）")
        return 1

    payload = json.loads(args.src.read_text(encoding="utf-8"))
    args.dst.parent.mkdir(parents=True, exist_ok=True)
    args.dst.write_text(render(payload), encoding="utf-8")
    print(f"出力: {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
