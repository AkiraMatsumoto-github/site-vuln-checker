"""WordPress「ツール → サイトヘルス → 情報」の解析（P0-18）。

外部からは 20〜40% しか分からない PHP のバージョンも、**管理者がログインしていれば**
この画面から確定できる（docs/proposal.md 6.4）。ここでは 2 種類の入力を扱う。

1. **HTML**: 拡張が実際に読む対象（``site-health.php?tab=debug`` の DOM）
2. **コピー用テキスト**: 「情報をクリップボードにコピー」で得られる ``### wp-core ###`` 形式。
   テストの**正解データ**として使う。

どちらも同じ正規化を通すので、結果が一致することをテストで確かめている。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from bs4 import BeautifulSoup

from .advisories import Judgement
from .detect import Analysis, Finding

#: セクション見出しの対応表。**判定は上から順**（"wp-plugins-active" を "wp-core" より先に）。
_SECTION_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("wp-plugins-active", ("wp-plugins-active", "active plugins", "有効なプラグイン")),
    ("wp-plugins-inactive", ("wp-plugins-inactive", "inactive plugins", "無効なプラグイン")),
    ("wp-themes-active", ("wp-active-theme", "active theme", "使用中のテーマ", "有効なテーマ")),
    (
        "wp-themes-inactive",
        ("wp-themes-inactive", "inactive themes", "未使用のテーマ", "無効なテーマ"),
    ),
    ("wp-server", ("wp-server", "server", "サーバー", "サーバ")),
    ("wp-database", ("wp-database", "database", "データベース")),
    ("wp-core", ("wp-core", "wordpress")),
)

_NAME_VERSION_RE = re.compile(r"^(?P<name>.+?)\s*[:：]\s*(?P<version>\d+[0-9A-Za-z.\-+]*)\s*$")
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*(?:[-+~][0-9A-Za-z.\-]+)?")
_JP_NAME_KEYS = {"name", "名前", "プラグイン名", "テーマ名"}
_JP_VERSION_KEYS = {"version", "バージョン"}


@dataclass(frozen=True)
class Component:
    """プラグイン/テーマ 1 件。"""

    name: str
    version: str | None

    @property
    def slug(self) -> str:
        """WordPress.org の slug の推定値。

        日本語名は正規化すると空になるため、その場合は**元の名前をそのまま**使う
        （空のコンポーネント名がレポートに出るのを防ぐ）。
        """
        return re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-") or self.name

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "version": self.version, "slug": self.slug}


@dataclass
class SiteHealthInfo:
    """サイトヘルスから取り出した情報（6.4 のフィールド対応表に対応）。"""

    core_version: str | None = None
    php_version: str | None = None
    php_sapi: str | None = None
    httpd: str | None = None
    database: str | None = None
    plugins_active: list[Component] = field(default_factory=list)
    plugins_inactive: list[Component] = field(default_factory=list)
    themes_active: list[Component] = field(default_factory=list)
    themes_inactive: list[Component] = field(default_factory=list)
    source: str = "html"

    def to_findings(self) -> list[Finding]:
        """照合（detect と同じパイプライン）に流せる形へ変換する。"""
        findings: list[Finding] = []
        if self.core_version:
            findings.append(
                Finding("core", "wordpress", self.core_version, 1.0, ("site-health:wp-core",))
            )
        for comp in self.plugins_active:
            findings.append(
                Finding(
                    "plugin",
                    comp.slug,
                    comp.version,
                    1.0,
                    (f"site-health:plugin:{comp.name}",),
                    active=True,
                )
            )
        for comp in self.plugins_inactive:
            findings.append(
                Finding(
                    "plugin",
                    comp.slug,
                    comp.version,
                    1.0,
                    (f"site-health:plugin-inactive:{comp.name}",),
                    active=False,
                )
            )
        for comp in self.themes_active:
            findings.append(
                Finding("theme", comp.slug, comp.version, 1.0, ("site-health:theme",), active=True)
            )
        for comp in self.themes_inactive:
            findings.append(
                Finding(
                    "theme", comp.slug, comp.version, 1.0, ("site-health:theme",), active=False
                )
            )
        if self.php_version:
            findings.append(
                Finding("language", "php", self.php_version, 0.98, ("site-health:wp-server",))
            )
        if self.httpd:
            m = _VERSION_RE.search(self.httpd)
            name = self.httpd.split("/")[0].strip().lower()
            findings.append(
                Finding("server", name, m.group(0) if m else None, 0.95, ("site-health:wp-server",))
            )
        if self.database:
            m = _VERSION_RE.search(self.database)
            name = self.database.split()[0].strip().lower()
            findings.append(
                Finding(
                    "database",
                    name,
                    m.group(0) if m else None,
                    0.95,
                    ("site-health:wp-database",),
                )
            )
        return findings

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "core_version": self.core_version,
            "php_version": self.php_version,
            "php_sapi": self.php_sapi,
            "httpd": self.httpd,
            "database": self.database,
            "plugins_active": [p.to_dict() for p in self.plugins_active],
            "plugins_inactive": [p.to_dict() for p in self.plugins_inactive],
            "themes_active": [t.to_dict() for t in self.themes_active],
            "themes_inactive": [t.to_dict() for t in self.themes_inactive],
        }

    @property
    def counts(self) -> dict[str, int]:
        """件数の要約（レポートと受け入れテストで使う）。"""
        return {
            "plugins_active": len(self.plugins_active),
            "plugins_inactive": len(self.plugins_inactive),
            "themes_active": len(self.themes_active),
            "themes_inactive": len(self.themes_inactive),
        }


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\u00a0", " ")).strip().rstrip(":：").lower()


def _normalize_heading(text: str) -> str:
    return _normalize(text).replace("#", "").strip()


def _match_section(text: str) -> str | None:
    """見出しの文字列からセクションを決める（英語キーと日本語ラベルの両方）。"""
    norm = _normalize_heading(text)
    if not norm:
        return None
    for section, aliases in _SECTION_ALIASES:
        if any(alias in norm for alias in aliases):
            return section
    return None


def _version_from(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(0) if m else None


_COMPONENT_SECTIONS = (
    "wp-plugins-active",
    "wp-plugins-inactive",
    "wp-themes-active",
    "wp-themes-inactive",
)
_LISTS = {
    "wp-plugins-active": "plugins_active",
    "wp-plugins-inactive": "plugins_inactive",
    "wp-themes-active": "themes_active",
    "wp-themes-inactive": "themes_inactive",
}


def _add_component(info: SiteHealthInfo, section: str, name: str, version: str | None) -> None:
    name = name.strip().rstrip(":：")
    if not name:
        return
    getattr(info, _LISTS[section]).append(Component(name=name, version=version))


def _apply_scalar(info: SiteHealthInfo, section: str, key: str, value: str) -> None:
    """プラグイン以外（コア・サーバ・DB）の 1 行を反映する。"""
    k = _normalize(key)
    value = value.strip()
    if not value:
        return
    if section == "wp-core" and k in _JP_VERSION_KEYS:
        info.core_version = info.core_version or _version_from(value)
    elif section == "wp-server":
        if "php" in k and ("sapi" in k):
            info.php_sapi = value
        elif "php" in k and ("version" in k or "バージョン" in k):
            info.php_version = info.php_version or _version_from(value)
        elif "httpd" in k or "web server" in k or "ウェブサーバ" in k or "webサーバ" in k:
            info.httpd = info.httpd or value
    elif section == "wp-database" and ("version" in k or "バージョン" in k):
        info.database = info.database or value


def _consume_row(
    info: SiteHealthInfo,
    section: str,
    key: str,
    value: str,
    pending: dict[str, str],
) -> None:
    """1 行分（キー, 値）を取り込む。HTML とテキストで共通に使う。"""
    if section not in _COMPONENT_SECTIONS:
        _apply_scalar(info, section, key, value)
        return

    k = _normalize(key)

    # 「Contact Form 7: 5.9.8」のように 1 セルに名前と版が入る形
    m = _NAME_VERSION_RE.match(key)
    if m and not _looks_like_key(value):
        _add_component(info, section, m.group("name"), m.group("version"))
        return

    # 「名前 / バージョン」が別セル・別行になる形
    if k in _JP_NAME_KEYS:
        pending[section] = value or key
        return
    if k in _JP_VERSION_KEYS:
        name = pending.pop(section, "")
        if name:
            _add_component(info, section, name, _version_from(value) or value.strip())
        return


def _looks_like_key(value: str) -> bool:
    """値が「キー:」の形（= まだ名前が来ていない）かどうか。"""
    v = _normalize(value)
    return v in _JP_NAME_KEYS or v in _JP_VERSION_KEYS


def parse_site_health_text(text: str) -> SiteHealthInfo:
    """「情報をクリップボードにコピー」したテキストを解析する。"""
    info = SiteHealthInfo(source="text")
    pending: dict[str, str] = {}
    section: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("###") and line.endswith("###"):
            section = _match_section(line)
            continue
        if section is None:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        _consume_row(info, section, key.strip(), value.strip(), pending)
    return info


def parse_site_health_html(html: str) -> SiteHealthInfo:
    """サイトヘルス「情報」タブの DOM（HTML）を解析する。

    実際のページはセクションごとに表を持つので、**表ごとに直前の見出し**を見て
    セクションを決める。見出しの位置やクラス名が変わっても壊れにくい。
    """
    soup = BeautifulSoup(html, "html.parser")
    info = SiteHealthInfo(source="html")
    pending: dict[str, str] = {}

    for table in soup.find_all("table"):
        section = None
        headings = table.find_all_previous(["h2", "h3", "h4", "h5"])
        for candidate in (table.find("caption"), *headings):
            if candidate is None:
                continue
            section = _match_section(candidate.get_text(" ", strip=True))
            if section:
                break
        if not section:
            continue

        for row in table.find_all("tr"):
            cells = [c.get_text(" ", strip=True) for c in row.find_all(["td", "th"])]
            cells = [c for c in cells if c]
            if not cells:
                continue
            if len(cells) >= 3 and _VERSION_RE.fullmatch(cells[1].strip()):
                # 「名前 / 5.9.8 / 自動更新: 有効」のように 3 列以上に分かれる形
                if section in _COMPONENT_SECTIONS:
                    _add_component(info, section, cells[0], cells[1].strip())
                else:
                    _apply_scalar(info, section, cells[0], cells[1])
                continue
            key = cells[0]
            value = cells[1] if len(cells) > 1 else ""
            _consume_row(info, section, key, value, pending)
    return info


def parse_site_health(data: str) -> SiteHealthInfo:
    """入力の形式を判定して解析する（``###`` があればコピー用テキスト）。"""
    if "###" in data:
        return parse_site_health_text(data)
    return parse_site_health_html(data)


#: 判定の表示（CLI）。拡張の画面と同じ並び・同じ言葉にする。
_LEVEL_TEXT = {
    "red": "赤",
    "yellow": "黄",
    "info": "情報",
    "gray": "不明",
    "none": "緑",
}

_COMPONENT_GROUPS = (
    ("有効なプラグイン", "plugins_active"),
    ("停止中のプラグイン", "plugins_inactive"),
    ("使用中のテーマ", "themes_active"),
    ("未使用のテーマ", "themes_inactive"),
)


def _read_health_file(path: Path) -> str:
    """サイトヘルスの出力を読む（UTF-8 / BOM 付き可。日本語版の HTML も想定）。"""
    return path.read_bytes().decode("utf-8-sig", errors="replace")


def format_report(info: SiteHealthInfo, judgements: list[Judgement] | None = None) -> str:
    """人が読む形（CLI の標準出力）にする。"""
    source = "HTML" if info.source == "html" else "コピー用テキスト"
    lines = [f"サイトヘルスから読み取りました（{source}）"]
    if info.core_version:
        lines.append(f"  WordPress {info.core_version}")
    if info.php_version:
        sapi = f"（{info.php_sapi}）" if info.php_sapi else ""
        lines.append(f"  PHP {info.php_version}{sapi}")
    if info.httpd:
        lines.append(f"  サーバ {info.httpd}")
    if info.database:
        lines.append(f"  データベース {info.database}")
    for label, attribute in _COMPONENT_GROUPS:
        components: list[Component] = getattr(info, attribute)
        if not components:
            continue
        lines.append(f"  {label}（{len(components)} 件）")
        for component in components:
            version = component.version or "Version 不明"
            lines.append(f"    {component.name} {version}")

    if judgements is not None:
        lines.append("")
        if not judgements:
            lines.append("判定: 索引に該当する勧告はありません")
        else:
            lines.append("判定:")
            for judgement in judgements:
                label = _LEVEL_TEXT.get(judgement.level, judgement.level)
                version = judgement.version or "Version 不明"
                lines.append(
                    f"  [{label}] {judgement.component} {version} ｜ {judgement.action}"
                )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """``svc-sitehealth``: サイトヘルスの写しから構成を読み取り、索引があれば判定する。

    例::

        svc-sitehealth --html site-health.html --index out/index.json
        svc-sitehealth --text site-health.txt
        pbpaste | svc-sitehealth --index out/index.json
    """
    parser = argparse.ArgumentParser(
        prog="svc-sitehealth",
        description=(
            "WordPress の「ツール → サイトヘルス → 情報」から構成を読み取る"
            "（外部からは見えない PHP の Version なども分かる）"
        ),
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--html", metavar="PATH", help="サイトヘルス画面の HTML（保存したファイル）"
    )
    source_group.add_argument(
        "--text",
        metavar="PATH",
        help="「情報をクリップボードにコピー」したテキスト（ファイル）",
    )
    parser.add_argument(
        "--index",
        metavar="PATH",
        help="勧告の索引（out/index.json など）。指定すると判定まで出す",
    )
    parser.add_argument("--json", action="store_true", help="JSON で出力する（機械処理用）")
    args = parser.parse_args(argv)

    if args.html:
        info = parse_site_health_html(_read_health_file(Path(args.html)))
    elif args.text:
        info = parse_site_health_text(_read_health_file(Path(args.text)))
    elif not sys.stdin.isatty():
        info = parse_site_health(sys.stdin.read())
    else:
        parser.error("--html か --text を指定してください（標準入力からも読めます）")
        return 2

    judgements: list[Judgement] | None = None
    if args.index:
        from .advisories import AdvisoryIndex, judge

        index = AdvisoryIndex.load(Path(args.index))
        analysis = Analysis(url="site-health:", findings=info.to_findings())
        judgements = list(judge(analysis, index))

    if args.json:
        payload: dict[str, object] = {"info": info.to_dict()}
        if judgements is not None:
            payload["judgements"] = [judgement.to_dict() for judgement in judgements]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(format_report(info, judgements))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
