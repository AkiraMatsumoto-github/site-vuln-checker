"""WordPress「ツール → サイトヘルス → 情報」の解析（P0-18）。

外部からは 20〜40% しか分からない PHP のバージョンも、**管理者がログインしていれば**
この画面から確定できる（docs/proposal.md 6.4）。ここでは 2 種類の入力を扱う。

1. **HTML**: 拡張が実際に読む対象（``site-health.php?tab=debug`` の DOM）
2. **コピー用テキスト**: 「情報をクリップボードにコピー」で得られる ``### wp-core ###`` 形式。
   テストの**正解データ**として使う。

どちらも同じ正規化を通すので、結果が一致することをテストで確かめている。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from .detect import Finding

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
        """WordPress.org の slug の推定値（表示名から機械的に作るだけ。API で確認する）。"""
        return re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")

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
