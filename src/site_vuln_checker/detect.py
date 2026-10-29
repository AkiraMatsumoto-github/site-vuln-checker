"""外部から観測できる情報だけを使って、サイトの技術構成を推定する。

方針（docs/proposal.md 6.1 / 8.1）:

- **L1 パッシブ**。すでに読み込まれた HTML とリソース URL だけを見る。追加リクエストはしない。
- 判定は必ず「推定」。 :class:`Finding` は ``confidence`` と ``evidence`` を持つ。
- バージョンが取れないものは ``version=None`` のまま返す（推測で埋めない）。
  これは「バージョン未特定を緑にしない」という企画の鉄則（7.6）に対応する。
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

#: バージョン表記（1.2 / 1.2.3 / 6.8.2-beta1）
VERSION_PATTERN = r"\d+\.\d+(?:\.\d+)*(?:[-+~][0-9A-Za-z.\-]+)?"

_QUERY_VER_RE = re.compile(r"[?&](?:ver|v)=(" + VERSION_PATTERN + r")")
_FIRST_VERSION_RE = re.compile(VERSION_PATTERN)
_WP_PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([A-Za-z0-9_\-.]+)/")
_WP_THEME_PATH_RE = re.compile(r"/wp-content/themes/([A-Za-z0-9_\-.]+)/")
_PHP_HEADER_RE = re.compile(r"PHP/(" + VERSION_PATTERN + ")", re.I)
_SERVER_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-]*)/(\d+(?:\.\d+)+)")

#: JS ライブラリの判定。**順序が重要**（jquery-ui を jquery より先に見る）。
_LIB_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("jquery-ui", ("jquery-ui", "jqueryui")),
    ("jquery", ("jquery",)),
    ("bootstrap", ("bootstrap",)),
    ("lodash", ("lodash",)),
    ("moment", ("moment",)),
    ("angular", ("angular",)),
    ("vue", ("vue.", "vue.min", "/vue@")),
    ("react", ("react.", "react-dom", "/react@")),
    ("swiper", ("swiper",)),
    ("gsap", ("gsap", "tweenmax", "tweenlite")),
)


@dataclass(frozen=True)
class Finding:
    """1 つの検出結果。

    :param kind: ``platform`` / ``core`` / ``plugin`` / ``theme`` / ``library`` /
        ``language`` / ``server``
    :param name: 正規化した名前（WordPress なら ``wordpress``、プラグインなら slug）
    :param version: 推定バージョン。取れなければ ``None``
    :param confidence: 0.0〜1.0。6.2 の重み付けに対応
    :param evidence: 判定の根拠（``meta:generator``、``asset:?ver=5.9.8`` など）
    """

    kind: str
    name: str
    version: str | None = None
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()
    active: bool | None = None

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "confidence": round(self.confidence, 2),
            "evidence": list(self.evidence),
            "active": self.active,
        }


@dataclass
class Analysis:
    """1 ページ分の解析結果。"""

    url: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def of_kind(self, *kinds: str) -> list[Finding]:
        return [f for f in self.findings if f.kind in kinds]

    @property
    def platforms(self) -> list[Finding]:
        return self.of_kind("platform")

    @property
    def plugin_slugs(self) -> list[str]:
        return [f.name for f in self.of_kind("plugin")]

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
        }


def _query_version(url: str) -> str | None:
    """``?ver=6.8.2`` 形式のバージョンを取り出す。"""
    m = _QUERY_VER_RE.search(url)
    return m.group(1) if m else None


def _basename(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1] or "/"


def _collect_meta(soup: BeautifulSoup) -> dict[str, str]:
    """``<meta name=... content=...>`` を小文字キーで集める。"""
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property")
        if not key:
            continue
        meta[str(key).strip().lower()] = str(tag.get("content") or "").strip()
    return meta


def _collect_resources(soup: BeautifulSoup, base_url: str) -> list[str]:
    """読み込まれているリソース URL を集める（すでに読み込まれたものだけ）。"""
    urls: list[str] = []
    for tag_name, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("source", "src")):
        for tag in soup.find_all(tag_name):
            value = tag.get(attr)
            if not value:
                continue
            value = str(value).strip()
            if not value or value.startswith(("data:", "javascript:", "#")):
                continue
            urls.append(urljoin(base_url, value))
    # 重複を落としつつ順序を保つ
    return list(dict.fromkeys(urls))


def _detect_platforms(
    html_lower: str, resources: list[str], meta: dict[str, str], generator: str
) -> list[Finding]:
    """プラットフォーム判定（6.2）。複数シグナルが一致するほど確度を上げる。"""
    evidence: dict[str, list[str]] = {}

    if "wordpress" in generator.lower():
        evidence.setdefault("wordpress", []).append("meta:generator")
    if any("/wp-content/" in u for u in resources) or "/wp-content/" in html_lower:
        evidence.setdefault("wordpress", []).append("path:/wp-content/")
    if any("/wp-includes/" in u for u in resources):
        evidence.setdefault("wordpress", []).append("path:/wp-includes/")
    if "/wp-json/" in html_lower or "api.w.org" in html_lower:
        evidence.setdefault("wordpress", []).append("link:api.w.org")
    if "shopify.theme" in html_lower or "cdn.shopify.com" in html_lower:
        evidence.setdefault("shopify", []).append("dom:Shopify.theme")
    if "shopify-section" in html_lower:
        evidence.setdefault("shopify", []).append("dom:shopify-section")
    if "drupal" in generator.lower():
        evidence.setdefault("drupal", []).append("meta:generator")
    if "/sites/default/files/" in html_lower:
        evidence.setdefault("drupal", []).append("path:/sites/default/files/")
    if "joomla" in generator.lower():
        evidence.setdefault("joomla", []).append("meta:generator")
    if "/media/system/js/" in html_lower:
        evidence.setdefault("joomla", []).append("path:/media/system/js/")
    if "__next_data__" in html_lower:
        evidence.setdefault("nextjs", []).append("dom:__NEXT_DATA__")
    if "/_next/static/" in html_lower:
        evidence.setdefault("nextjs", []).append("path:/_next/static/")
    if "laravel_session" in html_lower:
        evidence.setdefault("laravel", []).append("cookie:laravel_session")

    return [
        Finding(
            kind="platform",
            name=name,
            confidence=min(0.99, 0.7 + 0.1 * len(items)),
            evidence=tuple(items),
        )
        for name, items in evidence.items()
    ]


def _is_bundled_library(url: str) -> bool:
    """WordPress に同梱されている第三者ライブラリか（jQuery 等）。

    同梱ライブラリの ``?ver=`` はコアのバージョンではないため、
    コア版の推定から除外する（誤検知よけ）。
    """
    name_path = _basename(url).lower()
    return any(any(t in name_path for t in tokens) for _, tokens in _LIB_TOKENS)


def _detect_core(generator: str, resources: list[str]) -> Finding | None:
    """WordPress コアのバージョン（6.2 の V1 → V2 の順）。"""
    m = re.search(r"WordPress\s+(" + VERSION_PATTERN + ")", generator, re.I)
    if m:
        return Finding("core", "wordpress", m.group(1), 1.0, ("meta:generator",))

    # V2: /wp-includes/ のアセットの ?ver= 。同梱ライブラリを除き、最頻値を採る。
    versions = [
        ver
        for url in resources
        if "/wp-includes/" in url and not _is_bundled_library(url)
        for ver in [_query_version(url)]
        if ver
    ]
    if versions:
        ver = Counter(versions).most_common(1)[0][0]
        return Finding("core", "wordpress", ver, 0.85, (f"asset:wp-includes?ver={ver}",))
    return None


def _detect_plugins(resources: list[str], html: str) -> list[Finding]:
    """``/wp-content/plugins/<slug>/`` からプラグインを抽出する（6.2）。

    リソース URL に現れている = フロントで動いている、と推定し ``active=True``。
    HTML 本文に文字列があるだけのものは**有効かどうか分からない**ので ``active=None``。
    バージョンは ``?ver=`` から取る（取れなければ ``None`` のまま）。
    """
    evidence: dict[str, list[str]] = {}
    candidates: dict[str, list[str]] = {}
    from_resources: set[str] = set()

    for url in resources:
        m = _WP_PLUGIN_PATH_RE.search(url)
        if not m:
            continue
        slug = m.group(1)
        from_resources.add(slug)
        evidence.setdefault(slug, []).append(f"asset:{_basename(url)}")
        ver = _query_version(url)
        if ver:
            candidates.setdefault(slug, []).append(ver)

    # インラインの URL（JSON や CSS 内）も拾う。根拠は弱く、有効とも言えない。
    for m in _WP_PLUGIN_PATH_RE.finditer(html):
        evidence.setdefault(m.group(1), []).append("inline:path")

    findings: list[Finding] = []
    for slug, items in evidence.items():
        unique = tuple(dict.fromkeys(items))
        active = True if slug in from_resources else None
        versions = candidates.get(slug) or []
        if versions:
            # 同じ slug に複数の ?ver= がある（管理画面用 CSS と本体 JS など）。
            # 最初の 1 つではなく**最頻値**を採る（同数なら最初に出たもの）。
            ver = Counter(versions).most_common(1)[0][0]
            findings.append(
                Finding(
                    "plugin", slug, ver, 0.85, (*unique[:1], f"asset:?ver={ver}"), active=active
                )
            )
        else:
            findings.append(Finding("plugin", slug, None, 0.6, unique, active=active))
    return sorted(findings, key=lambda f: f.name)


def _detect_themes(resources: list[str], html: str) -> list[Finding]:
    """``/wp-content/themes/<slug>/`` からテーマを抽出する。版は style.css の ``?ver=`` のみ。"""
    evidence: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    for url in resources:
        m = _WP_THEME_PATH_RE.search(url)
        if not m:
            continue
        slug = m.group(1)
        evidence.setdefault(slug, []).append(f"asset:{_basename(url)}")
        if slug not in versions and _basename(url).startswith("style.css"):
            ver = _query_version(url)
            if ver:
                versions[slug] = ver
    for m in _WP_THEME_PATH_RE.finditer(html):
        evidence.setdefault(m.group(1), []).append("inline:path")

    findings: list[Finding] = []
    for slug, items in evidence.items():
        ver = versions.get(slug)
        findings.append(
            Finding("theme", slug, ver, 0.5 if ver else 0.35, tuple(dict.fromkeys(items)))
        )
    return sorted(findings, key=lambda f: f.name)


def _detect_libraries(resources: list[str]) -> list[Finding]:
    """JS ライブラリの名前とバージョン（6.2 の V3）。"""
    found: dict[str, Finding] = {}
    for url in resources:
        name_path = _basename(url).lower()
        for lib, tokens in _LIB_TOKENS:
            if not any(t in name_path for t in tokens):
                continue
            m = _FIRST_VERSION_RE.search(name_path)
            if m:
                finding = Finding("library", lib, m.group(0), 0.9, (f"file:{_basename(url)}",))
            else:
                ver = _query_version(url)
                finding = Finding(
                    "library", lib, ver, 0.85 if ver else 0.7, (f"asset:{_basename(url)}",)
                )
            existing = found.get(lib)
            if existing is None or finding.confidence > existing.confidence:
                found[lib] = finding
            break
    return sorted(found.values(), key=lambda f: f.name)


def _detect_server(headers: dict[str, str]) -> list[Finding]:
    """``X-Powered-By`` / ``Server`` から PHP と Web サーバを推定する。"""
    findings: list[Finding] = []

    m = _PHP_HEADER_RE.search(headers.get("x-powered-by", ""))
    if m:
        # ヘッダはプロキシで書き換わることもあるため確度は 0.6（6.2 の方針）
        findings.append(Finding("language", "php", m.group(1), 0.6, ("header:x-powered-by",)))

    server = headers.get("server", "")
    if server:
        m2 = _SERVER_RE.search(server)
        if m2:
            findings.append(
                Finding("server", m2.group(1).lower(), m2.group(2), 0.5, ("header:server",))
            )
        else:
            findings.append(
                Finding("server", server.split()[0].lower(), None, 0.4, ("header:server",))
            )
    return findings


def analyze(url: str, html: str, headers: dict[str, str] | None = None) -> Analysis:
    """1 ページ分の HTML とヘッダから技術構成を推定する。

    :param headers: 小文字キーのレスポンスヘッダ。無くても動く（ヘッダが取れない設定のため）
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    soup = BeautifulSoup(html, "html.parser")
    meta = _collect_meta(soup)
    resources = _collect_resources(soup, url)
    html_lower = html.lower()
    generator = meta.get("generator", "")

    analysis = Analysis(url=url)
    analysis.findings.extend(_detect_platforms(html_lower, resources, meta, generator))

    core = _detect_core(generator, resources)
    if core:
        analysis.findings.append(core)

    analysis.findings.extend(_detect_plugins(resources, html))
    analysis.findings.extend(_detect_themes(resources, html))
    analysis.findings.extend(_detect_libraries(resources))
    analysis.findings.extend(_detect_server(headers))

    if not analysis.platforms:
        analysis.notes.append("プラットフォームを判定できませんでした")
    unknown = [p.name for p in analysis.of_kind("plugin") if not p.version]
    if unknown:
        analysis.notes.append(
            f"バージョンが分からないプラグイン: {', '.join(unknown)}（灰判定になります）"
        )
    if not analysis.of_kind("language"):
        analysis.notes.append("PHP のバージョンは取得できませんでした（ヘッダ非公開）")
    return analysis
