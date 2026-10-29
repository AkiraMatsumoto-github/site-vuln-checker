"""既知の脆弱性（勧告）と突き合わせて、コンポーネントの判定を出す。

役割分担:

- **索引（JSON）を作る**のは取り込み側（NVD / OSV など）。ここは**照合と判定**だけを行う。
- 判定は 2 軸（docs/proposal.md 7.1）。軸A=勧告の有無、軸B=「修正版があるか」。
- **バージョンが分からないものは灰**。推測で埋めない（7.6 の鉄則）。

索引の形式::

    {
      "generated_at": "2026-10-29T00:00:00Z",
      "advisories": [
        {"id": "CVE-2025-0001", "name": "Contact Form 7", "slug": "contact-form-7",
         "affected_below": "5.9.9", "fixed": "5.9.9", "cvss": 9.8, "kev": true,
         "source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"}
      ]
    }

``affected_below`` は「この版より前が影響を受ける」を表す。NVD の説明文にある
「before 5.9.9」をそのまま使う（4.3 の方式）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .detect import Analysis, Finding

LEVEL_RED = "red"
LEVEL_YELLOW = "yellow"
LEVEL_GRAY = "gray"
LEVEL_NONE = "none"

LEVEL_ORDER = {LEVEL_RED: 0, LEVEL_YELLOW: 1, LEVEL_GRAY: 2, LEVEL_NONE: 3}

_SEGMENT_RE = re.compile(r"\d+|[A-Za-z]+")
_SLUG_RE = re.compile(r"[^a-z0-9]+")

#: 赤と判定するしきい値（7.5）。KEV か CVSS 9.0 以上。
RED_CVSS = 9.0


def normalize_slug(text: str) -> str:
    """表示名や slug を比較用に正規化する。"""
    return _SLUG_RE.sub("-", text.strip().lower()).strip("-")


def version_key(version: str) -> tuple[tuple[int, object], ...]:
    """比較用のキー。``1.2`` / ``1.2.0`` / ``5.9.9.1`` を数値として比べる。

    英字を含む版（``1.2-beta``）は数値より後ろに置く。厳密な semver ではなく、
    WordPress プラグインの版表記を扱うための割り切り（詳細は README の制限参照）。
    """
    parts = _SEGMENT_RE.findall(version.strip().lstrip("vV"))
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts)


def compare_versions(left: str, right: str) -> int:
    """``left`` と ``right`` を比べる（-1 / 0 / 1）。``1.2`` と ``1.2.0`` は等しい。"""
    a, b = version_key(left), version_key(right)
    width = max(len(a), len(b))
    pad = (0, 0)
    a = a + (pad,) * (width - len(a))
    b = b + (pad,) * (width - len(b))
    return (a > b) - (a < b)


@dataclass(frozen=True)
class Advisory:
    """1 件の勧告（CVE など）。"""

    id: str
    name: str
    slug: str | None = None
    affected_below: str | None = None
    fixed: str | None = None
    cvss: float | None = None
    kev: bool = False
    epss: float | None = None
    source: str = "nvd"
    url: str | None = None

    @property
    def key(self) -> str:
        return normalize_slug(self.slug or self.name)

    @classmethod
    def from_dict(cls, data: dict) -> Advisory:
        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or ""),
            slug=data.get("slug"),
            affected_below=data.get("affected_below"),
            fixed=data.get("fixed"),
            cvss=float(data["cvss"]) if data.get("cvss") is not None else None,
            kev=bool(data.get("kev") or False),
            epss=float(data["epss"]) if data.get("epss") is not None else None,
            source=str(data.get("source") or "nvd"),
            url=data.get("url"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "affected_below": self.affected_below,
            "fixed": self.fixed,
            "cvss": self.cvss,
            "kev": self.kev,
            "epss": self.epss,
            "source": self.source,
            "url": self.url,
        }


@dataclass
class AdvisoryIndex:
    """勧告の索引。slug（または表示名）から引けるようにする。"""

    advisories: list[Advisory] = field(default_factory=list)
    generated_at: str | None = None
    source_path: Path | None = None

    def __post_init__(self) -> None:
        self._by_key: dict[str, list[Advisory]] = {}
        for advisory in self.advisories:
            self._by_key.setdefault(advisory.key, []).append(advisory)

    def lookup(self, name_or_slug: str) -> list[Advisory]:
        return list(self._by_key.get(normalize_slug(name_or_slug), ()))

    def advisories_for(self, finding: Finding) -> list[Advisory]:
        """Finding に該当しうる勧告。slug と表示名の両方で引く。"""
        found = self.lookup(finding.name)
        if found:
            return found
        name_key = normalize_slug(finding.name)
        return [a for a in self.advisories if normalize_slug(a.name) == name_key]

    @classmethod
    def from_dict(cls, data: dict, source_path: Path | None = None) -> AdvisoryIndex:
        return cls(
            advisories=[Advisory.from_dict(item) for item in data.get("advisories", [])],
            generated_at=data.get("generated_at"),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: Path) -> AdvisoryIndex:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")), source_path=path)

    def to_dict(self) -> dict[str, object]:
        return {
            "generated_at": self.generated_at,
            "advisories": [a.to_dict() for a in self.advisories],
        }


@dataclass(frozen=True)
class Judgement:
    """1 コンポーネント分の判定。"""

    component: str
    version: str | None
    level: str
    action: str
    advisories: tuple[Advisory, ...] = ()
    note: str = ""

    @property
    def is_issue(self) -> bool:
        """「更新すべきもの」に出すか（灰は出すが、赤黄とは別扱い）。"""
        return self.level in (LEVEL_RED, LEVEL_YELLOW)

    def to_dict(self) -> dict[str, object]:
        return {
            "component": self.component,
            "version": self.version,
            "level": self.level,
            "action": self.action,
            "note": self.note,
            "advisories": [a.to_dict() for a in self.advisories],
        }


def _level_for(affected: list[Advisory]) -> str:
    """影響ありの勧告から赤/黄を決める（7.5）。KEV か CVSS 9.0 以上で赤。"""
    if any(a.kev for a in affected):
        return LEVEL_RED
    if any((a.cvss or 0.0) >= RED_CVSS for a in affected):
        return LEVEL_RED
    return LEVEL_YELLOW


def judge(analysis: Analysis, index: AdvisoryIndex) -> list[Judgement]:
    """検出結果と索引を突き合わせて、コンポーネントごとの判定を返す。

    プラグインとテーマを対象にする（コアは索引の持ち方が別なので別途）。
    """
    judgements: list[Judgement] = []

    for finding in analysis.of_kind("plugin", "theme"):
        advisories = index.advisories_for(finding)

        if finding.version is None:
            # 版が分からない = 判定不能。ただし「勧告の履歴がある」ものだけ灰で知らせる。
            if advisories:
                judgements.append(
                    Judgement(
                        component=finding.name,
                        version=None,
                        level=LEVEL_GRAY,
                        action="バージョンを確認する",
                        advisories=tuple(advisories),
                        note=f"過去に {len(advisories)} 件の勧告あり。版が不明なため判定できません",
                    )
                )
            continue

        affected = [
            advisory
            for advisory in advisories
            if advisory.affected_below
            and compare_versions(finding.version, advisory.affected_below) < 0
        ]

        if not affected:
            if advisories:
                judgements.append(
                    Judgement(
                        component=finding.name,
                        version=finding.version,
                        level=LEVEL_NONE,
                        action="該当なし（勧告は修正版以降）",
                        advisories=tuple(advisories),
                    )
                )
            continue

        fixed_versions = sorted({a.fixed for a in affected if a.fixed}, key=version_key)
        action = (
            f"→ {fixed_versions[-1]} へ更新" if fixed_versions else "修正版不明（ベンダに確認）"
        )
        judgements.append(
            Judgement(
                component=finding.name,
                version=finding.version,
                level=_level_for(affected),
                action=action,
                advisories=tuple(
                    sorted(affected, key=lambda a: (not a.kev, -(a.cvss or 0.0)))
                ),
            )
        )

    judgements.sort(key=lambda j: (LEVEL_ORDER[j.level], j.component))
    return judgements


def summarize(judgements: list[Judgement]) -> dict[str, int]:
    """判定の件数（レポートとテストで使う）。"""
    counts = {LEVEL_RED: 0, LEVEL_YELLOW: 0, LEVEL_GRAY: 0, LEVEL_NONE: 0}
    for judgement in judgements:
        counts[judgement.level] += 1
    return counts
