"""既知の脆弱性（勧告）と突き合わせて、コンポーネントの判定を出す。

役割分担:

- **索引（JSON）を作る**のは取り込み側（NVD / OSV など）。ここは**照合と判定**だけを行う。
- 判定は 2 軸（docs/proposal.md 7.1）。軸A=勧告の有無、軸B=「修正版があるか」。
- **バージョンが分からないものは不明**。推測で埋めない（7.6 の鉄則）。

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
from bisect import bisect_left
from dataclasses import dataclass, field, replace
from pathlib import Path

from .detect import Analysis, Finding
from .eol import LifecycleIndex, LifecycleStatus
from .versioning import compare_versions, version_key

__all__ = [
    "LEVEL_GRAY",
    "LEVEL_INFO",
    "LEVEL_NONE",
    "LEVEL_RED",
    "LEVEL_YELLOW",
    "Advisory",
    "AdvisoryIndex",
    "Judgement",
    "compare_versions",
    "judge",
    "range_text",
    "summarize",
    "version_key",
]

LEVEL_RED = "red"
LEVEL_YELLOW = "yellow"
LEVEL_INFO = "info"
LEVEL_GRAY = "gray"
LEVEL_NONE = "none"

LEVEL_ORDER = {
    LEVEL_RED: 0,
    LEVEL_YELLOW: 1,
    LEVEL_INFO: 2,
    LEVEL_GRAY: 3,
    LEVEL_NONE: 4,
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")

#: 赤と判定するしきい値（7.5）。KEV / CVSS 9.0 以上 / EPSS 0.5 以上。
RED_CVSS = 9.0
RED_EPSS = 0.5


def normalize_slug(text: str) -> str:
    """表示名や slug を比較用に正規化する。"""
    return _SLUG_RE.sub("-", text.strip().lower()).strip("-")


#: 前方一致で拾うための最小長。短すぎる slug（"seo" など）は誤爆するので対象外。
MIN_PREFIX_MATCH = 6


def range_text(advisory: Advisory) -> str | None:
    """勧告の「影響する Version」を文章にする（拡張の affectedRangeText と同じ）。"""
    lower = advisory.affected_at_or_above
    if advisory.affected_below:
        if lower:
            return f"{lower} 〜 {advisory.affected_below} 未満"
        return f"{advisory.affected_below} より前"
    if advisory.affected_upto:
        if lower:
            return f"{lower} 〜 {advisory.affected_upto} 以下"
        return f"{advisory.affected_upto} 以下"
    if lower:
        return f"{lower} 以降"
    return None


def is_affected(version: str, advisory: Advisory) -> bool:
    """``version`` が勧告の影響範囲に入るか。

    CPE（NVD の構造化データ）に由来する勧告は**下限**を持つ
    （例: PHP は ``7.3.0 以上 8.2.35 未満``）。下限より下の版を「影響あり」と
    誤判定しないよう、先に下限で弾く。
    """
    if advisory.affected_at_or_above and compare_versions(
        version, advisory.affected_at_or_above
    ) < 0:
        return False
    # 上限が無く下限だけの勧告は「X 以降すべてが影響」と解釈する
    if not (advisory.affected_below or advisory.affected_upto):
        return bool(advisory.affected_at_or_above)
    if advisory.affected_below and compare_versions(version, advisory.affected_below) < 0:
        return True
    return bool(
        advisory.affected_upto and compare_versions(version, advisory.affected_upto) <= 0
    )


@dataclass(frozen=True)
class Advisory:
    """1 件の勧告（CVE など）。

    影響範囲の表し方は 3 通りある（NVD の本文と CPE に合わせる）。

    - ``affected_below`` … 「before 5.9.9」= 5.9.9 未満が影響
    - ``affected_upto``  … 「3.29.11 以下」「up to, and including, 3.29.11」= その版以下が影響
    - ``affected_at_or_above`` … CPE の下限（``7.3.0 以上``）。単独では使わず上の 2 つと組に
    """

    id: str
    name: str
    slug: str | None = None
    affected_below: str | None = None
    affected_upto: str | None = None
    affected_at_or_above: str | None = None
    #: 同じ CVE が系統ごとに複数ある場合の「影響する Version」一覧（表示用）
    ranges: tuple[str, ...] = ()
    fixed: str | None = None
    cvss: float | None = None
    kev: bool = False
    kev_added: str | None = None
    kev_due: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    source: str = "nvd"
    url: str | None = None

    @property
    def key(self) -> str:
        return normalize_slug(self.slug or self.name)

    @property
    def range_key(self) -> str:
        """影響範囲の識別子。

        同じ CVE でも**系統ごとに修正版が違う**（PHP の 8.2.35 / 8.3.36 / 8.4.27…）。
        索引の重複排除はこの範囲まで含めて行う（CVE と名前だけで除くと 1 件に潰れる）。
        """
        return "|".join(
            filter(
                None,
                (
                    self.affected_at_or_above or "",
                    self.affected_below or "",
                    self.affected_upto or "",
                ),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Advisory:
        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or ""),
            slug=data.get("slug"),
            affected_below=data.get("affected_below"),
            affected_upto=data.get("affected_upto"),
            affected_at_or_above=data.get("affected_at_or_above"),
            ranges=tuple(str(item) for item in (data.get("ranges") or ())),
            fixed=data.get("fixed"),
            cvss=float(data["cvss"]) if data.get("cvss") is not None else None,
            kev=bool(data.get("kev") or False),
            kev_added=data.get("kev_added"),
            kev_due=data.get("kev_due"),
            epss=float(data["epss"]) if data.get("epss") is not None else None,
            epss_percentile=(
                float(data["epss_percentile"]) if data.get("epss_percentile") is not None else None
            ),
            source=str(data.get("source") or "nvd"),
            url=data.get("url"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "affected_below": self.affected_below,
            "affected_upto": self.affected_upto,
            "affected_at_or_above": self.affected_at_or_above,
            "ranges": list(self.ranges),
            "fixed": self.fixed,
            "cvss": self.cvss,
            "kev": self.kev,
            "kev_added": self.kev_added,
            "kev_due": self.kev_due,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "source": self.source,
            "url": self.url,
        }


@dataclass
class AdvisoryIndex:
    """勧告の索引。slug（または表示名）から引けるようにする。

    ``lifecycles`` はサポート終了（EOL）の情報（:mod:`site_vuln_checker.eol`）。
    拡張と CLI が同じ 1 ファイルを読めるよう、索引 JSON に同居させている。
    """

    advisories: list[Advisory] = field(default_factory=list)
    generated_at: str | None = None
    source_path: Path | None = None
    lifecycles: LifecycleIndex | None = None

    def __post_init__(self) -> None:
        # 索引は生成時に固定する（生成後に `advisories` を足しても反映されない）。
        # 前方一致を O(log n) で引くために、正規化した名前を並べ替えて持つ。
        self._by_key: dict[str, list[Advisory]] = {}
        self._by_name: dict[str, list[Advisory]] = {}
        for advisory in self.advisories:
            # 正規化すると空になる名前（日本語だけの名前など）は索引に入れない。
            # 空キーを入れると、名前が空のコンポーネントが全部一致してしまう。
            if advisory.key:
                self._by_key.setdefault(advisory.key, []).append(advisory)
            name_key = normalize_slug(advisory.name)
            if name_key:
                self._by_name.setdefault(name_key, []).append(advisory)
        self._sorted_names: list[str] = sorted(self._by_name)

    def lookup(self, name_or_slug: str) -> list[Advisory]:
        return list(self._by_key.get(normalize_slug(name_or_slug), ()))

    def advisories_for(self, finding: Finding) -> list[Advisory]:
        """Finding に該当しうる勧告を探す。

        1. slug の完全一致
        2. 表示名の完全一致（正規化後）
        3. 表示名の**前方一致**（CVE 本文の名前にはマーケティング名が続くことが多い）

        前方一致は**プラグインとテーマだけ**。``wordpress``（コア）に前方一致を許すと、
        「WordPress User Extra Fields」のようなプラグイン名を拾って誤検知になる。
        コア・言語・フレームワークは完全一致のみ（CPE 由来の勧告は slug が製品名そのもの）。
        """
        slug = normalize_slug(finding.name)

        found = self._by_key.get(slug)
        if found:
            return list(found)

        exact = self._by_name.get(slug)
        if exact:
            return list(exact)

        if finding.kind not in ("plugin", "theme"):
            return []
        if len(slug) < MIN_PREFIX_MATCH:
            return []

        # 前方一致は「slug-」で始まる名前だけ。並べ替え済みなので開始位置を二分探索する。
        prefix = f"{slug}-"
        matched: list[Advisory] = []
        index = bisect_left(self._sorted_names, prefix)
        while index < len(self._sorted_names) and self._sorted_names[index].startswith(prefix):
            matched.extend(self._by_name[self._sorted_names[index]])
            index += 1
        return matched

    @classmethod
    def from_dict(cls, data: dict, source_path: Path | None = None) -> AdvisoryIndex:
        return cls(
            advisories=[Advisory.from_dict(item) for item in data.get("advisories", [])],
            generated_at=data.get("generated_at"),
            source_path=source_path,
            lifecycles=LifecycleIndex.from_dict(data.get("lifecycles")),
        )

    @classmethod
    def load(cls, path: Path) -> AdvisoryIndex:
        """索引を読む。壊れているときは案内つきの ``ValueError`` にする。"""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls.from_dict(data, source_path=path)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"索引を読めません: {path}（JSON の形式を確認してください）"
            ) from exc

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            # 索引の形式の版。拡張が将来の変更を見分けられるようにする。
            "schema": 1,
            "generated_at": self.generated_at,
            "advisories": [a.to_dict() for a in self.advisories],
        }
        if self.lifecycles is not None:
            data["lifecycles"] = self.lifecycles.to_dict()
        return data


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
        """「更新すべきもの」に出すか（不明は出すが、赤黄とは別扱い）。"""
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
    """影響ありの勧告から赤/黄を決める（7.5）。

    赤 = KEV（悪用実績）/ CVSS 9.0 以上 / EPSS 0.5 以上（30 日以内に悪用される確率が 50% 超）。
    """
    if any(a.kev for a in affected):
        return LEVEL_RED
    if any((a.cvss or 0.0) >= RED_CVSS for a in affected):
        return LEVEL_RED
    if any((a.epss or 0.0) >= RED_EPSS for a in affected):
        return LEVEL_RED
    return LEVEL_YELLOW


def _unique_by_id(advisories: list[Advisory]) -> tuple[Advisory, ...]:
    """同じ CVE を 1 つにまとめる（**範囲は落とさない**）。

    CPE 由来の勧告は**系統ごとに別レコード**になる（PHP なら 8.2/8.3/8.4/8.5）。
    1 つだけ残すと、自分の Version が該当するかを判断できないため、
    複数あるときは ``ranges`` に全部持たせる。
    """
    groups: dict[str, list[Advisory]] = {}
    for advisory in advisories:
        groups.setdefault(advisory.id, []).append(advisory)

    merged: list[Advisory] = []
    for group in groups.values():
        first = group[0]
        ranges = tuple(dict.fromkeys(t for t in (range_text(a) for a in group) if t))
        merged.append(replace(first, ranges=ranges) if len(ranges) > 1 else first)
    return tuple(merged)


def impact_label(cvss: float | None) -> str:
    """攻撃時の影響度を 1 語にする（専門用語の CVSS は画面に出さない）。

    特大（9.0 以上）、大（7.0〜8.9）、中（4.0〜6.9）、微（3.9 以下）、不明。
    """
    if cvss is None:
        return "不明"
    score = float(cvss)
    if score >= 9:
        return "特大"
    if score >= 7:
        return "大"
    if score >= 4:
        return "中"
    return "微"


def exposure_label(kev: bool, epss: float | None) -> str:
    """攻撃の可能性を 1 語にする（拡張の ``exposureLabel`` と同じ）。

    - ``実績あり``: 実際に悪用された事例が確認されている（KEV）。予測より強い根拠
    - ``特大``: 30 日以内に悪用されると予測される確率が 50% 以上
    - ``大``: 10% 以上、``中``: 1% 以上、``微``: 1% 未満、``不明``: 情報なし
    """
    if kev:
        return "実績あり"
    if epss is None:
        return "不明"
    value = float(epss)
    if value >= 0.5:
        return "特大"
    if value >= 0.1:
        return "大"
    if value >= 0.01:
        return "中"
    return "微"


def _max_of(affected: list[Advisory], key: str) -> float:
    return max((float(getattr(advisory, key) or 0.0) for advisory in affected), default=0.0)


def _risk_reason(affected: list[Advisory]) -> str:
    """「なぜ危ないのか」を、画面と同じ 2 軸の言葉で 1 行にする。"""
    if any(advisory.kev for advisory in affected):
        return "攻撃の可能性: 実績あり"
    max_epss = _max_of(affected, "epss")
    if max_epss >= RED_EPSS:
        return f"攻撃の可能性: {exposure_label(False, max_epss)}"
    max_cvss = _max_of(affected, "cvss")
    if max_cvss:
        return f"攻撃時の影響度: {impact_label(max_cvss)}"
    return "弱点の影響を受けます"


def _judge_advisories(finding: Finding, index: AdvisoryIndex) -> Judgement | None:
    """1 コンポーネントを勧告（CVE）と突き合わせる。"""
    advisories = index.advisories_for(finding)

    if finding.version is None:
        # 版が分からない = 判定不能。ただし「勧告の履歴がある」ものだけ不明で知らせる。
        if not advisories:
            return None
        unique = _unique_by_id(advisories)
        return Judgement(
            component=finding.name,
            version=None,
            level=LEVEL_GRAY,
            action="Version を確認してください",
            advisories=unique,
            note=(
                "Version が不明なため判定できません。"
                "下の「影響する Version」と、実際の Version を比べてください"
            ),
        )

    affected = [advisory for advisory in advisories if is_affected(finding.version, advisory)]
    if not affected:
        if not advisories:
            return None
        unique = _unique_by_id(advisories)
        return Judgement(
            component=finding.name,
            version=finding.version,
            level=LEVEL_NONE,
            action="この Version に脆弱性の報告はありません",
            advisories=unique,
            note=f"過去の勧告 {len(unique)} 件は、すべて修正済みです",
        )

    fixed_versions = sorted({a.fixed for a in affected if a.fixed}, key=version_key)
    action = (
        f"修正版 {fixed_versions[-1]} に更新してください"
        if fixed_versions
        else "修正版は公開されていません（ベンダに確認してください）"
    )
    return Judgement(
        component=finding.name,
        version=finding.version,
        level=_level_for(affected),
        action=action,
        advisories=_unique_by_id(sorted(affected, key=lambda a: (not a.kev, -(a.cvss or 0.0)))),
        note=_risk_reason(affected),
    )


#: ライフサイクル（EOL）を判定する種別。プラグインは対象外（版の系統が無い）。
LIFECYCLE_KINDS = ("core", "language", "framework", "library")


def lifecycle_note(status: LifecycleStatus) -> str:
    """EOL 判定の説明文（画面と CLI で同じ言い方にする）。"""
    if status.state == "eol":
        return f"{status.eol} にサポート終了（{status.cycle} 系の修正版は出ません）"
    if status.state == "eol_soon":
        return f"{status.eol} にサポート終了予定です"
    # outdated（同一系に新しい版がある）は action だけで足りるので補足しない
    return ""


def _judge_lifecycle(
    finding: Finding, lifecycles: LifecycleIndex | None, today
) -> Judgement | None:
    """サポート終了（軸B）の判定。脆弱性が 0 件でも「移行が必要」を出す。"""
    if lifecycles is None or finding.version is None:
        return None
    if finding.kind not in LIFECYCLE_KINDS:
        return None

    status = lifecycles.check(finding.name, finding.version, today)
    if status is None or status.state in ("supported", "unknown"):
        return None

    if status.state == "eol":
        action = (
            f"サポートが終了しています。{status.move_to} 以降に移行してください"
            if status.move_to
            else "サポートが終了しています。サポート中の系統へ移行してください"
        )
        level = LEVEL_YELLOW
    elif status.state == "eol_soon":
        action = (
            f"サポート終了が近づいています。{status.move_to} 以降に更新してください"
            if status.move_to
            else "サポート終了が近づいています。サポート中の系統へ更新してください"
        )
        level = LEVEL_YELLOW
    else:  # outdated（同じ系に新しい版がある）
        action = f"同じ {status.cycle} 系の最新は {status.latest} です"
        level = LEVEL_INFO  # リスクではないので「情報」

    return Judgement(
        component=finding.name,
        version=finding.version,
        level=level,
        action=action,
        note=lifecycle_note(status),
    )


def judge(analysis: Analysis, index: AdvisoryIndex, today=None) -> list[Judgement]:
    """検出結果と索引を突き合わせて、コンポーネントごとの判定を返す。

    2 軸で見る（7.1）:

    - **軸A: 既知の脆弱性** … プラグイン / テーマ / コア / 言語 / フレームワーク
    - **軸B: ライフサイクル** … コア / 言語 / フレームワーク / JS（索引に EOL 情報がある場合）

    同じコンポーネントに両方が当たったときは 1 行にまとめ、重い方を採用する。
    """
    judgements: list[Judgement] = []
    kinds = ("plugin", "theme", "core", "language", "framework")

    for finding in analysis.findings:
        if finding.kind not in kinds:
            continue
        if judgement := _judge_advisories(finding, index):
            judgements.append(judgement)

    for finding in analysis.findings:
        if judgement := _judge_lifecycle(finding, index.lifecycles, today):
            judgements.append(judgement)

    merged: dict[str, Judgement] = {}
    for judgement in judgements:
        key = normalize_slug(judgement.component)
        existing = merged.get(key)
        merged[key] = judgement if existing is None else _merge(existing, judgement)

    result = sorted(merged.values(), key=lambda j: (LEVEL_ORDER[j.level], j.component))
    return result


def _merge(left: Judgement, right: Judgement) -> Judgement:
    """同じコンポーネントの 2 つの判定（脆弱性・EOL）を 1 行にまとめる。

    ``right`` はライフサイクル（EOL）の判定。**移行の提案を先に**出す
    （サポートが終わった枝にパッチを当てても長くはもたないため）。
    """
    level = left.level if LEVEL_ORDER[left.level] <= LEVEL_ORDER[right.level] else right.level
    actions = [right.action, left.action]
    action = " / ".join(dict.fromkeys(a for a in actions if a))
    notes = [left.note, right.note]
    note = "。".join(dict.fromkeys(n for n in notes if n))
    advisories = tuple({a.id: a for a in (*left.advisories, *right.advisories)}.values())
    return Judgement(
        component=left.component,
        version=left.version if left.version is not None else right.version,
        level=level,
        action=action,
        advisories=advisories,
        note=note,
    )


def summarize(judgements: list[Judgement]) -> dict[str, int]:
    """判定の件数（レポートとテストで使う）。"""
    counts = {
        LEVEL_RED: 0,
        LEVEL_YELLOW: 0,
        LEVEL_INFO: 0,
        LEVEL_GRAY: 0,
        LEVEL_NONE: 0,
    }
    for judgement in judgements:
        counts[judgement.level] += 1
    return counts
