"""NVD の CVE から勧告索引（``advisories.json``）を作る。

NVD の本文には**修正版の書き方が 3 通り**あるので、それぞれに対応する（企画書 4.3）。

- ``before 5.9.9`` … ``affected_below = 5.9.9``（5.9.9 未満が影響）
- ``1.7 and earlier`` … ``affected_upto = 1.7``（1.7 以下が影響）
- ``up to, and including, 3.29.11`` … ``affected_upto = 3.29.11``（X 以下が影響）

版の情報が本文に無い CVE は**取り込まない**（推測しない）。KEV / EPSS は別のソースで
後から足す（ここでは NVD だけを見る）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .advisories import Advisory, AdvisoryIndex
from .nvd import NvdClient

DEFAULT_OUT = Path("out") / "advisories.json"
DEFAULT_KEYWORD = "WordPress plugin"

_VERSION = r"\d+(?:\.\d+)+"

#: 「The <名前> plugin (for WordPress)」から名前を取る。
_NAME_RE = re.compile(r"\bthe\s+(?P<name>.+?)\s+(?:wordpress\s+)?plugin\b", re.IGNORECASE)
#: before 5.9.9 / prior to 1.2.3
_BEFORE_RE = re.compile(rf"\b(?:before|prior\s+to)\s+(?:version\s+)?(?P<v>{_VERSION})", re.I)
#: 1.7 and earlier / 1.7 or below
_UPTO_BEFORE_RE = re.compile(
    rf"(?P<v>{_VERSION})\s+(?:and|or)\s+(?:earlier|below|prior)(?:\s+versions?)?", re.I
)
#: up to, and including, 3.29.11 / through version 1.2.3（including の後ろのカンマも許す）
_UPTO_INCLUDING_RE = re.compile(
    rf"\b(?:up\s+to,?\s*(?:and\s+)?including|through)\s*,?\s*(?:version\s+)?(?P<v>{_VERSION})",
    re.I,
)
#: fixed in 2.0.0 / fixed in version 2.0.0（修正版が書かれている形）
_FIXED_IN_RE = re.compile(rf"\bfix(?:ed)?\s+in\s+(?:version\s+)?(?P<v>{_VERSION})", re.I)

#: 1 つの CVE が複数プラグインを列挙することがある（上限は誤取り込みよけ）
MAX_NAMES_PER_CVE = 5
#: 名前として不自然な文字（本文の断片を拾ってしまうのを防ぐ）。
#: WordPress プラグイン名には () | ? ! , : ; が普通に含まれるので許可する。
_BAD_NAME_CHARS = frozenset("`\"[]{}<>")
#: 名前の末尾に来たら「途中で切れている」とみなす語。
#: "…for WordPress plugin" のように for/with で終わる正規名があるので含めない。
_DANGLING_ENDINGS = (" in", " of", " is", " are", " that", " which")
#: 文の断片に特徴的な語（これを含むものは製品名ではない）
_SENTENCE_MARKERS = (
    " is ",
    " are ",
    " was ",
    " were ",
    " does ",
    " do not ",
    " not ",
    " may ",
    " can ",
    " which ",
    " that ",
    " allows ",
    " because ",
    " without ",
    " when ",
    " have ",
    " has ",
    " been ",
    " to be ",
    " a user ",
    " the ",
)
#: 名前として成立しない語
_STOP_NAMES = frozenset({"the", "a", "an", "plugin", "plugins", "wordpress"})
#: 名前の最大長（実データでは 80 文字超の正規名がある）
MAX_NAME_LENGTH = 100
#: 名前の最大語数（保険。長い marketing 名があるので緩め）
MAX_NAME_WORDS = 14


def is_plausible_name(name: str) -> bool:
    """CVE 本文から切り出した名前が「製品名らしい」か。

    実データでは ``the `value` parameter of the `update-photo` action in the plugin`` のように
    文中の別の "the ... plugin" を拾ってしまうことがある。長さや大文字小文字ではなく
    **文の断片に特徴的な語**で弾く（長い正規名・小文字始まりの名前を落とさないため）。
    """
    if not name or len(name) > MAX_NAME_LENGTH:
        return False
    if name.lower() in _STOP_NAMES:
        return False
    if any(char in name for char in _BAD_NAME_CHARS):
        return False
    lowered = name.lower()
    if any(marker in f" {lowered} " for marker in _SENTENCE_MARKERS):
        return False
    if any(lowered.endswith(word) for word in _DANGLING_ENDINGS):
        return False
    return len(name.split()) <= MAX_NAME_WORDS


def english_description(cve: dict[str, Any]) -> str:
    """CVE の英語説明を返す（無ければ空文字）。"""
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return ""


def extract_names(description: str) -> list[str]:
    """「The ◯◯ plugin」を**すべて**取り出す（1 つの CVE が複数プラグインを列挙する形がある）。

    文中の別の "the ... plugin" を拾ってしまうことがあるので、:func:`is_plausible_name` で弾く。
    """
    names: list[str] = []
    for match in _NAME_RE.finditer(description):
        name = re.sub(r"\s+", " ", match.group("name")).strip(" .,-")
        if not is_plausible_name(name) or name in names:
            continue
        names.append(name)
        if len(names) >= MAX_NAMES_PER_CVE:
            break
    return names


def extract_name(description: str) -> str | None:
    """最初のプラグイン名（後方互換）。"""
    names = extract_names(description)
    return names[0] if names else None


def _scope(description: str) -> str:
    """プラグイン名の位置から**後ろだけ**を返す。

    NVD の説明文には別製品のバージョンが混ざる（例:
    "WordPress before 6.0.1 allows X, and the Foo Bar plugin for WordPress 1.2 and earlier ..."）。
    全文を対象にすると WordPress コアの 6.0.1 をプラグインの修正版として採ってしまい、
    「ほぼ全部が影響あり」の誤検知になる。名前より前は見ない。
    """
    match = _NAME_RE.search(description)
    if not match:
        # プラグイン名が取れない説明文は対象外（名前が無ければ勧告にできない）
        return ""
    return description[match.start("name") :]


def extract_range(description: str) -> tuple[str | None, str | None]:
    """``(affected_below, affected_upto)`` を返す。判断できないときは両方 None。"""
    scope = _scope(description)
    if match := _BEFORE_RE.search(scope):
        return match.group("v"), None
    if match := _UPTO_INCLUDING_RE.search(scope):
        return None, match.group("v")
    if match := _UPTO_BEFORE_RE.search(scope):
        return None, match.group("v")
    # 「fixed in 2.0.0」は「2.0.0 未満が影響」と同じ意味（レビュー M5）
    if match := _FIXED_IN_RE.search(scope):
        return match.group("v"), None
    return None, None


def extract_cvss(cve: dict[str, Any]) -> float | None:
    """CVSS を新しい規格から順に探す。"""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            score = (entry.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def nvd_url(cve_id: str, references: list[dict[str, Any]]) -> str:
    for reference in references:
        url = str(reference.get("url") or "")
        if "nvd.nist.gov" in url:
            return url
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def parse_cves(item: dict[str, Any]) -> tuple[list[Advisory], str]:
    """1 件の CVE を勧告に変換する（複数プラグインを列挙していれば複数返す）。

    変換できないときは空リストと理由を返す（推測で埋めない）。
    """
    cve = item.get("cve") or {}
    cve_id = str(cve.get("id") or "")
    description = english_description(cve)
    if not cve_id or not description:
        return [], "ID か説明が無い"

    names = extract_names(description)
    if not names:
        return [], "プラグイン名を特定できない"

    below, upto = extract_range(description)
    if not below and not upto:
        return [], "影響バージョンを特定できない"

    cvss = extract_cvss(cve)
    url = nvd_url(cve_id, cve.get("references") or [])
    advisories = [
        Advisory(
            id=cve_id,
            name=name,
            affected_below=below,
            affected_upto=upto,
            fixed=below,  # 「before X」の X はそのまま修正版として使える
            cvss=cvss,
            source="nvd",
            url=url,
        )
        for name in names
    ]
    return advisories, "ok"


def parse_cve(item: dict[str, Any]) -> tuple[Advisory | None, str]:
    """最初の 1 件だけを返す（後方互換・テスト用）。"""
    advisories, reason = parse_cves(item)
    return (advisories[0] if advisories else None), reason


def build_index(
    items: list[dict[str, Any]], *, generated_at: str | None = None
) -> AdvisoryIndex:
    """CVE のリストから索引を作る（同じ CVE・同じ名前の重複を除く）。"""
    advisories: list[Advisory] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        parsed, _reason = parse_cves(item)
        for advisory in parsed:
            key = (advisory.id, advisory.key)
            if key in seen:
                continue
            seen.add(key)
            advisories.append(advisory)
    return AdvisoryIndex(
        advisories=advisories,
        generated_at=generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
    )


def summarize(items: list[dict[str, Any]]) -> dict[str, int]:
    """取り込みの内訳。

    - ``kept``: 索引に寄与した CVE の数
    - ``advisories``: 索引のレコード数（複数プラグインを列挙する CVE は 2 以上）
    - ``skipped``: 除外した CVE の数（理由別にも数える）
    """
    stats = {"total": len(items), "kept": 0, "skipped": 0, "advisories": 0}
    seen: set[tuple[str, str]] = set()
    for item in items:
        parsed, reason = parse_cves(item)
        if not parsed:
            stats["skipped"] += 1
            stats[reason] = stats.get(reason, 0) + 1
            continue
        fresh = [a for a in parsed if (a.id, a.key) not in seen]
        if not fresh:
            stats["skipped"] += 1
            stats["重複"] = stats.get("重複", 0) + 1
            continue
        for advisory in fresh:
            seen.add((advisory.id, advisory.key))
        stats["kept"] += 1
        stats["advisories"] += len(fresh)
    return stats


def save(index: AdvisoryIndex, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows のコンソール文字化け対策

    parser = argparse.ArgumentParser(description="NVD から勧告索引を作る")
    parser.add_argument("--keyword", default=DEFAULT_KEYWORD)
    parser.add_argument("--days", type=int, default=30, help="公開日が何日前までか")
    parser.add_argument("--limit", type=int, default=400, help="取得する CVE の上限（0=無制限）")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    end = datetime.now(UTC)
    start = end - timedelta(days=args.days)
    params = {
        "keywordSearch": args.keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    client = NvdClient()
    print(
        f"NVD から取得: keyword={args.keyword!r} / {args.days} 日分 / "
        f"キー={'あり' if client.authenticated else 'なし'}（間隔 {client.interval} 秒）"
    )

    items: list[dict[str, Any]] = []
    try:
        for item in client.iter_cves(page_size=200, **params):
            items.append(item)
            if args.limit and len(items) >= args.limit:
                break
            if len(items) % 200 == 0:
                print(f"  ... {len(items)} 件取得")
    except RuntimeError as exc:
        print(f"取得に失敗しました: {exc}")
        return 1
    finally:
        client.close()

    stats = summarize(items)
    index = build_index(items)
    save(index, args.out)

    print(
        f"\n取得 {stats['total']} 件 → 取り込み {stats['kept']} 件"
        f"（勧告 {stats['advisories']} 件）/ 除外 {stats['skipped']} 件"
    )
    for key, value in sorted(stats.items()):
        if key in {"total", "kept", "skipped", "advisories"}:
            continue
        print(f"  除外理由: {key} … {value} 件")
    below = sum(1 for a in index.advisories if a.affected_below)
    upto = sum(1 for a in index.advisories if a.affected_upto)
    with_cvss = sum(1 for a in index.advisories if a.cvss is not None)
    print(f"  affected_below {below} 件 / affected_upto {upto} 件 / CVSS あり {with_cvss} 件")
    print(f"\n出力: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
