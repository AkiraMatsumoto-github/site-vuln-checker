"""勧告索引に **KEV**（悪用実績）と **EPSS**（悪用予測）を付ける。

- **KEV**: CISA のカタログ JSON（1 リクエスト・約 1,700 件）。載っていれば「実際に悪用されている」。
- **EPSS**: FIRST の日次 CSV（gzip・約 25 万行）。30 日以内に悪用される確率（0〜1）。

どちらも *enrichment*（後付けの付加情報）。取れなくても索引は壊さない。
KEV に載っている勧告は **赤**、EPSS が高ければ（既定 0.5 以上）**赤**として扱う（企画書 7.5）。
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import httpx

from .advisories import (
    LEVEL_RED,
    LEVEL_YELLOW,
    RED_EPSS,
    Advisory,
    AdvisoryIndex,
    _level_for,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
USER_AGENT = "SVC-PoC/0.1 (+https://github.com/AkiraMatsumoto-github/site-vuln-checker)"
DEFAULT_INDEX = Path("out") / "advisories.json"


@dataclass(frozen=True)
class KevEntry:
    """KEV の 1 件。"""

    cve_id: str
    date_added: str | None = None
    due_date: str | None = None
    ransomware: bool = False


def parse_kev(payload: dict) -> dict[str, KevEntry]:
    """KEV の JSON を CVE ID → エントリの辞書にする。"""
    entries: dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").strip()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=item.get("dateAdded"),
            due_date=item.get("dueDate"),
            ransomware=str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
        )
    return entries


def parse_epss_csv(
    text: str, *, wanted: set[str] | None = None
) -> dict[str, tuple[float, float | None]]:
    """EPSS の日次 CSV を CVE ID → (epss, percentile) にする。

    CSV は先頭に ``#model_version:...,score_date:...`` のコメント行があり、
    そのあとに ``cve,epss,percentile`` のヘッダが来る。
    """
    scores: dict[str, tuple[float, float | None]] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if row[0].lower() == "cve":
            continue
        if len(row) < 2:
            continue
        cve_id = row[0].strip()
        if wanted is not None and cve_id not in wanted:
            continue
        try:
            epss = float(row[1])
        except ValueError:
            continue
        percentile: float | None = None
        if len(row) > 2:
            try:
                percentile = float(row[2])
            except ValueError:
                percentile = None
        scores[cve_id] = (epss, percentile)
    return scores


def enrich(
    index: AdvisoryIndex,
    kev: dict[str, KevEntry] | None = None,
    epss: dict[str, tuple[float, float | None]] | None = None,
) -> AdvisoryIndex:
    """索引の各勧告に KEV / EPSS を付けた新しい索引を返す。"""
    kev = kev or {}
    epss = epss or {}
    enriched: list[Advisory] = []
    for advisory in index.advisories:
        kev_entry = kev.get(advisory.id)
        epss_score, epss_percentile = epss.get(advisory.id, (None, None))
        enriched.append(
            replace(
                advisory,
                kev=bool(kev_entry) or advisory.kev,
                kev_added=(kev_entry.date_added if kev_entry else advisory.kev_added),
                kev_due=(kev_entry.due_date if kev_entry else advisory.kev_due),
                epss=epss_score if epss_score is not None else advisory.epss,
                epss_percentile=(
                    epss_percentile if epss_percentile is not None else advisory.epss_percentile
                ),
            )
        )
    return AdvisoryIndex(
        advisories=enriched, generated_at=index.generated_at, source_path=index.source_path
    )


def summarize(index: AdvisoryIndex) -> dict[str, int]:
    """結合の結果（何件に KEV / EPSS が付いたか、赤黄の内訳）。"""
    kev_hits = sum(1 for a in index.advisories if a.kev)
    epss_hits = sum(1 for a in index.advisories if a.epss is not None)
    high_epss = sum(1 for a in index.advisories if (a.epss or 0.0) >= RED_EPSS)
    levels = {LEVEL_RED: 0, LEVEL_YELLOW: 0}
    for advisory in index.advisories:
        levels[_level_for([advisory])] += 1
    return {
        "advisories": len(index.advisories),
        "kev": kev_hits,
        "epss": epss_hits,
        "epss_over_50pct": high_epss,
        "would_be_red": levels[LEVEL_RED],
        "would_be_yellow": levels[LEVEL_YELLOW],
    }


def _http_client() -> httpx.Client:
    return httpx.Client(
        timeout=60.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True
    )


def fetch_kev(url: str = KEV_URL) -> dict[str, KevEntry]:
    with _http_client() as client:
        response = client.get(url)
        response.raise_for_status()
        return parse_kev(response.json())


def fetch_epss(url: str = EPSS_URL) -> dict[str, tuple[float, float | None]]:
    with _http_client() as client:
        response = client.get(url)
        response.raise_for_status()
        raw = response.content
    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except OSError:  # 既に展開されている場合
        text = raw.decode("utf-8", errors="replace")
    return parse_epss_csv(text)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows のコンソール文字化け対策

    parser = argparse.ArgumentParser(description="勧告索引に KEV / EPSS を付ける")
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--out", type=Path, default=None, help="省略時は --index を上書き")
    parser.add_argument("--kev-url", default=KEV_URL)
    parser.add_argument("--epss-url", default=EPSS_URL)
    parser.add_argument("--skip-kev", action="store_true")
    parser.add_argument("--skip-epss", action="store_true")
    args = parser.parse_args(argv)

    try:
        index = AdvisoryIndex.load(args.index)
    except ValueError as exc:
        print(str(exc))
        return 1
    print(f"索引: {args.index}（{len(index.advisories)} 件）")

    kev: dict[str, KevEntry] = {}
    if args.skip_kev:
        print("KEV: スキップ")
    else:
        try:
            kev = fetch_kev(args.kev_url)
            print(f"KEV: {len(kev)} 件を取得")
        except (httpx.HTTPError, ValueError) as exc:
            print(f"KEV の取得に失敗しました（続行します）: {exc}")

    epss: dict[str, tuple[float, float | None]] = {}
    if args.skip_epss:
        print("EPSS: スキップ")
    else:
        try:
            epss = fetch_epss(args.epss_url)
            print(f"EPSS: {len(epss)} 件を取得")
        except (httpx.HTTPError, ValueError) as exc:
            print(f"EPSS の取得に失敗しました（続行します）: {exc}")

    enriched = enrich(index, kev, epss)
    out = args.out or args.index
    from .ingest import save  # 循環 import を避けるためここで読み込む

    save(enriched, out)

    stats = summarize(enriched)
    print(
        f"\n結合: KEV 該当 {stats['kev']} 件 / EPSS 付与 {stats['epss']} 件"
        f"（うち 50% 以上 {stats['epss_over_50pct']} 件）"
    )
    print(f"判定の内訳: 赤 {stats['would_be_red']} 件 / 黄 {stats['would_be_yellow']} 件")
    print(f"\n出力: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
