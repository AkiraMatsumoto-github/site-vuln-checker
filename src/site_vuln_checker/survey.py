"""外部判定の実測（P0-21）。

対応サイトを巡回し、**外部から何がどれだけ分かるか**を集計する。
判定の中身は :mod:`site_vuln_checker.detect`（拡張へ移植するロジックと同じ）。

使い方::

    uv run svc-survey --urls sites.sample.txt --limit 5 --delay 1.0
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .advisories import AdvisoryIndex, Judgement, judge, summarize
from .detect import Analysis, analyze
from .fetch import FetchError, PoliteFetcher

DEFAULT_OUT = Path("out")


@dataclass
class SiteResult:
    url: str
    ok: bool
    status: int | None = None
    elapsed_ms: int | None = None
    error: str | None = None
    analysis: Analysis | None = None
    judgements: list[Judgement] = field(default_factory=list)


@dataclass
class Survey:
    results: list[SiteResult] = field(default_factory=list)

    def add(self, result: SiteResult) -> None:
        self.results.append(result)

    # --- 集計 -------------------------------------------------------------
    @property
    def analyses(self) -> list[Analysis]:
        """取得できたサイトの解析結果だけ。"""
        return [r.analysis for r in self.results if r.ok and r.analysis is not None]

    def _rate(self, predicate: Callable[[Analysis], bool]) -> float:
        targets = self.analyses
        if not targets:
            return 0.0
        return sum(1 for a in targets if predicate(a)) / len(targets)

    def summary(self) -> dict[str, object]:
        analyses = self.analyses
        plugins = [p for a in analyses for p in a.of_kind("plugin")]
        versioned = [p for p in plugins if p.version]
        cores = [c for a in analyses for c in a.of_kind("core")]
        return {
            "sites_tried": len(self.results),
            "sites_fetched": len(analyses),
            "sites_failed": len(self.results) - len(analyses),
            "platform_rate": round(self._rate(lambda a: bool(a.platforms)), 3),
            "wordpress_rate": round(
                self._rate(lambda a: any(p.name == "wordpress" for p in a.platforms)), 3
            ),
            "core_version_rate": round(
                self._rate(lambda a: any(c.version for c in a.of_kind("core"))), 3
            ),
            "core_confidence_avg": round(sum(c.confidence for c in cores) / len(cores), 3)
            if cores
            else 0.0,
            "php_version_rate": round(
                self._rate(lambda a: any(f.version for f in a.of_kind("language"))), 3
            ),
            "server_version_rate": round(
                self._rate(lambda a: any(f.version for f in a.of_kind("server"))), 3
            ),
            "plugins_total": len(plugins),
            "plugins_versioned": len(versioned),
            "plugin_version_rate": round(len(versioned) / len(plugins), 3) if plugins else 0.0,
            "plugins_per_site": round(len(plugins) / len(analyses), 2) if analyses else 0.0,
            "levels": self.level_counts(),
        }

    def level_counts(self) -> dict[str, int]:
        """判定の内訳（赤/黄/灰/該当なし）。索引を渡していなければ全て 0。"""
        all_judgements = [j for result in self.results for j in result.judgements]
        return summarize(all_judgements)

    # --- 出力 -------------------------------------------------------------
    def to_json(self) -> dict[str, object]:
        return {
            "summary": self.summary(),
            "sites": [
                {
                    "url": r.url,
                    "ok": r.ok,
                    "status": r.status,
                    "elapsed_ms": r.elapsed_ms,
                    "error": r.error,
                    "analysis": r.analysis.to_dict() if r.analysis else None,
                    "judgements": [j.to_dict() for j in r.judgements],
                }
                for r in self.results
            ],
        }

    def write_csv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["url", "kind", "name", "version", "confidence", "evidence"])
            for result in self.results:
                if result.analysis is None:
                    continue
                for finding in result.analysis.findings:
                    writer.writerow(
                        [
                            result.url,
                            finding.kind,
                            finding.name,
                            finding.version or "",
                            finding.confidence,
                            " | ".join(finding.evidence),
                        ]
                    )


def read_urls(path: Path) -> list[str]:
    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def run(
    urls: list[str],
    *,
    delay: float,
    timeout: float,
    limit: int | None,
    index: AdvisoryIndex | None = None,
) -> Survey:
    survey = Survey()
    targets = urls[:limit] if limit else urls
    with PoliteFetcher(delay=delay, timeout=timeout) as fetcher:
        for url in targets:
            if not fetcher.allowed(url):
                survey.add(SiteResult(url=url, ok=False, error="robots.txt で不許可"))
                print(f"  skip  {url}  (robots.txt)")
                continue
            try:
                page = fetcher.fetch(url)
            except FetchError as exc:
                survey.add(SiteResult(url=url, ok=False, error=str(exc)))
                print(f"  fail  {url}  {exc}")
                continue
            analysis = analyze(page.final_url, page.html, page.headers)
            judgements = judge(analysis, index) if index else []
            survey.add(
                SiteResult(
                    url=url,
                    ok=True,
                    status=page.status,
                    elapsed_ms=page.elapsed_ms,
                    analysis=analysis,
                    judgements=judgements,
                )
            )
            reds = sum(1 for j in judgements if j.level == "red")
            extra = f", 赤 {reds} 件" if index else ""
            print(f"  ok    {url}  ({page.elapsed_ms} ms, {len(analysis.findings)} 件{extra})")
    return survey


def print_summary(summary: dict[str, object]) -> None:
    print("\n=== 外部判定の実測（P0-21） ===")
    print(f"対象: {summary['sites_fetched']} / {summary['sites_tried']} サイト取得")
    print(f"プラットフォーム判定率    : {summary['platform_rate']:.0%}")
    print(f"WordPress 判定率          : {summary['wordpress_rate']:.0%}")
    print(f"コアのバージョン特定率    : {summary['core_version_rate']:.0%}")
    print(f"PHP のバージョン特定率    : {summary['php_version_rate']:.0%}")
    print(f"サーバのバージョン特定率  : {summary['server_version_rate']:.0%}")
    print(
        f"プラグイン: 1 サイト平均 {summary['plugins_per_site']} 件 / "
        f"版の特定率 {summary['plugin_version_rate']:.0%}"
        f"（{summary['plugins_versioned']}/{summary['plugins_total']}）"
    )
    levels = summary.get("levels") or {}
    if any(levels.values()):
        print(
            f"判定: 赤 {levels.get('red', 0)} / 黄 {levels.get('yellow', 0)} / "
            f"灰 {levels.get('gray', 0)} / 該当なし {levels.get('none', 0)}"
        )
    print("※ 企画書 8.1 の見込み値と比べる。件数が少ないので参考値として扱う")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows のコンソール文字化け対策

    parser = argparse.ArgumentParser(description="外部判定の実測（P0-21）")
    parser.add_argument("--urls", type=Path, default=Path("sites.sample.txt"))
    parser.add_argument("--limit", type=int, default=None, help="先頭から N 件だけ")
    parser.add_argument("--delay", type=float, default=1.0, help="同一ホストへの間隔（秒）")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--advisories",
        type=Path,
        default=None,
        help="勧告索引の JSON。指定すると赤/黄/灰の判定まで行う",
    )
    args = parser.parse_args(argv)

    urls = read_urls(args.urls)
    if not urls:
        print(f"URL がありません: {args.urls}")
        return 1

    index = AdvisoryIndex.load(args.advisories) if args.advisories else None
    if index:
        print(f"勧告索引: {args.advisories}（{len(index.advisories)} 件）")

    print(f"{len(urls)} 件を対象に取得します（delay={args.delay}s）")
    survey = run(urls, delay=args.delay, timeout=args.timeout, limit=args.limit, index=index)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "survey.json").write_text(
        json.dumps(survey.to_json(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    survey.write_csv(args.out / "survey.csv")
    summary = survey.summary()
    (args.out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print_summary(summary)
    print(f"\n出力: {args.out / 'survey.json'} / survey.csv / summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
