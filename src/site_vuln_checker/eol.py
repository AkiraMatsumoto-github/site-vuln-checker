"""サポート終了（EOL）の判定に使うライフサイクル情報。

役割（docs/proposal.md 7.3 の軸B）:

- **脆弱性が 0 件でも「もう直されない枝」なら更新すべき**。これを判定するのがこのモジュール。
- データは `endoflife.date <https://endoflife.date>`_ の公開 API を使う（無料・キー不要）。
- 取得したデータは索引（``advisories.json``）の ``lifecycles`` に同居させる。
  こうすると拡張も CLI も**同じ 1 ファイル**を読むだけで済む。

判定の考え方:

- ``eol`` が過去 → ``eol``（その枝に修正版は出ない。移行が必要）
- ``eol`` が近い（既定 90 日以内）→ ``eol_soon``
- サポート中でも枝内の最新より古い → ``outdated``（パッチ未適用の可能性）
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx

from .versioning import compare_versions

API = "https://endoflife.date/api/{product}.json"

#: 対応する製品（キーは検出・入力で使う名前と揃える）。
PRODUCTS: dict[str, str] = {
    "php": "PHP",
    "wordpress": "WordPress",
    "laravel": "Laravel",
    "symfony": "Symfony",
    "codeigniter": "CodeIgniter",
    "cakephp": "CakePHP",
    "django": "Django",
    "rails": "Ruby on Rails",
    "jquery": "jQuery",
}

#: サポート終了が「近い」とみなす日数。
EOL_SOON_DAYS = 90

DEFAULT_OUT = Path("out") / "advisories.json"


@dataclass(frozen=True)
class Cycle:
    """1 つのリリース系統（PHP の 8.1、Laravel の 10 など）。"""

    cycle: str
    eol: str | None = None
    latest: str | None = None
    support: str | None = None
    release_date: str | None = None

    @property
    def parts(self) -> int:
        return len(self.cycle.split("."))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Cycle:
        eol = data.get("eol")
        return cls(
            cycle=str(data.get("cycle") or ""),
            # endoflife.date は「未定」を false で返す。日付だけを残す。
            eol=str(eol) if isinstance(eol, str) else None,
            latest=str(data["latest"]) if data.get("latest") else None,
            support=str(data["support"]) if isinstance(data.get("support"), str) else None,
            release_date=str(data["releaseDate"]) if data.get("releaseDate") else None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "cycle": self.cycle,
            "eol": self.eol,
            "latest": self.latest,
            "support": self.support,
            "release_date": self.release_date,
        }



@dataclass(frozen=True)
class LifecycleStatus:
    """1 コンポーネントのライフサイクル判定結果。"""

    product: str
    name: str
    version: str
    state: str  # eol / eol_soon / outdated / supported / unknown
    cycle: str | None = None
    eol: str | None = None
    support: str | None = None
    latest: str | None = None
    move_to: str | None = None

    @property
    def is_issue(self) -> bool:
        return self.state in ("eol", "eol_soon")


def parse_date(value: str | None) -> date | None:
    """``2025-12-31`` を ``date`` に。読めなければ ``None``。"""
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


@dataclass
class Lifecycle:
    """1 製品分のライフサイクル（複数の系統を持つ）。"""

    product: str
    name: str = ""
    cycles: list[Cycle] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = PRODUCTS.get(self.product, self.product)
        # 長い cycle（8.1）を短いもの（8）より先に照合する
        self.cycles.sort(key=lambda c: c.parts, reverse=True)

    def cycle_for(self, version: str) -> Cycle | None:
        """バージョンが属する系統を返す（``8.1.27`` → ``8.1``）。"""
        parts = [
            p for p in str(version).strip().lstrip("vV").replace("-", ".").split(".") if p
        ]
        digits = [f"{int(p):d}" if p.isdigit() else p for p in parts]
        for cycle in self.cycles:
            width = cycle.parts
            if len(digits) >= width and ".".join(digits[:width]) == cycle.cycle:
                return cycle
        return None

    def supported_cycles(self, today: date) -> list[Cycle]:
        """まだサポート中の系統（新しい順）。"""
        alive = [
            cycle
            for cycle in self.cycles
            if (eol := parse_date(cycle.eol)) is None or eol >= today
        ]
        return sorted(
            alive,
            key=lambda c: [int(p) for p in c.cycle.split(".") if p.isdigit()],
            reverse=True,
        )

    def check(self, version: str, today: date | None = None) -> LifecycleStatus:
        """``version`` の状態を判定する。"""
        today = today or datetime.now(UTC).date()
        cycle = self.cycle_for(version)
        if cycle is None:
            return LifecycleStatus(self.product, self.name, version, "unknown")

        eol_date = parse_date(cycle.eol)
        behind = bool(cycle.latest and compare_versions(version, cycle.latest) < 0)

        state = "supported"
        if eol_date is not None:
            if eol_date < today:
                state = "eol"
            elif (eol_date - today).days <= EOL_SOON_DAYS:
                state = "eol_soon"
            elif behind:
                state = "outdated"
        elif behind:
            state = "outdated"

        move_to = None
        if state in ("eol", "eol_soon"):
            alive = [c for c in self.supported_cycles(today) if c.latest]
            if alive:
                move_to = alive[0].latest

        return LifecycleStatus(
            product=self.product,
            name=self.name,
            version=version,
            state=state,
            cycle=cycle.cycle,
            eol=cycle.eol,
            support=cycle.support,
            latest=cycle.latest,
            move_to=move_to,
        )



@dataclass
class LifecycleIndex:
    """製品名 → ライフサイクル。索引（``advisories.json``）の ``lifecycles`` と対応する。"""

    products: dict[str, Lifecycle] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # 製品名（大文字小文字を無視）でも引けるようにする
        self._by_alias: dict[str, Lifecycle] = {}
        for key, lifecycle in self.products.items():
            self._by_alias[key.lower()] = lifecycle
            self._by_alias[lifecycle.name.lower()] = lifecycle

    def get(self, product: str) -> Lifecycle | None:
        return self._by_alias.get(str(product).strip().lower())

    def check(
        self, product: str, version: str, today: date | None = None
    ) -> LifecycleStatus | None:
        lifecycle = self.get(product)
        if lifecycle is None:
            return None
        return lifecycle.check(version, today)

    @property
    def size(self) -> int:
        return len(self.products)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> LifecycleIndex | None:
        if not data:
            return None
        products: dict[str, Lifecycle] = {}
        for key, raw in (data.get("products") or data).items():
            if not isinstance(raw, dict):
                continue
            products[str(key)] = Lifecycle(
                product=str(key),
                name=str(raw.get("name") or PRODUCTS.get(str(key), str(key))),
                cycles=[Cycle.from_dict(item) for item in raw.get("cycles") or []],
            )
        return cls(products=products) if products else None

    def to_dict(self) -> dict[str, object]:
        return {
            "source": "endoflife.date",
            "products": {
                key: {"name": lifecycle.name, "cycles": [c.to_dict() for c in lifecycle.cycles]}
                for key, lifecycle in self.products.items()
            },
        }


def fetch_lifecycles(
    products: list[str], timeout: float = 30.0
) -> tuple[LifecycleIndex, list[str]]:
    """endoflife.date からライフサイクルを取得する。取れなかった製品名も返す。"""
    found: dict[str, Lifecycle] = {}
    missing: list[str] = []
    with httpx.Client(timeout=timeout, headers={"User-Agent": "SVC-PoC/0.1"}) as client:
        for product in products:
            try:
                response = client.get(API.format(product=product))
                response.raise_for_status()
                raw = response.json()
            except (httpx.HTTPError, ValueError):
                missing.append(product)
                continue
            if not isinstance(raw, list) or not raw:
                missing.append(product)
                continue
            found[product] = Lifecycle(
                product=product,
                name=PRODUCTS.get(product, product),
                cycles=[Cycle.from_dict(item) for item in raw if isinstance(item, dict)],
            )
    return LifecycleIndex(products=found), missing


def merge_into_index(path: Path, lifecycles: LifecycleIndex) -> int:
    """既存の索引 JSON に ``lifecycles`` を書き込む（他のキーは保つ）。"""
    data: dict[str, Any] = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"索引を読めません: {path}（JSON の形式を確認してください）") from exc
    data["lifecycles"] = lifecycles.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(data.get("advisories") or [])


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="サポート終了（EOL）情報を索引に足す")
    parser.add_argument(
        "--products",
        default=",".join(PRODUCTS),
        help="対象の製品（カンマ区切り。既定は対応製品すべて）",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    products = [p.strip() for p in args.products.split(",") if p.strip()]
    index, missing = fetch_lifecycles(products)
    if not index.size:
        print("ライフサイクルを取得できませんでした（ネットワークを確認してください）")
        return 1

    advisories = merge_into_index(args.out, index)
    print(f"ライフサイクルを取得: {index.size} 製品（{', '.join(sorted(index.products))}）")
    if missing:
        print(f"  取得できなかった製品: {', '.join(missing)}")

    today = datetime.now(UTC).date()
    for _key, lifecycle in sorted(index.products.items()):
        alive = lifecycle.supported_cycles(today)
        ended = [
            c for c in lifecycle.cycles if (eol := parse_date(c.eol)) and eol < today
        ]
        newest = alive[0].cycle if alive else "—"
        print(
            f"  {lifecycle.name:<14} 系統 {len(lifecycle.cycles):>2} / サポート中 {len(alive):>2}"
            f" / 終了 {len(ended):>2} / 最新の系統 {newest}"
        )
    print(f"\n出力: {args.out}（勧告 {advisories} 件 + ライフサイクル {index.size} 製品）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
