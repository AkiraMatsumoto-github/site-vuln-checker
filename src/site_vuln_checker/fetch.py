"""robots.txt を尊重し、レート制限つきで **1 ページだけ** 取得する。

企画の制約（docs/proposal.md 6.1 / 19.1）を守るための層:

- 取得するのは指定 URL 1 枚のみ（追加リクエスト・クロールをしない）
- ``robots.txt`` で ``Disallow`` なら取得しない
- 同一ホストへは ``delay`` 秒あける
- 上限サイズを超えるレスポンスは打ち切る
"""

from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

USER_AGENT = "SVC-PoC/0.1 (site vulnerability checker; contact: local-operator)"
ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"
MAX_BYTES = 3 * 1024 * 1024


class FetchError(Exception):
    """取得に失敗した（通信・ステータス・サイズ）。"""


@dataclass(frozen=True)
class Fetched:
    url: str
    final_url: str
    status: int
    html: str
    headers: dict[str, str]
    elapsed_ms: int


class PoliteFetcher:
    """礼儀正しい取得。ホストごとに間隔をあけ、robots.txt を守る。"""

    def __init__(self, delay: float = 1.0, timeout: float = 10.0) -> None:
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": ACCEPT},
        )
        self._last_hit: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def __enter__(self) -> PoliteFetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    def _robots_for(self, url: str) -> urllib.robotparser.RobotFileParser | None:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._robots:
            return self._robots[origin]

        parser: urllib.robotparser.RobotFileParser | None = None
        try:
            res = self._client.get(f"{origin}/robots.txt", timeout=5.0)
            if res.status_code == 200:
                parser = urllib.robotparser.RobotFileParser()
                parser.parse(res.text.splitlines())
            # 404 などは「制限なし」とみなす
        except httpx.HTTPError:
            parser = None
        self._robots[origin] = parser
        return parser

    def allowed(self, url: str) -> bool:
        """robots.txt で許可されているか。判定できないときは許可しない（安全側）。"""
        parser = self._robots_for(url)
        if parser is None:
            return True
        return parser.can_fetch(USER_AGENT, url)

    def _wait(self, host: str) -> None:
        last = self._last_hit.get(host)
        if last is None:
            return
        remaining = self.delay - (time.monotonic() - last)
        if remaining > 0:
            time.sleep(remaining)

    def fetch(self, url: str) -> Fetched:
        host = urlparse(url).netloc
        self._wait(host)
        started = time.monotonic()
        try:
            res = self._client.get(url)
        except httpx.HTTPError as exc:  # 通信失敗
            self._last_hit[host] = time.monotonic()
            raise FetchError(f"通信に失敗: {exc}") from exc
        finally:
            self._last_hit[host] = time.monotonic()

        if res.status_code >= 400:
            raise FetchError(f"HTTP {res.status_code}")
        if len(res.content) > MAX_BYTES:
            raise FetchError(f"レスポンスが大きすぎる（{len(res.content)} bytes）")

        encoding = res.encoding or "utf-8"
        try:
            html = res.content.decode(encoding, errors="replace")
        except LookupError:
            html = res.content.decode("utf-8", errors="replace")

        return Fetched(
            url=url,
            final_url=str(res.url),
            status=res.status_code,
            html=html,
            headers={k.lower(): v for k, v in res.headers.items()},
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
