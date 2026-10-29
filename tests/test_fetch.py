"""fetch のテスト。

**ネットワークは使わない**（偽の HTTP クライアントを差し込む）。
robots.txt の尊重・Content-Type の扱い・エラー時の挙動を固定する。
"""

import httpx
import pytest

from site_vuln_checker.fetch import FetchError, PoliteFetcher


class _Response:
    def __init__(
        self,
        status_code: int = 200,
        content: bytes = b"<html><body>ok</body></html>",
        headers: dict | None = None,
        url: str = "https://example.com/",
    ) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = {"content-type": "text/html"} if headers is None else headers
        self.encoding = "utf-8"
        self.url = url

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")


class _Client:
    """URL ごとにレスポンス（または例外）を返す偽クライアント。"""

    def __init__(self, responses: dict) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, url: str, **_kwargs) -> _Response:
        self.calls.append(url)
        result = self.responses.get(url)
        if isinstance(result, Exception):
            raise result
        if result is None:
            raise httpx.ConnectError("no route")
        return result

    def close(self) -> None:
        return None


def _fetcher(responses: dict, delay: float = 0.0) -> PoliteFetcher:
    fetcher = PoliteFetcher(delay=delay)
    fetcher._client.close()  # 本物のクライアントは使わない
    fetcher._client = _Client(responses)  # type: ignore[assignment]
    return fetcher


def test_allowed_when_robots_missing() -> None:
    fetcher = _fetcher({"https://example.com/robots.txt": _Response(404)})
    assert fetcher.allowed("https://example.com/private") is True


def test_allowed_when_robots_unreachable() -> None:
    fetcher = _fetcher({"https://example.com/robots.txt": httpx.ConnectError("boom")})
    assert fetcher.allowed("https://example.com/") is True


def test_disallow_is_respected() -> None:
    robots = _Response(content=b"User-agent: *\nDisallow: /private\n")
    fetcher = _fetcher({"https://example.com/robots.txt": robots})
    assert fetcher.allowed("https://example.com/private/page") is False
    assert fetcher.allowed("https://example.com/public") is True


def test_fetch_html() -> None:
    fetcher = _fetcher({"https://example.com/": _Response()})
    page = fetcher.fetch("https://example.com/")
    assert page.status == 200
    assert "ok" in page.html
    assert page.headers["content-type"] == "text/html"


def test_fetch_rejects_non_html() -> None:
    pdf = _Response(headers={"content-type": "application/pdf"})
    fetcher = _fetcher({"https://example.com/doc.pdf": pdf})
    with pytest.raises(FetchError, match="HTML ではありません"):
        fetcher.fetch("https://example.com/doc.pdf")


def test_fetch_rejects_error_status() -> None:
    fetcher = _fetcher({"https://example.com/": _Response(500)})
    with pytest.raises(FetchError, match="HTTP 500"):
        fetcher.fetch("https://example.com/")


def test_fetch_rejects_too_large() -> None:
    big = _Response(content=b"x" * (3 * 1024 * 1024 + 1))
    fetcher = _fetcher({"https://example.com/": big})
    with pytest.raises(FetchError, match="大きすぎる"):
        fetcher.fetch("https://example.com/")
