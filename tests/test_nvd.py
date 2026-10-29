"""NVD クライアントのテスト。

**ネットワークは使わない**（レート間隔・キーの扱い・ヘッダだけを固定する）。
"""

from pathlib import Path

import pytest

from site_vuln_checker import nvd


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _install_fake(client: nvd.NvdClient, monkeypatch, payload: dict) -> dict:
    captured: dict = {}

    def fake_get(url: str, params: dict | None = None, headers: dict | None = None):
        captured["url"] = url
        captured["params"] = params or {}
        captured["headers"] = headers or {}
        return _FakeResponse(payload)

    monkeypatch.setattr(client._client, "get", fake_get)  # type: ignore[arg-type]
    return captured


def test_min_interval() -> None:
    assert nvd.min_interval(None) == pytest.approx(6.0), "キー無しは 5 req/30s"
    assert nvd.min_interval("key") == pytest.approx(0.6), "キーありは 50 req/30s"


def test_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "  abc  ")
    assert nvd.api_key_from_env() == "abc"
    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert nvd.api_key_from_env() is None


def test_api_key_from_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text('# コメント\nNVD_API_KEY="dotenv-key"\n', encoding="utf-8")
    assert nvd.api_key_from_env(env) == "dotenv-key"

    missing = tmp_path / "none.env"
    assert nvd.api_key_from_env(missing) is None


def test_client_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "secret")
    client = nvd.NvdClient()
    try:
        assert client.authenticated is True
        assert client.interval == pytest.approx(0.6)
    finally:
        client.close()


def test_search_sends_api_key_header(monkeypatch: pytest.MonkeyPatch) -> None:
    client = nvd.NvdClient(api_key="secret")
    try:
        captured = _install_fake(client, monkeypatch, {"totalResults": 0, "vulnerabilities": []})
        result = client.search(keywordSearch="WordPress plugin")
        assert result["totalResults"] == 0
        assert captured["headers"] == {"apiKey": "secret"}
        assert captured["params"]["resultsPerPage"] == nvd.DEFAULT_PAGE_SIZE
        assert captured["url"] == nvd.BASE_URL
    finally:
        client.close()


def test_search_without_key_sends_no_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    client = nvd.NvdClient(api_key="")
    try:
        captured = _install_fake(client, monkeypatch, {"totalResults": 0, "vulnerabilities": []})
        client.search(keywordSearch="x")
        assert captured["headers"] == {}, "キーが無いときはヘッダを付けない"
    finally:
        client.close()


def test_page_size_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    client = nvd.NvdClient(api_key="secret")
    try:
        captured = _install_fake(client, monkeypatch, {"totalResults": 0, "vulnerabilities": []})
        client.search(keywordSearch="x", resultsPerPage=9999)
        assert captured["params"]["resultsPerPage"] == nvd.MAX_PAGE_SIZE
    finally:
        client.close()


def test_iter_cves_pages_until_total(monkeypatch: pytest.MonkeyPatch) -> None:
    client = nvd.NvdClient(api_key="secret")
    pages = [
        {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": ["a", "b"]},
        {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": ["c"]},
    ]
    calls: list[int] = []

    def fake_search(**params):
        calls.append(params["startIndex"])
        return pages[len(calls) - 1]

    try:
        monkeypatch.setattr(client, "search", fake_search)
        assert list(client.iter_cves(page_size=2, keywordSearch="x")) == ["a", "b", "c"]
        assert calls == [0, 2]
    finally:
        client.close()
