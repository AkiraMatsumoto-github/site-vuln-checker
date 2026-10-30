"""NVD API 2.0 のクライアント（脆弱性情報の取り込みの土台）。

- API キーは環境変数 ``NVD_API_KEY`` から読む。**無くても動く**（レートが 1/10）。
- レート制限（キー無し 5 req/30s、キーあり 50 req/30s）に合わせて**自動で間隔を空ける**。
- 秘密は**リポジトリにも拡張にも入れない**（docs/proposal.md 12.5）。GitHub Actions では
  Secret、ローカルでは環境変数か ``.env``（コミットしない）に置く。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "SVC-PoC/0.1 (+https://github.com/AkiraMatsumoto-github/site-vuln-checker)"

#: NVD の公開仕様（30 秒あたりのリクエスト数）
RATE_WITHOUT_KEY = 5
RATE_WITH_KEY = 50
WINDOW_SECONDS = 30.0

DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 2000


def api_key_from_env(env_path: Path | None = None) -> str | None:
    """API キーを決める。

    1. 環境変数 ``NVD_API_KEY``
    2. ``.env``（リポジトリ直下。``.gitignore`` 済み）

    どちらも無ければ ``None``（キー無しでも動くが遅い）。
    """
    value = os.environ.get("NVD_API_KEY", "").strip()
    if value:
        return value

    path = env_path or Path(".env")
    if not path.is_file():
        return None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        if key.strip() != "NVD_API_KEY":
            continue
        return val.strip().strip('"').strip("'") or None
    return None


def min_interval(api_key: str | None) -> float:
    """リクエスト間の最小間隔（秒）。キーがあると 10 倍速い。"""
    rate = RATE_WITH_KEY if api_key else RATE_WITHOUT_KEY
    return WINDOW_SECONDS / rate


@dataclass
class NvdClient:
    """NVD CVE API の薄いクライアント。"""

    api_key: str | None = None
    timeout: float = 30.0
    max_retries: int = 3
    _last_request: float = field(default=0.0, repr=False)
    _client: httpx.Client | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = api_key_from_env()
        self._client = httpx.Client(
            timeout=self.timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    def __enter__(self) -> NvdClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    @property
    def authenticated(self) -> bool:
        return bool(self.api_key)

    @property
    def interval(self) -> float:
        return min_interval(self.api_key)

    def _wait(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)

    def search(self, **params: Any) -> dict[str, Any]:
        """CVE API を 1 回叩く。``params`` は NVD のクエリ（``keywordSearch`` など）。"""
        if self._client is None:  # pragma: no cover - 防御的
            raise RuntimeError("client が初期化されていません")

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params.setdefault("resultsPerPage", DEFAULT_PAGE_SIZE)
        if int(params["resultsPerPage"]) > MAX_PAGE_SIZE:
            params["resultsPerPage"] = MAX_PAGE_SIZE

        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            self._wait()
            try:
                response = self._client.get(BASE_URL, params=params, headers=headers)
            finally:
                self._last_request = time.monotonic()

            if response.status_code == 403:
                # 403 は「キーが無効・権限なし」。再試行しても直らないので即座に止める。
                raise RuntimeError(
                    "NVD API が 403 を返しました。API キーが無効か権限がありません"
                    "（.env の NVD_API_KEY を確認してください）"
                )
            if response.status_code == 429:
                # レート超過。待ってやり直す（キー無しだと起きやすい）。
                last_error = "HTTP 429"
                wait = 6.0 * attempt
                retry_after = getattr(response, "headers", {}).get("retry-after", "")
                if retry_after.isdigit():
                    wait = max(wait, float(retry_after))
                time.sleep(min(60.0, wait))
                continue
            if response.status_code in (502, 503, 504):
                # NVD 側の一時的な混雑（大きなページを要求すると起きやすい）。待ってやり直す。
                last_error = f"HTTP {response.status_code}"
                time.sleep(min(30.0, 3.0 * attempt))
                continue
            response.raise_for_status()
            return response.json()

        raise RuntimeError(
            f"NVD API に失敗しました（{last_error}）。間隔を空けて再実行してください"
        )

    def iter_cves(self, *, page_size: int = DEFAULT_PAGE_SIZE, **params: Any):
        """``startIndex`` を進めながら全件を返すジェネレータ（差分取得にも使う）。"""
        start = 0
        while True:
            payload = self.search(startIndex=start, resultsPerPage=page_size, **params)
            yield from payload.get("vulnerabilities", [])
            total = int(payload.get("totalResults", 0))
            start += int(payload.get("resultsPerPage", page_size)) or page_size
            if start >= total:
                return
