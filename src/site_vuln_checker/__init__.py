"""サイト脆弱性チェッカー（SVC）PoC。

外部から観測できる情報だけでサイトの技術構成を推定する（detect）。
WordPress の「サイトヘルス → 情報」を解析して PHP・プラグインを確定する（sitehealth）。
"""

__all__ = ["detect", "fetch", "report", "sitehealth", "survey"]
