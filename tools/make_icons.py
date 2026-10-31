"""拡張のアイコン（PNG）を生成する。

デザイン: 判定 UI に合わせた**信号機**（赤・黄・緑）。
- 角丸の濃い背景に、3 つのランプを**横一列**に並べる
- 16px でも判別できるよう、要素を大きく・余白を広めに取る

使い方::

    uv run python tools/make_icons.py

``extension/icons/icon{16,32,48,128}.png`` を書き出す（外部ライブラリ不要）。
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

#: 内部で描く解像度（最後に縮小してアンチエイリアスにする）
SUPER = 512
OUT_DIR = Path("extension/icons")

BACKGROUND = (31, 41, 55, 255)  # #1f2937
RED = (229, 62, 62, 255)  # #e53e3e
YELLOW = (214, 158, 46, 255)  # #d69e2e
GREEN = (56, 161, 105, 255)  # #38a169
#: 各ランプ（左から赤・黄・緑）。中心の x 座標を SUPER 基準の比率で持つ
LAMPS = ((RED, 0.26), (YELLOW, 0.50), (GREEN, 0.74))
#: ランプの半径（比率）。0.12 を超えると隣とくっつくので 0.105 にする
LAMP_RADIUS = 0.105


def _rounded_alpha(px: float, py: float, size: int, radius: float) -> bool:
    """角丸四角の内側か。"""
    cx = min(max(px, radius), size - radius)
    cy = min(max(py, radius), size - radius)
    return (px - cx) ** 2 + (py - cy) ** 2 <= radius**2


def render_super() -> list[tuple[int, int, int, int]]:
    """SUPER x SUPER の RGBA を描く（ランプは横一列）。"""
    size = SUPER
    radius = size * 0.22
    lamp_radius = size * LAMP_RADIUS
    center_y = size / 2

    pixels: list[tuple[int, int, int, int]] = []
    for y in range(size):
        for x in range(size):
            px, py = x + 0.5, y + 0.5
            if not _rounded_alpha(px, py, size, radius):
                pixels.append((0, 0, 0, 0))
                continue

            color = BACKGROUND
            for lamp_color, ratio in LAMPS:
                cx = size * ratio
                if (px - cx) ** 2 + (py - center_y) ** 2 <= lamp_radius**2:
                    color = lamp_color
                    break
            pixels.append(color)
    return pixels


def downsample(
    pixels: list[tuple[int, int, int, int]], src: int, dst: int
) -> list[tuple[int, int, int, int]]:
    """src -> dst に縮小する（単純な箱型フィルタ）。"""
    factor = src // dst
    out: list[tuple[int, int, int, int]] = []
    for y in range(dst):
        for x in range(dst):
            r = g = b = a = 0
            for dy in range(factor):
                for dx in range(factor):
                    sx, sy = x * factor + dx, y * factor + dy
                    pr, pg, pb, pa = pixels[sy * src + sx]
                    # 透明部分は色を持たないので、アルファで重み付けして平均する
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            count = factor * factor
            if a == 0:
                out.append((0, 0, 0, 0))
            else:
                out.append((r // a, g // a, b // a, a // count))
    return out


def write_png(path: Path, size: int, pixels: list[tuple[int, int, int, int]]) -> None:
    """RGBA のピクセル列を PNG として書き出す。"""
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # フィルタなし
        for x in range(size):
            raw.extend(pixels[y * size + x])

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8bit RGBA
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def main() -> int:
    big = render_super()
    for size in (16, 32, 48, 128):
        pixels = big if size == SUPER else downsample(big, SUPER, size)
        path = OUT_DIR / f"icon{size}.png"
        write_png(path, size, pixels)
        print(f"{path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
