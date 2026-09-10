"""
Generate launcher/assets/app.ico using only the Python standard library.

Draws a simple shield glyph on a dark background at several sizes and packs
them into a multi-resolution .ico file. No third-party dependencies.
"""

import struct
import zlib
from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "assets"
SIZES = [16, 32, 48, 64, 128, 256]

BG = (13, 17, 23)          # #0d1117
SHIELD = (88, 166, 255)    # #58a6ff
SHIELD_DK = (31, 111, 235)  # depth
CHECK = (63, 185, 80)      # #3fb950


def in_shield(px, py, size):
    """Return True if the point is inside a rounded shield centered in the image."""
    # Normalize to 0..1
    x = (px + 0.5) / size
    y = (py + 0.5) / size
    # Shield bounds
    cx = 0.5
    top, bottom = 0.14, 0.90
    half_w = 0.30
    if y < top or y > bottom:
        return False
    # Upper part: straight sides; lower part: taper to a point
    mid = 0.55
    if y <= mid:
        w = half_w
    else:
        t = (y - mid) / (bottom - mid)
        w = half_w * (1.0 - t)
    return abs(x - cx) <= w


def in_check(px, py, size):
    """A simple check mark inside the shield."""
    x = (px + 0.5) / size
    y = (py + 0.5) / size
    # Two thick strokes forming a check
    def near_seg(ax, ay, bx, by, thick):
        dx, dy = bx - ax, by - ay
        L2 = dx * dx + dy * dy
        if L2 == 0:
            return False
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / L2))
        projx, projy = ax + t * dx, ay + t * dy
        return (x - projx) ** 2 + (y - projy) ** 2 <= thick * thick

    return near_seg(0.36, 0.50, 0.46, 0.62, 0.045) or \
        near_seg(0.46, 0.62, 0.66, 0.36, 0.045)


def render_rgba(size):
    px = bytearray()
    for y in range(size):
        for x in range(size):
            if in_check(x, y, size):
                r, g, b, a = (*CHECK, 255)
            elif in_shield(x, y, size):
                # slight vertical shade
                shade = y / size
                r = int(SHIELD[0] * (1 - shade) + SHIELD_DK[0] * shade)
                g = int(SHIELD[1] * (1 - shade) + SHIELD_DK[1] * shade)
                b = int(SHIELD[2] * (1 - shade) + SHIELD_DK[2] * shade)
                a = 255
            else:
                r, g, b, a = (*BG, 0)  # transparent background
            px += bytes((r, g, b, a))
    return bytes(px)


def rgba_to_png(rgba, size):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)  # filter: none
        raw += rgba[y * stride:(y + 1) * stride]
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def build_ico(path):
    images = []
    for size in SIZES:
        png = rgba_to_png(render_rgba(size), size)
        images.append((size, png))

    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)  # reserved, type=1 (icon), count
    entries = b""
    offset = 6 + count * 16
    data = b""
    for size, png in images:
        dim = 0 if size >= 256 else size  # 0 means 256 in ICONDIRENTRY
        entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset
        )
        data += png
        offset += len(png)
    path.write_bytes(header + entries + data)


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)
    out = ASSETS / "app.ico"
    build_ico(out)
    print(f"Wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
