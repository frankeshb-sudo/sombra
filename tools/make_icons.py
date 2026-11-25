"""Genera los iconos de Sombra (PNG + ICO) sin dependencias externas.

Dibujo: fondo violeta oscuro redondeado con una luna creciente (la "sombra").
Uso: python tools/make_icons.py
"""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "icons")
BG = (22, 20, 31)
RING = (83, 74, 183)
MOON = (175, 169, 236)


def pixel(x, y, n):
    """Color RGBA de un punto (coordenadas 0..1)."""
    # Cuadrado redondeado
    r = 0.22
    cx = min(max(x, r), 1 - r)
    cy = min(max(y, r), 1 - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r:
        return (0, 0, 0, 0)
    d = ((x - 0.5) ** 2 + (y - 0.5) ** 2) ** 0.5
    # Luna creciente: círculo grande menos círculo desplazado
    big = d < 0.30
    cut = ((x - 0.62) ** 2 + (y - 0.40) ** 2) ** 0.5 < 0.26
    if big and not cut:
        return MOON + (255,)
    if 0.33 < d < 0.36:
        return RING + (255,)
    return BG + (255,)


def render(n, ss=4):
    rows = []
    for py in range(n):
        row = bytearray([0])
        for px in range(n):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    c = pixel((px + (sx + 0.5) / ss) / n, (py + (sy + 0.5) / ss) / n, n)
                    a = c[3]
                    acc[0] += c[0] * a
                    acc[1] += c[1] * a
                    acc[2] += c[2] * a
                    acc[3] += a
            k = ss * ss
            a = acc[3] / k
            if acc[3]:
                row += bytes([int(acc[0] / acc[3]), int(acc[1] / acc[3]), int(acc[2] / acc[3]), int(a)])
            else:
                row += bytes([0, 0, 0, 0])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(pngs):
    head = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries, data = b"", b""
    for size, png in pngs:
        s = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", s, s, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return head + entries + data


def main():
    os.makedirs(OUT, exist_ok=True)
    sizes = {16: None, 24: None, 32: None, 48: None, 64: None, 128: None, 256: None, 512: None}
    for s in sizes:
        sizes[s] = render(s, 4 if s <= 128 else 2)
    open(os.path.join(OUT, "32x32.png"), "wb").write(sizes[32])
    open(os.path.join(OUT, "128x128.png"), "wb").write(sizes[128])
    open(os.path.join(OUT, "128x128@2x.png"), "wb").write(sizes[256])
    open(os.path.join(OUT, "icon.png"), "wb").write(sizes[512])
    open(os.path.join(OUT, "icon.ico"), "wb").write(ico([(s, sizes[s]) for s in (16, 24, 32, 48, 64, 128, 256)]))
    print("Iconos generados en", os.path.abspath(OUT))


if __name__ == "__main__":
    main()
