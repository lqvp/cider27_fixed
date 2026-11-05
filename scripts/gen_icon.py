#!/usr/bin/env python3
"""
gen_icon.py — build the app icon as a PNG with no external image library.

The mark: a dark rounded field, a struck arc of ember, and a thin ring of twenty small
ticks around it — the ring is the twenty-two fix families, the arc is the write that
carries a chosen value. Drawn with a signed-distance renderer at 4x and box-downsampled,
so edges stay clean without a graphics stack.
"""
import math
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Resources")
os.makedirs(OUT, exist_ok=True)

SIZE = 1024
SS = 1                      # analytic antialiasing via smoothstep; no supersampling needed


def srgb(c):
    return max(0, min(255, int(round(c))))


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


# ---------------------------------------------------------------- geometry helpers
def sd_circle(px, py, cx, cy, r):
    return math.hypot(px - cx, py - cy) - r


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    qx = abs(px - cx) - (hw - r)
    qy = abs(py - cy) - (hh - r)
    outside = math.hypot(max(qx, 0.0), max(qy, 0.0))
    inside = min(max(qx, qy), 0.0)
    return outside + inside - r


def sd_segment(px, py, ax, ay, bx, by, r):
    pax, pay = px - ax, py - ay
    bax, bay = bx - ax, by - ay
    denom = bax * bax + bay * bay
    h = 0.0 if denom == 0 else max(0.0, min(1.0, (pax * bax + pay * bay) / denom))
    return math.hypot(pax - bax * h, pay - bay * h) - r


def smoothstep(e0, e1, x):
    t = max(0.0, min(1.0, (x - e0) / (e1 - e0)))
    return t * t * (3 - 2 * t)


# ---------------------------------------------------------------- palette
BG_TOP = (0.075, 0.078, 0.094)
BG_BOT = (0.030, 0.031, 0.040)
EMBER = (1.00, 0.42, 0.16)
EMBER_HOT = (1.00, 0.72, 0.38)
ASH = (0.42, 0.44, 0.50)


def shade(px, py):
    """Return (r,g,b) in 0..1 for one sample point."""
    # vertical gradient field
    t = py / SIZE
    col = mix(BG_TOP, BG_BOT, t)

    # subtle radial lift behind the mark
    d = math.hypot(px - SIZE * 0.5, py - SIZE * 0.46)
    lift = 1.0 - smoothstep(0.0, SIZE * 0.62, d)
    col = tuple(min(1.0, col[i] + 0.055 * lift) for i in range(3))

    cx, cy = SIZE * 0.5, SIZE * 0.5

    # ---- outer ring of ticks: one per localized fix family (22)
    ring_r = SIZE * 0.345
    tick_outer = SIZE * 0.408
    ticks = 22
    ang = math.atan2(py - cy, px - cx)
    for i in range(ticks):
        a = (i / ticks) * math.tau - math.pi / 2
        # gap at the top-right where the arc breaks through
        if 0.30 < ((a + math.pi / 2) % math.tau) < 0.72:
            continue
        ax = cx + math.cos(a) * ring_r
        ay = cy + math.sin(a) * ring_r
        bx = cx + math.cos(a) * tick_outer
        by = cy + math.sin(a) * tick_outer
        sd = sd_segment(px, py, ax, ay, bx, by, SIZE * 0.0075)
        cov = 1.0 - smoothstep(-1.2, 1.2, sd)
        if cov > 0:
            col = mix(col, ASH, cov * 0.55)

    # ---- the arc: a heavy quarter sweep, hot at the leading end
    arc_r = SIZE * 0.245
    arc_w = SIZE * 0.052
    sd = abs(math.hypot(px - cx, py - cy) - arc_r)
    a01 = (math.atan2(py - cy, px - cx) + math.pi * 1.15) % math.tau
    span = math.tau * 0.62
    if a01 < span:
        edge = smoothstep(0.0, 0.10, a01) * (1.0 - smoothstep(span - 0.22, span, a01))
        cov = (1.0 - smoothstep(-1.2, 1.2, sd - arc_w * 0.5)) * edge
        if cov > 0:
            heat = smoothstep(span * 0.55, span, a01)
            col = mix(col, mix(EMBER, EMBER_HOT, heat), cov)

    # ---- core: a struck point with a halo
    core_r = SIZE * 0.062
    sd_core = math.hypot(px - cx, py - cy) - core_r
    halo = 1.0 - smoothstep(0.0, SIZE * 0.16, math.hypot(px - cx, py - cy))
    if halo > 0:
        col = tuple(min(1.0, col[i] + 0.16 * halo * halo * (EMBER[i])) for i in range(3))
    cov = 1.0 - smoothstep(-1.2, 1.2, sd_core)
    if cov > 0:
        col = mix(col, EMBER_HOT, cov)

    # ---- the write: a single straight stroke leaving the core, value-carrying
    sd_w = sd_segment(px, py, cx + SIZE * 0.075, cy + SIZE * 0.075,
                      cx + SIZE * 0.245, cy + SIZE * 0.245, SIZE * 0.0115)
    cov_w = 1.0 - smoothstep(-1.2, 1.2, sd_w)
    if cov_w > 0:
        col = mix(col, EMBER, cov_w * 0.92)

    return col


def render():
    """One sample per pixel — every edge already uses smoothstep on a signed distance,
    which is antialiased on its own. Supersampling 1024x1024 by 3 was 9.4M shade() calls
    and took minutes; this is the same image in a couple of seconds."""
    out = bytearray()
    radius = SIZE * 0.2237
    half = SIZE / 2
    tau = math.tau
    cos, sin, atan2, hypot, sqrt = math.cos, math.sin, math.atan2, math.hypot, math.sqrt

    # precompute tick segments
    ring_r = SIZE * 0.345
    tick_outer = SIZE * 0.408
    ticks = []
    for i in range(22):
        a = (i / 22) * tau - math.pi / 2
        if 0.30 < ((a + math.pi / 2) % tau) < 0.72:
            continue
        ticks.append((half + cos(a) * ring_r, half + sin(a) * ring_r,
                      half + cos(a) * tick_outer, half + sin(a) * tick_outer))

    arc_r = SIZE * 0.245
    arc_w2 = SIZE * 0.026
    span = tau * 0.62
    core_r = SIZE * 0.062
    halo_r = SIZE * 0.16
    tick_w2 = SIZE * 0.0075
    write_r = SIZE * 0.0115
    wx0, wy0 = half + SIZE * 0.075, half + SIZE * 0.075
    wx1, wy1 = half + SIZE * 0.245, half + SIZE * 0.245
    wdx, wdy = wx1 - wx0, wy1 - wy0
    wden = wdx * wdx + wdy * wdy

    for y in range(SIZE):
        out.append(0)
        py = y + 0.5
        for x in range(SIZE):
            px = x + 0.5

            # background gradient
            t = py / SIZE
            r = BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t
            g = BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t
            b = BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t

            dx, dy = px - half, py - half
            dist = hypot(dx, dy)

            # radial lift
            lift = 1.0 - smoothstep(0.0, SIZE * 0.62, dist)
            if lift > 0:
                add = 0.055 * lift
                r += add; g += add; b += add

            # ticks
            for (ax, ay, bx, by) in ticks:
                pax, pay = px - ax, py - ay
                bax, bay = bx - ax, by - ay
                den = bax * bax + bay * bay
                h = 0.0 if den == 0 else (pax * bax + pay * bay) / den
                if h < 0.0: h = 0.0
                elif h > 1.0: h = 1.0
                sd = hypot(pax - bax * h, pay - bay * h) - tick_w2
                if sd < 1.2:
                    cov = 1.0 - smoothstep(-1.2, 1.2, sd)
                    if cov > 0:
                        k = cov * 0.55
                        r += (ASH[0] - r) * k
                        g += (ASH[1] - g) * k
                        b += (ASH[2] - b) * k

            # arc
            sd = abs(dist - arc_r)
            if sd < arc_w2 + 1.2:
                a01 = (atan2(dy, dx) + math.pi * 1.15) % tau
                if a01 < span:
                    edge = smoothstep(0.0, 0.10, a01) * (1.0 - smoothstep(span - 0.22, span, a01))
                    cov = (1.0 - smoothstep(-1.2, 1.2, sd - arc_w2)) * edge
                    if cov > 0:
                        heat = smoothstep(span * 0.55, span, a01)
                        cr = EMBER[0] + (EMBER_HOT[0] - EMBER[0]) * heat
                        cg = EMBER[1] + (EMBER_HOT[1] - EMBER[1]) * heat
                        cb = EMBER[2] + (EMBER_HOT[2] - EMBER[2]) * heat
                        r += (cr - r) * cov
                        g += (cg - g) * cov
                        b += (cb - b) * cov

            # halo + core
            if dist < halo_r:
                halo = 1.0 - smoothstep(0.0, halo_r, dist)
                hk = 0.16 * halo * halo
                r += EMBER[0] * hk
                g += EMBER[1] * hk
                b += EMBER[2] * hk
            sd_core = dist - core_r
            if sd_core < 1.2:
                cov = 1.0 - smoothstep(-1.2, 1.2, sd_core)
                if cov > 0:
                    r += (EMBER_HOT[0] - r) * cov
                    g += (EMBER_HOT[1] - g) * cov
                    b += (EMBER_HOT[2] - b) * cov

            # the write stroke
            pax, pay = px - wx0, py - wy0
            h = (pax * wdx + pay * wdy) / wden
            if h < 0.0: h = 0.0
            elif h > 1.0: h = 1.0
            sd_w = hypot(pax - wdx * h, pay - wdy * h) - write_r
            if sd_w < 1.2:
                cov = 1.0 - smoothstep(-1.2, 1.2, sd_w)
                if cov > 0:
                    k = cov * 0.92
                    r += (EMBER[0] - r) * k
                    g += (EMBER[1] - g) * k
                    b += (EMBER[2] - b) * k

            # rounded-rect alpha
            qx = abs(px - half) - (half - 0.5 - radius)
            qy = abs(py - half) - (half - 0.5 - radius)
            ox = qx if qx > 0 else 0.0
            oy = qy if qy > 0 else 0.0
            sd_r = hypot(ox, oy) + (qx if qx > qy else qy) - radius
            a = 1.0 - smoothstep(-0.75, 0.75, sd_r)

            out += bytes([srgb(min(1.0, r) * 255), srgb(min(1.0, g) * 255),
                          srgb(min(1.0, b) * 255), srgb(a * 255)])
    return bytes(out)


def write_png(path, width, height, rgba):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        c += struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return c

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = zlib.compress(rgba, 9)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", raw)
           + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


def main():
    data = render()
    icon = os.path.join(OUT, "AppIcon-1024.png")
    write_png(icon, SIZE, SIZE, data)
    print("wrote", icon, os.path.getsize(icon), "bytes")

    # A small preview strip is handy when eyeballing the result.
    preview = os.path.join(OUT, "AppIcon-preview.png")
    write_png(preview, SIZE, SIZE, data)
    print("wrote", preview)


if __name__ == "__main__":
    main()
