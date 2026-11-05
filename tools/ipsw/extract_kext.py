#!/usr/bin/env python3
"""Extract one fileset entry (kext) from a kernelcache into a standalone Mach-O.

Usage: python3 extract_kext.py <kernel> <entries.json> <bundle-id> <out.macho>
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipswlib

LC_SEGMENT_64 = 0x19


def extract(data, off, out):
    m = ipswlib.MachO(data, off)
    end = 32 + m.sizeofcmds
    for s in m.segments:
        base = s["fileoff"] if s["fileoff"] >= off else off + s["fileoff"]
        end = max(end, base + s["filesize"])
    blob = bytearray(data[off:end])

    o = 32
    for _ in range(m.ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, o)
        if cmd == LC_SEGMENT_64:
            # segment_command_64: cmd8 cmdsize8 segname16 vmaddr8 vmsize8 fileoff8 ...
            fileoff = struct.unpack_from("<Q", blob, o + 40)[0]
            if fileoff >= off:
                struct.pack_into("<Q", blob, o + 40, fileoff - off)
            nsects = struct.unpack_from("<I", blob, o + 64)[0]
            so = o + 72
            for _s in range(nsects):
                soff = struct.unpack_from("<I", blob, so + 48)[0]
                if soff >= off:
                    struct.pack_into("<I", blob, so + 48, soff - off)
                so += 80
        elif cmd == 0x2:  # LC_SYMTAB
            for f in (8, 16):
                v = struct.unpack_from("<I", blob, o + f)[0]
                if v >= off: struct.pack_into("<I", blob, o + f, v - off)
        elif cmd == 0xb:  # LC_DYSYMTAB
            for f in (32, 40, 48, 56, 64, 72):
                v = struct.unpack_from("<I", blob, o + f)[0]
                if v >= off: struct.pack_into("<I", blob, o + f, v - off)
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO / _ONLY
            for f in (8, 16, 24, 32, 40):
                v = struct.unpack_from("<I", blob, o + f)[0]
                if v >= off: struct.pack_into("<I", blob, o + f, v - off)
        elif cmd in (0x26, 0x1d, 0x80000033, 0x80000034):  # FUNCTION_STARTS, CODE_SIG, EXPORTS_TRIE, CHAINED_FIXUPS
            v = struct.unpack_from("<I", blob, o + 8)[0]
            if v >= off: struct.pack_into("<I", blob, o + 8, v - off)
        o += cmdsize

    with open(out, "wb") as f:
        f.write(blob)
    return len(blob)


if __name__ == "__main__":
    kernel, entries, bid, out = sys.argv[1:5]
    data = open(kernel, "rb").read()
    table = {n: o for n, o, v in json.load(open(entries))}
    n = extract(data, table[bid], out)
    print("wrote", out, n, "bytes")
