#!/usr/bin/env python3
"""Minimal IPSW / IM4P / Mach-O toolkit for the 27.0.1 vs 27.2 kernel diff.

No external ipsw binary is available on this host, so this implements the pieces
needed for the kernelcache comparison:

  * IM4P container parse + LZFSE payload decode
  * embedded Mach-O (kext) scan inside a prelinked kernelcache
  * UUID / segment / function-start extraction
  * function-level hashing and a two-build diff

Only reads files; nothing here writes to a device.
"""
import hashlib
import os
import struct
import sys
import zipfile

try:
    import lzfse
except ImportError:
    lzfse = None


# ── IM4P ────────────────────────────────────────────────────────────────────
def im4p_payload(data: bytes) -> bytes:
    if data[:4] != b"IM4P":
        return data
    # magic(4) type(4) header_len(4 BE) header payload
    hlen = struct.unpack(">I", data[8:12])[0]
    return data[12 + hlen:]


def decompress(payload: bytes) -> bytes:
    # LZFSE streams start with bvx2 / bvx- / bvx$
    for magic in (b"bvx2", b"bvx-", b"bvx$"):
        i = payload.find(magic)
        if i >= 0:
            if lzfse is None:
                raise RuntimeError("lzfse module missing")
            return lzfse.decompress(payload[i:])
    if payload[:2] == b"\x1f\x8b":
        import gzip
        return gzip.decompress(payload)
    return payload


def read_kernelcache(ipsw_path: str, member: str) -> bytes:
    with zipfile.ZipFile(ipsw_path) as z:
        raw = z.read(member)
    return decompress(im4p_payload(raw))


# ── Mach-O ──────────────────────────────────────────────────────────────────
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_UUID = 0x1B
LC_FUNCTION_STARTS = 0x26
LC_UNIXTHREAD = 0x5

CPU_NAMES = {0x0100000C: "arm64", 0x0100000C | 0x02000000: "arm64e"}


class MachO:
    def __init__(self, data: bytes, off: int = 0):
        self.data = data
        self.off = off
        magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from(
            "<IiiIIIII", data, off)
        if magic != MH_MAGIC_64:
            raise ValueError("not a 64-bit Mach-O")
        self.magic = magic
        self.cputype = cputype
        self.cpusub = cpusub
        self.filetype = filetype
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.flags = flags
        self.segments = []
        self.uuid = None
        self.function_starts = None
        self.symtab = None
        self._parse_commands()

    def _parse_commands(self):
        o = self.off + 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, o)
            if cmdsize < 8:
                break
            if cmd == LC_SEGMENT_64:
                name = self.data[o + 8:o + 24].split(b"\0")[0].decode("ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, o + 24)
                maxprot, initprot, nsects, flags = struct.unpack_from("<IIII", self.data, o + 56)
                seg = {
                    "name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                    "fileoff": fileoff, "filesize": filesize,
                    "maxprot": maxprot, "initprot": initprot, "nsects": nsects,
                    "sections": [],
                }
                so = o + 72
                for _s in range(nsects):
                    sect = self.data[so:so + 16].split(b"\0")[0].decode("ascii", "replace")
                    segn = self.data[so + 16:so + 32].split(b"\0")[0].decode("ascii", "replace")
                    addr, size, offset = struct.unpack_from("<QQI", self.data, so + 32)
                    seg["sections"].append({"seg": segn, "sect": sect, "addr": addr,
                                            "size": size, "offset": offset})
                    so += 80
                self.segments.append(seg)
            elif cmd == LC_UUID:
                self.uuid = self.data[o + 8:o + 24].hex()
            elif cmd == LC_FUNCTION_STARTS:
                dataoff, datasize = struct.unpack_from("<II", self.data, o + 8)
                self.function_starts = (dataoff, datasize)
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", self.data, o + 8)
                self.symtab = (symoff, nsyms, stroff, strsize)
            o += cmdsize

    def text_segment(self):
        for s in self.segments:
            if s["name"] == "__TEXT_EXEC":
                return s
        for s in self.segments:
            if s["name"] == "__TEXT":
                return s
        return None

    def function_offsets(self):
        """Absolute file offsets of function starts, decoded from LC_FUNCTION_STARTS."""
        if not self.function_starts:
            return []
        dataoff, datasize = self.function_starts
        base = self.off + dataoff
        end = base + datasize
        text = self.text_segment()
        if text is None:
            return []
        # LC_FUNCTION_STARTS dataoff is relative to the Mach-O header (linkedit).
        addr = text["vmaddr"]
        out = []
        p = base
        while p < end and self.data[p] != 0:
            delta = 0
            shift = 0
            while True:
                b = self.data[p]
                p += 1
                delta |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            addr += delta
            out.append(addr)
        return out

    def _file_base(self, s):
        # In a MH_FILESET, segment fileoffs are absolute in the container; in a
        # standalone Mach-O they are relative to the header (which sits at self.off).
        return s["fileoff"] if s["fileoff"] >= self.off else self.off + s["fileoff"]

    def vm_to_file(self, addr, seg=None):
        for s in self.segments:
            if s["vmaddr"] <= addr < s["vmaddr"] + s["vmsize"]:
                return self._file_base(s) + (addr - s["vmaddr"])
        return None

    def cstring_bytes(self):
        out = bytearray()
        for seg in self.segments:
            for sec in seg.get("sections", []):
                if sec["sect"] in ("__cstring", "__oslogstring"):
                    base = sec["offset"] if sec["offset"] >= self.off else self.off + sec["offset"]
                    out += self.data[base: base + sec["size"]]
                    out += b"\0"
        return bytes(out)

    def text_bytes(self):
        t = self.text_segment()
        if not t:
            return b""
        base = self._file_base(t)
        return self.data[base: base + t["filesize"]]


def scan_machos(data: bytes, limit=20000):
    """Scan a prelinked kernelcache for embedded Mach-O headers (page aligned)."""
    out = []
    off = 0
    n = len(data)
    while off + 32 <= n and len(out) < limit:
        if data[off:off + 4] == b"\xcf\xfa\xed\xfe":
            try:
                m = MachO(data, off)
                out.append(m)
            except Exception:
                pass
        off += 0x1000  # kexts are page aligned
    return out


def macho_summary(m: MachO) -> dict:
    text = m.text_bytes()
    return {
        "off": m.off,
        "cpu": CPU_NAMES.get(m.cputype, hex(m.cputype)),
        "sub": m.cpusub,
        "filetype": m.filetype,
        "uuid": m.uuid,
        "text_size": len(text),
        "text_sha256": hashlib.sha256(text).hexdigest()[:16],
        "segments": [(s["name"], s["vmsize"]) for s in m.segments if s["name"].startswith("__")],
        "nfuncs": len(m.function_offsets()) if m.function_starts else 0,
    }


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "list":
        with zipfile.ZipFile(sys.argv[2]) as z:
            for i in z.infolist():
                if any(k in i.filename for k in ("kernelcache", "dyld_shared_cache", "BuildManifest")):
                    print(i.filename, i.file_size)
    elif cmd == "kernel":
        data = read_kernelcache(sys.argv[2], sys.argv[3])
        print("kernelcache bytes", len(data), "sha256", hashlib.sha256(data).hexdigest()[:16])
        ms = scan_machos(data)
        print("embedded Mach-Os:", len(ms))
        for m in ms[:10]:
            print(macho_summary(m))
    else:
        print("usage: ipswlib.py list <ipsw> | kernel <ipsw> <member>")


def dump_macho(m: MachO, path: str) -> int:
    """Write the Mach-O image (header through the last segment's file extent)."""
    end = 32 + m.sizeofcmds
    for s in m.segments:
        end = max(end, s["fileoff"] + s["filesize"])
    blob = m.data[m.off:m.off + end]
    with open(path, "wb") as f:
        f.write(blob)
    return len(blob)
