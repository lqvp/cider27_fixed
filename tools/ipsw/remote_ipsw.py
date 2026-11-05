#!/usr/bin/env python3
"""Remote ZIP reader over HTTP Range, so the kernelcache can be inspected before the
full IPSW finishes downloading.

Usage:
  python3 remote_ipsw.py list <url>
  python3 remote_ipsw.py extract <url> <member-substring> <out>
"""
import io
import sys
import urllib.request
import zipfile


class HTTPRangeFile(io.RawIOBase):
    def __init__(self, url, block=4 << 20):
        self.url = url
        self.pos = 0
        self.block = block
        self.cache = {}
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as r:
            self.size = int(r.headers["Content-Length"])
            self.ranges = r.headers.get("Accept-Ranges", "").lower() == "bytes"

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        if whence == 0: self.pos = off
        elif whence == 1: self.pos += off
        else: self.pos = self.size + off
        return self.pos

    def _fetch(self, start, end):
        key = (start // self.block) * self.block
        if key in self.cache:
            return self.cache[key]
        stop = min(self.size - 1, key + self.block - 1)
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={key}-{stop}"})
        with urllib.request.urlopen(req) as r:
            data = r.read()
        self.cache[key] = data
        if len(self.cache) > 8:
            self.cache.pop(next(iter(self.cache)))
        return data

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        if n == 0 or self.pos >= self.size:
            return b""
        out = bytearray()
        while n > 0 and self.pos < self.size:
            block = self._fetch(self.pos, self.pos)
            base = (self.pos // self.block) * self.block
            off = self.pos - base
            take = min(n, len(block) - off)
            if take <= 0:
                break
            out += block[off:off + take]
            self.pos += take
            n -= take
        return bytes(out)


def main():
    cmd, url = sys.argv[1], sys.argv[2]
    f = HTTPRangeFile(url)
    print("size", f.size, "range", f.ranges)
    z = zipfile.ZipFile(f)
    if cmd == "list":
        for i in z.infolist():
            if any(k in i.filename for k in ("kernelcache", "dyld_shared_cache", "BuildManifest")):
                print(i.filename, i.file_size, i.compress_type)
    elif cmd == "extract":
        pat, out = sys.argv[3], sys.argv[4]
        names = [i.filename for i in z.infolist() if pat in i.filename and not i.is_dir()]
        print("matches:", names[:10], "count", len(names))
        if not names:
            return
        name = names[0]
        with z.open(name) as src, open(out, "wb") as dst:
            while True:
                chunk = src.read(8 << 20)
                if not chunk: break
                dst.write(chunk)
        print("wrote", out)
    else:
        print("usage: list|extract")


if __name__ == "__main__":
    main()
