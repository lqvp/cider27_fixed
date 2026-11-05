#!/usr/bin/env python3
"""Diff two prelinked kernelcaches (27.0.1 vs 27.2) at kext and function level.

Usage:
  python3 diff_kernel.py <a.ipsw> <a-member> <b.ipsw> <b-member> [outdir]

Outputs:
  kexts.json        per-kext uuid/text hash/bundle id for both builds
  changed.txt       human-readable summary
  strings-<id>.txt  string adds/removes for changed kexts
"""
import hashlib
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipswlib


def ascii_strings(data, minlen=6):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "ignore"))
    return out


BID_RE = re.compile(r"^com\.apple\.[A-Za-z0-9_.-]{4,}$")


def bundle_id(m):
    """Heuristic: the kext identifier is the longest com.apple.* string in __TEXT."""
    cands = [s for s in ascii_strings(m.text_bytes()) if BID_RE.match(s)]
    cands.sort(key=lambda s: (-s.count("."), -len(s)))
    return cands[0] if cands else None


def func_hashes(m):
    starts = m.function_offsets()
    text = m.text_bytes()
    t = m.text_segment()
    out = []
    for i, addr in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else t["vmaddr"] + t["vmsize"]
        off = m.vm_to_file(addr)
        endoff = m.vm_to_file(end)
        if off is None or endoff is None or endoff < off:
            continue
        chunk = m.data[off:endoff]
        out.append((addr, hashlib.sha256(chunk).hexdigest()[:16], len(chunk)))
    return out


def load(ipsw, member):
    data = ipswlib.read_kernelcache(ipsw, member)
    ms = ipswlib.scan_machos(data)
    rows = []
    for m in ms:
        rows.append({
            "uuid": m.uuid,
            "cpu": ipswlib.CPU_NAMES.get(m.cputype, hex(m.cputype)),
            "bid": bundle_id(m),
            "text_sha": hashlib.sha256(m.text_bytes()).hexdigest()[:16],
            "text_size": len(m.text_bytes()),
            "nfuncs": len(m.function_offsets()) if m.function_starts else 0,
            "_m": m,
        })
    return data, rows


def main():
    a_ipsw, a_mem, b_ipsw, b_mem = sys.argv[1:5]
    outdir = sys.argv[5] if len(sys.argv) > 5 else "work/kernel-diff"
    os.makedirs(outdir, exist_ok=True)

    print("== extracting", a_mem)
    a, ra = load(a_ipsw, a_mem)
    print("== extracting", b_mem)
    b, rb = load(b_ipsw, b_mem)

    def index(rows):
        by_bid = {}
        no_bid = []
        for r in rows:
            if r["bid"]:
                by_bid.setdefault(r["bid"], []).append(r)
            else:
                no_bid.append(r)
        return by_bid, no_bid

    ia, na = index(ra)
    ib, nb = index(rb)

    changed, added, removed, same = [], [], [], []
    for bid in sorted(set(ia) | set(ib)):
        la = ia.get(bid, [])
        lb = ib.get(bid, [])
        if la and lb:
            # pair in order; usually one Mach-O per kext
            for x, y in zip(la, lb):
                if x["uuid"] == y["uuid"] and x["text_sha"] == y["text_sha"]:
                    same.append(bid)
                else:
                    changed.append((bid, x, y))
        elif la:
            removed += [bid]
        else:
            added += [bid]

    lines = []
    lines.append(f"kexts: a={len(ra)} b={len(rb)} same={len(same)} changed={len(changed)} added={len(added)} removed={len(removed)}")
    lines.append("")
    for bid, x, y in changed:
        lines.append(f"CHANGED {bid}: uuid {x['uuid']} -> {y['uuid']}  text {x['text_size']} -> {y['text_size']}  funcs {x['nfuncs']} -> {y['nfuncs']}")
    for bid in added:
        lines.append(f"ADDED   {bid}")
    for bid in removed:
        lines.append(f"REMOVED {bid}")
    open(os.path.join(outdir, "changed.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:80]))

    # string + function diff for changed kexts
    for bid, x, y in changed:
        ma = x["_m"]
        mb = y["_m"]
        sa = set(ascii_strings(ma.text_bytes(), 8))
        sb = set(ascii_strings(mb.text_bytes(), 8))
        new = sorted(sb - sa)
        gone = sorted(sa - sb)
        safe = bid.replace("/", "_")
        with open(os.path.join(outdir, f"strings-{safe}.txt"), "w") as f:
            f.write(f"# {bid}\n## new strings ({len(new)})\n")
            for s in new[:400]:
                f.write(s + "\n")
            f.write(f"\n## removed strings ({len(gone)})\n")
            for s in gone[:200]:
                f.write(s + "\n")
        fa = func_hashes(ma)
        fb = func_hashes(mb)
        changed_funcs = sum(1 for p, q in zip(fa, fb) if p[1] != q[1])
        lines.append(f"  {bid}: functions {len(fa)} -> {len(fb)}, hash-changed in common prefix {changed_funcs}")

    open(os.path.join(outdir, "changed.txt"), "w").write("\n".join(lines) + "\n")
    json.dump([
        {"bid": bid, "a": {k: v for k, v in x.items() if not k.startswith("_")},
         "b": {k: v for k, v in y.items() if not k.startswith("_")}}
        for bid, x, y in changed
    ], open(os.path.join(outdir, "kexts-changed.json"), "w"), indent=1)
    print("wrote", outdir)


if __name__ == "__main__":
    main()
