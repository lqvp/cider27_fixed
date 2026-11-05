#!/usr/bin/env python3
"""Disassembly diff for two standalone Mach-O kexts (same bundle id, two builds).

Usage: python3 disasm_diff.py <a.macho> <b.macho> [max_lines]
Normalizes branch targets and absolute addresses so the diff shows real
instruction changes rather than layout noise.
"""
import difflib
import re
import subprocess
import sys

ADDR = re.compile(r"\b[0-9a-f]{8,16}\b")


def disasm(path):
    p = subprocess.run(["xcrun", "llvm-objdump", "--disassemble", path],
                       capture_output=True, text=True)
    lines = []
    for line in p.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]{8,16}):\s+([0-9a-f ]+?)\s{2,}(\S.*)$", line)
        if not m:
            continue
        ins = m.group(3).strip()
        ins = re.sub(r"0x[0-9a-f]{6,}", "0xADDR", ins)
        ins = re.sub(r"#0x[0-9a-f]{4,}", "#0xIMM", ins)
        lines.append(ins)
    return lines


def main():
    a, b = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    la, lb = disasm(a), disasm(b)
    print(f"# {a}: {len(la)} insns")
    print(f"# {b}: {len(lb)} insns")
    sm = difflib.SequenceMatcher(a=la, b=lb, autojunk=False)
    shown = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if shown >= limit:
            print("... truncated")
            break
        print(f"\n## {tag} a[{i1}:{i2}] b[{j1}:{j2}]")
        for x in la[i1:i2][:14]:
            print("  - " + x)
        for x in lb[j1:j2][:14]:
            print("  + " + x)
        shown += 1


if __name__ == "__main__":
    main()
