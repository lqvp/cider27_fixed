# IPSW kernel-diff toolkit

Read-only helpers used for the 27.0.1 → 27.2 kernel comparison in
[`docs/IOS27.2-KERNEL-DIFF.md`](../../docs/IOS27.2-KERNEL-DIFF.md).

| Script | Purpose |
|---|---|
| `remote_ipsw.py` | HTTP-Range ZIP reader: list/extract a member without downloading the whole IPSW |
| `ipswlib.py` | IM4P/LZFSE decode, Mach-O/fileset parse, cstring extraction |
| `extract_kext.py` | dump one fileset entry as a standalone Mach-O (linkedit offsets rebased) |
| `disasm_diff.py` | normalized `llvm-objdump` instruction diff for two kexts |
| `diff_kernel.py` | kext-level diff (bundle id, size, strings, function hashes) |
| `map_advisory.py` | advisory CVE list → component/binary candidate table |

Requirements: Python 3, `pip install lzfse macholib`, Xcode command line tools
(`llvm-objdump`). Nothing writes to a device.
