# ARM64 decompiler (Cutter / rizin / rz-ghidra)

IDA Pro is commercial; this uses the open-source decompiler bundled with Cutter 2.5.0
(`/Applications/Cutter.app`). No Java is involved, so it works on macOS 27 where the
Ghidra JVM crashes in CodeHeap.

```bash
tools/decompiler/decompile.sh <raw-arm64-text.bin> <function-offset-hex>
```

Raw blobs are the `__TEXT_EXEC,__text` section of a Mach-O (see
`tools/ipsw/ipswlib.py` for extraction). `SLEIGHHOME` is set to the bundled
`rz_ghidra_sleigh` specs; without it rz-ghidra reports "No sleigh specification".

Limitations: PAC instructions (`pacibsp`, `retab`) and some pointer-auth branches
truncate the decompiler output. Patch `retab` (0xd65f0fff) to `ret` (0xd65f03c0) in
a copy of the blob before decompiling; keep the original for ground truth.
