# iOS 27.2 kernel differential — 27.0.1 vs 27.2 (iPhone19,7)

Scope: the iOS 27.2 security update (24B119) against 27.0.1 (24A446) for iPhone 18
Pro Max (`iPhone19,7`). The question: what does the update actually change in the
kernel, which of the 162 advisory CVEs can be tied to a fix site, and does anything
in the diff look like a PPL / SPTM / MIE bypass.

## How the images were obtained

Both restore images are the production IPSWs from Apple's CDN:

| Build | Version | Size | Kernelcache member |
|---|---|---|---|
| 24A446 | 27.0.1 | 12,728,434,807 B | `kernelcache.release.v6x-pandia` |
| 24B119 | 27.2 | 13,722,855,612 B | `kernelcache.release.v6x-pandia` |

The kernelcache was pulled straight out of the ZIP with HTTP Range requests, so the
analysis did not wait for the full 26 GB. The container is IM4P; the payload is LZFSE.

| Build | Kernelcache (decoded) | SHA-256 (first 16) |
|---|---|---|
| 27.0.1 | 78,315,520 B | `dec73956a9a443c5` |
| 27.2 (v6x-pandia) | 78,675,968 B | `1aaf47dbc73650e3` |

Both are `MH_FILESET` images with a `__DATA_SPTM` segment, carrying 303 (27.0.1)
and 304 (27.2) fileset entries. One kext is new: `com.apple.driver.ApplePencilDriver`;
none were removed.

27.2 ships three kernelcaches (`v63`, `v64`, `v6x-pandia`); iPhone19,7 uses
`v6x-pandia` (member SHA-256 `0777eb09…`). The numbers and addresses below are
from that member, not from the first kernelcache in the ZIP.

## Reading the diff

Raw text-segment hashes are useless here: the fileset is relinked, so branch
displacements and absolute literal pools move in almost every kext even when the
code is unchanged. The diff therefore keys on:

1. `__TEXT_EXEC` size change (layout-independent),
2. `__cstring` / `__oslogstring` set difference (new checks usually add a message),
3. `llvm-objdump` instruction diff for the kexts that survive both filters.

93 of 303 common kexts changed text size (v6x-pandia). The largest are the ones the advisory
points at:

| Delta | Kext | Advisory component |
|---|---|---|
| +115,472 | `com.apple.driver.ASIOKit` | IOKit / audio |
| +39,624 | `com.apple.driver.AppleH16ANEInterface` | Apple Neural Engine |
| +29,376 | `com.apple.kernel` | Kernel |
| +16,080 | `com.apple.driver.AppleAVE2` | AVEVideoEncoder |
| +9,572 | `com.apple.driver.FairPlayIOKit` | Security |
| +9,316 | `com.apple.driver.AppleDisplayCrossbar` | IOMobileFrameBuffer |
| +8,304 | `com.apple.AGXG19P` | GPU |
| +4,712 | `com.apple.driver.AppleMobileDispH19P-DCP` | IOMobileFrameBuffer |
| +4,480 | `com.apple.driver.RTBuddy` | Kernel / RTKit |
| +4,152 | `com.apple.driver.AppleSARService` | Kernel |

## Fix sites that are confirmed by strings

### CVE-2026-112705 — AppleAVE2 temporal layers

27.2 adds the upper bound that 27.0.1 lacks:

```
number of temporal layers (prop) is out of range %d %d %d
0 <= pInfo->uPropCfg.sHEVC.iNumberOfTemporalLayers
    && pInfo->uPropCfg.sHEVC.iNumberOfTemporalLayers <= 7
0 < pInfo->sSessionCfg.sEnc.sAlgCfg.sGOP.iNumOfTemporalLayer
    && (... <= 7)
AVE_HEVC_CheckVPSExtBounds
HEVC VPS vps_max_layers_minus1 is out of range
HEVC VPS layer_id_in_nuh is out of range
HEVC VPS layer-set total is out of range
```

The property is now clamped to **0…7**. The trigger in the 27.0.1 dossier
(`NumberOfTemporalLayers = 16463`, first frame → AppleAVE2 +0xDA78) is exactly the
value this assertion rejects. A `--sweep` mode was added to both POCs: it sets
0…12 and submits no frame. On macOS 27.0 it accepts 1…12 (and 16463); on 27.2 the
>7 rungs must return an error.

### CVE-2026-113910 — decmpfs chunked zlib

27.2 adds the produced-vs-expected check in
`AppleFSCompression/Common/ChunkCompression.cpp`:

```
%s:%d: chunk %u produced %lld of %lld expected bytes
```

That is the exact under-production condition the leak harness drives. The C POC's
`--loop` / `--keep` collector now sits on a documented fix site.

### CVE-2026-112507 — ipc_port request table

27.2 adds the checks the 27.0.1 code was missing:

```
ipr != ((void*)0)
table != ((void*)0)
ipc_misc.c
```

This is a **NULL-check fix**, not a reclaimable-object fix. It matches the device
result already recorded: `mach_port_request_notification` returns -300
(MIG_TYPE_ERROR) for every type/right combination, 0 of 12,288 registrations armed,
so the request-table path is never entered from an unentitled app.

### Other kernel changes

The core kernel gains 62 meaningful strings (build paths and UUIDs excluded). The
security-relevant ones:

- `VM entry %p lock shared lock overflow` — a new vm_map lock-overflow panic,
  consistent with the COW / vm_map CVEs (112474 / 112576).
- `Page modified after framebank withdraw %p` — page-lifecycle check.
- `size <= sdl->sdl_alen` — sockaddr_dl bounds check in the network stack.
- `speculative_pages_freed` / `_demoted` / `_requeued_inactive` — pageout counters.
- `FilterDropBadDirection`, `nx_netif_filter_pkt_to_mbuf`, `pktap != NULL`,
  `ret == TB_ERROR_SUCCESS` — network filter validation.
- `ipr != NULL`, `table != NULL`, `ipc_misc.c` — the 112507 fix.
- New entitlements: `com.apple.private.verified-jit-mode`,
  `com.apple.private.vfs.unmunged-access-time`, `com.apple.security.cs.debugger`.

These line up with the 15 Kernel entries in the advisory (UAF, OOB read/write, race,
type confusion, COW integrity, kernel-layout disclosure). The advisory does not
assign individual functions, so the mapping above is evidence-based, not a
per-CVE signature.

## PPL / SPTM / MIE

**Correction:** the kernel's `__DATA_SPTM` segment is byte-identical (311,296 B,
same SHA), but SPTM is a separate firmware image and **did** change:

- `Firmware/sptm.t8160`: SPTM-820.0.22 → **SPTM-820.40.24**, 1,261,600 → 1,327,136 B
  (+64 KiB, all in `__LATE_CONST`); `__TEXT_EXEC` same size, different hash.
- New checks: DART `VIOLATION_T8110_DART_UNGANG_GAPF_RACE`, GMMU TLBI
  verification, IOMMU read-refcount validation, UAT Dekker lock timeouts,
  `VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_LATCH`, hibernation handoff page count.
- `txm.iphoneos`: same size, build-path/version only (Image4 374~7022 → 374~8637).
- `exclavecore`: 33,259,754 → 33,489,130 B (+229,376) — separate domain.
- MIE/MTE policy in SPTM is unchanged: the `MTE tag page containing SK tags`
  check is a 210-instruction function in both builds (relocated, same shape), and
  the kernel's MTE strings are identical. The Exclave image changed separately.

The full analysis, function addresses, and candidate bypass directions (DART
GAPF race, hibernation handoff, SK tag-page aliasing, dangling tag storage) are in
[SPTM-MIE-27.2.md](SPTM-MIE-27.2.md). No working SPTM/MIE bypass was produced: the
27.2 changes add checks, and the candidate paths need a reachable primitive that
the diff does not contain.

## Kernel fix-site candidates (27.2, address in the final 24B119 kernelcache)

These are the functions that reference the new 27.2 strings. They are candidate
fix sites for the 15 Kernel CVEs; the advisory does not map a CVE to a function,
so treat the CVE attribution as an inference.

| New string | Function (27.2) | Likely area |
|---|---|---|
| `size <= sdl->sdl_alen` | `0xfffffe000aeee474` (assert at `0xfffffe000aeee74c`) | sockaddr_dl / ifaddr bounds (info leak candidate, cf. 112665) |
| `Failed mbuf validity check` | `0xfffffe000aeaf8ac`, `0xfffffe000aecee70`, `0xfffffe000b0161bc`, `0xfffffe000b0c17a0` | mbuf length vs off+len (OOB read/write candidate) |
| `VM entry %p lock shared lock overflow` | `0xfffffe000b4bad74` | vm_map shared-lock state (COW / 112576 candidate) |
| `Page modified after framebank withdraw %p` | `0xfffffe000ad831b8` | pmap page lifecycle (UAF candidate) |

The `sdl` site is the most user-reachable of the four: it is on the network
interface/address path and the string is an assertion added in 27.2. The mbuf
site is next. Neither has a trigger or a demonstrated R/W effect; they are the
next functions to audit with a device.

## What can be turned into a PoC

| CVE | Primitive | PoC status |
|---|---|---|
| 2026-112705 | fixed-offset constant fill in AppleAVE2 | existing Swift/C POC + new `--sweep`; kernel panic on 27.0.1, property refused on 27.2 |
| 2026-113910 | kernel heap disclosure through decmpfs | existing C collector (`--loop`, `--keep`, pointer classes); read-only |
| 2026-112507 | request-table NULL check / race | existing harness; unreachable from an unentitled app (-300) |
| 2026-112696 | ANE validation, +39 KB | no trigger in the diff; ANE kext strings show resource/scheduler validation, not a user-reachable entry |
| 2026-65385 | IOHIDEvent fixed-offset write | IOHIDFamily grew only 236 B (+ `TCCService`); the advisory's IOKit fix is likely in the userland IOKit.framework (DSC), not this kext |
| other Kernel CVEs | UAF/OOB/race | fix sites visible as strings, but no trigger or reclaim strategy; writing a PoC would be guesswork |

The WebKit, ImageIO, CoreMedia and other userland components live in the dyld shared
cache inside the root filesystem image, which is not part of the ZIP's plain files;
those were not diffed here.

## Reproduce

```bash
python3 tools/ipsw/remote_ipsw.py extract <ipsw-url> kernelcache work/kernel/27.2.im4p
python3 tools/ipsw/ipswlib.py kernel ...            # decode + list
python3 tools/ipsw/extract_kext.py work/kernel/27.2.kernel \
        work/kernel/27.2-entries.json com.apple.driver.AppleAVE2 out.macho
python3 tools/ipsw/disasm_diff.py a.macho b.macho
```

The tools are read-only: no device is touched, and no firmware is modified.
