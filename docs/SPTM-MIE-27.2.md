# SPTM / MIE deep dive — iOS 27.2 (24B119) vs 27.0.1 (24A446)

This is the part that the kernelcache alone cannot answer. SPTM is a separate
firmware image in the IPSW (`Firmware/sptm.t8160.release.im4p`), and it **did**
change in 27.2. The earlier note that "SPTM is unchanged" was based only on the
kernel's `__DATA_SPTM` segment and was wrong: that segment is identical, but the
SPTM monitor itself is not.

## Component inventory

| Component | 27.0.1 | 27.2 | Change |
|---|---|---|---|
| `sptm.t8160` | 1,261,600 B · SPTM-820.0.22 | 1,327,136 B · SPTM-820.40.24 | **+65,536 B** |
| `txm.iphoneos` | 557,088 B · Image4 374~7022 | 557,088 B · Image4 374~8637 | build-only |
| `exclavecore.t8160` | 33,259,754 B | 33,489,130 B | +229,376 B |
| kernel `__DATA_SPTM` | 311,296 B · sha f4bc1e5e… | 311,296 B · sha f4bc1e5e… | **identical** |
| kernel MTE strings | `VM_KERN_MEMORY_MTAG`, taggable pages | same | unchanged |

SPTM segment sizes:

| Segment | 27.0.1 | 27.2 |
|---|---|---|
| `__TEXT_EXEC` | 425,984 | 425,984 |
| `__LATE_CONST` | 524,288 | **589,824** (+65,536) |
| `__TEXT` / `__DATA` / `__BOOTDATA` | 98,304 / 65,536 / 98,304 | same |

The +64 KiB is entirely in `__LATE_CONST`; the executable text kept its size but
its hash changed (`347aa218…` → `064c286f…`), so functions were edited/relocated.

## What 27.2 adds to SPTM

String diff (32 new, 7 removed) is dominated by IOMMU/DART and hibernation
hardening — none of it is named in the 162-CVE advisory:

- `VIOLATION_T8110_DART_UNGANG_GAPF_RACE`
- `%s: %s: iommu_read_refcnt (0x%hhx) > read_refcnt(0x%x) for FTE %p`
- `%s: Failed to verify TLBI`
- `%s: The GMMU TLBI verification register should be 8B-aligned`
- `gmmu-tlbi-verification-reg` / `gmmu-tlbi-verification-bit`
- `%s: UAT Dekker gate acquisition timed out after %llu ns`
- `%s: UAT Dekker lock acquisition timed out after %llu ns`
- `%s: dart %p (%s:%u): relaxed_rw_protections and allow_pte_remap are not supported together`
- `%s: dart %p (%s:%u): Inconsistent unganged clock protection configuration`
- `VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_LATCH`
- `hib_header_copy->handoffPageCount < HIB_HANDOFF_PAGECOUNT_LIMIT`
- `sptm_allow_vm_isa_internal_guests`, `sptm_is_iuou_or_iuos_device`
- `SPTM-820.40.24|2026-10-03:14:50:35`

The TLBI string has five code xrefs in 27.2, at functions starting near
`0xfffffff0270c7aac`, `0xfffffff0270c85f8`, `0xfffffff0270c987c`,
`0xfffffff0270cacf4` and `0xfffffff027109940`.

Function-level alignment makes the change concrete. The first TLBI function
(`0xfffffff0270c7aac`, **369 instructions**) matches a **264-instruction**
function at `0xfffffff0270b7a90` in 27.0.1 (prefix similarity 0.90). The 27.2
version inserts a block that:

1. reads `DAIF` and masks interrupts (`msr DAIFSet, #0x7`, `dsb sy`);
2. reads `CNTVCTSS_EL0` and `CNTFRQ_EL0` and computes a deadline;
3. loads a timeout constant (`0x3d40` = 15680 units) and the TLBI verification
   register address;
4. polls/validates the GMMU TLBI completion, and only then continues.

The 27.0.1 function issues the invalidation and proceeds without that wait. This
is not a relocated instruction; it is an added completion check.

The DART violation names are not referenced by a direct `adr`/`adrp+add` — they
are indexed through a violation table, so their exact raiser is a table lookup.
The name itself is the evidence that 27.2 adds a check for the T8110 DART
"ungang GAPF" race.

## MIE / MTE surface

MIE is not a single binary. The relevant pieces are:

- **SPTM**: manages tag pages and checks `MTE tag page containing SK tags is
  mapped`. The function is at `0xfffffff0270c6320` in 27.0.1 and
  `0xfffffff0270d7028` in 27.2; both are exactly 210 instructions, same prologue
  and same range-check shape (`subs` + `ccmp` against two globals). It was
  relocated, not rewritten.
- **Kernel**: the MTE page allocator (`VM_KERN_MEMORY_MTAG`, taggable pages, MTE
  fill thread) has the same strings in both builds; no new MTE logic appears in
  the 62 new kernel strings.
- **Exclave core**: carries the PMM tag machinery (`pmmtag_l4_decode`,
  `Conclave MTE tag check fault`, shared-memory tags), and grew by 229,376 B.
  That is a separate firmware update; no CVE in the advisory names it.

So the MIE *policy* surface in SPTM and XNU is unchanged in 27.2. The only
MIE-adjacent code that changed is inside Exclave, which is a separate domain.

Related SPTM strings that were already present in 27.0.1 and remain:

- `%s: Dangling tag storage reference from previous mapping attempt`
- `%s: Found SK-owned memory in non-wired memory`
- `%s: dart %p (%s:%u): power down not permitted as SK still using the DART`

The dangling-tag check is a real state machine: a previous tag-storage mapping
attempt can leave a reference that SPTM detects later. It exists in both builds,
so it is not a 27.2 fix; it is an audit target.

### MTE check semantics (27.2, `0xfffffff0270d7028`)

The 210-instruction function is a PA-range gate, not a tag-value check:

```
x19 = page PA
if (x19 - [0xfffffff0270ae218] < ([0xfffffff0270ae220] - [0xfffffff0270ae218])) {
    ... state bit test ...
    if (state bit) panic("%s: MTE tag page containing SK tags is mapped %#lx", x19)
}
```

The comparison is on the physical address. An alias that maps the same physical tag
page at a different virtual address does not move the PA, so it does not avoid the
check. A bypass would need to make SPTM see a different PA for the same tag memory
(a page-table/IOMMU bug), or to corrupt the range globals / state bit — none of
which is present in the 27.2 diff. This is why the MTE line remains a hypothesis,
not a finding.

## Why Titan does not transfer

Titan (iOS 16.1–17.4b3, A14–A17) is not an SPTM logic bug. It uses:

1. AGX coprocessor code execution to overwrite the AGX `power` thread state;
2. the AGX hibernation context to restore a attacker-supplied `TTBR1_EL1` and a
   second ROP stack (microPPL bypass);
3. a self-referencing page-table entry to map and write any physical page,
   defeating PPL/SPTM.

Apple patched the AGX thread-state PAC in 18.1b4 and the TTBR restore in 17.4b4.
The 27.2 SPTM diff is not a return of that bug: it is DART/hibernation hardening
inside the monitor. A 27.2-era bypass would need a new primitive that can either
(a) make SPTM map a page table it does not protect, or (b) corrupt the tag/SK
metadata that SPTM trusts. There is no such primitive in the diff.

## Candidate bypass directions (hypotheses, not PoCs)

These are grounded in the 27.2 changes and the unchanged MIE checks. None is a
working exploit; each needs a reachable primitive that the firmware diff does
not supply.

0. **GMMU TLBI completion race (strongest static lead).** 27.0.1 lacks the
   completion wait that 27.2 adds to the DART invalidation path. A DMA-capable
   device whose translation is invalidated can keep using a stale GMMU entry if
   the invalidation has not completed; the stale entry is a DMA read/write to a
   page that SPTM has already unmapped or repurposed. This is an IOMMU bypass,
   not a page-table permission bypass, but it defeats the same isolation goal.
   Reachability requires a userclient that owns DART mappings and can keep DMA
   in flight across an unmap — the next thing to test on hardware.
1. **DART unganged-GAPF race.** 27.2 adds a violation for a race between
   unganging a DART and a page-table remap. On 27.0.1 the race can leave a stale
   DART translation if a mapping is unganged while a PTE is remapped. A stale
   IOMMU translation is a DMA read/write primitive to memory SPTM considers
   protected. Reachability: a userclient that owns DART mappings (IOGPU, display,
   NVMe, PCIe). This is the closest analogue to a "SPTM bypass", but it is an
   IOMMU bypass, not a page-table permission bypass.
2. **Hibernation handoff page count.** 27.2 adds
   `hib_header_copy->handoffPageCount < HIB_HANDOFF_PAGECOUNT_LIMIT` and the
   NVMe hibernation queue latch violation. On 27.0.1 a corrupted hibernation
   header could make SPTM restore from a handoff page it did not size-check.
   Reachability: modifying the hibernation image or the NVMe queue, not an app.
3. **SK tag-page aliasing.** The SPTM check only rejects a tag page whose
   physical address falls in the `[start,end)` range loaded from two globals. A
   mapping that aliases the same physical tag page at a different PA, or a
   remap that changes the range after the check, would let user-controlled tags
   cover SK memory. That is an MIE bypass: forge the tag for an SK page, then
   read/write it. Reachability: a kernel primitive that maps tag storage with a
   user-influenced PA; not present in the 27.2 diff.
4. **Dangling tag-storage reference.** SPTM already detects a dangling
   reference from a previous mapping attempt. A race between unmap and remap of
   tag storage could leave the stale reference usable; the freed tag page could
   be reallocated as a user tag page. Same MIE impact as (3).

## Verdict

- SPTM **did** change: 820.0.22 → 820.40.24, +64 KiB, DART/TLBI/hibernation
  hardening. The kernel-side `__DATA_SPTM` being identical is not evidence that
  SPTM is unchanged.
- No SPTM/MIE bypass is named in the 27.2 advisory, and no page-table permission
  check was removed or weakened in the diff. The changes add checks.
- MIE policy in SPTM/XNU is unchanged; Exclave changed separately.
- A working bypass was **not** produced. The candidate paths above need a
  reachable primitive (DART userclient, tag-storage mapping, or hibernation
  image control) and a device session; writing one blind would be guesswork.

## Critical finding — the 27.2 TLBI verification is disabled on iPhone19,7

The check is conditional. SPTM's `uat_bootstrap_parse_dt` (27.2,
`0xfffffff0270cbe18`) reads the `/arm-io/sgx` node and looks up
`verify-gmmu-tlbis-at-sync`. The property-missing path is explicit:

```
0xfffffff0270cc184  adrp x8, 0xfffffff0270ae000
0xfffffff0270cc188  ldr  x22, [x8, #0x208]
0xfffffff0270cc18c  strb wzr, [x22, #0x81]     ; verify flag = 0
0xfffffff0270cc190  ... continue parsing
```

So if the property is absent, the verification is **off**, not fatal.

Now the device mapping:

- `BuildManifest.plist` maps **iPhone19,7 → DeviceClass `v64sap`**.
- The 27.2 `DeviceTree.v64sap.im4p` (406,684 B decoded) contains
  `agx-address-space-mgmt-mode`, `tlbi-aperture-offset`, `dart-options` and the
  SAPT node, but **no** `verify-gmmu-tlbis-at-sync`,
  `gmmu-tlbi-verification-reg` or `gmmu-tlbi-verification-bit`.
- The same strings are absent from the 27.2 iBoot, the AGX firmware, and the
  whole kernelcache. They exist only in SPTM itself.

The iPad images the reference report analysed (`j817ap` / `j820ap`) do carry the
property, which is why beta3 looks fixed there. On iPhone19,7 the gate is
missing, so the 27.2 build executes the **beta2 behaviour**: AMXOP25 loop →
`dsb oshnxs` → clear pending count → continue, with the verification block
skipped.

### What this means

- Reachability on the final 27.2 v6x-pandia build is confirmed: the
  `IOGPUFamily` kext still exports `IOGPUDeviceUserClient::s_new_resource`,
  `s_submit_command_buffers`, `s_create_io_command_queue`,
  `s_destroy_io_command_queue`, `s_perform_io`, `s_group_add_resources`,
  `s_group_remove_resources`, `s_create_vniodesc`; the kernel still contains
  `IOUAT doUnmap/queueUnmap/commitUnmaps/prepareFWUnmap`,
  `uat_get_root_table_paddr`, `pmap_iommu_ioctl_internal` and
  `sptm_check_sapt_is_writable`. So the user path from IOGPU to the SPTM UAT
  unmap exists unchanged.
- Method handler addresses in the final v6x kext:
  `IOGPUDeviceUserClient::s_new_resource` = `0xfffffe000a176094`,
  `s_submit_command_buffers` = `0xfffffe000a176424`. Selector recovery is still
  blocked: there is no direct `bl` to either handler and no raw/chained pointer
  in the kext or the kernelcache; the dispatch is indirect and the table is
  relocated at boot. Recovering the selector numbers needs a decompiler
  (Ghidra/IDA/Hopper) or a live kernel view, neither of which is available here.
- On iPhone19,7, the GMMU TLBI completion window is **not closed by 27.2**.
  The UAT unmap → data page freed → GMMU stale translation race remains.
- The fix is a code change plus a per-device DeviceTree gate; the gate is absent
  on the iPhone 19,7 image. This is a fix-gating gap, not a new memory-safety bug.
- This makes the Titan-style end goal (data page → PAPT page → GPU stale write →
  RO-zone writable alias) still applicable on an iPhone running 27.2, assuming
  the rest of the chain is reachable.

Caveat: this is static evidence (parser + DT + BuildManifest + component search).
Runtime confirmation is a 27.2 iPhone boot with the DT dumped and the SPTM verify
flag read; that device was not available here. The 18PM in this lab is 27.0.1,
where the check does not exist at all.

### If the flag is present

If a future iPhone build adds the DT property, the check runs and the window
closes (panic `Failed to verify TLBI` on a still-pending GMMU TLBI). That is the
condition to test in the next firmware.

## Cutter / rz-ghidra decompilation

The open-source decompiler in Cutter 2.5.0 (`rizin` + `rz-ghidra`, no Java) was used
to confirm the two key functions. Raw `__TEXT_EXEC,__text` is loaded as ARM64, and
`retab` is patched to `ret` in a copy so the decompiler does not truncate.

MTE SK tag-page check (`0xfffffff0270d7028`, raw offset `0x23028`):

```c
if ((uint64_t)arg1 < *(uint64_t *)0xffffffffffffa218 ||
    *(uint64_t *)0xffffffffffffa220 <= (uint64_t)arg1) {
    func_0x0004b2ac(arg1);      // outside the SK tag-page PA range: normal path
}
// inside the range: panic "MTE tag page containing SK tags is mapped"
```

TLBI completion path (`0xfffffff0270c7aac`, raw offset `0x13aac`): the decompiler
shows the verification state being read (`uVar15 >> bit & 1`), a countdown
(`uVar14`), and the GMMU invalidation issued through a code pointer inside the
loop; 27.0.1 lacks this block (function 264 vs 369 instructions).

The IOGPU method handlers (`s_new_resource` at raw offset `0x70a4`,
`s_submit_command_buffers` at `0x7434`) are PAC-heavy and the decompiler truncates
at the first `pacibsppc`/`braa`; disassembly is still available, but selector
recovery needs the dispatch table or a live kernel.

## Verification plan — GMMU TLBI completion race

The static delta is real, but exploitability depends on keeping a DART client's
DMA in flight across an unmap. The test is hardware-only; it is written down here
so the next session does not have to rediscover the shape.

Target: a disposable 27.0.1 device (vulnerable) and a 27.2 device (control).

Primitive needed: an IOGPU userclient plus IOSurface/metal command buffers. The
kernel DART and IOGPU kexts are unchanged in 27.2 (IOGPU only gained a
`systemPagingOff()` timeout diagnostic), so the user-reachable map/unmap path is
the same on both builds; the fix lives inside SPTM.

Steps:

1. Allocate a page-aligned IOSurface `S`, fill it with a canary, map it through
   IOGPU, and record its physical pages if the API exposes them.
2. Submit a long-running GPU write into `S` (a compute shader that keeps writing
   a pattern for several milliseconds).
3. While the GPU work is in flight, unmap/free `S` through IOGPU so the DART
   entry is invalidated. On 27.0.1 the invalidation is not completion-checked.
4. Immediately allocate a fresh page `P` (user or kernel object) and fill it with
   a different canary. If the GPU's writes land in `P`, the GMMU entry survived
   the unmap: a stale DMA write primitive.
5. Escalate only after step 4 is observed: reuse `P` as a kernel object with a
   pointer field and use the GPU write to corrupt it.

Success criterion: a write to `P` after `S` was unmapped, reproducible on 27.0.1
and absent on 27.2. A GPU timeout or a single crash is not success; the canary
difference is.

Safety: run with the phone's panic log enabled, one stage at a time, and stop on
the first unexpected kernel panic. The harness must journal the stage before the
unmap (same pattern as Cinder27's GuardJournal).

## Verification plan — MIE tag storage

The SPTM `MTE tag page containing SK tags` check is unchanged, so a bypass here
would be a new bug, not a 27.2 regression. It needs a kernel primitive that maps
tag storage with a caller-influenced physical address (or a dangling tag-storage
reference). The 27.2 diff does not expose such a primitive. The audit order is:

1. Find the kernel callers of the SPTM tag-storage map/unmap operations (the
   kernel MTE allocator, `VM_KERN_MEMORY_MTAG`).
2. Check whether the PA is derived from a user-controlled IOSurface/descriptor.
3. If yes, attempt an alias (map the same PA at a different address) and see
   whether the SPTM range check still rejects it.
4. If the check is bypassed, forge the tag for an SK page and read/write it.

Until step 1 yields a user-influenced PA, this remains a hypothesis.

## Reproduce

```bash
python3 tools/ipsw/remote_ipsw.py extract <url> sptm work/fw/27.2-sptm.im4p
python3 tools/ipsw/ipswlib.py kernel ...          # IM4P/LZFSE decode
python3 tools/string_xref.py work/fw/27.2-sptm.bin "Failed to verify TLBI"
python3 tools/fw_diff.py work/fw/27.0.1-sptm.bin work/fw/27.2-sptm.bin
```
