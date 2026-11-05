# Kernel read/write feasibility — high and critical dossiers

Scope: the kernel-reachable entries rated High or Critical in the Cinder27 dossiers.
Question: can any of them be turned into arbitrary kernel read/write that does not
panic the device?

Short answer: **no, not from the material as it stands.** One entry gives a real
kernel heap leak (read), one gives a bounded read model, one gives a race receipt
on a UAF-shaped bug. The write entries either write a constant at a fixed offset or
never reach the kernel interface at all. This document records what each primitive
actually provides, what an arbitrary-R/W chain still needs, and what was added to
the POCs.

## Guardrails

- The host Mac was panicked once by the CVE-2026-112705 encode path. That path is
  never executed on the host again; its C twin refuses to submit a frame without
  `--force-host`.
- No blind kernel writes are attempted from any POC. A wrong guess in the kernel
  heap is a panic, not a data point.
- The simulator has no AppleAVE2 hardware encoder and no ANE kernel interface, so
  the write primitives cannot be exercised there either. Their app modules are
  split into a safe probe and a deliberate fire module.

## Primitive inventory

| CVE | Entry | Primitive as shipped | Read | Write | Kernel R/W verdict |
|---|---|---|---|---|---|
| 2026-112705 | AppleAVE2 `NumberOfTemporalLayers` | fixed-offset constant fill in the driver | no | fixed value, fixed offset | **DoS only.** No address control, no value control. The original write-up says explicitly: no arbitrary read/write capability. |
| 2026-65385 | IOKit `IOHIDEventAppendEvent` | fixed-offset write into a short heap allocation | no | bounded, offset fixed | **Not reachable as a primitive here.** The POC stops at symbol resolution; the vendor-defined constructor is missing on the host. No leak, no reclaim, no gadget. |
| 2026-112696 | AppleH16ANEInterface | kernel interface reachability | no | none observed | **No primitive.** The ANE kernel symbols are absent for a third-party process; the module is an honest negative. |
| 2026-112507 | XNU `ipc_port.c` request-table race | stale index → UAF-shaped race | no | none direct | **Not reachable from the app.** Device receipt: 12,288 notification registrations, 0 armed, 12,288 refused with -300 (MIG_TYPE_ERROR). No request-table entry exists, so there is no stale index to consume. |
| 2026-113910 | decmpfs chunked zlib | under-produced chunks expose uninitialised kernel heap through a file read | **yes** (bounded) | no | **Leak only.** Useful as a KASLR step; cannot write. |
| 2026-112554 | GPT partition-name scan | 72-B scan over a 28-B field | **yes** (bounded, model) | no | **Leak only.** The C twin models the width; the real read runs in the storage kext. |

## What arbitrary kernel R/W actually requires

Every iOS kernel R/W chain needs five independent capabilities. A bug that supplies
one of them is a chain step, not a chain.

1. **KASLR defeat** — a kernel text or heap pointer with a known relationship to the
   unslid base. 113910 and 112554 can supply candidates; neither guarantees a text
   pointer, and a heap pointer alone does not give the slide.
2. **Heap grooming** — deterministic placement of a victim object next to the
   corrupted allocation, in the same zone, at the same size class.
3. **Controlled reclaim / corruption** — for a UAF: free the object, reallocate the
   slot with attacker-influenced contents, and keep a stale reference alive. For an
   OOB write: a value and an offset that land on a field worth corrupting.
4. **A read/write gadget** — an object whose corrupted field yields a load or store
   of an attacker-chosen address (e.g. a length+pointer pair, a page-table entry, a
   thread's `pcb` pointer).
5. **PAC / PPL bypass** — kernel code pointers are PAC-signed; page tables are
   protected by PPL on modern devices. A data-only path can sometimes avoid both,
   but it still needs 1–4.

None of the six entries supplies 2–5. 112507 is the only one that could plausibly
reach step 3, and reaching it requires a device, kernel symbols, and a reclaim
strategy that the repository does not have.

## Per-entry notes

### CVE-2026-112705 — fixed constant, fixed offset

The driver indexes a layer table with the declared count and writes a constant at a
fixed offset past it. There is no attacker-chosen value and no attacker-chosen
address. The only observable is a kernel data abort. Calling this "R/W" would
require a second bug that turns the corrupted field into a pointer; nothing in the
dossier provides one. The correct classification is a reliable kernel DoS.

### CVE-2026-112507 — reachability closed on the device (2026-10-31)

The staged lifecycle harness was run on the target device (iPhone19,7, iOS 27.0.1)
with an ad-hoc signed build, and the race module was re-run with an `armed` counter:

- `mach_port_request_notification(DEAD_NAME)` → **-300** (MIG_TYPE_ERROR), `prev = 0`.
- Send to the dead name → `MACH_SEND_INVALID_DEST`; receive → `MACH_RCV_TIMED_OUT`.
- `kern.ipc`: 12,288 registration attempts, **0 armed, 12,288 refused**.
- On macOS 27 the same call was swept over 13 combinations of notification type
  (SEND_POSSIBLE / PORT_DESTROYED / NO_SENDERS / DEAD_NAME) and right layout
  (receive-only, send+receive, send-only; notify port receive or send). Every
  combination returned -300.

The kernel refuses to arm a request-table entry for this process. With no entry,
the stale-index consumers in `ipc_port.c` have nothing to consume: the race cannot
be driven from an unentitled third-party app, and the "survived" line from the old
harness was measuring port churn, not the bug. The published fix shape (NULL checks
on `ipr` / `table`) is consistent with a denial or null-dereference path, not with a
reclaimable object.

**27.2 firmware confirmation (2026-10-31):** the 27.2 kernel adds `ipr != NULL` /
`table != NULL` in `ipc_misc.c` — a NULL-check fix, not a reclaimable-object fix.
The 27.0.1/27.2 kernelcache diff is in [IOS27.2-KERNEL-DIFF.md](IOS27.2-KERNEL-DIFF.md).

**Verdict: closed for this app.** The remaining hypothetical is a platform process
that is allowed to register notifications; that is outside Cinder27's reach.

### CVE-2026-112507 — the race itself

The ring allocates receive rights, arms two notification kinds per port, tears down
half the ring, then sends to the survivors. The request-table index consumers are
the target of the race. A weaponised version would need:

- a win condition that is observable without panicking (a receipt, not a crash);
- a same-zone reclaim object with controllable contents (Mach ports themselves are
  one candidate, but the request-table entry's layout is not attacker-shaped);
- a stale consumer that dereferences the reclaimed slot after the free;
- a leak to place the reclaim object and to find the kernel base.

The POC records `-300` and `invalid destination` receipts and reports that the
interleaving survived. That is the honest limit of a userspace race harness: it can
show the window exists, not that the window is controllable.

### CVE-2026-113910 — the leak that was worth improving

This is the only entry where more code produces more signal. The C twin now:

- sweeps 8 chunk configurations (including `produce=0`, which promises 64 KiB per
  chunk and writes none of it);
- repeats the sweep `--loop N` times;
- classifies every 8-byte-aligned value as kernel-text (`0xfffffff0…`), kernel-data
  (`0xffffffe0…`), kernel-other, or user;
- writes the raw readback to `--keep out.bin` for offline analysis;
- never dereferences a candidate.

On the macOS host decmpfs does not engage for a file that already has data (the
documented oracle), so the run reports zero candidates and 3.2 MB of plain 0x41
readback. On an iOS device where the chunked xattr is honoured, the same sweep is
the KASLR step. It still does not write.

### CVE-2026-112554 — a read-width model, not a kernel reader

The C twin builds the overlong-name GPT and walks the name field the way 27.0 does.
It proves the scan width (72 B against a 28-B field) but the bytes come from the
image, not from the kernel heap. Treat it as a seed/oracle model. The real read
would have to run through the storage kext on a mounted image; that is not attempted
on the host.

## What was deliberately not done

- No attempt to fire 112705 or 65385 on the host: both can panic the kernel, and a
  panic is not evidence of control.
- No blind write into a guessed kernel address: with KASLR and PAC in play, a wrong
  guess is indistinguishable from a bug that does not work.
- No claim that 112507 is exploitable: a race receipt is not a UAF primitive until
  the free/reclaim/stale-dereference sequence is observed.

## Bottom line

Arbitrary kernel R/W without a panic is **not achievable from these six entries as
shipped**, and the one entry that had a theoretical UAF path (112507) is now closed
by device evidence: notification registration is refused, so the request table is
never armed. The maximum safe capability the lab demonstrates is:

- a repeatable kernel heap **leak** with pointer classification (113910);
- a read-width model for the GPT scan (112554);
- a race-window harness with receipts (112507);
- honest negatives for the write entries that never reach a controllable primitive.

The next real step is not more code in this repository; it is a device session with
kernel symbols, a reclaim strategy for 112507, and a stop condition for every write.
