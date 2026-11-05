import Foundation

/// Bilingual text for every primitive. Chinese is the source and lives next to the module
/// definition; English lives here. A module whose id is missing from this table falls back
/// to the Chinese text rather than showing a key, so a new primitive is never blank.
enum ModuleText {

    enum Field {
        case title, summary, notes
    }

    static func resolve(_ id: String, _ field: Field, zh: String) -> String {
        guard Lang.resolved == .en else { return zh.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard let row = en[id] else { return zh.trimmingCharacters(in: .whitespacesAndNewlines) }
        switch field {
        case .title: return row.title
        case .summary: return row.summary
        case .notes: return row.notes
        }
    }

    struct Row {
        let title: String
        let summary: String
        let notes: String
    }

    static let en: [String: Row] = [

        // MARK: CoreGraphics

        "cg.shading": Row(
            title: "Type-5 shading stack overflow (value-controlled OOB write)",
            summary: """
            A /ShadingType 5 dictionary whose /Function declares a /Range dimension that does not match the component count of its /ColorSpace. At draw time _cg_shading_type5_draw builds one 72-byte mesh record per triangle vertex — the colour area sits at record +0x20 with capacity nc×8 bytes — then calls CGFunctionEvaluate, which bounds its write by its own [func+0x30] field (the /Range dimension) and writes that many doubles into the colour area. No comparison exists between the write length and the destination capacity. The mesh array is alloca'd on the stack by CGTriangleMeshCreate, so the last record's write walks past the record tail, the auxiliary arrays, the row buffers and the saved registers in order.
            """,
            notes: """
            With R=136, nc=1 and /C0=/C1=1.0 every written double has the bit pattern 0x3FF0000000000000. The overflow also overwrites the two spill slots holding the triangle count and the mesh pointer; the loop-exit comparison reads the overwritten count and keeps going, then dereferences the overwritten pointer. The fault address is therefore the PDF-chosen double bit pattern plus a structural offset — measured on device as 0x3ff000000000001c, where 0x1c = idx×16 + 0xc. iOS 27.2 rejects the dictionary at parse time with CG-SEC-187882049; the draw code is byte-identical on both builds, so this is a gate-only fix.
            """),

        "cg.shading.sweep": Row(
            title: "Overflow length sweep (finding the absorption threshold)",
            summary: """
            A short overflow is absorbed by the adjacent VLA without faulting — the write has to be long enough to reach live state. This pass steps R from 4 to 256, recording at each value whether rendering still completes, and thereby maps the real boundary of the stack layout on this build. That threshold sets the length budget for every subsequent payload.
            """,
            notes: """
            Executed in ascending order. Small values finish first and the process terminates at the first fatal one, so the write-ahead journal retains the last successful value and a single run locates the boundary.
            """),

        "cg.cmap": Row(
            title: "CMap /UseCMap recursion out-of-bounds write (negative-result probe)",
            summary: """
            _cmap_convert passes the outer codespace length (up to 255) into an output slot sized for a single result (2-byte code / 8-byte len) when it recurses. iOS 27.2 adds a min(L,4) clamp and re-lays out the output slots.
            """,
            notes: """
            In the source analysis the embedded-CMap vehicle was refuted by three independent reachability blockers. The value of this module is that it records the negative result too: a crash here would mean the vehicle has been reopened and the conclusion has to be revised.
            """),

        // MARK: ImageIO

        "iio.tiff.planar": Row(
            title: "TIFF planar scatter out-of-bounds write",
            summary: """
            With PlanarConfiguration=2 and SamplesPerPixel greater than the channel count implied by Photometric, the scatter pointer offset is computed with a 32-bit multiply and the result is never compared against the destination row capacity. iOS 27.2 switches to a 64-bit umull and compares required bytes against capacity.
            """,
            notes: """
            The error string that 27.2 adds is absent on 24A435: "*** ERROR: decodeStripPlanar destination row is %u bytes, the scatter needs %llu".
            """),

        "iio.tiff.trunc": Row(
            title: "TIFF truncated strip → uninitialised heap into pixels",
            summary: """
            The return value of TIFFReadEncodedStrip is never checked. On read failure the uninitialised malloc'd strip buffer is scattered into the output image, so the decoded pixels are whatever was left on the process heap.
            """,
            notes: """
            Detection: decode the same file three times and compare output fingerprints. If the strip region differs each run, the buffer is uninitialised heap. iOS 27.2 zero-fills it and reports "strip %d is zero-filled".
            """),

        "iio.apng.fctl": Row(
            title: "APNG fcTL truncation → uninitialised frame geometry on the stack",
            summary: """
            Thirty-four bytes are read at the fcTL offset and the return value is not checked. When the file is truncated mid-fcTL only the front of that 34-byte stack buffer is written; the remainder is parsed as frame width, height, offsets and delay.
            """,
            notes: """
            iOS 27.2 reads 26 bytes, checks cmp x0,#0x1a, and reports "*** truncated 'fcTL' chunk at offset %ld".
            """),

        "iio.jpeg.marker": Row(
            title: "JPEG marker length out of bounds",
            summary: """
            When a marker declares a length far beyond the bytes actually present, 27.0 logs one "*** WARNING: check markerLength" and keeps parsing, reading out of bounds. 27.2 aborts the parse.
            """,
            notes: """
            Declared length 0xFFEE against 28 bytes of real payload.
            """),

        "iio.jpeg.comment": Row(
            title: "EXIF UserComment short read → metadata disclosure",
            summary: """
            The return value of getBytesAtOffset is never checked. When an entry's value offset falls outside the marker the read comes up short, the tail of the malloc'd buffer stays uninitialised, and that buffer is then handed back to the caller as the UserComment metadata value — a direct read of the process heap.
            """,
            notes: """
            count declares 0x400 with the value offset at +0x4000. The result line prints how many bytes were actually obtained and the first 24 of them.
            """),

        "iio.jpeg.gps": Row(
            title: "GPS IFD value offset out of bounds",
            summary: """
            The GPS-IFD walk uses raw pointer dereferences plus one unchecked read32. When an entry's value offset points outside the GPS block the read goes straight out of bounds. iOS 27.2 rewrites every access through checkCapacity / checkInitializedLength / pointerToOffset / read32Unchecked and throws OutOfBounds on violation.
            """,
            notes: """
            The RATIONAL offset for GPSAltitude points at +0x10000.
            """),

        "iio.dds.bc7": Row(
            title: "BC7 texture mip truncation",
            summary: """
            A truncated mip level produces only a WARNING on 27.0 and block decoding continues, so the block decoder reads past the data. iOS 27.2 turns "zero complete mips" into a hard error and adds 64-bit mip size arithmetic plus dimension and data-size gates.
            """,
            notes: """
            A 512×512 BC7 surface needs 65536 bytes; 64 are supplied.
            """),

        "iio.ktx2": Row(
            title: "KTX2 dimension and level size arithmetic",
            summary: """
            KTX/KTX2 level byte counts and block counts lack 64-bit umull/umulh protection, and the existing check is keyed on the wrong quantity (channels rather than source bpp). iOS 27.2 adds "image dimensions overflow" and "expected %llu bytes" gates.
            """,
            notes: """
            Dimensions 0xFFFF×0xFFFF with the level index declaring 64 bytes.
            """),

        // MARK: libarchive

        "arc.iso": Row(
            title: "ISO9660 Joliet pathname heap overflow",
            summary: """
            After recursively appending the parent path, build_pathname_utf16be unconditionally writes a 2-byte UTF-16BE '/' without re-checking the running length against the 1024 limit. When a directory chain sums to exactly 1024 bytes the deepest unwind writes at p[1024] and p[1025], two bytes past a malloc(1024) buffer, and 0x002F overwrites the adjacent heap chunk header.
            """,
            notes: """
            The chain length 4×206 + 192 + 4×2 = 1024 aligns exactly with the limit. Reproduced on the macOS fork of the same version with bsdtar; a hardware breakpoint hit the write instruction immediately before "Pathname is too long".
            """),

        "arc.iso.stress": Row(
            title: "Joliet path length loop",
            summary: """
            The same ISO is traversed repeatedly so the 2-byte out-of-bounds write happens many times and interleaves with other allocations. A single two-byte write is usually absorbed by malloc metadata; repetition is what pushes the damage into a visible position.
            """,
            notes: """
            32 rounds, each with a fresh archive handle.
            """),

        "arc.cab": Row(
            title: "CAB LZX match against uninitialised history",
            summary: """
            LZX decoding computes copy_pos = (w_pos − copy_pos) & w_mask and drops straight into the copy loop. While the window has not yet been written, copy_pos points into uninitialised memory and the copied bytes are residual heap. iOS 27.2 adds copy_pos == 0 || copy_pos > w_filled → ARCHIVE_FAILED.
            """,
            notes: """
            The second site under the same CVE (the first is the Joliet pathname). The seed is a grammar probe: a structurally complete CAB container plus an LZX block that opens with a match, using libarchive's own return code as the progress receipt.
            """),

        "arc.rr": Row(
            title: "RockRidge relocation cycle (unfixed sibling)",
            summary: """
            Upstream fixed the infinite loop caused by a RockRidge relocation cycle in September 2026 (d14de384fcc6) and Apple did not take the commit. The defect is present on both 27.0 and 27.2, making it the only candidate in this project that also holds on current systems.
            """,
            notes: """
            Builds a CL entry pointing at its own directory using the same structure as the Joliet seed. If the path is live it hangs, so the run is timed against a threshold.
            """),

        // MARK: CoreMedia

        "cm.rpu": Row(
            title: "Dolby Vision RPU extension metadata block array overrun",
            summary: """
            Three fixed-capacity arrays (A: 4×28 B, B: 8×14 B, C: 5×36 B) have no count bound before writing. The 27.0 cmp + b.hi only skips the count increment; the write still executes indexed by the unchecked count. Array A's overrun crosses the end of the 0x73b4-byte struct and lands in the caller's saved-register area — CMGetDMVersionLevelFromRPU places that struct on its own stack frame.
            """,
            notes: """
            This is the only CoreMedia line the advisory explicitly labels "arbitrary code execution". The header grammar was reconstructed in the source research only as far as the entry checks (magic / rpu_type / rpu_format, verified live on the macOS twin), so this uses a parameterised grammar probe and treats the parser's own error as the progress receipt.
            """),

        "cm.rpu.sweep": Row(
            title: "RPU block count and block type sweep",
            summary: """
            Block-ids 1/2/6 are aimed at the three arrays (capacities 4/8/5) in turn, each from one element over capacity up to eight over, recording where the parser starts refusing or terminates.
            """,
            notes: """
            Array A is the only one that escapes the struct into saved registers; B and C stay intra-struct and corrupt neighbouring fields.
            """),

        // MARK: XNU

        "kern.ipc": Row(
            title: "ipc_port request table index race",
            summary: """
            iOS 27.2 adds cmp/b.hi and NULL traps to every function that consumes a per-space port request table index (ipc_port.c:21/24/34/38/40/41). On 27.0 the free path computes the bounds and discards the result, still performing the read-modify-write through the unchecked base; the mark path has no bounds computation at all. The index comes from the space's saved request-table slot, so the defect shape is a stale index under concurrency between table growth or teardown and notification registration or message send.
            """,
            notes: """
            The entry points on this path were believed to be ungated: mach_msg and port notification registration. On the actual target (iOS 27.0.1, iPhone 19,7) and on macOS 27, all 13 combinations of notification type and right layout return -300 (MIG_TYPE_ERROR): the kernel refuses to arm a request-table entry for a third-party process. With no entry, there is no stale index to consume — this module is now a reachability negative, not race evidence. When armed is 0, no "survived" line is a 112507 conclusion.
            """),

        "kern.decmpfs": Row(
            title: "decmpfs chunked decompression under-produce → kernel heap disclosure",
            summary: """
            When chunked zlib decompression produces fewer bytes than expected, 27.0 does not compare produced against expected, so the tail of the kernel page buffer is left unwritten; read() then hands the whole buffer back to the app, which receives stale heap content. iOS 27.2 adds that comparison.
            """,
            notes: """
            One of the few kernel paths in this set that needs no entitlement at all: the app writes a file carrying a com.apple.decmpfs extended attribute inside its own container and reads back what the kernel decompressed. Scanning in 8-byte windows, any value inside the kernel address range (≥ 0xFFFFFFE000000000) is a candidate pointer.
            """),

        "kern.baseline": Row(
            title: "Mach namespace baseline",
            summary: """
            Reads the bootstrap port and the process's own port namespace to establish the starting point before any race: can ports be listed, and how many names are available.
            """,
            notes: """
            Every race result has to be read against this baseline.
            """),

        // MARK: Audio

        "aud.lc3": Row(
            title: "LC3 decoder input buffer overflow",
            summary: """
            memcpy uses mDataByteSize as its length and never consults the (begin, end) capacity of the input vector. iOS 27.2 adds a capacity < size rejection. LC3 is the Bluetooth LE Audio codec and its instantiation is gated by com.apple.coreaudio.allow-lc3-codec, so the crash lands in the system audio process — matching the advisory's "system termination".
            """,
            notes: """
            The module first checks whether the process holds that entitlement, then tries to construct an LC3 AudioConverter to see which layer refuses. Without the entitlement it always fails, but where it fails is itself informative.
            """),

        "aud.hoa": Row(
            title: "HOA spatial audio coefficient out-of-bounds read",
            summary: """
            mNumHOAcoeffs is deserialised from the file's hoa::CodecConfig. The existing check only rejects values above 122, while anything from 37 to 121 indexes an array of length 37. iOS 27.2 changes the comparison threshold to 0x25.
            """,
            notes: """
            The coefficient ceiling comes from kMaxNumSCs_DynSelSCs4EachSB. Actually driving this needs an MPEG-H / immersive audio file; from the app side only the decoder's reachability can be probed.
            """),

        "aud.haptic": Row(
            title: "AVHaptic custom audio event format validation",
            summary: """
            On 27.0 createCustomAudioEvent neither validates the ASBD nor compares frames×bytesPerFrame against the actual waveform byte count. iOS 27.2 adds both checks. The XPC server side of this interface lives in the CoreHaptics server process.
            """,
            notes: """
            Driven through the audioCustom event on CHHapticEngine, which is the closest public path to the server-side input.
            """),

        "aud.immersive": Row(
            title: "Immersive renderer data deserialisation capacity gap",
            summary: """
            The count and dataByteSize taken off the wire are compared only against "how much is left on the wire", never against "how much the destination buffer holds", producing a linear heap overflow inside the audio server process. iOS 27.2 adds ReadImmersiveRendererDataV1/V2, folds destination capacity into the check, and adds a version 1..3 validity gate.
            """,
            notes: """
            No seed file is needed — the payload is the wire format itself. But the entry is on the audio service's XPC side, so from the app only the codec and immersive renderer reachability can be probed.
            """),

        "aud.drc": Row(
            title: "MPEG-D DRC downmix matrix coefficient validation",
            summary: """
            On 27.0 selectDownmixMatrix has only zero and equality checks; the matrix dimensions come straight from DRC metadata and are never compared against the coefficient array's real length. iOS 27.2 adds three gates — nChannels ≤ 8, ordered dimensions, coefficient count == rows×cols — plus count checks in getSignalPeakLevel and Process.
            """,
            notes: """
            Needs an audio file carrying MPEG-D DRC metadata. From the app side this probes whether AudioCodecs exports those symbols.
            """),

        // MARK: Video

        "vid.avc": Row(
            title: "AVC slice count cap missing",
            summary: """
            The fix carrier for all three CVEs in this group is the in-process AVD.videodecoder plugin, not a kext: 112416 is the slice count cap ("too many slices!"), 112415 is MVHEVC layer-id validation, and 112454 replaces the histogram IOSurface pointer with a random cookie.
            """,
            notes: """
            The NAL-verified single-variable control is 32 slices → 900 slices. This module builds the 900-slice structure and hands it to CMVideoFormatDescription / VTDecompressionSession, judging by the plugin's own error code.
            """),

        "vid.hevc": Row(
            title: "MVHEVC layer id out of range",
            summary: """
            Multilayer HEVC layer ids are not range-checked on 27.0, so an out-of-range value goes straight into the plugin's layer table index. iOS 27.2 adds layer id validation.
            """,
            notes: """
            Layer id 0x3F, outside the valid range.
            """),

        // MARK: Fonts / Model I/O

        "font.cff": Row(
            title: "CFF Type2 charstring operand stack overflow",
            summary: """
            The Type2 charstring interpreter's operand stack is a fixed 48-entry array. On 27.0 only the pop path checks the count; the push path does not. iOS 27.2 adds Push/Pop stack guards, widens the scan scratch area's 32-bit multiply to 64-bit, and fixes a sign-extended pointer.
            """,
            notes: """
            The seed is a bare CFF: a single charstring pushing 300 operands then endchar. The interpreter only runs when a glyph is actually drawn.
            """),

        "font.gdef": Row(
            title: "GDEFLigatureCaret offset-chain out-of-bounds read",
            summary: """
            GDEF LigCaretList → LigGlyph → CaretValue offsets are followed directly on 27.0: the caret offset is read as a big-endian u16 and added to the LigGlyph base with neither an end-check nor a sign-check. The CaretValue offset is file-controlled, so pointing it outside the table walks out of the GDEF and the i16 coordinate read there is handed back to the caller as-is. iOS 27.2 clamps the offset against the GDEF table slice.
            """,
            notes: """
            The seed is a structurally complete TrueType whose LigCaretList covers glyph 1 with a CaretValue offset of 0x7F00 — about 32 KB past the font data. Driven through the public API CTFontGetLigatureCaretPositions: when the chain is followed a non-zero caret count comes back with heap-residue coordinates; when clamped the call returns 0. Also recorded: GDEF's other consumer, AttachList/AttachPoint, has the same offset-chasing shape and was not touched in this fix window — a negative result, kept on file.
            """),

        "mdl.usda": Row(
            title: "USDA declaration nesting depth",
            summary: """
            The fix carrier for Model I/O is libusd_ms 24.1.30 → 24.1.32: 64-bit checked image allocation, Ptex log2 and page guards, a USDA declaration nesting cap, and SdfZipFile size checks. ModelIO.dylib itself carries none of the fix.
            """,
            notes: """
            2000 nested def Xform declarations. iOS 27.2 refuses at the nesting cap; 27.0 recurses.
            """),

        // MARK: kext / IOKit

        "probe.hid": Row(
            title: "IOHIDFamily preparsed data table index",
            summary: """
            A signed int32 index from the record is scaled by 0x14 straight into the caps table base with only a 32-bit multiply-overflow trap and no comparison against the count. Negative indices read below the table, over-range indices read adjacent kernel heap, and the u32 that comes back enters element/event data — a kernel memory disclosure. iOS 27.2 adds cmp idx,count, a NULL guard and 64-bit index arithmetic.
            """,
            notes: """
            The entry is a kernel-side serialised "hid " preparsed container. Whether the app side can push such data in is precisely the question this step answers.
            """),

        "probe.ane": Row(
            title: "ANE kernel interface reachability",
            summary: """
            An unchecked program symbolIndex indexes kernel tables and is written back — matching the advisory's "write kernel memory" shape. This module only probes whether the app can reach the ANE user-space entry points.
            """,
            notes: """
            10.19.6 → 10.102.4, one of the largest single kext deltas in the whole diff.
            """),

        "probe.privset": Row(
            title: "This process's privilege surface",
            summary: """
            The final privilege ceiling of this whole chain depends on what the process already holds. The csops flags, the entitlements, and the set of paths the sandbox permits together define the furthest point a modification tool can reach.
            """,
            notes: """
            Every directory in the path matrix that reads "writable" is the tool's real working range.
            """),

        "kext.gpt": Row(
            title: "GPT partition name scan 72-byte kernel heap out-of-bounds read",
            summary: """
            The partition name scan's bound constant tightens from 0x48 to 0x24. 0x48 is 72 bytes, while the name field inside a GPT entry is only 36 UTF-16 units, so the 27.0 scan runs past the entry tail and into adjacent kernel heap.
            """,
            notes: """
            The app cannot attach a disk image, so this module does two things: build the image that would make 27.0 overrun, and parse it in user space to show the name field really is truncated inside the entry — the overrun itself happens kernel-side.
            """),

        "kext.iohid": Row(
            title: "IOKit event short-heap fixed-offset write",
            summary: """
            This defect's carrier is user-space IOKit.framework rather than a kext: IOHIDEventAppendEvent performs an OR write at a fixed offset on a short heap event. iOS 27.2 fixes it inside the framework; the kernel's __DATA_CONST assert table has no related record.
            """,
            notes: """
            Probes whether user-space IOKit exports the event construction entry points.
            """),

        // MARK: app and system processes

        "sb.stash": Row(
            title: "SpringBoard stashed layout name validation",
            summary: """
            iOS 27.2 adds +[SBHomeScreenService _validationErrorForStashedLayoutName:]: reject empty, cap length at 64, apply a character-set allowlist, on the stash/restore XPC interface. The 27.0 interface has no such layer.
            """,
            notes: """
            From the app only reachability of the SpringBoard service and presence of the class in-process can be observed. The real entry is XPC and requires crossing the sandbox.
            """),

        "cal.unzip": Row(
            title: "Calendar attachment extraction containment",
            summary: """
            iOS 27.2 replaces _UnzipArchive (288 B, no limits at all) with _UnzipArchiveWithLimits (2040 B) and adds _CalUnzipEntryDestinationPath / _CalUnzipParentIsContained / _CalUnzipTrackTopLevelPath plus isSymbolicLinkAtURL. The ICS parser itself is untouched — the whole fix sits in the attachment archive extraction containment layer.
            """,
            notes: """
            From the app one can verify whether CalendarFoundation's classes and methods are visible, and whether libarchive path traversal is contained in this process (test with an archive using a ../ name).
            """),

        // MARK: cross-sandbox

        "cm.fdleak": Row(
            title: "CoreMedia bytestream XPC cross-sandbox file descriptor acquisition",
            summary: """
            The launchd service com.apple.coremedia.mediaplaybackd.bytestream.xpc is reachable from any sandboxed third-party app, checks no entitlement and raises no permission prompt. Its FigXPC memory-origin handshake (.rp1 → .rp2 → .org) returns status 0 for an unprivileged client; the subsequent 'Curl' create message carries a client-chosen absolute file:// path in CreationURL, and the daemon opens that path with its own credentials without checking either that it lies inside the requesting app's container or that the requester can read it. The reply's ByteStreamDetails dictionary carries a live FileDescriptor. The app dups it and preads — descriptor-level I/O is not subject to the client sandbox's path checks, so the full contents of a file the app's own open() returns EPERM for land in the app container.
            """,
            notes: """
            The same primitive carries three capabilities: 'Curl' against a protected directory returns a directory descriptor that fdopendir/readdir can enumerate; a real but forbidden path returns -12203 and a nonexistent one -17913, forming an existence oracle. iOS 27.0 sealed the read / fdsc / getL auxiliary opcodes (-16158) but left the primary fd-vending path inside the Curl create reply intact — verified end to end on both 27.0 and 27.0.1. The readable domain was mapped across 27 targets in both directions: only /private/var/mobile/Media/iTunes_Control/iTunes/ opens; Photos, Messages, Contacts, the TCC database, keychain, Safari, Health, Wallet and other app containers all return -12203. The write path is denied on both versions (-12878), so the primitive is read / enumerate / oracle, never write.
            """),

        "cm.fdleak.boundary": Row(
            title: "Cross-sandbox readable domain boundary mapping",
            summary: """
            Fifteen high-value targets are each given a 'Curl' probe and the daemon's server-side error code is recorded, fixing the primitive's actual readable domain. Three outcomes are distinguished: opens, exists but denied (-12203), does not exist (-17913). The value of this pass is that it leaves the negative results on record — a target that was refused and a target that was never tested are entirely different conclusions.
            """,
            notes: """
            The source research probed 27 targets across 26.5 and 27.0 with a consistent result: only the iTunes media library directory opens. Photos, Messages, Contacts, TCC, keychain, Safari, Health, Wallet, other app containers and shared App Groups were all refused. This module reproduces that mapping so the boundary is measured on this device rather than cited.
            """),

        "sbx.toctou": Row(
            title: "sandbox_extension symlink TOCTOU out-of-bounds read",
            summary: """
            sandbox_extension_issue_file resolves a symlink at issue time but does not enforce SANDBOX_EXTENSION_NOFOLLOW. The token it returns is therefore bound to the target resolved at issue time, and the kernel does not re-verify that the path used at consume time is the path the token was issued for. The sequence: create symlink L inside the sandbox pointing at in-sandbox file S; issue an extension for L (the kernel records S); repoint L at out-of-sandbox target T; consume the token and read through L. The kernel permits S's class while the path actually opened is T's.
            """,
            notes: """
            The sequence is deterministic and needs no race window — the link swap happens between two syscalls the app itself controls, not concurrently with the kernel. Apple's position is that an app cannot issue extensions for paths it does not own; the premise is true and irrelevant, because the extension is issued for a path the app does own and that path is then made to denote something else. Apple does not treat this as a security issue, so there is no CVE and none is invented here. The reliable targets are several files under /etc — readable at the vnode level and denied to the app only by the sandbox profile, which is exactly the gap this crosses.
            """),

        // MARK: toolchain self-tests

        "tool.ipa": Row(
            title: "IPA surgery self-test (rename / inject / prepare for re-sign)",
            summary: """
            Builds a minimal IPA on the spot (Info.plist plus a real Mach-O) and runs the full modification flow: unpack → change CFBundleIdentifier → inject LC_LOAD_DYLIB → remove LC_CODE_SIGNATURE → repack with the project's own ZIP writer. The output lands in Documents/Cinder27/IPA and can be signed directly.
            """,
            notes: """
            This is not a vulnerability, it is proof of the toolchain. It passing means the IPA panel works on your device, not merely on the build machine.
            """),

        "tool.zip": Row(
            title: "ZIP writer round-trip self-test",
            summary: """
            Builds an archive of random content with the project's own ZIP writer, unpacks it with libarchive, and compares byte for byte. This is what proves repacking does not quietly corrupt files — the one failure a modification tool must never have.
            """,
            notes: """
            64 files of 4 KB random content each, comparing CRC and length.
            """),

        "tool.macho": Row(
            title: "Mach-O parser self-test",
            summary: """
            Runs header parsing over several real binaries on the system volume: architecture, type, platform, minimum OS, SDK, encryption state, linked libraries, rpaths. Encryption state is the most informative field in the whole set — system frameworks have cryptid 0, third-party app binaries do not.
            """,
            notes: """
            Both the project's own parser and MachOInspector run, and the two results should agree.
            """),

        "tool.hex": Row(
            title: "Hex search and replace self-test",
            summary: """
            Plants known patterns in a random buffer, then searches, replaces and re-searches using both hex and text notation, confirming the hit counts and offsets.
            """,
            notes: """
            This guards the place a modification tool is least allowed to be wrong.
            """),

        "tool.container": Row(
            title: "Container read/write normalisation (data container self-test and repair)",
            summary: """
            Resolves every directory the tooling uses inside the data container, creates it, then actually creates a file, writes, fsyncs, reads back, compares and deletes. The four real reasons container writes failed before are all named here: a URL is not a directory, isWritableFile is a bad probe, container UUIDs change, and Library/Preferences belongs to cfprefsd.
            """,
            notes: """
            Leaves container_health.txt behind. The repair actions are idempotent and run again on every launch.
            """),

        "tool.backup": Row(
            title: "Backup and restore round-trip self-test",
            summary: """
            Places a set of known-content files in the container, packs them into a ZIP, extracts to another directory, compares byte for byte, then removes them. This guards whether a backup can actually be restored — the previous version wrote a homegrown format under a .tar name and could not be read back.
            """,
            notes: """
            Also verifies that ../ and symlinks cannot escape the destination during extraction.
            """),

        "tool.paths": Row(
            title: "Filesystem permission matrix sweep",
            summary: """
            Tries reading and writing across 30-plus key paths, recording readability, writability, entry count and errno. This is the activity map for the modification tool — it determines how far every panel can go.
            """,
            notes: """
            The result is also written to a text file in Documents for comparison.
            """),

        // MARK: probes

        "iio.appx": Row(
            title: "APP marker out-of-bounds read → leaked bytes written into the output JPEG",
            summary: """
            _APPx::writeToStream on 27.0 writes (buffer + offset, length) straight to the output stream with no bounds arithmetic at all. When a marker declares a length beyond the actual block, the re-encode path writes adjacent heap bytes directly into the produced JPEG — the leak is the artifact itself, needing no exfiltration channel. iOS 27.2 computes end − offset and clamps with csel, reporting "marker 0x%04X is out of bounds" when it overruns.
            """,
            notes: """
            The only primitive in the set whose disclosure carrier is the produced file itself. The flow: feed an APP2 marker declaring 0xFFF0 against only 12 real bytes, decode, re-encode through CGImageDestination, then scan the output beyond the source marker's range for non-image bytes.
            """),

        "iio.tiff.direntry": Row(
            title: "TIFF directory entry allocation 32-bit truncation",
            summary: """
            The output allocation size is computed as lsl w0, count, #log2(elemsize) — a 32-bit truncation. With count = 0x20000000 and 8-byte elements the allocation wraps to zero while the per-element conversion loop still performs count writes. iOS 27.2 switches to _TIFFCheckMalloc_type's 64-bit checked size.
            """,
            notes: """
            The primitive's precondition is count×elemsize crossing 2^32. This module drives the allocator with a 0x20000000 SBYTE array and observes whether it returns a null pointer (clean refusal) or a block far smaller than requested (truncation holds).
            """),

        "iio.pdf.raster": Row(
            title: "PDF rasterisation decode buffer overrun",
            summary: """
            The PDF page is rasterised into a caller-supplied decode buffer with no check that the buffer is large enough. iOS 27.2 adds umull width×bpp, compares against have, branches b.hi, and reports "decode buffer too small: need %zu bytes (%zu x %zu), have %zu".
            """,
            notes: """
            A 4000×4000 page, entered through CGImageSource's PDF read path (not a direct drawPDFPage call) so that decodeImageData is hit.
            """),

        "iio.pvr": Row(
            title: "PVR bits-per-pixel below the channel bit sum",
            summary: """
            The mutual consistency check between channel bit widths has always been present, but there is no lower bound comparing bitsPerPixel against the sum of channel bits. iOS 27.2 adds "_bitsPerPixel %d is too small for 4 channels of %d bits".
            """,
            notes: """
            Four channels at 8 bits each, while declaring bitsPerPixel = 8.
            """),

        // MARK: arrivals (112705 / 112621 / 84636)

        "ave.ntl": Row(
            title: "AppleAVE2 temporal-layer property surface (NumberOfTemporalLayers)",
            summary: """
            The HEVC compression session forwards NumberOfTemporalLayers verbatim to the AppleAVE2 driver, which indexes a fixed-size layer table by the declared value. 16463 walks past the table: the first frame submit writes at a fixed offset in AppleAVE2 (+0xDA78) and the kernel data-aborts; 16462 survives. iOS 27.2 refuses the property at SetProperty with -12900. This module only covers the property surface — session, EncoderUsage=1, RCMode=20, NTL write and readback — and submits no frame.
            """,
            notes: """
            The fire module submits the frame. The same driver is reachable on macOS: 16463 returns 0 at SetProperty there and reads back normalised to 1, so the value is accepted but not propagated; a frame submit still risks the host kernel. That is why the host builds this file but never executes the encode path.
            """),

        "ave.ntl.fire": Row(
            title: "AppleAVE2 temporal-layer out-of-bounds write (fire: one frame)",
            summary: """
            The full 112705 trigger: HEVC session → EncoderUsage=1 → RCMode=20 → NumberOfTemporalLayers=16463 → one frame. On iOS 27.0–27.1 the driver writes past its table while preparing that frame, the kernel data-aborts and the device reboots. Nothing returns in-process: the evidence is the processDied verdict on the overview after reboot and the panic .ips in Analytics.
            """,
            notes: """
            Tap only on a device that is allowed to reboot. The simulator has no AVE2 hardware encoder, so encode only returns a status there; do not run the equivalent C encode path on macOS (same driver, panics the host). On 27.2 the property is refused at SetProperty and fire returns -12900 cleanly.
            """),

        "lp.heic": Row(
            title: "LinkPresentation two-frame size mismatch (pool accounting)",
            summary: """
            LPAnimatedImageTranscoder configures its video writer from frame 0's pixel size, while encodeNextFrame takes the draw width/height from the current decoded frame and draws into the pool allocated for frame 0. A 256×16 then 256×48 container makes CGContextClearRect clear 48 rows (49,152 bytes) into a 16,384-byte pool — 32,768 bytes past the end. This module only builds the container and checks frames against pool capacity; it does not transcode.
            """,
            notes: """
            Width must stay equal: CoreGraphics rejects a width that exceeds the pool's row stride, so a 512-wide second frame fails at CGBitmapContextCreate and never reaches the clear. HEIC is the advisory carrier; when the platform cannot encode it the module falls back to TIFF delivered as image/gif — LPImage's _isAnimated trusts the response MIME, ImageIO still identifies the content.
            """),

        "lp.heic.fire": Row(
            title: "LinkPresentation link-preview out-of-bounds write (fire: loopback + LPMetadataProvider)",
            summary: """
            The public delivery path: a loopback endpoint serves one HTML page and one image, the page's og:image points at the two-frame container, and LPMetadataProvider fetches it. LinkPresentation reads the page, fetches the image, builds the pool and enters LPAnimatedImageTranscoder. iOS 27.0/27.1 writes out of bounds on the transcoder queue and dies with SIGBUS/SIGSEGV; 27.2 compares the current frame with frame 0 in encodeNextFrame and fails the transcode without drawing.
            """,
            notes: """
            This is an in-process primitive: the app dies, not the kernel. After the crash the module's verdict is processDied and the last engine log line is the fire start. The receiving-Messages path (tap "Load Preview" on a sent link) is the same code; this module only replaces the delivery end with loopback so no external network is involved.
            """),

        "kern.ipc.lifecycle": Row(
            title: "Mach port dead-name notification and name reuse baseline (112507 prerequisite)",
            summary: """
            A single-threaded walk through the lifecycle the 112507 race has to keep correct: allocate a receive right → insert a send right → register a dead-name notification → drop the receive right (the send right becomes a dead name) → send into the dead name (expected MACH_SEND_INVALID_DEST) → receive the dead-name message from the notification port → release the dead name and check whether the next allocation reuses the same numeric name. No race, no freeing of live request-table entries.
            """,
            notes: """
            This is the prerequisite baseline for the race module and cannot panic the kernel. Two observations decide whether the 112507 conclusion holds: whether the dead-name notification is actually delivered, and whether the name gets reused. If this already misbehaves, fix the platform semantics first; do not treat it as UAF evidence. On a device the notification registration should return KERN_SUCCESS; the simulator may refuse it.
            """),

        "sc.dynamicstore": Row(
            title: "SSID and router MAC from configd's dynamic store (no wifi-info entitlement)",
            summary: """
            configd's dynamic store exposes en0/AirPort (SSID_STR, BSSID, channel, auth type) and the service IPv4 entry's ARPResolvedHardwareAddress (router MAC), plus Global/DNS, DHCP leases and Bluetooth/hotspot/AutoUnlock state, to any sandboxed process. SCDynamicStoreCreate + CopyValue needs no com.apple.developer.networking.wifi-info and triggers no location prompt, while the supported CNCopyCurrentNetworkInfo returns nil in the same process. SSID plus router MAC is enough for WiGLE/Google wireless geolocation (~10–30 m).
            """,
            notes: """
            The module prints both paths side by side: the supported API's answer and the raw dynamic-store dictionary. The simulator usually has no en0/AirPort entry (the Mac side runs on utun); a real device on Wi-Fi supplies SSID and ARP. An absent key is still a valid result — it means the platform converged the surface.
            """),
    ]
}
