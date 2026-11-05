import Foundation
import UIKit
import CoreGraphics
import CoreText
import ImageIO
import ModelIO
import AVFoundation
import CoreHaptics
import Darwin

// MARK: - Shared runners

enum Runners {

    // ---- CoreGraphics PDF render (the in-process trigger for the CG family)

    @discardableResult
    static func renderPDF(_ data: Data, pixels: Int = 256, page: Int = 1) throws -> String {
        guard let provider = CGDataProvider(data: data as CFData) else {
            throw LabError(message: tl("CGDataProvider 创建失败"))
        }
        guard let document = CGPDFDocument(provider) else {
            throw LabError(message: tl("CGPDFDocument 解析失败（文件被拒绝）"))
        }
        guard let pg = document.page(at: page) else {
            throw LabError(message: tl("PDF 无第 ") + "\(page)" + tl(" 页"))
        }
        let bytesPerRow = pixels * 4
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bytesPerRow * pixels, alignment: 16)
        defer { buffer.deallocate() }
        guard let ctx = CGContext(data: buffer, width: pixels, height: pixels,
                                  bitsPerComponent: 8, bytesPerRow: bytesPerRow,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw LabError(message: tl("CGBitmapContext 创建失败"))
        }
        ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: pixels, height: pixels))

        let start = CFAbsoluteTimeGetCurrent()
        // === trigger ===
        ctx.drawPDFPage(pg)
        let ms = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)

        // sample the middle of the bitmap to prove the page actually rasterised
        let mid = bytesPerRow * (pixels / 2) + (pixels / 2) * 4
        let ptr = buffer.assumingMemoryBound(to: UInt8.self)
        let sample = "\(ptr[mid]),\(ptr[mid + 1]),\(ptr[mid + 2]),\(ptr[mid + 3])"
        return tl("页面渲染完成 ") + "\(ms)" + tl(" ms；中心像素 RGBA = ") + "\(sample)"
    }

    // ---- ImageIO decode

    struct ImageResult {
        var frameCount: Int
        var decoded: Bool
        var width: Int
        var height: Int
        var properties: String
        var thumbnail: Bool
    }

    static func decodeImage(_ data: Data, wantThumbnail: Bool = false) throws -> ImageResult {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else {
            throw LabError(message: tl("CGImageSource 拒绝该数据"))
        }
        let count = CGImageSourceGetCount(source)
        var width = 0, height = 0, decoded = false, thumbOK = false
        var props = ""

        if let dict = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [String: Any] {
            width = dict[kCGImagePropertyPixelWidth as String] as? Int ?? 0
            height = dict[kCGImagePropertyPixelHeight as String] as? Int ?? 0
            props = dict.keys.sorted().prefix(8).joined(separator: ", ")
            if let exif = dict[kCGImagePropertyExifDictionary as String] as? [String: Any] {
                if let comment = exif[kCGImagePropertyExifUserComment as String] as? Data {
                    props += " | UserComment(\(comment.count)B)=\(comment.prefix(24).map { String(format: "%02x", $0) }.joined())"
                } else if let comment = exif[kCGImagePropertyExifUserComment as String] as? String {
                    props += " | UserComment=\(comment.prefix(40))"
                }
            }
            if let gps = dict[kCGImagePropertyGPSDictionary as String] as? [String: Any] {
                props += " | GPS keys=\(gps.keys.count)"
            }
        }

        if let image = CGImageSourceCreateImageAtIndex(source, 0, nil) {
            decoded = true
            width = image.width
            height = image.height
        }
        if wantThumbnail {
            let opts: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceThumbnailMaxPixelSize: 256,
            ]
            thumbOK = CGImageSourceCreateThumbnailAtIndex(source, 0, opts as CFDictionary) != nil
        }
        return ImageResult(frameCount: count, decoded: decoded, width: width, height: height,
                           properties: props, thumbnail: thumbOK)
    }

    // ---- libarchive

    enum Archive {
        typealias NewFn = @convention(c) () -> UnsafeMutableRawPointer?
        typealias Int1Fn = @convention(c) (UnsafeMutableRawPointer?) -> Int32
        typealias OpenMemFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeRawPointer?, Int) -> Int32
        typealias NextFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
        typealias PathFn = @convention(c) (UnsafeMutableRawPointer?) -> UnsafePointer<CChar>?
        typealias SizeFn = @convention(c) (UnsafeMutableRawPointer?) -> Int64
        typealias FreeFn = @convention(c) (UnsafeMutableRawPointer?) -> Int32
        typealias ExtractFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, Int32) -> Int32

        struct Bindings {
            let new: NewFn
            let supportFilterAll: Int1Fn
            let supportFormatAll: Int1Fn
            let openMemory: OpenMemFn
            let nextHeader: NextFn
            let pathname: PathFn
            let size: SizeFn
            let free: FreeFn
            let extract: ExtractFn
        }

        static func bind() -> Bindings? {
            guard let h = DyLib.shared.handle("/usr/lib/libarchive.2.dylib") else { return nil }
            guard let s1 = dlsym(h, "archive_read_new"),
                  let s2 = dlsym(h, "archive_read_support_filter_all"),
                  let s3 = dlsym(h, "archive_read_support_format_all"),
                  let s4 = dlsym(h, "archive_read_open_memory"),
                  let s5 = dlsym(h, "archive_read_next_header"),
                  let s6 = dlsym(h, "archive_entry_pathname"),
                  let s7 = dlsym(h, "archive_entry_size"),
                  let s8 = dlsym(h, "archive_read_free"),
                  let s9 = dlsym(h, "archive_read_extract") else { return nil }
            return Bindings(
                new: unsafeBitCast(s1, to: NewFn.self),
                supportFilterAll: unsafeBitCast(s2, to: Int1Fn.self),
                supportFormatAll: unsafeBitCast(s3, to: Int1Fn.self),
                openMemory: unsafeBitCast(s4, to: OpenMemFn.self),
                nextHeader: unsafeBitCast(s5, to: NextFn.self),
                pathname: unsafeBitCast(s6, to: PathFn.self),
                size: unsafeBitCast(s7, to: SizeFn.self),
                free: unsafeBitCast(s8, to: FreeFn.self),
                extract: unsafeBitCast(s9, to: ExtractFn.self))
        }

        static func list(_ data: Data) throws -> (entries: [String], status: String) {
            guard let b = bind() else {
                throw LabError(message: tl("libarchive.2.dylib 无法 dlopen（沙盒或路径受限）"))
            }
            guard let handle = b.new() else { throw LabError(message: tl("archive_read_new 失败")) }
            defer { _ = b.free(handle) }
            _ = b.supportFilterAll(handle)
            _ = b.supportFormatAll(handle)

            let rc = data.withUnsafeBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return -1 }
                return b.openMemory(handle, base, data.count)
            }
            guard rc == 0 else { throw LabError(message: "archive_read_open_memory rc=\(rc)") }

            var entries: [String] = []
            var status = ""
            while true {
                var entry: UnsafeMutableRawPointer?
                let r = b.nextHeader(handle, &entry)
                if r == 0, let e = entry {
                    let name = b.pathname(e).map { String(cString: $0) } ?? "<noname>"
                    entries.append("\(name)  (\(b.size(e)) B)")
                    if entries.count > 64 { break }
                } else if r == 1 {
                    status = "EOF"
                    break
                } else {
                    status = "next_header rc=\(r)"
                    break
                }
            }
            return (entries, status)
        }

        /// Extract every entry into `destination`. Uses archive_read_extract so IPA, DEB,
        /// tar and zip all unpack through the same path — no external binary needed.
        static func extractAll(_ data: Data, to destination: URL) -> (count: Int, errors: Int, status: String) {
            let fm = FileManager.default
            try? fm.createDirectory(at: destination, withIntermediateDirectories: true)
            guard let b = bind() else { return (0, 0, tl("libarchive 不可用")) }
            guard let handle = b.new() else { return (0, 0, tl("archive_read_new 失败")) }
            defer { _ = b.free(handle) }
            _ = b.supportFilterAll(handle)
            _ = b.supportFormatAll(handle)
            let rc = data.withUnsafeBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return -1 }
                return b.openMemory(handle, base, data.count)
            }
            guard rc == 0 else { return (0, 0, "open_memory rc=\(rc)") }

            let previous = fm.currentDirectoryPath
            fm.changeCurrentDirectoryPath(destination.path)
            defer { fm.changeCurrentDirectoryPath(previous) }

            var count = 0
            var errors = 0
            while true {
                var entry: UnsafeMutableRawPointer?
                let r = b.nextHeader(handle, &entry)
                if r != 0 { break }
                guard let e = entry else { break }
                // ARCHIVE_EXTRACT_TIME | PERM | SECURE_SYMLINKS | SECURE_NODOTDOT.
                // NOT NO_AUTODIR (0x0400) — archives without explicit directory entries
                // need the parents created for them.
                let flags: Int32 = 0x0004 | 0x0002 | 0x0100 | 0x0200
                if b.extract(handle, e, flags) == 0 { count += 1 } else { errors += 1 }
                if count + errors > 20000 { break }
            }
            return (count, errors, tl("完成"))
        }
    }

    // ---- CoreMedia Dolby Vision RPU parser

    static func rpuParse(_ payload: Data, version: inout UInt32, level: inout UInt32) throws -> Int32 {
        guard let sym = DyLib.shared.symbol("CMGetDMVersionLevelFromRPU", in: [
            "/System/Library/Frameworks/CoreMedia.framework/CoreMedia"
        ]) else {
            throw LabError(message: tl("CMGetDMVersionLevelFromRPU 未导出"))
        }
        typealias Fn = @convention(c) (UnsafePointer<UInt8>?, Int,
                                       UnsafeMutablePointer<UInt32>?, UnsafeMutablePointer<UInt32>?) -> Int32
        let fn = unsafeBitCast(sym, to: Fn.self)
        var v: UInt32 = 0
        var l: UInt32 = 0
        let rc: Int32 = payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return fn(base, payload.count, &v, &l)
        }
        version = v
        level = l
        return rc
    }

    // ---- AppleFSCompression (decmpfs) round trip

    struct DecmpfsResult {
        var wroteXattr: Bool
        var readBack: Int
        var kernelPointerHits: Int
        var samples: [String]
        var note: String
    }

    static func decmpfsProbe(at url: URL, uncompressed: Int, chunks: Int, producePerChunk: Int) -> DecmpfsResult {
        let fm = FileManager.default
        try? fm.removeItem(at: url)
        fm.createFile(atPath: url.path, contents: Data(repeating: 0x41, count: max(64, uncompressed)))

        let payload = Decmpfs.chunkedXattr(uncompressedSize: uncompressed,
                                           chunkCount: chunks,
                                           producePerChunk: producePerChunk)
        let ok = payload.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return setxattr(url.path, "com.apple.decmpfs", base, payload.count, 0, 0) == 0
        }
        if !ok {
            return DecmpfsResult(wroteXattr: false, readBack: 0, kernelPointerHits: 0, samples: [],
                                 note: tl("setxattr 失败 errno=") + "\(errno)")
        }

        guard let back = try? Data(contentsOf: url) else {
            return DecmpfsResult(wroteXattr: true, readBack: 0, kernelPointerHits: 0, samples: [],
                                 note: tl("读取失败 errno=") + "\(errno)")
        }

        // scan for kernel-space pointers in whatever the kernel handed back
        var hits = 0
        var samples: [String] = []
        let bytes = [UInt8](back)
        if bytes.count >= 8 {
            var i = 0
            while i + 8 <= bytes.count {
                var v: UInt64 = 0
                for k in 0..<8 { v |= UInt64(bytes[i + k]) << (8 * UInt64(k)) }
                if v >= 0xFFFF_FFE0_0000_0000 {
                    hits += 1
                    if samples.count < 8 { samples.append(String(format: "0x%016llx @ +0x%x", v, i)) }
                }
                i += 8
            }
        }
        return DecmpfsResult(wroteXattr: true, readBack: back.count, kernelPointerHits: hits,
                             samples: samples, note: tl("读取 ") + "\(back.count)" + tl(" 字节"))
    }

    // ---- FontParser

    static func loadFont(_ data: Data) throws -> String {
        guard let provider = CGDataProvider(data: data as CFData) else {
            throw LabError(message: tl("CGDataProvider 创建失败"))
        }
        guard let font = CGFont(provider) else {
            throw LabError(message: tl("CGFont 拒绝该字体数据"))
        }
        let name = font.fullName as String? ?? font.postScriptName as String? ?? "<unnamed>"
        let glyphCount = font.numberOfGlyphs

        let ctFont = CTFontCreateWithGraphicsFont(font, 96, nil, nil)
        let pixels = 256
        let bytesPerRow = pixels * 4
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bytesPerRow * pixels, alignment: 16)
        defer { buffer.deallocate() }
        guard let ctx = CGContext(data: buffer, width: pixels, height: pixels,
                                  bitsPerComponent: 8, bytesPerRow: bytesPerRow,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
            throw LabError(message: tl("上下文创建失败"))
        }
        // drawing forces the charstring interpreter to run.
        // glyphCount == 0 is a real malformed-font shape (the POCs feed exactly those),
        // and `1..<0` would trap — guard the range instead of assuming the count.
        let upper = min(Int(glyphCount), 8)
        var drawn = 0
        if upper > 1 {
            for g in 1..<upper {
                var glyph = CGGlyph(g)
                var position = CGPoint(x: 20, y: CGFloat(40 * (g + 1)))
                CTFontDrawGlyphs(ctFont, &glyph, &position, 1, ctx)
                drawn += 1
            }
        }
        return tl("字体加载成功 name=") + "\(name)" + tl(" glyphs=") + "\(glyphCount)" + tl("，已绘制 ") + "\(drawn)" + tl(" 个字形")
    }

    // ---- Model I/O (libusd_ms)

    static func loadUSDA(at url: URL) throws -> String {
        let start = CFAbsoluteTimeGetCurrent()
        let asset = MDLAsset(url: url)
        let ms = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
        return tl("MDLAsset 载入完成 ") + "\(ms)" + tl(" ms，对象数 ") + "\(asset.count)"
    }

    // ---- CoreHaptics / AVHaptic

    static func hapticCustomAudio(frameCount: Int, declaredBytes: Int) -> String {
        var report: [String] = []
        let engine: CHHapticEngine
        do { engine = try CHHapticEngine() } catch {
            return tl("CHHapticEngine 初始化失败: ") + "\(error.localizedDescription)"
        }
        do {
            try engine.start()
            report.append(tl("CHHapticEngine 启动成功"))
        } catch {
            return tl("引擎启动失败: ") + "\(error.localizedDescription)"
        }

        // Build a mono 16-bit WAV with exactly `frameCount` samples and register it as an
        // audio resource. The declared byte count is what the server is asked to trust.
        let sampleRate = 48000
        let frames = max(1, frameCount)
        var wav: [UInt8] = []
        wav += B.ascii("RIFF")
        wav += B.le32(UInt32(36 + frames * 2))
        wav += B.ascii("WAVEfmt ")
        wav += B.le32(16) + B.le16(1) + B.le16(1)
        wav += B.le32(UInt32(sampleRate)) + B.le32(UInt32(sampleRate * 2))
        wav += B.le16(2) + B.le16(16)
        wav += B.ascii("data") + B.le32(UInt32(frames * 2))
        wav += [UInt8](repeating: 0, count: frames * 2)

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cinder_haptic.wav")
        try? Data(wav).write(to: url)

        var resourceID: CHHapticAudioResourceID = 0
        do {
            resourceID = try engine.registerAudioResource(url, options: [AnyHashable: Any]())
        } catch {
            report.append(tl("registerAudioResource 失败: ") + "\(error.localizedDescription)")
            engine.stop()
            return report.joined(separator: "\n")
        }
        report.append(tl("音频资源 id=") + "\(resourceID)" + tl("  frames=") + "\(frames)" + tl("  declaredBytes=") + "\(declaredBytes)")

        do {
            let event = CHHapticEvent(audioResourceID: resourceID, parameters: [],
                                      relativeTime: 0, duration: 0.25)
            let pattern = try CHHapticPattern(events: [event], parameters: [])
            let player = try engine.makePlayer(with: pattern)
            try player.start(atTime: 0)
            report.append(tl("audioCustom 事件已投递"))
            Thread.sleep(forTimeInterval: 0.4)
            engine.stop()
            report.append(tl("引擎已停止"))
        } catch {
            report.append(tl("事件投递失败: ") + "\(error.localizedDescription)")
            engine.stop()
        }
        return report.joined(separator: "\n")
    }

    // ---- AudioCodecs probes

    static func audioConverter(format: UInt32, sampleRate: Double, channels: UInt32) -> String {
        var inFormat = AudioStreamBasicDescription(mSampleRate: sampleRate,
                                                   mFormatID: format,
                                                   mFormatFlags: 0,
                                                   mBytesPerPacket: 0,
                                                   mFramesPerPacket: 1,
                                                   mBytesPerFrame: 0,
                                                   mChannelsPerFrame: channels,
                                                   mBitsPerChannel: 0,
                                                   mReserved: 0)
        var outFormat = AudioStreamBasicDescription(mSampleRate: sampleRate,
                                                    mFormatID: kAudioFormatLinearPCM,
                                                    mFormatFlags: kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked,
                                                    mBytesPerPacket: 4,
                                                    mFramesPerPacket: 1,
                                                    mBytesPerFrame: 4,
                                                    mChannelsPerFrame: 1,
                                                    mBitsPerChannel: 32,
                                                    mReserved: 0)
        var converter: AudioConverterRef?
        let status = AudioConverterNew(&inFormat, &outFormat, &converter)
        if let c = converter { AudioConverterDispose(c) }
        return "AudioConverterNew(\(fourCC(format))) = \(status)"
    }

    static func fourCC(_ v: UInt32) -> String {
        let bytes = [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        let s = bytes.map { ($0 >= 0x20 && $0 < 0x7f) ? String(UnicodeScalar($0)) : "?" }.joined()
        return "'\(s)'"
    }

    // ---- IOKit / private framework probes

    static func dlopenProbe(_ path: String, symbols: [String]) -> String {
        guard let handle = dlopen(path, RTLD_NOW) else {
            let err = dlerror().map { String(cString: $0) } ?? tl("dlopen 失败")
            return "✗ \(path)\n  \(err)"
        }
        var found: [String] = []
        var missing: [String] = []
        for s in symbols {
            if dlsym(handle, s) != nil { found.append(s) } else { missing.append(s) }
        }
        var out = "✓ \(path)"
        if !found.isEmpty { out += "\n  resolved: " + found.joined(separator: ", ") }
        if !missing.isEmpty { out += "\n  missing: " + missing.joined(separator: ", ") }
        return out
    }
}
