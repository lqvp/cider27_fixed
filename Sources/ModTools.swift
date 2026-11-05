import Foundation
import Darwin
import CoreText
import UIKit

// MARK: - ZIP writer (stored entries, no external dependency)

/// A minimal but correct ZIP writer. iOS installation only needs a valid archive, and
/// stored entries keep the whole thing deterministic — no compressor to get wrong.
struct ZipWriter {
    struct Entry {
        let name: String
        let data: Data
    }

    private var entries: [Entry] = []

    mutating func add(_ name: String, _ data: Data) {
        entries.append(Entry(name: name, data: data))
    }

    mutating func add(url: URL, as name: String) {
        guard let data = try? Data(contentsOf: url) else { return }
        add(name, data)
    }

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

    func build() -> Data {
        var out = Data()
        var central = Data()
        let now = Date()
        let cal = Calendar(identifier: .gregorian)
        let comps = cal.dateComponents([.year, .month, .day, .hour, .minute, .second], from: now)
        let dosTime = UInt16(((comps.hour ?? 0) << 11) | ((comps.minute ?? 0) << 5) | ((comps.second ?? 0) / 2))
        let dosDate = UInt16((((comps.year ?? 2026) - 1980) << 9) | ((comps.month ?? 1) << 5) | (comps.day ?? 1))

        var count: UInt16 = 0
        for entry in entries {
            let nameBytes = Array(entry.name.utf8)
            let payload = [UInt8](entry.data)
            let crc = Self.crc32(payload)
            let offset = UInt32(out.count)
            let size = UInt32(payload.count)

            out.append(contentsOf: [0x50, 0x4B, 0x03, 0x04])
            out.append(contentsOf: B.le16(20))
            out.append(contentsOf: B.le16(0x0800))       // UTF-8 flag
            out.append(contentsOf: B.le16(0))            // stored
            out.append(contentsOf: B.le16(dosTime))
            out.append(contentsOf: B.le16(dosDate))
            out.append(contentsOf: B.le32(crc))
            out.append(contentsOf: B.le32(size))
            out.append(contentsOf: B.le32(size))
            out.append(contentsOf: B.le16(UInt16(nameBytes.count)))
            out.append(contentsOf: B.le16(0))
            out.append(contentsOf: nameBytes)
            out.append(contentsOf: payload)

            central.append(contentsOf: [0x50, 0x4B, 0x01, 0x02])
            central.append(contentsOf: B.le16(20))       // version made by
            central.append(contentsOf: B.le16(20))       // version needed
            central.append(contentsOf: B.le16(0x0800))
            central.append(contentsOf: B.le16(0))
            central.append(contentsOf: B.le16(dosTime))
            central.append(contentsOf: B.le16(dosDate))
            central.append(contentsOf: B.le32(crc))
            central.append(contentsOf: B.le32(size))
            central.append(contentsOf: B.le32(size))
            central.append(contentsOf: B.le16(UInt16(nameBytes.count)))
            central.append(contentsOf: B.le16(0))
            central.append(contentsOf: B.le16(0))
            central.append(contentsOf: B.le16(0))
            central.append(contentsOf: B.le16(0))
            central.append(contentsOf: B.le32(0))
            central.append(contentsOf: B.le32(offset))
            central.append(contentsOf: nameBytes)

            count += 1
        }

        let centralOffset = UInt32(out.count)
        out.append(central)
        out.append(contentsOf: [0x50, 0x4B, 0x05, 0x06])
        out.append(contentsOf: B.le16(0))
        out.append(contentsOf: B.le16(0))
        out.append(contentsOf: B.le16(count))
        out.append(contentsOf: B.le16(count))
        out.append(contentsOf: B.le32(UInt32(central.count)))
        out.append(contentsOf: B.le32(centralOffset))
        out.append(contentsOf: B.le16(0))
        return out
    }
}

// MARK: - Mach-O surgery

enum MachO {

    struct Header {
        var magic: UInt32
        var cputype: UInt32
        var cpusubtype: UInt32
        var filetype: UInt32
        var ncmds: UInt32
        var sizeofcmds: UInt32
        var flags: UInt32
        var reserved: UInt32
        var is64: Bool
        var headerSize: Int { is64 ? 32 : 28 }
    }

    struct LoadCommand {
        var cmd: UInt32
        var size: UInt32
        var offset: Int
    }

    static func header(_ data: Data) -> Header? {
        guard data.count >= 32 else { return nil }
        let magic = data.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self) }
        guard magic == 0xFEEDFACF || magic == 0xFEEDFACE || magic == 0xCFFAEDFE else { return nil }
        let is64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE
        return Header(
            magic: magic,
            cputype: data.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) },
            cpusubtype: data.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt32.self) },
            filetype: data.withUnsafeBytes { $0.load(fromByteOffset: 12, as: UInt32.self) },
            ncmds: data.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) },
            sizeofcmds: data.withUnsafeBytes { $0.load(fromByteOffset: 20, as: UInt32.self) },
            flags: data.withUnsafeBytes { $0.load(fromByteOffset: 24, as: UInt32.self) },
            reserved: is64 ? data.withUnsafeBytes { $0.load(fromByteOffset: 28, as: UInt32.self) } : 0,
            is64: is64)
    }

    static func commands(_ data: Data) -> [LoadCommand] {
        guard let h = header(data) else { return [] }
        var out: [LoadCommand] = []
        var offset = h.headerSize
        for _ in 0..<min(Int(h.ncmds), 8192) {
            guard offset + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            let size = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 4, as: UInt32.self) }
            guard size >= 8, offset + Int(size) <= data.count else { break }
            out.append(LoadCommand(cmd: cmd, size: size, offset: offset))
            offset += Int(size)
        }
        return out
    }

    /// Lowest file offset occupied by real segment content — the padding window we may
    /// write into without moving anything.
    static func firstSectionOffset(_ data: Data) -> Int? {
        guard header(data) != nil else { return nil }
        var lowest: Int?
        for c in commands(data) where c.cmd == 0x19 || c.cmd == 0x1 {   // LC_SEGMENT_64 / LC_SEGMENT
            let is64 = c.cmd == 0x19
            var sectionOffset = c.offset + (is64 ? 72 : 56)
            let nsectsOffset = c.offset + (is64 ? 64 : 48)
            guard nsectsOffset + 4 <= data.count else { continue }
            let nsects = data.withUnsafeBytes { $0.load(fromByteOffset: nsectsOffset, as: UInt32.self) }
            let sectSize = is64 ? 80 : 68
            for _ in 0..<min(Int(nsects), 4096) {
                guard sectionOffset + sectSize <= data.count else { break }
                let offsetField = is64 ? sectionOffset + 48 : sectionOffset + 40
                let fileOffset = data.withUnsafeBytes { $0.load(fromByteOffset: offsetField, as: UInt32.self) }
                if fileOffset != 0 {
                    let v = Int(fileOffset)
                    if lowest == nil || v < lowest! { lowest = v }
                }
                sectionOffset += sectSize
            }
        }
        return lowest
    }

    /// Append an LC_LOAD_DYLIB to a thin Mach-O. Returns the patched image, or throws when
    /// there is no room in the header padding (which is the honest failure mode).
    static func injectLoad(_ data: Data, dylibPath: String) throws -> Data {
        guard let h = header(data) else { throw LabError(message: tl("不是 Mach-O")) }
        guard h.is64 else { throw LabError(message: tl("只支持 64 位 Mach-O")) }

        let pathBytes = Array(dylibPath.utf8)
        let rawSize = 24 + pathBytes.count + 1
        let cmdSize = (rawSize + 7) & ~7

        let insertAt = h.headerSize + Int(h.sizeofcmds)
        let limit = firstSectionOffset(data) ?? data.count
        guard insertAt + cmdSize <= limit else {
            throw LabError(message: tl("头部空隙不足：需要 ") + "\(cmdSize)" + tl(" B，可用 ") + "\(max(0, limit - insertAt))" + tl(" B"))
        }

        var out = data
        var cmd = Data()
        cmd.append(contentsOf: B.le32(0x0C))                 // LC_LOAD_DYLIB
        cmd.append(contentsOf: B.le32(UInt32(cmdSize)))
        cmd.append(contentsOf: B.le32(24))                   // name offset
        cmd.append(contentsOf: B.le32(2))                    // timestamp
        cmd.append(contentsOf: B.le32(0x00010000))           // current version
        cmd.append(contentsOf: B.le32(0x00010000))           // compat version
        cmd.append(contentsOf: pathBytes)
        cmd.append(0)
        while cmd.count < cmdSize { cmd.append(0) }

        out.replaceSubrange(insertAt..<(insertAt + cmdSize), with: cmd)
        // bump ncmds / sizeofcmds
        var ncmds = h.ncmds + 1
        var sizeofcmds = h.sizeofcmds + UInt32(cmdSize)
        withUnsafeBytes(of: &ncmds) { out.replaceSubrange(16..<20, with: $0) }
        withUnsafeBytes(of: &sizeofcmds) { out.replaceSubrange(20..<24, with: $0) }
        return out
    }

    /// Remove LC_CODE_SIGNATURE from the load-command stream so a re-sign starts clean.
    ///
    /// The command is spliced out and the remaining commands are shifted down — zeroing it
    /// in place would leave a cmdsize==0 hole and desync every loader that walks the list.
    static func stripSignature(_ data: Data) throws -> (Data, Int) {
        guard let h = header(data) else { throw LabError(message: tl("不是 Mach-O")) }
        var out = data
        var removed = 0
        var offset = h.headerSize
        var kept = Data()

        for _ in 0..<min(Int(h.ncmds), 8192) {
            guard offset + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            let size = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 4, as: UInt32.self) }
            guard size >= 8, offset + Int(size) <= data.count else { break }
            if cmd == 0x1D {                       // LC_CODE_SIGNATURE
                removed += 1
            } else {
                kept.append(data[offset..<(offset + Int(size))])
            }
            offset += Int(size)
        }
        guard removed > 0 else { return (data, 0) }

        // rewrite the command stream in place, then zero the tail of the old region.
        // sizeofcmds is attacker-controlled in a malformed header — clamp before indexing,
        // or the zeroing loop below walks off the end of the image.
        let streamStart = h.headerSize
        let oldEnd = min(streamStart + Int(h.sizeofcmds), out.count)
        out.replaceSubrange(streamStart..<(streamStart + kept.count), with: kept)
        if streamStart + kept.count < oldEnd {
            for i in (streamStart + kept.count)..<oldEnd { out[i] = 0 }
        }
        var ncmds = h.ncmds - UInt32(removed)
        var sizeofcmds = UInt32(kept.count)
        withUnsafeBytes(of: &ncmds) { out.replaceSubrange(16..<20, with: $0) }
        withUnsafeBytes(of: &sizeofcmds) { out.replaceSubrange(20..<24, with: $0) }
        return (out, removed)
    }

    static func patchStrings(_ data: Data, find: String, replace: String) throws -> (Data, Int) {
        let needle = Array(find.utf8)
        let replacement = Array(replace.utf8)
        guard !needle.isEmpty else { throw LabError(message: tl("搜索串为空")) }
        guard replacement.count <= needle.count else {
            throw LabError(message: tl("替换串不能比原串长（") + "\(replacement.count)" + tl(" > ") + "\(needle.count)" + tl("）"))
        }
        var haystack = [UInt8](data)
        var hits = 0
        var i = 0
        while i + needle.count <= haystack.count {
            var matched = true
            for k in 0..<needle.count where haystack[i + k] != needle[k] { matched = false; break }
            if matched {
                for k in 0..<replacement.count { haystack[i + k] = replacement[k] }
                for k in replacement.count..<needle.count { haystack[i + k] = 0 }
                hits += 1
                i += needle.count
            } else {
                i += 1
            }
        }
        return (Data(haystack), hits)
    }
}

// MARK: - IPA surgery

struct IPARecipe {
    var bundleID: String?
    var displayName: String?
    var version: String?
    var buildVersion: String?
    var minOS: String?
    var injectedDylib: String?
    var patchedString: String?
    var patchedReplacement: String?
    var stripSignature: Bool = true
}

struct IPAResult {
    var outputURL: URL
    var entries: Int
    var notes: [String]
}

enum IPASurgeon {

    static func patch(source: URL, recipe: IPARecipe, workdir: URL) throws -> IPAResult {
        let fm = FileManager.default
        let stage = workdir.appendingPathComponent("ipa-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
        try? fm.removeItem(at: stage)
        try fm.createDirectory(at: stage, withIntermediateDirectories: true)

        guard let archive = try? Data(contentsOf: source) else {
            throw LabError(message: tl("读取 IPA 失败"))
        }
        let extracted = Runners.Archive.extractAll(archive, to: stage)
        guard extracted.count > 0 else {
            throw LabError(message: tl("解包失败：") + "\(extracted.status)")
        }

        var notes: [String] = [tl("解包 ") + "\(extracted.count)" + tl(" 项")]
        let payload = stage.appendingPathComponent("Payload")
        guard let appName = (try? fm.contentsOfDirectory(atPath: payload.path))?
            .first(where: { $0.hasSuffix(".app") }) else {
            throw LabError(message: tl("Payload/ 下没有 .app"))
        }
        let app = payload.appendingPathComponent(appName)
        notes.append(tl("目标 ") + "\(appName)")

        // ---- Info.plist rewrite
        let infoURL = app.appendingPathComponent("Info.plist")
        if var info = (try? Data(contentsOf: infoURL))
            .flatMap({ try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] }) {
            if let v = recipe.bundleID { info["CFBundleIdentifier"] = v; notes.append("bundle id → \(v)") }
            if let v = recipe.displayName { info["CFBundleDisplayName"] = v; notes.append(tl("名称 → ") + "\(v)") }
            if let v = recipe.version { info["CFBundleShortVersionString"] = v }
            if let v = recipe.buildVersion { info["CFBundleVersion"] = v }
            if let v = recipe.minOS { info["MinimumOSVersion"] = v }
            if let data = try? PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0) {
                try? data.write(to: infoURL)
            }
        } else {
            notes.append(tl("Info.plist 读取失败，跳过字段改写"))
        }

        // ---- executable surgery
        guard let execName = (try? Data(contentsOf: infoURL))
            .flatMap({ try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] })?["CFBundleExecutable"] as? String
            ?? (try? fm.contentsOfDirectory(atPath: app.path))?.first(where: { $0 == appName.replacingOccurrences(of: ".app", with: "") }) else {
            throw LabError(message: tl("找不到主二进制名"))
        }
        let execURL = app.appendingPathComponent(execName)

        if let binary = try? Data(contentsOf: execURL) {
            var current = binary
            if let dylib = recipe.injectedDylib, !dylib.isEmpty {
                do {
                    current = try MachO.injectLoad(current, dylibPath: dylib)
                    notes.append(tl("注入 LC_LOAD_DYLIB → ") + "\(dylib)")
                } catch {
                    notes.append(tl("注入失败: ") + "\(error.localizedDescription)")
                }
            }
            if let find = recipe.patchedString, !find.isEmpty {
                do {
                    let (patched, hits) = try MachO.patchStrings(current,
                                                                find: find,
                                                                replace: recipe.patchedReplacement ?? "")
                    current = patched
                    notes.append(tl("字符串替换 ") + "\(hits)" + tl(" 处"))
                } catch {
                    notes.append(tl("替换失败: ") + "\(error.localizedDescription)")
                }
            }
            if recipe.stripSignature {
                if let (stripped, removed) = try? MachO.stripSignature(current) {
                    current = stripped
                    if removed > 0 { notes.append(tl("移除 LC_CODE_SIGNATURE ×") + "\(removed)") }
                }
            }
            try? current.write(to: execURL)
        } else {
            notes.append(tl("主二进制读取失败（可能已加密）"))
        }

        // ---- repack
        var zip = ZipWriter()
        let enumerator = fm.enumerator(at: stage, includingPropertiesForKeys: [.isDirectoryKey])
        var files = 0
        while let url = enumerator?.nextObject() as? URL {
            let values = try? url.resourceValues(forKeys: [.isDirectoryKey])
            if values?.isDirectory == true { continue }
            let relative = url.path.replacingOccurrences(of: stage.path + "/", with: "")
            if let data = try? Data(contentsOf: url) {
                zip.add(relative, data)
                files += 1
            }
        }
        notes.append(tl("重打包 ") + "\(files)" + tl(" 个文件"))

        let outURL = workdir.appendingPathComponent("patched-\(appName.replacingOccurrences(of: ".app", with: "")).ipa")
        try zip.build().write(to: outURL)
        try? fm.removeItem(at: stage)
        return IPAResult(outputURL: outURL, entries: files, notes: notes)
    }
}

// MARK: - Hex editing

enum HexTool {
    static func search(_ data: Data, pattern: String, limit: Int = 500) -> [Int] {
        let needle: [UInt8]
        if pattern.contains(" ") || pattern.hasPrefix("0x") {
            let cleaned = pattern.replacingOccurrences(of: "0x", with: "")
                .replacingOccurrences(of: " ", with: "")
            guard cleaned.count % 2 == 0 else { return [] }
            var bytes: [UInt8] = []
            var i = cleaned.startIndex
            while i < cleaned.endIndex {
                let next = cleaned.index(i, offsetBy: 2)
                guard let b = UInt8(cleaned[i..<next], radix: 16) else { return [] }
                bytes.append(b)
                i = next
            }
            needle = bytes
        } else {
            needle = Array(pattern.utf8)
        }
        guard !needle.isEmpty else { return [] }

        var hits: [Int] = []
        let hay = [UInt8](data)
        var i = 0
        while i + needle.count <= hay.count && hits.count < limit {
            var matched = true
            for k in 0..<needle.count where hay[i + k] != needle[k] { matched = false; break }
            if matched { hits.append(i); i += needle.count } else { i += 1 }
        }
        return hits
    }

    static func replace(_ data: Data, pattern: String, with replacement: String) -> (Data, Int) {
        var bytes = [UInt8](data)
        let needle: [UInt8]
        let replacementBytes: [UInt8]
        if pattern.contains(" ") || pattern.hasPrefix("0x") {
            let cleaned = pattern.replacingOccurrences(of: "0x", with: "").replacingOccurrences(of: " ", with: "")
            var out: [UInt8] = []
            var i = cleaned.startIndex
            while i < cleaned.endIndex {
                // odd trailing hex digit: malformed input, refuse instead of trapping
                guard cleaned.distance(from: i, to: cleaned.endIndex) >= 2,
                      let next = Optional(cleaned.index(i, offsetBy: 2)),
                      let b = UInt8(cleaned[i..<next], radix: 16) else { return (data, 0) }
                out.append(b)
                i = next
            }
            needle = out
        } else {
            needle = Array(pattern.utf8)
        }
        if replacement.contains(" ") || replacement.hasPrefix("0x") {
            let cleaned = replacement.replacingOccurrences(of: "0x", with: "").replacingOccurrences(of: " ", with: "")
            var out: [UInt8] = []
            var i = cleaned.startIndex
            while i < cleaned.endIndex {
                // odd trailing hex digit: malformed input, refuse instead of trapping
                guard cleaned.distance(from: i, to: cleaned.endIndex) >= 2,
                      let next = Optional(cleaned.index(i, offsetBy: 2)),
                      let b = UInt8(cleaned[i..<next], radix: 16) else { return (data, 0) }
                out.append(b)
                i = next
            }
            replacementBytes = out
        } else {
            replacementBytes = Array(replacement.utf8)
        }
        guard !needle.isEmpty, replacementBytes.count <= needle.count else { return (data, 0) }

        var hits = 0
        var i = 0
        while i + needle.count <= bytes.count {
            var matched = true
            for k in 0..<needle.count where bytes[i + k] != needle[k] { matched = false; break }
            if matched {
                for k in 0..<replacementBytes.count { bytes[i + k] = replacementBytes[k] }
                for k in replacementBytes.count..<needle.count { bytes[i + k] = 0 }
                hits += 1
                i += needle.count
            } else {
                i += 1
            }
        }
        return (Data(bytes), hits)
    }
}

// MARK: - xattr / decmpfs surgery

enum XattrTool {
    static func list(_ path: String) -> [(String, Int)] {
        var size = listxattr(path, nil, 0, 0)
        guard size > 0 else { return [] }
        var buffer = [CChar](repeating: 0, count: size)
        size = listxattr(path, &buffer, size, 0)
        guard size > 0 else { return [] }
        var names: [String] = []
        var current: [CChar] = []
        for c in buffer {
            if c == 0 {
                if !current.isEmpty { names.append(String(cString: current)); current = [] }
            } else { current.append(c) }
        }
        return names.map { name in
            var vlen = getxattr(path, name, nil, 0, 0, 0)
            if vlen < 0 { vlen = 0 }
            return (name, vlen)
        }
    }

    static func read(_ path: String, name: String) -> Data? {
        let len = getxattr(path, name, nil, 0, 0, 0)
        guard len > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: len)
        let got = getxattr(path, name, &buffer, len, 0, 0)
        guard got > 0 else { return nil }
        return Data(buffer.prefix(got))
    }

    @discardableResult
    static func write(_ path: String, name: String, value: Data) -> String? {
        let rc = value.withUnsafeBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return setxattr(path, name, base, value.count, 0, 0)
        }
        return rc == 0 ? nil : "setxattr errno=\(errno)"
    }

    @discardableResult
    static func remove(_ path: String, name: String) -> String? {
        removexattr(path, name, 0) == 0 ? nil : "removexattr errno=\(errno)"
    }

    static func decmpfsHeader(_ data: Data) -> String {
        guard data.count >= 16 else { return tl("数据过短") }
        let magic = data.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self) }
        guard magic == 0x636D_7066 else { return tl("不是 decmpfs（magic 0x") + "\(String(magic, radix: 16))" + tl("）") }
        let type = data.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
        let size = data.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt64.self) }
        let names: [UInt32: String] = [3: "zlib", 4: "zlib-chunked", 7: "lzvn", 8: "lzfse", 9: "lzbitmap", 11: "lzfse-chunked", 12: "lzvn-chunked"]
        return tl("magic cmpf · 类型 ") + "\(type)" + tl(" (") + "\(names[type] ?? tl("未知"))" + tl(") · 原始大小 ") + "\(size)" + tl(" B · xattr ") + "\(data.count)" + tl(" B")
    }
}

// MARK: - SQLite

#if canImport(SQLite3)
import SQLite3

enum SQLiteBrowser {
    struct Result {
        var columns: [String]
        var rows: [[String]]
        var error: String?
    }

    static func tables(_ path: String) -> [String] {
        query(path, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;").rows.compactMap { $0.first }
    }

    static func query(_ path: String, _ sql: String) -> Result {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let handle = db else {
            return Result(columns: [], rows: [], error: tl("打开失败"))
        }
        defer { sqlite3_close(handle) }

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK, let s = stmt else {
            return Result(columns: [], rows: [], error: String(cString: sqlite3_errmsg(handle)))
        }
        defer { sqlite3_finalize(s) }

        var columns: [String] = []
        for i in 0..<sqlite3_column_count(s) {
            columns.append(String(cString: sqlite3_column_name(s, i)))
        }
        var rows: [[String]] = []
        while sqlite3_step(s) == SQLITE_ROW {
            var row: [String] = []
            for i in 0..<sqlite3_column_count(s) {
                if let cstr = sqlite3_column_text(s, i) {
                    row.append(String(cString: cstr))
                } else {
                    row.append("NULL")
                }
            }
            rows.append(row)
            if rows.count >= 2000 { break }
        }
        return Result(columns: columns, rows: rows, error: nil)
    }
}
#endif

// MARK: - Font installer

enum FontInstaller {
    static func install(_ url: URL) -> String {
        var error: Unmanaged<CFError>?
        let ok = CTFontManagerRegisterFontsForURL(url as CFURL, .user, &error)
        if ok { return tl("已注册到用户字体域：") + "\(url.lastPathComponent)" }
        if let e = error?.takeRetainedValue() {
            return tl("注册失败：") + "\(e)"
        }
        return tl("注册失败（无错误信息）")
    }

    static func installed() -> [String] {
        let descriptors = CTFontManagerCopyAvailablePostScriptNames() as? [String] ?? []
        return descriptors.sorted()
    }
}

// MARK: - System telemetry

enum Telemetry {
    static func battery() -> [(String, String)] {
        var rows: [(String, String)] = []
        guard let sym = DyLib.shared.symbol("IOPSCopyPowerSourcesInfo") else {
            return [(tl("电源"), tl("IOPSCopyPowerSourcesInfo 不可用"))]
        }
        typealias CopyFn = @convention(c) () -> Unmanaged<CFTypeRef>?
        let fn = unsafeBitCast(sym, to: CopyFn.self)
        guard let info = fn()?.takeRetainedValue() else { return [(tl("电源"), tl("无数据"))] }
        let arr = info as? [[String: Any]] ?? []
        for source in arr {
            if let cap = source["Current Capacity"] as? Int,
               let max = source["Max Capacity"] as? Int, max > 0 {
                rows.append((tl("电量"), "\(cap * 100 / max)%"))
            }
            if let charging = source["Is Charging"] as? Bool {
                rows.append((tl("充电中"), charging ? tl("是") : tl("否")))
            }
            if let name = source["Name"] as? String { rows.append((tl("电源"), name)) }
            if let temp = source["Temperature"] as? Int { rows.append((tl("温度"), "\(Double(temp) / 10.0) °C")) }
        }
        if rows.isEmpty { rows.append((tl("电源"), tl("未返回数据（沙盒或接口不可用）"))) }
        return rows
    }

    static func interfaces() -> [(String, String)] {
        var rows: [(String, String)] = []
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return [(tl("网络"), tl("getifaddrs 失败"))] }
        defer { freeifaddrs(addrs) }
        var seen = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cursor {
            let ifa = p.pointee
            let name = String(cString: ifa.ifa_name)
            if !seen.contains(name), let addr = ifa.ifa_addr {
                let family = addr.pointee.sa_family
                if family == UInt8(AF_INET) || family == UInt8(AF_INET6) {
                    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count),
                                   nil, 0, NI_NUMERICHOST) == 0 {
                        let text = String(cString: host)
                        if !text.hasPrefix("fe80") && text != "::1" && text != "127.0.0.1" {
                            rows.append((name, text))
                            seen.insert(name)
                        }
                    }
                }
            }
            cursor = ifa.ifa_next
        }
        return rows.isEmpty ? [(tl("网络"), tl("无外部地址"))] : rows
    }

    static func thermal() -> [(String, String)] {
        var rows: [(String, String)] = []
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: rows.append((tl("热状态"), "nominal"))
        case .fair: rows.append((tl("热状态"), "fair"))
        case .serious: rows.append((tl("热状态"), "serious"))
        case .critical: rows.append((tl("热状态"), "critical"))
        @unknown default: rows.append((tl("热状态"), "unknown"))
        }
        rows.append((tl("低电量模式"), ProcessInfo.processInfo.isLowPowerModeEnabled ? tl("开") : tl("关")))
        rows.append((tl("物理内存"), ByteCountFormatter.string(fromByteCount: Int64(ProcessInfo.processInfo.physicalMemory), countStyle: .memory)))
        if let stats = Mach.vmStats() {
            rows.append((tl("空闲"), ByteCountFormatter.string(fromByteCount: Int64(stats.free), countStyle: .memory)))
            rows.append((tl("活跃"), ByteCountFormatter.string(fromByteCount: Int64(stats.active), countStyle: .memory)))
            rows.append((tl("联动"), ByteCountFormatter.string(fromByteCount: Int64(stats.wired), countStyle: .memory)))
        }
        rows.append((tl("运行时长"), uptimeString()))
        return rows
    }

    private static func uptimeString() -> String {
        var boottime = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &boottime, &size, nil, 0) == 0 else { return "—" }
        let uptime = Date().timeIntervalSince1970 - Double(boottime.tv_sec)
        let h = Int(uptime) / 3600
        let m = (Int(uptime) % 3600) / 60
        return "\(h)h \(m)m"
    }
}

// MARK: - Provisioning profile census

enum ProfileCensus {
    struct Profile {
        var name: String
        var uuid: String
        var teamID: String
        var appID: String
        var expires: Date?
        var devices: Int
        var entitlements: [String]
        var path: String
    }

    static func installed() -> [Profile] {
        let dirs = ["/private/var/MobileDevice/ProvisioningProfiles",
                    "/private/var/mobile/Library/MobileDevice/ProvisioningProfiles"]
        var out: [Profile] = []
        for dir in dirs {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for name in names where name.hasSuffix(".mobileprovision") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let text = String(data: data, encoding: .isoLatin1),
                      let start = text.range(of: "<?xml"),
                      let end = text.range(of: "</plist>") else { continue }
                let xml = String(text[start.lowerBound..<end.upperBound])
                guard let plistData = xml.data(using: .utf8),
                      let obj = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] else { continue }
                let ents = obj["Entitlements"] as? [String: Any] ?? [:]
                out.append(Profile(
                    name: obj["Name"] as? String ?? name,
                    uuid: obj["UUID"] as? String ?? "—",
                    teamID: (obj["TeamIdentifier"] as? [String])?.first ?? "—",
                    appID: ents["application-identifier"] as? String ?? "—",
                    expires: obj["ExpirationDate"] as? Date,
                    devices: (obj["ProvisionedDevices"] as? [String])?.count ?? 0,
                    entitlements: ents.keys.sorted(),
                    path: path))
            }
        }
        return out
    }
}
