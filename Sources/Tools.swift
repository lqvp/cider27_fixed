import Foundation
import UIKit
import Darwin
import MachO

// MARK: - Installed application census (LSApplicationWorkspace)

struct InstalledApp: Identifiable, Hashable {
    var id: String { bundleID }
    let bundleID: String
    let name: String
    let version: String
    let bundlePath: String
    let dataPath: String
    let isSystem: Bool
    let isPlaceholder: Bool

    var displayName: String { name.isEmpty ? bundleID : name }
}

enum AppCensus {
    typealias DefaultWorkspaceFn = @convention(c) () -> AnyObject?
    typealias AllAppsFn = @convention(c) (AnyObject, Selector) -> AnyObject?

    /// LSApplicationWorkspace is private; call it through the ObjC runtime so nothing
    /// has to be linked at build time.
    static func installed() -> [InstalledApp] {
        guard let cls = NSClassFromString("LSApplicationWorkspace") as? NSObject.Type else { return [] }
        let sel = NSSelectorFromString("defaultWorkspace")
        guard cls.responds(to: sel) else { return [] }
        let workspace = cls.perform(sel)?.takeUnretainedValue()
        guard let ws = workspace else { return [] }

        let allSel = NSSelectorFromString("allInstalledApplications")
        guard ws.responds(to: allSel), let proxy = ws.perform(allSel)?.takeUnretainedValue() else { return [] }
        let array = proxy as? [AnyObject] ?? []

        var out: [InstalledApp] = []
        for item in array {
            let obj = item as AnyObject
            func str(_ name: String) -> String {
                let s = NSSelectorFromString(name)
                guard obj.responds(to: s) else { return "" }
                return (obj.perform(s)?.takeUnretainedValue() as? String) ?? ""
            }
            func url(_ name: String) -> String {
                let s = NSSelectorFromString(name)
                guard obj.responds(to: s) else { return "" }
                return ((obj.perform(s)?.takeUnretainedValue()) as? NSURL)?.path ?? ""
            }
            let bid = str("bundleIdentifier")
            guard !bid.isEmpty else { continue }
            out.append(InstalledApp(
                bundleID: bid,
                name: str("localizedName"),
                version: str("shortVersionString"),
                bundlePath: url("bundleURL"),
                dataPath: url("dataContainerURL"),
                isSystem: str("applicationType").contains("System"),
                isPlaceholder: str("applicationType").contains("Placeholder")))
        }
        return out.sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    /// Read an app's Info.plist even when its bundle path is unreadable, by asking the
    /// installation machinery for the metadata dictionary instead of the file.
    static func metadata(for bundleID: String) -> [String: Any] {
        guard let cls = NSClassFromString("LSApplicationProxy") as? NSObject.Type else { return [:] }
        let sel = NSSelectorFromString("applicationProxyForIdentifier:")
        guard cls.responds(to: sel) else { return [:] }
        guard let proxy = cls.perform(sel, with: bundleID)?.takeUnretainedValue() else { return [:] }
        let obj = proxy as AnyObject
        let dictSel = NSSelectorFromString("entitlements")
        var out: [String: Any] = [:]
        if obj.responds(to: dictSel) {
            out["entitlements"] = obj.perform(dictSel)?.takeUnretainedValue()
        }
        let groupSel = NSSelectorFromString("groupContainerURLs")
        if obj.responds(to: groupSel) {
            out["groupContainers"] = obj.perform(groupSel)?.takeUnretainedValue()
        }
        return out
    }
}

// MARK: - Process list (sysctl)

struct ProcInfo: Identifiable {
    var id: Int32 { pid }
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let name: String
    let command: String
}

enum ProcList {
    static func snapshot() -> [ProcInfo] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 4, &buffer, &size, nil, 0) == 0 else { return [] }

        let count = size / MemoryLayout<kinfo_proc>.stride
        return buffer.withUnsafeBytes { raw -> [ProcInfo] in
            guard let base = raw.baseAddress else { return [] }
            var out: [ProcInfo] = []
            for i in 0..<count {
                let kp = base.advanced(by: i * MemoryLayout<kinfo_proc>.stride)
                    .assumingMemoryBound(to: kinfo_proc.self).pointee
                let pid = kp.kp_proc.p_pid
                if pid <= 0 { continue }
                let name = withUnsafeBytes(of: kp.kp_proc.p_comm) { buf -> String in
                    let bytes = buf.prefix(while: { $0 != 0 })
                    return String(decoding: bytes, as: UTF8.self)
                }
                out.append(ProcInfo(pid: pid,
                                    ppid: kp.kp_eproc.e_ppid,
                                    uid: kp.kp_eproc.e_ucred.cr_uid,
                                    name: name,
                                    command: name))
            }
            return out.sorted { $0.pid < $1.pid }
        }
    }
}

// MARK: - Launch services / daemon census

enum LaunchCensus {
    struct Daemon: Identifiable {
        var id: String { path }
        let path: String
        let label: String
        let program: String
        let runAtLoad: Bool
        let keepAlive: Bool
    }

    static func daemons() -> [Daemon] {
        let dirs = ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents",
                    "/Library/LaunchDaemons", "/private/var/jb/Library/LaunchDaemons"]
        var out: [Daemon] = []
        for dir in dirs {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for name in names where name.hasSuffix(".plist") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                    continue
                }
                let args = obj["ProgramArguments"] as? [String] ?? []
                out.append(Daemon(path: path,
                                  label: obj["Label"] as? String ?? name,
                                  program: obj["Program"] as? String ?? args.first ?? "",
                                  runAtLoad: (obj["RunAtLoad"] as? Bool) ?? false,
                                  keepAlive: (obj["KeepAlive"] as? Bool) ?? false))
            }
        }
        return out
    }
}

// MARK: - Keychain / identity surface

enum Identity {
    static func summary() -> [(String, String)] {
        var rows: [(String, String)] = []
        rows.append((tl("UDID (设备)"), sysctlString("kern.uuid") ?? "—"))
        rows.append((tl("机型"), sysctlString("hw.machine") ?? "—"))
        rows.append((tl("硬件型号"), sysctlString("hw.model") ?? "—"))
        rows.append((tl("序列号可读"), tl("否（需 IOKit 平台 Expert 接口）")))
        rows.append((tl("主机名"), sysctlString("kern.hostname") ?? "—"))
        rows.append((tl("启动 UUID"), sysctlString("kern.bootsessionuuid") ?? "—"))
        rows.append((tl("启动时间"), sysctlString("kern.boottime") ?? "—"))
        rows.append((tl("市场名称"), DeviceModel.current().marketingName))
        rows.append((tl("广告标识符"), ASIdentifierSummary.current))
        return rows
    }
}

enum ASIdentifierSummary {
    static var current: String {
        // ASIdentifierManager is in AdSupport; read through the runtime so nothing is linked.
        guard let cls = NSClassFromString("ASIdentifierManager") as? NSObject.Type else { return tl("不可用") }
        let sel = NSSelectorFromString("sharedManager")
        guard cls.responds(to: sel), let mgr = cls.perform(sel)?.takeUnretainedValue() else { return tl("不可用") }
        let uuidSel = NSSelectorFromString("advertisingIdentifier")
        guard (mgr as AnyObject).responds(to: uuidSel),
              let uuid = (mgr as AnyObject).perform(uuidSel)?.takeUnretainedValue() else { return tl("不可用") }
        return "\(uuid)"
    }
}

// MARK: - Crash log reader

struct CrashReport: Identifiable {
    var id: String { path }
    let path: String
    let name: String
    let date: Date?
    let process: String
    let exception: String
    let faultingSymbol: String
    let frames: [String]
    let size: Int
}

enum CrashLogs {
    static func searchPaths() -> [String] {
        var paths: [String] = []
        let home = NSHomeDirectory()
        paths.append(home + "/Library/Logs/DiagnosticReports")
        paths.append(home + "/Library/Logs/CrashReporter")
        paths.append("/private/var/mobile/Library/Logs/CrashReporter")
        paths.append("/private/var/mobile/Library/Logs/DiagnosticReports")
        return paths
    }

    static func list() -> [CrashReport] {
        let fm = FileManager.default
        var out: [CrashReport] = []
        for dir in searchPaths() {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in names where name.hasSuffix(".ips") || name.hasSuffix(".crash") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let attrs = try? fm.attributesOfItem(atPath: path) else { continue }
                let size = (attrs[.size] as? NSNumber)?.intValue ?? 0
                let date = attrs[.modificationDate] as? Date
                var process = ""
                var exception = ""
                var fault = ""
                var frames: [String] = []
                if let data = try? Data(contentsOf: URL(fileURLWithPath: path)), data.count < 8_000_000 {
                    if let parsed = parse(data) {
                        process = parsed.process
                        exception = parsed.exception
                        fault = parsed.fault
                        frames = parsed.frames
                    }
                }
                out.append(CrashReport(path: path, name: name, date: date, process: process,
                                       exception: exception, faultingSymbol: fault,
                                       frames: frames, size: size))
            }
        }
        return out.sorted { ($0.date ?? .distantPast) > ($1.date ?? .distantPast) }
    }

    private static func parse(_ data: Data) -> (process: String, exception: String, fault: String, frames: [String])? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let bodyData = parts[1].data(using: .utf8),
              let body = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] else {
            // legacy .crash text format
            let lines = text.split(separator: "\n").map(String.init)
            let proc = lines.first ?? ""
            let exc = lines.first(where: { $0.contains("Exception Type") }) ?? ""
            return (proc, exc, "", [])
        }
        let process = (body["procName"] as? String) ?? ""
        var exception = ""
        if let e = body["exception"] as? [String: Any] {
            let type = e["type"] as? String ?? ""
            let sub = e["subtype"] as? String ?? ""
            exception = sub.isEmpty ? type : "\(type) — \(sub)"
        }
        var frames: [String] = []
        var fault = ""
        let images = body["usedImages"] as? [[String: Any]] ?? []
        if let threads = body["threads"] as? [[String: Any]],
           let idx = body["faultingThread"] as? Int, idx < threads.count {
            let thread = threads[idx]
            if let fs = thread["frames"] as? [[String: Any]] {
                for f in fs.prefix(14) {
                    let imageIdx = f["imageIndex"] as? Int ?? 0
                    let image = imageIdx < images.count ? (images[imageIdx]["name"] as? String ?? "?") : "?"
                    let symbol = f["symbol"] as? String ?? ""
                    frames.append(symbol.isEmpty ? image : "\(image) · \(symbol)")
                }
                fault = frames.first ?? ""
            }
        }
        return (process, exception, fault, frames)
    }
}

// MARK: - Unified log reader

struct LogLine: Identifiable {
    var id = UUID()
    let time: Date
    let process: String
    let subsystem: String
    let message: String
}

enum UnifiedLog {
    /// OSLogStore is private-ish but reachable from an app for its own process scope.
    static func recent(minutes: Int = 5, limit: Int = 300) -> [LogLine] {
        guard let cls = NSClassFromString("OSLogStore") as? NSObject.Type else { return [] }
        let localSel = NSSelectorFromString("localStoreAndReturnError:")
        guard cls.responds(to: localSel) else { return [] }
        let store = cls.perform(localSel, with: nil)?.takeUnretainedValue()
        guard let storeObj = store as AnyObject? else { return [] }

        let posSel = NSSelectorFromString("positionWithDate:")
        guard storeObj.responds(to: posSel),
              let pos = storeObj.perform(posSel, with: Date().addingTimeInterval(-Double(minutes) * 60))?
                .takeUnretainedValue() else { return [] }

        let entriesSel = NSSelectorFromString("entriesFromPosition:to:options:error:")
        guard storeObj.responds(to: entriesSel) else { return [] }
        // Build the invocation-free path: entriesFromPosition:to:options:error: needs four
        // args, which perform(_:with:) cannot express. Fall back to the one-arg variant.
        let simpleSel = NSSelectorFromString("entriesEnumeratorWithOptions:position:predicate:error:")
        guard storeObj.responds(to: simpleSel) else { return [] }

        var out: [LogLine] = []
        guard let enumerator = storeObj.perform(simpleSel, with: pos)?.takeUnretainedValue() as? NSEnumerator else {
            return []
        }
        while let entry = enumerator.nextObject() as AnyObject? {
            if out.count >= limit { break }
            let dateSel = NSSelectorFromString("date")
            let compSel = NSSelectorFromString("composedMessage")
            let procSel = NSSelectorFromString("processIdentifier")
            let date = (entry.responds(to: dateSel) ? entry.perform(dateSel)?.takeUnretainedValue() as? Date : nil) ?? Date()
            let message = (entry.responds(to: compSel) ? entry.perform(compSel)?.takeUnretainedValue() as? String : nil) ?? ""
            let pid = (entry.responds(to: procSel) ? entry.perform(procSel)?.takeUnretainedValue() as? Int32 : nil) ?? 0
            guard !message.isEmpty else { continue }
            out.append(LogLine(time: date, process: "\(pid)", subsystem: "", message: message))
        }
        return out
    }
}

// MARK: - Binary inspector

struct MachOInfo {
    var arch: String = "—"
    var fileType: String = "—"
    var platform: String = "—"
    var minOS: String = "—"
    var sdk: String = "—"
    var isEncrypted: Bool = false
    var cryptID: UInt32 = 0
    var linkedLibraries: [String] = []
    var rpaths: [String] = []
    var entitlements: [String] = []
    var isFat: Bool = false
}

enum MachOInspector {
    static func inspect(_ path: String) -> MachOInfo? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        // a Mach-O header needs at least the magic; anything shorter is not one. The
        // load below would read past the buffer (or hit a nil base on empty Data).
        guard data.count >= 4 else { return nil }
        var info = MachOInfo()

        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        let fatMagic: UInt32 = 0xCAFEBABE
        let fatMagic64: UInt32 = 0xCAFEBABF
        if magic == fatMagic || magic == fatMagic64 {
            info.isFat = true
            return info
        }

        guard let header = parseHeader(data) else { return nil }
        info.arch = header.arch
        info.fileType = header.fileType
        info.platform = header.platform
        info.minOS = header.minOS
        info.sdk = header.sdk
        info.isEncrypted = header.cryptID != 0
        info.cryptID = header.cryptID
        info.linkedLibraries = header.libraries
        info.rpaths = header.rpaths
        return info
    }

    private struct Header {
        var arch = "—"
        var fileType = "—"
        var platform = "—"
        var minOS = "—"
        var sdk = "—"
        var cryptID: UInt32 = 0
        var libraries: [String] = []
        var rpaths: [String] = []
    }

    private static func parseHeader(_ data: Data) -> Header? {
        guard data.count > 32 else { return nil }
        var h = Header()
        let cputype = data.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
        switch cputype {
        case 0x0100_000C: h.arch = "arm64"
        case 0x0100_0007: h.arch = "x86_64"
        case 0x0000_000C: h.arch = "armv7"
        default: h.arch = "0x" + String(cputype, radix: 16)
        }
        let filetype = data.withUnsafeBytes { $0.load(fromByteOffset: 12, as: UInt32.self) }
        switch filetype {
        case 2: h.fileType = "MH_EXECUTE"
        case 6: h.fileType = "MH_DYLIB"
        case 8: h.fileType = "MH_BUNDLE"
        case 1: h.fileType = "MH_OBJECT"
        default: h.fileType = "type \(filetype)"
        }

        let ncmds = data.withUnsafeBytes { $0.load(fromByteOffset: 16, as: UInt32.self) }
        var offset = 32
        for _ in 0..<min(Int(ncmds), 4096) {
            guard offset + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            let size = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 4, as: UInt32.self) }
            guard size >= 8, offset + Int(size) <= data.count else { break }

            switch cmd {
            case 0x32: // LC_BUILD_VERSION
                if offset + 16 <= data.count {
                    let platform = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 8, as: UInt32.self) }
                    let minos = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 12, as: UInt32.self) }
                    h.platform = platformName(platform)
                    h.minOS = versionString(minos)
                    if offset + 20 <= data.count {
                        let sdk = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 16, as: UInt32.self) }
                        h.sdk = versionString(sdk)
                    }
                }
            case 0x24: // LC_VERSION_MIN_IPHONEOS
                if offset + 12 <= data.count {
                    h.platform = "iOS"
                    let minos = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 8, as: UInt32.self) }
                    h.minOS = versionString(minos)
                }
            case 0x21C: // LC_ENCRYPTION_INFO_64
                if offset + 20 <= data.count {
                    h.cryptID = data.withUnsafeBytes { $0.load(fromByteOffset: offset + 16, as: UInt32.self) }
                }
            case 0xC: // LC_LOAD_DYLIB
                if let s = string(in: data, at: offset + 24, limit: offset + Int(size)) {
                    h.libraries.append((s as NSString).lastPathComponent)
                }
            case 0x1C: // LC_RPATH
                if let s = string(in: data, at: offset + 12, limit: offset + Int(size)) {
                    h.rpaths.append(s)
                }
            default:
                break
            }
            offset += Int(size)
        }
        return h
    }

    private static func string(in data: Data, at offset: Int, limit: Int) -> String? {
        guard offset < data.count, offset < limit else { return nil }
        var bytes: [UInt8] = []
        var i = offset
        while i < min(limit, data.count), data[i] != 0 {
            bytes.append(data[i])
            i += 1
        }
        return bytes.isEmpty ? nil : String(decoding: bytes, as: UTF8.self)
    }

    private static func platformName(_ v: UInt32) -> String {
        switch v {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 6: return "Mac Catalyst"
        case 7: return "iOS Simulator"
        case 11: return "visionOS"
        default: return "platform \(v)"
        }
    }

    private static func versionString(_ v: UInt32) -> String {
        "\(v >> 16).\((v >> 8) & 0xff).\(v & 0xff)"
    }
}
