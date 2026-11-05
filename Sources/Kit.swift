import Foundation
import Darwin
import UIKit

// MARK: - Byte helpers

enum B {
    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
    static func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8 & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
    }
    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xff), UInt8(v >> 8 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 24 & 0xff)]
    }
    static func be64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (56 - UInt64($0) * 8)) & 0xff) }
    }
    static func le64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (UInt64($0) * 8)) & 0xff) }
    }
    static func both16(_ v: UInt16) -> [UInt8] { le16(v) + be16(v) }
    static func both32(_ v: UInt32) -> [UInt8] { le32(v) + be32(v) }
    static func ascii(_ s: String) -> [UInt8] { Array(s.utf8) }
}

func hexdump(_ data: Data, limit: Int = 4096) -> String {
    let bytes = [UInt8](data.prefix(limit))
    var out = ""
    var offset = 0
    while offset < bytes.count {
        let end = min(offset + 16, bytes.count)
        let slice = bytes[offset..<end]
        let hex = slice.map { String(format: "%02x", $0) }.enumerated()
            .map { $0.offset == 7 ? $0.element + " " : $0.element }
            .joined(separator: " ")
        let ascii = slice.map { ($0 >= 0x20 && $0 < 0x7f) ? String(UnicodeScalar($0)) : "." }.joined()
        out += String(format: "%08x  ", offset) + hex.padding(toLength: 48, withPad: " ", startingAt: 0) + "  " + ascii + "\n"
        offset = end
    }
    if data.count > limit { out += "... (\(data.count) bytes total)\n" }
    return out
}

// MARK: - sysctl

func sysctlString(_ name: String) -> String? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var buffer = [CChar](repeating: 0, count: size + 1)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
    return String(cString: buffer)
}

func sysctlUInt64(_ name: String) -> UInt64? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size == 8 else { return nil }
    var value: UInt64 = 0
    var localSize = size
    guard sysctlbyname(name, &value, &localSize, nil, 0) == 0 else { return nil }
    return value
}

// MARK: - dlsym

final class DyLib {
    static let shared = DyLib()
    private var handles: [String: UnsafeMutableRawPointer] = [:]
    private let lock = NSLock()

    func handle(_ path: String) -> UnsafeMutableRawPointer? {
        lock.lock(); defer { lock.unlock() }
        if let h = handles[path] { return h }
        guard let h = dlopen(path, RTLD_NOW | RTLD_GLOBAL) else { return nil }
        handles[path] = h
        return h
    }

    /// Resolve a symbol across the shared cache libraries we care about.
    func symbol(_ name: String, in libraries: [String] = DyLib.defaultLibraries) -> UnsafeMutableRawPointer? {
        if let direct = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) { return direct }
        for lib in libraries {
            if let h = handle(lib), let s = dlsym(h, name) { return s }
        }
        return nil
    }

    static let defaultLibraries = [
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
        "/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox",
        "/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
        "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore",
        "/usr/lib/libarchive.2.dylib",
        "/System/Library/Frameworks/Accelerate.framework/Accelerate",
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        "/System/Library/Frameworks/Security.framework/Security",
        "/usr/lib/libcompression.dylib",
    ]
}

// MARK: - csops / codesign state

enum CodeSign {
    struct State {
        var flags: UInt32 = 0
        var valid: Bool = false
        var descriptions: [String] = []
    }

    static func current() -> State {
        var st = State()
        guard let sym = DyLib.shared.symbol("csops") else { return st }
        typealias Fn = @convention(c) (pid_t, UInt32, UnsafeMutableRawPointer?, Int) -> Int32
        let fn = unsafeBitCast(sym, to: Fn.self)
        var flags: UInt32 = 0
        let rc = withUnsafeMutablePointer(to: &flags) { ptr -> Int32 in
            fn(getpid(), 0, UnsafeMutableRawPointer(ptr), MemoryLayout<UInt32>.size)
        }
        guard rc == 0 else { return st }
        st.flags = flags
        st.valid = true
        let names: [(UInt32, String)] = [
            (0x00000001, "CS_VALID"),
            (0x00000002, "CS_ADHOC"),
            (0x00000004, "CS_GET_TASK_ALLOW"),
            (0x00000008, "CS_INSTALLER"),
            (0x00000010, "CS_HARD"),
            (0x00000020, "CS_KILL"),
            (0x00000040, "CS_CHECK_EXPIRATION"),
            (0x00000080, "CS_RESTRICT"),
            (0x00000100, "CS_ENFORCEMENT"),
            (0x00000200, "CS_REQUIRE_LV"),
            (0x00000400, "CS_ENTITLEMENTS_VALIDATED"),
            (0x00000800, "CS_NVRAM_UNRESTRICTED"),
            (0x00001000, "CS_RUNTIME"),
            (0x00002000, "CS_LINKER_SIGNED"),
        ]
        st.descriptions = names.filter { flags & $0.0 != 0 }.map { $0.1 }
        return st
    }
}

// MARK: - entitlements (in-process)

enum Entitlements {
    static func dump() -> [String: Any] {
        guard let createSym = DyLib.shared.symbol("SecTaskCreateFromSelf"),
              let copySym = DyLib.shared.symbol("SecTaskCopyValueForEntitlement") else { return [:] }
        typealias CreateFn = @convention(c) (CFAllocator?) -> CFTypeRef?
        typealias CopyFn = @convention(c) (CFTypeRef?, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFTypeRef?
        let create = unsafeBitCast(createSym, to: CreateFn.self)
        let copy = unsafeBitCast(copySym, to: CopyFn.self)
        guard let task = create(nil) else { return [:] }
        guard let value = copy(task, "entitlements" as CFString, nil) else { return [:] }
        return (value as? [String: Any]) ?? [:]
    }
}

// MARK: - Path reachability

struct PathProbe: Identifiable, Hashable {
    let id = UUID()
    let path: String
    let readable: Bool
    let writable: Bool
    let entryCount: Int
    let errno: Int32
    let note: String
}

enum Probe {
    static func path(_ rawPath: String) -> PathProbe {
        let fm = FileManager.default
        let p = Container.normalize(rawPath)
        var readable = false
        var writable = false
        var count = 0
        var err: Int32 = 0
        var note = ""

        if let listing = try? fm.contentsOfDirectory(atPath: p) {
            readable = true
            count = listing.count
        } else {
            err = errno
            if fm.fileExists(atPath: p) { readable = true }
        }

        // isWritableFile is access(W_OK) — the sandbox answers that against the vnode path,
        // not against the extension the app actually holds. Probe by writing instead, but
        // only inside paths we are allowed to touch at all (never create files in /System).
        let insideContainer = p.hasPrefix(Container.rootPath)
        if insideContainer {
            writable = Container.probe(URL(fileURLWithPath: p, isDirectory: true)).canWrite
        } else if readable {
            writable = fm.isWritableFile(atPath: p)
        }

        if !readable {
            switch err {
            case EACCES: note = tl("EPERM — 沙盒拒绝")
            case ENOENT: note = tl("不存在")
            case ENOTDIR: note = tl("路径中间不是目录")
            default: note = Container.describe(err)
            }
        } else if !writable {
            note = insideContainer ? tl("只读（探针未通过）") : tl("只读")
        } else {
            note = tl("可写")
        }
        return PathProbe(path: p, readable: readable, writable: writable,
                         entryCount: count, errno: err, note: note)
    }

    static let interestingRoots = [
        "/",
        "/System",
        "/System/Library",
        "/System/Library/CoreServices",
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
        "/System/Library/Extensions",
        "/System/Library/LaunchDaemons",
        "/usr",
        "/usr/lib",
        "/usr/bin",
        "/usr/share",
        "/private/etc",
        "/private/var",
        "/private/var/mobile",
        "/private/var/mobile/Library",
        "/private/var/mobile/Containers",
        "/private/var/mobile/Containers/Data",
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/mobile/Media",
        "/private/var/db",
        "/private/var/jb",
        "/private/preboot",
        "/tmp",
        "/var/tmp",
        "/dev",
        "/cores",
    ]
}

// MARK: - Mach / kernel interface

enum Mach {
    static func taskSelf() -> mach_port_t { mach_task_self_ }

    /// Host statistics page size etc. Cheap, always allowed.
    static func vmStats() -> (free: UInt64, active: UInt64, wired: UInt64)? {
        var stats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &stats) { ptr -> kern_return_t in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, intPtr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let pageSize = UInt64(vm_kernel_page_size)
        return (UInt64(stats.free_count) * pageSize,
                UInt64(stats.active_count) * pageSize,
                UInt64(stats.wire_count) * pageSize)
    }
}

// MARK: - Device model

struct DeviceModel {
    let machine: String
    let hwModel: String
    let osVersion: String
    let osBuild: String
    let kernel: String
    let cpuCount: Int
    let physicalMemory: UInt64
    let displayName: String

    var marketingName: String {
        let table: [String: String] = [
            "iPhone17,1": "iPhone 16 Pro",
            "iPhone17,2": "iPhone 16 Pro Max",
            "iPhone17,3": "iPhone 16",
            "iPhone17,4": "iPhone 16 Plus",
            "iPhone17,5": "iPhone 16e",
            "iPhone18,1": "iPhone 17 Pro",
            "iPhone18,2": "iPhone 17 Pro Max",
            "iPhone18,3": "iPhone 17",
            "iPhone18,4": "iPhone 17 Air",
            "iPhone19,1": "iPhone 18 Pro",
            "iPhone19,2": "iPhone 18 Pro Max",
            "iPhone19,3": "iPhone 18",
            "iPhone19,4": "iPhone 18 Air",
            "iPhone19,7": "iPhone 18 Pro Max",
        ]
        return table[machine] ?? machine
    }

    /// The 27.2 fix window. Everything strictly below 27.2 carries the whole CVE set.
    /// Mirrors VersionGate: 17.0 through 27.1 carry the live bugs, 27.2+ carries the fixes.
    var vulnerabilityClass: String {
        let parts = osVersion.split(separator: ".").compactMap { Int($0) }
        guard let major = parts.first else { return "UNKNOWN" }
        let minor = parts.count > 1 ? parts[1] : 0
        if major < 17 { return "UNKNOWN" }
        if major < 27 { return "VULNERABLE" }
        if major == 27 { return minor < 2 ? "VULNERABLE" : "PATCHED" }
        return "PATCHED"
    }

    var buildHint: String {
        switch vulnerabilityClass {
        case "VULNERABLE": return "Pre-27.2 build — all 82 localized fixes are live"
        case "PATCHED": return "27.2 or later — the gate wave is in place"
        default: return "unclassified build"
        }
    }

    static func current() -> DeviceModel {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return DeviceModel(
            machine: sysctlString("hw.machine") ?? "unknown",
            hwModel: sysctlString("hw.model") ?? "unknown",
            osVersion: "\(v.majorVersion).\(v.minorVersion)" + (v.patchVersion != 0 ? ".\(v.patchVersion)" : ""),
            osBuild: sysctlString("kern.osversion") ?? "unknown",
            kernel: sysctlString("kern.version") ?? "unknown",
            cpuCount: ProcessInfo.processInfo.processorCount,
            physicalMemory: ProcessInfo.processInfo.physicalMemory,
            displayName: UIDevice.current.name
        )
    }
}
