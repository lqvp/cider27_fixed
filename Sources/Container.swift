import Foundation
import Darwin

// MARK: - Container resolution, creation and write verification
//
// Why container writes fail, in the order they actually bite:
//
// 1. The URL you get from FileManager is a *promise*, not a directory. On a fresh install
//    only Documents, Library, Library/Caches, Library/Preferences, SystemData and tmp
//    exist. `Application Support`, `Library/NoCloud`, `Library/WebKit` and anything you
//    invent do NOT — and `Data.write(options: .atomic)` returns ENOENT, not "permission
//    denied", because the parent is missing. That reads like a sandbox failure and isn't.
//
//    Two paths are deliberately absent from the probe list: the container root itself and
//    SystemData. Both exist and are readable, but neither accepts newly created files on
//    iOS — a write probe there returns EPERM on a perfectly healthy container. Probing
//    them measures the wrong thing, so the list starts at Documents.
//
// 2. `isWritableFile(atPath:)` is `access(W_OK)`, which the sandbox answers against the
//    vnode path, not against your sandbox extension. It reports false for directories the
//    app can absolutely write to. It is a bad probe; a real create/write/fsync/read-back
//    cycle is the only honest one.
//
// 3. Container UUIDs change on reinstall. A path captured earlier —
//    /var/mobile/Containers/Data/Application/<OLD-UUID>/Documents — is a dead path that
//    returns ENOENT even though "the container" plainly exists. Every stored path has to be
//    re-rooted against the live container before use.
//
// 4. Library/Preferences is owned by cfprefsd. Writes land on disk but cfprefsd holds the
//    authoritative cache and will overwrite them; use UserDefaults for your own keys, and
//    treat direct plist writes there as a cold-storage edit that only takes effect on next
//    launch (and never for other apps' domains).
//
// This file makes all four explicit and repairable.

struct ContainerProbe {
    var url: URL
    var exists: Bool
    var canCreate: Bool
    var canWrite: Bool
    var canReadBack: Bool
    var errno: Int32
    var note: String

    var ok: Bool { exists && canWrite && canReadBack }

    var symbol: String {
        if ok { return "checkmark.circle.fill" }
        if exists { return "exclamationmark.triangle.fill" }
        return "xmark.circle"
    }
}

enum Container {

    /// The live data container root. Never hard-code this — it changes on reinstall.
    static var root: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
    }

    static var rootPath: String { NSHomeDirectory() }

    /// Every directory the tooling writes into, with the API base it hangs off and the
    /// suffix beneath that base. Resolving this way is what makes `Application Support`
    /// and everything under it actually exist — the URL alone is only a promise.
    struct Standard {
        enum Base {
            case container, documents, library, appSupport, caches, tmp
        }
        /// Stable ASCII lookup key — never changes with language.
        let id: String
        /// Display name. Chinese is the source; English comes from RuntimeText.
        let name: String
        let base: Base
        let suffix: String

        init(id: String, name: String, base: Base, suffix: String = "") {
            self.id = id
            self.name = name
            self.base = base
            self.suffix = suffix
        }
    }

    static let standards: [Standard] = [
        Standard(id: "documents", name: "Documents", base: .documents),
        Standard(id: "library", name: "Library", base: .library),
        Standard(id: "appsupport", name: "Application Support", base: .appSupport),
        Standard(id: "caches", name: "Caches", base: .caches),
        Standard(id: "preferences", name: "Preferences", base: .library, suffix: "Preferences"),
        Standard(id: "tmp", name: "tmp", base: .tmp),
        Standard(id: "nocloud", name: "NoCloud", base: .appSupport, suffix: "NoCloud"),
        Standard(id: "webkit", name: "WebKit", base: .library, suffix: "WebKit"),
        Standard(id: "cinder27", name: "Cinder27", base: .appSupport, suffix: "Cinder27"),
        Standard(id: "work", name: tl("工作区"), base: .appSupport, suffix: "Cinder27/work"),
        Standard(id: "backups", name: tl("备份"), base: .documents, suffix: "Cinder27/Backups"),
        Standard(id: "ipa", name: tl("IPA 产出"), base: .documents, suffix: "Cinder27/IPA"),
    ]

    /// Resolve a standard directory to its *full* path and create it. The API gives the
    /// base; the suffix is appended and mkdir -p'd, which is the part that was missing.
    static func resolve(_ standard: Standard) -> URL {
        let fm = FileManager.default
        var base: URL
        switch standard.base {
        case .container:
            base = root
        case .documents:
            base = (try? fm.url(for: .documentDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))
                ?? root.appendingPathComponent("Documents", isDirectory: true)
        case .library:
            base = (try? fm.url(for: .libraryDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))
                ?? root.appendingPathComponent("Library", isDirectory: true)
        case .appSupport:
            base = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))
                ?? root.appendingPathComponent("Library/Application Support", isDirectory: true)
        case .caches:
            base = (try? fm.url(for: .cachesDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))
                ?? root.appendingPathComponent("Library/Caches", isDirectory: true)
        case .tmp:
            base = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        }
        let full = standard.suffix.isEmpty
            ? base
            : base.appendingPathComponent(standard.suffix, isDirectory: true)
        try? fm.createDirectory(at: full, withIntermediateDirectories: true)
        return full
    }

    static func named(_ id: String) -> URL {
        if let match = standards.first(where: { $0.id == id }) { return resolve(match) }
        return documents
    }

    /// Convenience accessors — everything else should use these instead of index lookups.
    static var documents: URL { named("documents") }
    static var appSupport: URL { named("appsupport") }
    static var work: URL { named("work") }
    static var backups: URL { named("backups") }
    static var ipaOutput: URL { named("ipa") }

    /// Create every standard directory. Idempotent, safe to call on every launch.
    @discardableResult
    static func ensureAll() -> [String] {
        var created: [String] = []
        let fm = FileManager.default
        for standard in standards {
            let url = resolve(standard)
            if !fm.fileExists(atPath: url.path) {
                try? fm.createDirectory(at: url, withIntermediateDirectories: true)
                created.append(tl(standard.name))
            }
        }
        return created
    }

    // MARK: - Real write probe

    /// Create a file, write, fsync, read it back, compare, unlink. Anything less than this
    /// is a guess about the sandbox.
    static func probe(_ url: URL) -> ContainerProbe {
        let fm = FileManager.default
        var result = ContainerProbe(url: url, exists: false, canCreate: false,
                                    canWrite: false, canReadBack: false,
                                    errno: 0, note: "")

        var isDir: ObjCBool = false
        result.exists = fm.fileExists(atPath: url.path, isDirectory: &isDir) && isDir.boolValue

        if !result.exists {
            do {
                try fm.createDirectory(at: url, withIntermediateDirectories: true)
                result.canCreate = true
                result.exists = true
            } catch {
                result.errno = errno
                result.note = tl("mkdir 失败: ") + "\(describe(result.errno))"
                return result
            }
        } else {
            result.canCreate = true
        }

        let probeFile = url.appendingPathComponent(".cinder27-probe-\(UInt32.random(in: 0...UInt32.max))")
        let payload = Data("cinder27-write-probe".utf8)

        do {
            try payload.write(to: probeFile, options: .atomic)
            result.canWrite = true
        } catch {
            result.errno = errno
            result.note = tl("写入失败: ") + "\(describe(result.errno))"
            return result
        }

        // fsync so the probe proves durability, not just a page-cache accept
        if let handle = FileHandle(forWritingAtPath: probeFile.path) {
            fsync(handle.fileDescriptor)
            try? handle.close()
        }

        if let back = try? Data(contentsOf: probeFile) {
            result.canReadBack = (back == payload)
            if !result.canReadBack { result.note = tl("读回内容不一致") }
        } else {
            result.errno = errno
            result.note = tl("读回失败: ") + "\(describe(result.errno))"
        }

        try? fm.removeItem(at: probeFile)
        if result.canReadBack && result.note.isEmpty {
            result.note = tl("读写正常")
        }
        return result
    }

    static func health() -> [(Standard, ContainerProbe)] {
        standards.map { ($0, probe(resolve($0))) }
    }

    // MARK: - Repair

    /// Bring the container to a known-good state. Returns the human-readable actions taken.
    static func repair() -> [String] {
        var actions: [String] = []
        let fm = FileManager.default

        // 1. every standard directory exists
        for standard in standards {
            let url = resolve(standard)
            var isDir: ObjCBool = false
            if !fm.fileExists(atPath: url.path, isDirectory: &isDir) {
                do {
                    try fm.createDirectory(at: url, withIntermediateDirectories: true)
                    actions.append(tl("创建 ") + tl(standard.name) + " → \(shortPath(url))")
                } catch {
                    actions.append(tl("无法创建 ") + tl(standard.name) + ": \(describe(errno))")
                }
            } else if !isDir.boolValue {
                actions.append(tl(standard.name) + tl(" 是文件而不是目录 —— 跳过"))
            }
        }

        // 2. the container root and SystemData are readable but reject new files by design;
        //    confirm they are reachable instead of trying to write into them
        for (label, path) in [(tl("容器根"), rootPath), ("SystemData", rootPath + "/SystemData")] {
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: path, isDirectory: &isDir) {
                let readable = (try? fm.contentsOfDirectory(atPath: path)) != nil
                actions.append("\(label)" + tl(" 存在且") + "\(readable ? tl("可读") : tl("不可读") + tl("（按设计不接受新建文件，不计入探针）"))")
            }
        }

        // 3. sweep stale probe files from an interrupted run
        for standard in standards {
            let url = resolve(standard)
            guard let names = try? fm.contentsOfDirectory(atPath: url.path) else { continue }
            for name in names where name.hasPrefix(".cinder27-probe-") {
                try? fm.removeItem(at: url.appendingPathComponent(name))
                actions.append(tl("清理残留探针 ") + "\(name)")
            }
        }

        // 4. make sure the work directory is not carrying a half-written journal
        let journal = appSupport.appendingPathComponent("cinder27-journal.json")
        if let data = try? Data(contentsOf: journal),
           (try? JSONSerialization.jsonObject(with: data)) == nil {
            try? fm.removeItem(at: journal)
            actions.append(tl("移除损坏的 journal"))
        }

        // 5. verify with a real probe and report anything still broken
        for standard in standards {
            let p = probe(resolve(standard))
            if !p.ok {
                actions.append(tl(standard.name) + tl(" 仍不可用: ") + "\(p.note)")
            }
        }

        if actions.isEmpty { actions.append(tl("容器已处于正常状态，无需修复")) }
        return actions
    }

    // MARK: - Path normalisation

    /// Re-root any absolute path that points into *a* data container onto the live one.
    /// Stored paths, hard-coded UUIDs and paths captured before a reinstall all land here.
    static func normalize(_ path: String) -> String {
        var p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty { return rootPath }
        if p == "~" { return rootPath }
        if p.hasPrefix("~/") { p = rootPath + String(p.dropFirst()) }

        // /var/mobile/Containers/Data/Application/<UUID>/rest  →  <live>/rest
        let markers = [
            "/var/mobile/Containers/Data/Application/",
            "/private/var/mobile/Containers/Data/Application/",
        ]
        for marker in markers where p.hasPrefix(marker) {
            let rest = p.dropFirst(marker.count)
            if let slash = rest.firstIndex(of: "/") {
                let tail = String(rest[rest.index(after: slash)...])
                return tail.isEmpty ? rootPath : rootPath + "/" + tail
            }
            return rootPath
        }
        return p
    }

    static func url(_ path: String) -> URL {
        URL(fileURLWithPath: normalize(path))
    }

    /// Write that cannot fail on a missing parent and cannot half-write.
    @discardableResult
    static func write(_ data: Data, to path: String) throws -> URL {
        let url = self.url(path)
        let parent = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) {
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        }
        try data.write(to: url, options: .atomic)
        return url
    }

    @discardableResult
    static func write(_ text: String, to path: String) throws -> URL {
        try write(Data(text.utf8), to: path)
    }

    @discardableResult
    static func makeDirectory(_ path: String) throws -> URL {
        let url = self.url(path)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    // MARK: - Helpers

    static func shortPath(_ url: URL) -> String {
        url.path.replacingOccurrences(of: rootPath, with: "~")
    }

    static func describe(_ code: Int32) -> String {
        switch code {
        case 0: return tl("无错误")
        case EPERM: return tl("EPERM 操作被拒绝")
        case ENOENT: return tl("ENOENT 父目录或文件不存在")
        case EACCES: return tl("EACCES 沙盒拒绝访问")
        case EEXIST: return tl("EEXIST 已存在")
        case ENOSPC: return tl("ENOSPC 空间不足")
        case EROFS: return tl("EROFS 只读文件系统")
        case ENOTDIR: return tl("ENOTDIR 路径中间是文件")
        case EISDIR: return tl("EISDIR 目标是目录")
        case ENAMETOOLONG: return tl("ENAMETOOLONG 名称过长")
        case EDQUOT: return tl("EDQUOT 超出配额")
        case EXDEV: return tl("EXDEV 跨卷（.atomic 写到了别的卷）")
        default: return "errno \(code)"
        }
    }

    /// Free space in the container's volume.
    static func freeSpace() -> Int64? {
        guard let attrs = try? FileManager.default.attributesOfFileSystem(forPath: rootPath),
              let free = attrs[.systemFreeSize] as? NSNumber else { return nil }
        return free.int64Value
    }

    static func usedSpace() -> Int64? {
        let fm = FileManager.default
        var total: Int64 = 0
        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) else {
            return nil
        }
        for case let url as URL in enumerator {
            guard let v = try? url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
                  v.isRegularFile == true else { continue }
            total += Int64(v.fileSize ?? 0)
        }
        return total
    }
}
