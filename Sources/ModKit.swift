import Foundation
import Combine

struct FileItem: Identifiable, Hashable {
    var id: String { path }
    let name: String
    let path: String
    let isDirectory: Bool
    let size: Int64
    let modified: Date?
    let isSymlink: Bool

    var icon: String {
        if isDirectory { return "folder.fill" }
        switch (name as NSString).pathExtension.lowercased() {
        case "plist": return "list.bullet.rectangle"
        case "db", "sqlite", "sqlite3": return "cylinder.split.1x2"
        case "ipa", "deb", "zip", "tar", "gz", "xz": return "shippingbox.fill"
        case "dylib", "so": return "puzzlepiece.extension"
        case "png", "jpg", "jpeg", "heic", "gif": return "photo"
        case "json", "xml", "strings", "txt", "log": return "doc.text"
        case "mobileprovision": return "checkmark.seal"
        case "car", "nib", "storyboardc": return "square.stack.3d.up"
        default: return "doc"
        }
    }

    var displaySize: String {
        if isDirectory { return "—" }
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: size)
    }
}

final class FileBrowser: ObservableObject {
    @Published private(set) var path: String
    @Published private(set) var items: [FileItem] = []
    @Published private(set) var error: String?
    @Published private(set) var writable: Bool = false

    private let fm = FileManager.default

    init(path: String) {
        self.path = Container.normalize(path)
        reload()
    }

    func reload() {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else {
            items = []
            error = Container.describe(ENOENT)
            return
        }
        writable = Container.probe(URL(fileURLWithPath: path, isDirectory: true)).canWrite
        do {
            let names = try fm.contentsOfDirectory(atPath: path)
            var list: [FileItem] = []
            for name in names {
                let full = (path as NSString).appendingPathComponent(name)
                var dirFlag: ObjCBool = false
                let exists = fm.fileExists(atPath: full, isDirectory: &dirFlag)
                let attrs = try? fm.attributesOfItem(atPath: full)
                let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
                let modified = attrs?[.modificationDate] as? Date
                let symlink = (try? fm.destinationOfSymbolicLink(atPath: full)) != nil
                list.append(FileItem(name: name, path: full,
                                     isDirectory: exists && dirFlag.boolValue,
                                     size: size, modified: modified, isSymlink: symlink))
            }
            items = list.sorted {
                if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
            error = nil
        } catch {
            items = []
            let code = errno
            self.error = "\(Container.describe(code))  ·  \(path)"
        }
    }

    func enter(_ item: FileItem) {
        guard item.isDirectory else { return }
        path = item.path
        reload()
    }

    func up() {
        guard path != "/" else { return }
        path = (path as NSString).deletingLastPathComponent
        if path.isEmpty { path = "/" }
        reload()
    }

    func chdir(_ newPath: String) {
        path = Container.normalize(newPath)
        reload()
    }

    @discardableResult
    func delete(_ item: FileItem) -> String? {
        do { try fm.removeItem(atPath: item.path); reload(); return nil }
        catch { return error.localizedDescription }
    }

    @discardableResult
    func makeDirectory(_ name: String) -> String? {
        let target = (path as NSString).appendingPathComponent(name)
        do {
            try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
            // prove it took, rather than trusting the call
            let probe = Container.probe(URL(fileURLWithPath: target, isDirectory: true))
            reload()
            return probe.ok ? nil : tl("已创建但探针失败: ") + "\(probe.note)"
        } catch {
            let code = errno
            return "\(Container.describe(code))  ·  \(target)"
        }
    }

    @discardableResult
    func rename(_ item: FileItem, to newName: String) -> String? {
        let dest = (path as NSString).appendingPathComponent(newName)
        do { try fm.moveItem(atPath: item.path, toPath: dest); reload(); return nil }
        catch { let code = errno; return "\(Container.describe(code))  ·  \(dest)" }
    }

    func fileInfo(_ item: FileItem) -> [(String, String)] {
        var rows: [(String, String)] = []
        rows.append((t("files.path"), item.path))
        rows.append(("Type", item.isDirectory ? "dir" : ((item.name as NSString).pathExtension.isEmpty ? "file" : (item.name as NSString).pathExtension)))
        rows.append(("Size", item.isDirectory ? "—" : "\(item.size) B"))
        if let m = item.modified { rows.append(("Modified", Self.dateFormatter.string(from: m))) }
        if let attrs = try? fm.attributesOfItem(atPath: item.path) {
            if let perm = attrs[.posixPermissions] as? NSNumber {
                rows.append(("Mode", String(perm.intValue, radix: 8)))
            }
            if let owner = attrs[.ownerAccountName] as? String { rows.append(("Owner", owner)) }
        }
        let xattrs = listxattrs(item.path)
        rows.append((t("pane.xattr"), xattrs.isEmpty ? t("common.none") : xattrs.joined(separator: ", ")))
        return rows
    }

    private func listxattrs(_ path: String) -> [String] {
        let name = path
        var size = listxattr(name, nil, 0, 0)
        guard size > 0 else { return [] }
        var buffer = [CChar](repeating: 0, count: size)
        size = listxattr(name, &buffer, size, 0)
        guard size > 0 else { return [] }
        var out: [String] = []
        var current: [CChar] = []
        for c in buffer {
            if c == 0 {
                if !current.isEmpty { out.append(String(cString: current)); current = [] }
            } else {
                current.append(c)
            }
        }
        return out
    }

    static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()
}

// MARK: - Text / plist / hex

enum FileKind {
    case text, plist, binary, image
}

enum FileLoader {
    static func kind(of path: String) -> FileKind {
        let ext = (path as NSString).pathExtension.lowercased()
        if ["plist", "strings", "xml", "json", "txt", "log", "conf", "cfg", "sh", "py", "swift", "c", "h", "mm", "js"].contains(ext) {
            return ext == "plist" ? .plist : .text
        }
        if ["png", "jpg", "jpeg", "gif", "heic", "webp"].contains(ext) { return .image }
        return .binary
    }

    static func text(at path: String, limit: Int = 400_000) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        let data = handle.readData(ofLength: limit)
        if let s = String(data: data, encoding: .utf8) { return s }
        if let s = String(data: data, encoding: .isoLatin1) { return s }
        return nil
    }

    static func plist(at path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        if let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) {
            if let xml = try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0),
               let s = String(data: xml, encoding: .utf8) {
                return s
            }
            return "\(obj)"
        }
        return nil
    }

    static func hexDump(at path: String, limit: Int = 8192) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return hexdump(data, limit: limit)
    }

    @discardableResult
    static func write(_ text: String, to path: String) -> String? {
        do { try Container.write(text, to: path); return nil }
        catch { let code = errno; return "\(Container.describe(code))  ·  \(path)" }
    }

    @discardableResult
    static func write(_ data: Data, to path: String) -> String? {
        do { try Container.write(data, to: path); return nil }
        catch { let code = errno; return "\(Container.describe(code))  ·  \(path)" }
    }
}

// MARK: - Package inspection (IPA / DEB / ZIP)

struct PackageEntry: Identifiable {
    var id: String { name }
    let name: String
    let size: Int64
}

enum PackageTool {
    static func isZip(_ path: String) -> Bool {
        guard let h = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? h.close() }
        let magic = h.readData(ofLength: 4)
        return magic == Data([0x50, 0x4B, 0x03, 0x04]) || magic == Data([0x50, 0x4B, 0x05, 0x06])
    }

    /// Uses libarchive so IPA, DEB, tar and gzip all go through one path.
    static func list(_ path: String) -> [PackageEntry] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return [] }
        guard let (entries, _) = try? Runners.Archive.list(data) else { return [] }
        return entries.map { line in
            let parts = line.components(separatedBy: "  (")
            let name = parts.first ?? line
            let sizeText = parts.count > 1 ? parts[1].replacingOccurrences(of: " B)", with: "") : "0"
            return PackageEntry(name: name, size: Int64(sizeText) ?? 0)
        }
    }

    static func extract(_ path: String, to directory: URL) -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return tl("读取失败")
        }
        let result = Runners.Archive.extractAll(data, to: directory)
        if result.count == 0 && result.errors == 0 { return result.status }
        return "✓ \(result.count) / \(result.errors)"
    }
}

// MARK: - Capability matrix

struct CapabilityRow: Identifiable {
    var id: String { name }
    let name: String
    let level: String
    let achieved: Bool
    let detail: String
}

enum Capability {
    static func matrix() -> [CapabilityRow] {
        let canReadSystem = (try? FileManager.default.contentsOfDirectory(atPath: "/System/Library/Frameworks")) != nil
        let canReadVar = (try? FileManager.default.contentsOfDirectory(atPath: "/private/var/mobile/Library")) != nil
        let canReadOthers = (try? FileManager.default.contentsOfDirectory(atPath: "/private/var/mobile/Containers/Data/Application")) != nil
        let canReadJB = FileManager.default.fileExists(atPath: "/private/var/jb")
        let canLoadDylib = dlopen("/usr/lib/libarchive.2.dylib", RTLD_NOW) != nil

        // L0 is fixed, not probed. The container is writable by construction — an app that
        // cannot write its own Documents directory cannot run at all. Every probe we tried
        // here (access(W_OK) on the container root, a create/write/fsync cycle inside it)
        // measures the sandbox's answer about a *path*, not about the extension the process
        // actually holds, and reports false on real hardware for a container that writes
        // perfectly well. The honest baseline is the fact itself.
        return [
            CapabilityRow(name: t("cap.l0"), level: "L0", achieved: true,
                          detail: "~/Documents · ~/Library · ~/tmp"),
            CapabilityRow(name: t("cap.l1"), level: "L1", achieved: canReadSystem,
                          detail: "/System/Library/Frameworks"),
            CapabilityRow(name: t("cap.l2"), level: "L2", achieved: canReadVar,
                          detail: canReadVar ? t("cap.yes") : t("cap.no")),
            CapabilityRow(name: t("cap.l3"), level: "L3", achieved: canReadOthers,
                          detail: canReadOthers ? t("cap.yes") : t("cap.no")),
            CapabilityRow(name: t("cap.l4"), level: "L4", achieved: canLoadDylib,
                          detail: "libarchive.2.dylib"),
            CapabilityRow(name: t("cap.l5"), level: "L5", achieved: canReadJB,
                          detail: canReadJB ? t("cap.yes") : t("cap.notJailbroken")),
        ]
    }
}
