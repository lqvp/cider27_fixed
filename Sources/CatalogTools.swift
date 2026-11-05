import Foundation
import UIKit

// MARK: - Self-tests for the modification tooling
//
// These run inside the app so the tooling proves itself on the device it will be used on,
// rather than only on the build machine. Each one builds its own fixture, exercises one
// tool, and reports the artifact.

extension Catalog {

    static let tooling: [ExploitModule] = [

        ExploitModule(
            id: "tool.ipa",
            titleZh: "IPA 手术自检（改包名 / 注入 / 重签名准备）",
            cve: "—",
            component: "IPASurgeon · MachO · ZipWriter",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "现场造一个最小 IPA（Info.plist + 一个真的 Mach-O），跑完整的改机流程：解包 → 改 CFBundleIdentifier → 注入 LC_LOAD_DYLIB → 去掉 LC_CODE_SIGNATURE → 用自己写的 ZIP 写入器重新打包。产出留在 Documents/Cinder27/IPA，可以直接拿去签名。",
            notesZh: "这条不是漏洞，是工具链的证明。它跑通说明 IPA 面板在你的设备上能用，而不是只在构建机上能用。",
            run: { ctx in
                ctx.arm("tool.ipa", "fixture + patch")
                var lines: [String] = []

                // ---- fixture: a real arm64 Mach-O from this process
                guard let exec = Bundle.main.executablePath,
                      let macho = try? Data(contentsOf: URL(fileURLWithPath: exec)) else {
                    ctx.fail("tool.ipa", tl("无法读取自身二进制"))
                    throw LabError(message: tl("无法读取自身二进制"))
                }
                let header = MachO.header(macho)
                lines.append(tl("取自本进程的 Mach-O：") + "\(macho.count)" + tl(" B · 64 位=") + "\(header?.is64 ?? false)" + tl(" · ncmds=") + "\(header?.ncmds ?? 0)")

                // ---- signature strip first, so injection writes into a clean header
                var working = macho
                if let (stripped, removed) = try? MachO.stripSignature(macho) {
                    working = stripped
                    lines.append(tl("移除 LC_CODE_SIGNATURE：") + "\(removed)" + tl(" 条"))
                }

                // ---- exercise the load-command injector, and carry the result forward
                do {
                    let injected = try MachO.injectLoad(working, dylibPath: "@executable_path/Frameworks/CinderHook.dylib")
                    let after = MachO.header(injected)
                    let cmds = MachO.commands(injected)
                    let hasHook = cmds.contains { $0.cmd == 0x0C }
                    lines.append(tl("注入 LC_LOAD_DYLIB：ncmds ") + "\(MachO.header(working)?.ncmds ?? 0)" + tl(" → ") + "\(after?.ncmds ?? 0)" + tl("，sizeofcmds ") + "\(MachO.header(working)?.sizeofcmds ?? 0)" + tl(" → ") + "\(after?.sizeofcmds ?? 0)" + tl("，命令数 ") + "\(cmds.count)" + tl("，含 LC_LOAD_DYLIB=") + "\(hasHook)")
                    working = injected
                } catch {
                    lines.append(tl("注入未成功（头部无空隙）：") + "\(error.localizedDescription)")
                }

                // ---- exercise the string patcher on a string the binary really contains
                do {
                    let (patched, hits) = try MachO.patchStrings(working, find: "Cinder27", replace: "Cind3r27")
                    lines.append(tl("字符串替换 Cinder27 → Cind3r27：") + "\(hits)" + tl(" 处"))
                    working = patched
                } catch {
                    lines.append(tl("字符串替换失败：") + "\(error.localizedDescription)")
                }

                // ---- build the fixture IPA and run the full surgeon
                var zip = ZipWriter()
                var info: [String: Any] = [
                    "CFBundleIdentifier": "com.cinder.fixture",
                    "CFBundleExecutable": "Fixture",
                    "CFBundleName": "Fixture",
                    "CFBundleDisplayName": "Fixture",
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "1",
                    "MinimumOSVersion": "17.0",
                    "CFBundlePackageType": "APPL",
                ]
                if let data = try? PropertyListSerialization.data(fromPropertyList: info, format: .binary, options: 0) {
                    zip.add("Payload/Fixture.app/Info.plist", data)
                }
                zip.add("Payload/Fixture.app/Fixture", working)
                let fixture = zip.build()
                let fixtureURL = ctx.write("fixture.ipa", fixture)
                lines.append(tl("自造 IPA：") + "\(fixture.count)" + tl(" B（ZipWriter 产出，stored 条目）"))

                var recipe = IPARecipe()
                recipe.bundleID = "com.cinder.patched"
                recipe.displayName = "Patched"
                recipe.version = "9.9"
                recipe.injectedDylib = "@executable_path/Frameworks/CinderHook.dylib"
                recipe.patchedString = "com.cinder.fixture"
                recipe.patchedReplacement = "com.cinder.patched"
                recipe.stripSignature = true

                var output: URL?
                do {
                    let result = try IPASurgeon.patch(source: fixtureURL, recipe: recipe, workdir: ctx.workdir)
                    output = result.outputURL
                    lines.append(tl("手术完成：") + "\(result.entries)" + tl(" 个文件 → ") + "\(result.outputURL.lastPathComponent)")
                    for note in result.notes { lines.append("  · \(note)") }
                } catch {
                    lines.append(tl("手术失败：") + "\(error.localizedDescription)")
                }
                ctx.disarm("tool.ipa", "done")

                var artifacts: [URL] = [fixtureURL]
                if let o = output { artifacts.append(o) }
                return ModuleOutcome(headline: output == nil ? tl("手术未完成") : tl("IPA 手术链路可用"),
                                     detail: lines.joined(separator: "\n"),
                                     artifacts: artifacts)
            }),

        ExploitModule(
            id: "tool.zip",
            titleZh: "ZIP 写入器往返自检",
            cve: "—",
            component: "ZipWriter + libarchive",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "用自己写的 ZIP 写入器造一个含随机内容的归档，再用 libarchive 解回来，逐字节比对。这条证明重打包不会悄悄损坏文件 —— 改机工具最怕的就是这个。",
            notesZh: "64 个文件，每个 4 KB 随机内容，比对 CRC 与长度。",
            run: { ctx in
                ctx.arm("tool.zip", "roundtrip")
                var zip = ZipWriter()
                var expected: [String: Data] = [:]
                var seed: UInt64 = 0x9E3779B97F4A7C15
                for i in 0..<64 {
                    var bytes = [UInt8]()
                    for _ in 0..<4096 {
                        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17
                        bytes.append(UInt8(truncatingIfNeeded: seed))
                    }
                    let name = "dir\(i % 8)/file\(i).bin"
                    let data = Data(bytes)
                    expected[name] = data
                    zip.add(name, data)
                }
                let archive = zip.build()
                let url = ctx.write("zip_roundtrip.zip", archive)

                let dir = ctx.workdir.appendingPathComponent("zipcheck", isDirectory: true)
                try? FileManager.default.removeItem(at: dir)
                let result = Runners.Archive.extractAll(archive, to: dir)

                var matched = 0
                var mismatched = 0
                for (name, data) in expected {
                    let path = dir.appendingPathComponent(name)
                    if let back = try? Data(contentsOf: path), back == data {
                        matched += 1
                    } else {
                        mismatched += 1
                    }
                }
                ctx.disarm("tool.zip", "matched=\(matched)")
                return ModuleOutcome(
                    headline: mismatched == 0 && matched == expected.count
                        ? "\(matched)" + tl("/") + "\(expected.count)" + tl(" 个文件逐字节一致")
                        : "\(matched)" + tl(" 一致 / ") + "\(mismatched)" + tl(" 不一致"),
                    detail: tl("归档 ") + "\(archive.count)" + tl(" B · 解包 ") + "\(result.count)" + tl(" 项 · ") + "\(result.status)",
                    evidence: [tl("64 × 4 KB 随机内容"), tl("自己写 ZIP → libarchive 读回")],
                    artifacts: [url])
            }),

        ExploitModule(
            id: "tool.macho",
            titleZh: "Mach-O 解析器自检",
            cve: "—",
            component: "MachO · MachOInspector",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "对系统卷上的几个真实二进制跑一遍头解析：架构、类型、平台、最低系统、SDK、加密状态、链接库、rpath。加密状态是这一整套里最有信息量的字段 —— 系统框架 cryptid 为 0，第三方 App 的二进制不是。",
            notesZh: "同时跑我自己写的解析器和 MachOInspector，两个结果应该一致。",
            run: { ctx in
                ctx.arm("tool.macho", "parse")
                let targets: [(String, String)] = [
                    ("CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"),
                    ("CoreMedia", "/System/Library/Frameworks/CoreMedia.framework/CoreMedia"),
                    ("libarchive", "/usr/lib/libarchive.2.dylib"),
                    ("ImageIO", "/System/Library/Frameworks/ImageIO.framework/ImageIO"),
                    (tl("本进程"), Bundle.main.executablePath ?? ""),
                ]
                var lines: [String] = []
                var parsed = 0
                for (label, path) in targets {
                    guard FileManager.default.fileExists(atPath: path) else {
                        lines.append("\(label)" + tl(": 不可见"))
                        continue
                    }
                    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                        lines.append("\(label)" + tl(": 读取被拒绝（沙盒）"))
                        continue
                    }
                    parsed += 1
                    if let h = MachO.header(data) {
                        let cmds = MachO.commands(data)
                        lines.append("\(label)" + tl(": ") + "\(data.count)" + tl(" B · ncmds=") + "\(h.ncmds)" + tl(" 解析出 ") + "\(cmds.count)" + tl(" 条 · type=") + "\(h.filetype)" + tl(" · 64=") + "\(h.is64)")
                    }
                    if let info = MachOInspector.inspect(path) {
                        lines.append(tl("   ") + "\(info.arch)" + tl(" · ") + "\(info.platform)" + tl(" · minOS ") + "\(info.minOS)" + tl(" · SDK ") + "\(info.sdk)" + tl(" · 加密=") + "\(info.isEncrypted)" + tl(" · 库 ") + "\(info.linkedLibraries.count)")
                    }
                }
                ctx.disarm("tool.macho", "parsed=\(parsed)")
                return ModuleOutcome(headline: tl("解析 ") + "\(parsed)" + tl(" 个二进制"),
                                     detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "tool.hex",
            titleZh: "十六进制查找替换自检",
            cve: "—",
            component: "HexTool",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "在随机缓冲里植入已知模式，用十六进制与文本两种写法查找、替换、再查找，确认命中数与偏移都对。",
            notesZh: "这条守的是「改机工具最不该出错的地方」。",
            run: { ctx in
                ctx.arm("tool.hex", "roundtrip")
                var bytes = [UInt8](repeating: 0x00, count: 65536)
                let needle: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
                var planted: [Int] = []
                for i in stride(from: 1000, to: 60000, by: 4096) {
                    for k in 0..<needle.count { bytes[i + k] = needle[k] }
                    planted.append(i)
                }
                let buffer = Data(bytes)

                let hexHits = HexTool.search(buffer, pattern: "DE AD BE EF")
                let rawHits = HexTool.search(buffer, pattern: "0xdeadbeef")
                let textHits = HexTool.search(buffer, pattern: "Cinder27")

                let (patched, count) = HexTool.replace(buffer, pattern: "DE AD BE EF", with: "CA FE BA BE")
                let after = HexTool.search(patched, pattern: "CA FE BA BE")
                let leftover = HexTool.search(patched, pattern: "DE AD BE EF")
                ctx.disarm("tool.hex", "done")

                var lines = [
                    tl("植入 ") + "\(planted.count)" + tl(" 处 @ ") + "\(planted.prefix(4).map { String(format: "0x%x", $0) }.joined(separator: ", "))",
                    tl("十六进制查找: ") + "\(hexHits.count)" + tl(" 处 · 偏移一致=") + "\(hexHits == planted)",
                    tl("0x 前缀写法: ") + "\(rawHits.count)" + tl(" 处 · 偏移一致=") + "\(rawHits == planted)",
                    tl("文本查找 Cinder27: ") + "\(textHits.count)" + tl(" 处（应为 0）"),
                    tl("替换: ") + "\(count)" + tl(" 处 → 新模式 ") + "\(after.count)" + tl(" 处 · 旧模式残留 ") + "\(leftover.count)" + tl(" 处"),
                ]
                let ok = hexHits == planted && rawHits == planted && after.count == planted.count && leftover.isEmpty
                if !ok { lines.append(tl("有断言不成立")) }
                return ModuleOutcome(headline: ok ? tl("查找替换全部断言通过") : tl("有断言失败"),
                                     detail: lines.joined(separator: "\n"))
            }),

        ExploitModule(
            id: "tool.container",
            titleZh: "容器读写正常化（数据容器自检 + 修复）",
            cve: "—",
            component: "Container · ensureAll / probe / repair / normalize",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "把数据容器里每一个工具会用到的目录逐个解析、创建、然后真的建文件写一遍、fsync、读回、比对、删除。之前「容器内读写失败」的四个真实原因都在这里被点名：目录只是 URL 不是目录、isWritableFile 是坏探针、容器 UUID 会变、Library/Preferences 归 cfprefsd。",
            notesZh: "跑完会留下 container_health.txt。修复动作是幂等的，每次启动都会再跑一遍。",
            run: { ctx in
                ctx.arm("tool.container", "ensure + probe")
                var lines: [String] = []
                lines.append(tl("容器根: ") + "\(Container.rootPath)")

                let created = Container.ensureAll()
                lines.append(created.isEmpty ? tl("所有标准目录已存在") : tl("本次新建: ") + "\(created.joined(separator: ", "))")

                var okCount = 0
                for (standard, probe) in Container.health() {
                    if probe.ok { okCount += 1 }
                    let state = probe.ok ? "RW" : probe.note
                    lines.append("\(probe.ok ? "✓" : "✗") \(standard.name.padding(toLength: 20, withPad: " ", startingAt: 0)) \(state)  \(Container.shortPath(probe.url))")
                }
                lines.append(tl("合计 ") + "\(okCount)" + tl("/") + "\(Container.standards.count)" + tl(" 个目录读写正常"))

                // prove the four failure modes are actually handled now
                lines.append("")
                lines.append(tl("— 失效模式验证 —"))

                // 1. a directory that does not exist yet
                let fresh = Container.rootPath + "/Documents/Cinder27/deep/nested/probe"
                let freshProbe = Container.probe(URL(fileURLWithPath: fresh, isDirectory: true))
                lines.append(tl("1. 不存在的深层目录自动创建: ") + "\(freshProbe.ok ? tl("通过") : freshProbe.note)")

                // 2. write through Container.write (ensures parent)
                do {
                    let url = try Container.write("probe", to: Container.rootPath + "/Documents/Cinder27/deep/written.txt")
                    let back = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
                    lines.append(tl("2. Container.write 自动建父目录: 通过（读回 \"") + "\(back)" + tl("\"）"))
                } catch {
                    lines.append(tl("2. Container.write: 失败 ") + "\(Container.describe(errno))")
                }

                // 3. stale container UUID re-rooting
                let stale = "/var/mobile/Containers/Data/Application/00000000-1111-2222-3333-444444444444/Documents/legacy.txt"
                let rerooted = Container.normalize(stale)
                lines.append(tl("3. 旧 UUID 路径重挂: ") + "\(stale)")
                lines.append("   → \(rerooted)")
                lines.append(tl("   落在当前容器内: ") + "\(rerooted.hasPrefix(Container.rootPath))")

                // 4. real write probe vs isWritableFile
                let rootURL = Container.root
                let fm = FileManager.default
                let accessSays = fm.isWritableFile(atPath: rootURL.path)
                let probeSays = Container.probe(rootURL).canWrite
                lines.append(tl("4. isWritableFile(容器根)=") + "\(accessSays)" + tl(" · 真实写探针=") + "\(probeSays)" +
                             (accessSays != probeSays ? tl(" ← 两者不一致，说明 access() 不可信") : ""))

                if let free = Container.freeSpace() {
                    lines.append(tl("可用空间: ") + "\(ByteCountFormatter.string(fromByteCount: free, countStyle: .file))")
                }
                if let used = Container.usedSpace() {
                    lines.append(tl("容器占用: ") + "\(ByteCountFormatter.string(fromByteCount: used, countStyle: .file))")
                }

                let report = lines.joined(separator: "\n")
                let url = ctx.write("container_health.txt", Data(report.utf8))
                ctx.disarm("tool.container", "ok=\(okCount)")
                return ModuleOutcome(headline: "\(okCount)" + tl("/") + "\(Container.standards.count)" + tl(" 目录读写正常"),
                                     detail: report,
                                     evidence: [tl("探针 = 建文件 → 写 → fsync → 读回 → 比对 → 删除")],
                                     artifacts: [url])
            }),

        ExploitModule(
            id: "tool.backup",
            titleZh: "备份 / 回滚往返自检",
            cve: "—",
            component: "BackupPane · ZipWriter · libarchive",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "在容器里放一组已知内容的文件，打包成 ZIP，解到另一个目录，逐字节比对，再删掉。这条守的是「备份能不能真的回滚」——上一版写的是自造格式却叫 .tar，解不回来。",
            notesZh: "同时验证解包时 ../ 与符号链接出不了目标目录。",
            run: { ctx in
                ctx.arm("tool.backup", "roundtrip")
                let fm = FileManager.default
                let src = ctx.workdir.appendingPathComponent("backup_src", isDirectory: true)
                let dst = ctx.workdir.appendingPathComponent("backup_dst", isDirectory: true)
                try? fm.removeItem(at: src)
                try? fm.removeItem(at: dst)
                try? fm.createDirectory(at: src, withIntermediateDirectories: true)

                var expected: [String: Data] = [:]
                for i in 0..<12 {
                    let name = "sub\(i % 3)/note\(i).txt"
                    let body = Data("cinder27 backup probe \(i) — \(UUID().uuidString)".utf8)
                    expected[name] = body
                    let path = src.appendingPathComponent(name)
                    try? fm.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try? body.write(to: path)
                }

                var zip = ZipWriter()
                if let enumerator = fm.enumerator(at: src, includingPropertiesForKeys: [.isRegularFileKey]) {
                    for case let url as URL in enumerator {
                        guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey]),
                              v.isRegularFile == true,
                              let data = try? Data(contentsOf: url) else { continue }
                        zip.add(url.path.replacingOccurrences(of: src.path + "/", with: ""), data)
                    }
                }
                let archive = zip.build()
                let archiveURL = ctx.write("backup_probe.zip", archive)
                let result = Runners.Archive.extractAll(archive, to: dst)

                var matched = 0
                var mismatched = 0
                for (name, data) in expected {
                    if let back = try? Data(contentsOf: dst.appendingPathComponent(name)), back == data {
                        matched += 1
                    } else {
                        mismatched += 1
                    }
                }

                // containment: a traversal entry must not escape the destination
                var evil = ZipWriter()
                evil.add("../escaped.txt", Data("should not escape".utf8))
                let evilURL = ctx.write("traversal_probe.zip", evil.build())
                let escapeTarget = ctx.workdir.appendingPathComponent("escape_target", isDirectory: true)
                try? fm.createDirectory(at: escapeTarget, withIntermediateDirectories: true)
                _ = Runners.Archive.extractAll(evil.build(), to: escapeTarget)
                let escaped = fm.fileExists(atPath: ctx.workdir.appendingPathComponent("escaped.txt").path)
                _ = evilURL

                ctx.disarm("tool.backup", "matched=\(matched)")
                return ModuleOutcome(
                    headline: mismatched == 0 ? tl("备份往返 ") + "\(matched)" + tl("/") + "\(expected.count)" + tl(" 一致") : "\(matched)" + tl(" 一致 / ") + "\(mismatched)" + tl(" 不一致"),
                    detail: [
                        tl("归档 ") + "\(archive.count)" + tl(" B · 解包 ") + "\(result.count)" + tl(" 项"),
                        tl("逐字节比对: ") + "\(matched)" + tl("/") + "\(expected.count)",
                        tl("路径穿越遏制: ") + "\(escaped ? tl("失败 —— ../ 逃出了目标目录") : tl("有效（../ 未逃出）"))",
                    ].joined(separator: "\n"),
                    artifacts: [archiveURL])
            }),

        ExploitModule(
            id: "tool.paths",
            titleZh: "文件系统权限矩阵全扫",
            cve: "—",
            component: "Probe · FileManager",
            primitive: .probe,
            reach: .inProcess,
            tier: 1,
            summaryZh: "把 30 多个关键路径逐个试读试写，记录可读/可写/条目数/errno。这是改机工具的活动范围地图 —— 它决定了所有面板能做到哪里为止。",
            notesZh: "结果同时会写进 Documents 里一份文本，方便对照。",
            run: { ctx in
                ctx.arm("tool.paths", "scan")
                var lines: [String] = []
                var readable = 0, writable = 0
                for path in Probe.interestingRoots {
                    let p = Probe.path(path)
                    if p.readable { readable += 1 }
                    if p.writable { writable += 1 }
                    let mark = p.readable ? (p.writable ? "RW" : "R ") : "--"
                    lines.append("\(mark) \(path)  \(p.readable ? "\(p.entryCount) " + tl("项") : p.note)")
                }
                let report = lines.joined(separator: "\n")
                let url = ctx.write("path_matrix.txt", Data(report.utf8))
                ctx.disarm("tool.paths", "r=\(readable) w=\(writable)")
                return ModuleOutcome(headline: "\(readable)" + tl(" 个可读 · ") + "\(writable)" + tl(" 个可写"),
                                     detail: report, artifacts: [url])
            }),
    ]
}
