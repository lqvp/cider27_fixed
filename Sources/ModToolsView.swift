import SwiftUI
import UniformTypeIdentifiers
import CoreText

// MARK: - IPA surgery

struct IPAPane: View {
    @State private var source: URL?
    @State private var picking = false
    @State private var bundleID = ""
    @State private var displayName = ""
    @State private var version = ""
    @State private var buildVersion = ""
    @State private var minOS = ""
    @State private var dylib = ""
    @State private var patchFind = ""
    @State private var patchReplace = ""
    @State private var stripSig = true
    @State private var busy = false
    @State private var log: [String] = []
    @State private var output: URL?

    private var workdir: URL {
        let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("Cinder27/IPA", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: tl("源 IPA"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "shippingbox.fill").font(.system(size: 12))
                                Text(source?.lastPathComponent ?? tl("选择一个 .ipa")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(source == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        Text(tl("工具会解包、改 Info.plist、往主二进制里插 LC_LOAD_DYLIB、做字节级字符串替换、去掉 LC_CODE_SIGNATURE，然后重新打成 zip。产出仍然是未签名的 —— 你用同一套证书签它。"))
                            .font(T.tiny).foregroundColor(.white.opacity(0.35))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: "Info.plist")
                        field("Bundle ID", $bundleID, "com.example.app")
                        field(tl("显示名称"), $displayName, tl("新名字"))
                        field(tl("版本"), $version, "2.0")
                        field(tl("构建号"), $buildVersion, "42")
                        field(tl("最低系统"), $minOS, "17.0")
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("二进制"))
                        field(tl("注入 dylib 路径"), $dylib, "@executable_path/Frameworks/Hook.dylib")
                        field(tl("搜索字符串"), $patchFind, "com.old.bundleid")
                        field(tl("替换为"), $patchReplace, "com.new.bundleid")
                        Toggle(isOn: $stripSig) {
                            Text(tl("移除 LC_CODE_SIGNATURE")).font(T.body).foregroundColor(.white.opacity(0.75))
                        }.tint(T.ember)
                        Text(tl("替换串不能比原串长 —— 这是原地改写，不改文件布局，所以不会破坏任何偏移。注入 LC_LOAD_DYLIB 需要头部有空隙，没有就会明确报出来。"))
                            .font(T.tiny).foregroundColor(.white.opacity(0.32))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                RunButton(title: busy ? tl("处理中…") : tl("生成改机 IPA"),
                          systemImage: "wand.and.stars", tint: T.ember, disabled: busy || source == nil) {
                    run()
                }

                if !log.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(text: tl("过程"))
                            ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                                Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                if let output = output {
                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionLabel(text: tl("产出"))
                            Text(output.lastPathComponent).font(T.mono).foregroundColor(T.good)
                            Text(output.path).font(T.monoSm).foregroundColor(.white.opacity(0.35))
                                .textSelection(.enabled)
                            if let size = (try? FileManager.default.attributesOfItem(atPath: output.path))?[.size] as? NSNumber {
                                Text("\(size.int64Value) B").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .sheet(isPresented: $picking) {
            FilePickerSheet(isPresented: $picking) { url in
                source = url
                log = [tl("已选择 ") + "\(url.lastPathComponent)"]
            }
        }
    }

    private func field(_ label: String, _ binding: Binding<String>, _ placeholder: String) -> some View {
        HStack(spacing: 10) {
            Text(label).font(T.body).foregroundColor(.white.opacity(0.45)).frame(width: 96, alignment: .leading)
            TextField(placeholder, text: binding)
                .font(T.mono)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
        }
    }

    private func run() {
        guard let source = source else { return }
        busy = true
        log = []
        output = nil
        var recipe = IPARecipe()
        recipe.bundleID = bundleID.isEmpty ? nil : bundleID
        recipe.displayName = displayName.isEmpty ? nil : displayName
        recipe.version = version.isEmpty ? nil : version
        recipe.buildVersion = buildVersion.isEmpty ? nil : buildVersion
        recipe.minOS = minOS.isEmpty ? nil : minOS
        recipe.injectedDylib = dylib.isEmpty ? nil : dylib
        recipe.patchedString = patchFind.isEmpty ? nil : patchFind
        recipe.patchedReplacement = patchReplace.isEmpty ? nil : patchReplace
        recipe.stripSignature = stripSig

        let dir = workdir
        DispatchQueue.global(qos: .userInitiated).async {
            var lines: [String] = []
            var result: URL?
            do {
                let r = try IPASurgeon.patch(source: source, recipe: recipe, workdir: dir)
                lines = r.notes
                lines.append(tl("产出 ") + "\(r.entries)" + tl(" 个文件"))
                result = r.outputURL
            } catch {
                lines.append(tl("失败: ") + "\(error.localizedDescription)")
            }
            DispatchQueue.main.async {
                log = lines
                output = result
                busy = false
            }
        }
    }
}

// MARK: - Hex editor

struct HexPane: View {
    @State private var target: URL?
    @State private var picking = false
    @State private var dump = ""
    @State private var find = ""
    @State private var replaceWith = ""
    @State private var hits: [Int] = []
    @State private var status = ""
    @State private var offsetLimit = 8192

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: tl("目标"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "doc.text.magnifyingglass").font(.system(size: 12))
                                Text(target?.lastPathComponent ?? tl("选择一个文件")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(target == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        if !status.isEmpty {
                            Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("查找 / 替换"))
                        TextField(tl("文本，或 41 42 43 / 0x414243"), text: $find)
                            .font(T.mono).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .padding(8).background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        TextField(tl("替换（可选，不能更长）"), text: $replaceWith)
                            .font(T.mono).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .padding(8).background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        HStack(spacing: 8) {
                            RunButton(title: tl("查找"), systemImage: "magnifyingglass", tint: T.info,
                                      disabled: target == nil || find.isEmpty) { search() }
                            RunButton(title: tl("替换并保存"), systemImage: "arrow.triangle.2.circlepath",
                                      tint: T.ember,
                                      disabled: target == nil || find.isEmpty || replaceWith.isEmpty) { replace() }
                        }
                        if !hits.isEmpty {
                            Text(tl("命中 ") + "\(hits.count)" + tl(" 处: ") + hits.prefix(12).map { String(format: "0x%x", $0) }.joined(separator: ", "))
                                .font(T.monoSm).foregroundColor(T.good)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                if !dump.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                SectionLabel(text: tl("十六进制"))
                                Spacer()
                                Button(tl("更多")) { offsetLimit += 16384; load() }
                                    .font(T.tiny).tint(T.ember)
                            }
                            Text(dump)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.white.opacity(0.72))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .padding(16)
        }
        .sheet(isPresented: $picking) {
            FilePickerSheet(isPresented: $picking) { url in
                target = url
                hits = []
                status = ""
                load()
            }
        }
    }

    private func load() {
        guard let target = target else { return }
        guard let data = try? Data(contentsOf: target) else {
            status = tl("读取失败")
            return
        }
        dump = hexdump(data, limit: offsetLimit)
        status = "\(data.count) B"
    }

    private func search() {
        guard let target = target, let data = try? Data(contentsOf: target) else { return }
        hits = HexTool.search(data, pattern: find)
        status = hits.isEmpty ? tl("未命中") : tl("命中 ") + "\(hits.count)" + tl(" 处")
    }

    private func replace() {
        guard let target = target, let data = try? Data(contentsOf: target) else { return }
        let backup = target.path + ".cinder27.bak"
        if !FileManager.default.fileExists(atPath: backup) {
            try? FileManager.default.copyItem(atPath: target.path, toPath: backup)
        }
        let (patched, count) = HexTool.replace(data, pattern: find, with: replaceWith)
        if count == 0 {
            status = tl("未命中，未写入")
            return
        }
        do {
            try patched.write(to: target)
            status = tl("替换 ") + "\(count)" + tl(" 处并已保存（备份 ") + "\(URL(fileURLWithPath: backup).lastPathComponent)" + tl("）")
            load()
            hits = HexTool.search(patched, pattern: replaceWith)
        } catch {
            status = tl("写入失败: ") + "\(error.localizedDescription)"
        }
    }
}

// MARK: - xattr / decmpfs

struct XattrPane: View {
    @State private var target: URL?
    @State private var picking = false
    @State private var entries: [(String, Int)] = []
    @State private var detail: [String] = []
    @State private var status = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: tl("目标文件"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "tag.fill").font(.system(size: 12))
                                Text(target?.lastPathComponent ?? tl("选择文件")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(target == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        if !status.isEmpty {
                            Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 6) {
                        SectionLabel(text: tl("扩展属性"))
                        if entries.isEmpty {
                            Text(tl("无")).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                        } else {
                            ForEach(Array(entries.enumerated()), id: \.offset) { _, e in
                                HStack {
                                    Text(e.0).font(T.monoSm).foregroundColor(.white.opacity(0.75))
                                    Spacer()
                                    Text("\(e.1) B").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                }
                            }
                        }
                    }
                }

                if !detail.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(text: tl("详情"))
                            ForEach(Array(detail.enumerated()), id: \.offset) { _, line in
                                Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.65))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("decmpfs 操作"))
                        Text(tl("com.apple.decmpfs 是内核压缩文件系统用的属性。改它等于直接改内核解压的输入 —— CVE-2026-113910 就是这条路径上「解压产出少于预期」时内核把未写满的页缓冲交给用户态。这里可以手动设一个、读回来、再删掉。"))
                            .font(T.tiny).foregroundColor(.white.opacity(0.38))
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 8) {
                            RunButton(title: tl("写入探测属性"), systemImage: "square.and.arrow.down",
                                      tint: T.ember, disabled: target == nil) { plantDecmpfs() }
                            RunButton(title: tl("移除"), systemImage: "trash", tint: T.warn,
                                      disabled: target == nil) { removeDecmpfs() }
                        }
                    }
                }
            }
            .padding(16)
        }
        .sheet(isPresented: $picking) {
            FilePickerSheet(isPresented: $picking) { url in
                target = url
                reload()
            }
        }
    }

    private func reload() {
        guard let target = target else { return }
        entries = XattrTool.list(target.path)
        detail = []
        if let data = XattrTool.read(target.path, name: "com.apple.decmpfs") {
            detail.append(XattrTool.decmpfsHeader(data))
            detail.append(hexdump(data, limit: 128))
        }
        status = "\(entries.count)" + tl(" 个属性")
    }

    private func plantDecmpfs() {
        guard let target = target else { return }
        let payload = Decmpfs.chunkedXattr(uncompressedSize: 65536, chunkCount: 1, producePerChunk: 4096)
        if let err = XattrTool.write(target.path, name: "com.apple.decmpfs", value: payload) {
            status = tl("写入失败: ") + "\(err)"
        } else {
            status = tl("已写入 ") + "\(payload.count)" + tl(" B 的 decmpfs 属性")
        }
        reload()
    }

    private func removeDecmpfs() {
        guard let target = target else { return }
        if let err = XattrTool.remove(target.path, name: "com.apple.decmpfs") {
            status = tl("移除失败: ") + "\(err)"
        } else {
            status = tl("已移除")
        }
        reload()
    }
}

// MARK: - SQLite

struct SQLitePane: View {
    @State private var target: URL?
    @State private var picking = false
    @State private var tables: [String] = []
    @State private var sql = "SELECT * FROM sqlite_master LIMIT 20;"
    @State private var columns: [String] = []
    @State private var rows: [[String]] = []
    @State private var status = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: tl("数据库"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "cylinder.split.1x2").font(.system(size: 12))
                                Text(target?.lastPathComponent ?? tl("选择 .sqlite / .db")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(target == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        if !tables.isEmpty {
                            Text(tl("表: ") + tables.prefix(12).joined(separator: ", "))
                                .font(T.monoSm).foregroundColor(.white.opacity(0.45))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("查询（只读）"))
                        TextEditor(text: $sql)
                            .font(.system(size: 11.5, design: .monospaced))
                            .frame(height: 90)
                            .scrollContentBackground(.hidden)
                            .background(T.panelHi)
                            .cornerRadius(8)
                        RunButton(title: tl("执行"), systemImage: "play.fill", tint: T.info,
                                  disabled: target == nil) { runQuery() }
                        if !status.isEmpty {
                            Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                        }
                    }
                }

                if !columns.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(columns.joined(separator: "  |  "))
                                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                .foregroundColor(T.emberSoft)
                                .fixedSize(horizontal: false, vertical: true)
                            Divider().overlay(T.stroke)
                            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                                Text(row.joined(separator: "  |  "))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.7))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .sheet(isPresented: $picking) {
            FilePickerSheet(isPresented: $picking) { url in
                target = url
                open()
            }
        }
    }

    private func open() {
        guard let target = target else { return }
        #if canImport(SQLite3)
        tables = SQLiteBrowser.tables(target.path)
        status = "\(tables.count)" + tl(" 张表")
        #else
        status = tl("SQLite3 不可用")
        #endif
    }

    private func runQuery() {
        guard let target = target else { return }
        #if canImport(SQLite3)
        let result = SQLiteBrowser.query(target.path, sql)
        columns = result.columns
        rows = result.rows
        status = result.error ?? "\(result.rows.count)" + tl(" 行")
        #endif
    }
}

// MARK: - Fonts

struct FontPane: View {
    @State private var picking = false
    @State private var log: [String] = []
    @State private var names: [String] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: tl("字体安装"))
                        Text(tl("把字体文件注册进本进程的字体域。iOS 允许应用注册用户字体，注册后 CoreText 立刻可见 —— 这是改机里唯一一条完全不需要任何越权就能改「系统观感」的路径，代价是只在本进程生效。"))
                            .font(T.body).foregroundColor(.white.opacity(0.65))
                            .fixedSize(horizontal: false, vertical: true)
                        RunButton(title: tl("选择字体文件"), systemImage: "textformat", tint: T.ember) {
                            picking = true
                        }
                    }
                }

                if !log.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(text: tl("结果"))
                            ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                                Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.65))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 4) {
                        SectionLabel(text: tl("系统可用字体（") + "\(names.count)" + tl("）"))
                        ForEach(names.prefix(80), id: \.self) { n in
                            Text(n).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                        }
                    }
                }
            }
            .padding(16)
        }
        .onAppear {
            if names.isEmpty {
                DispatchQueue.global(qos: .userInitiated).async {
                    let list = FontInstaller.installed()
                    DispatchQueue.main.async { names = list }
                }
            }
        }
        .sheet(isPresented: $picking) {
            FilePickerSheet(isPresented: $picking) { url in
                let result = FontInstaller.install(url)
                log.append(result)
                names = FontInstaller.installed()
            }
        }
    }
}
