import SwiftUI

// MARK: - Chain

struct ChainStage: Identifiable {
    let id: String
    let index: Int
    let title: String
    let goal: String
    let moduleIDs: [String]
    let unlock: String
}

enum ChainPlan {
    static let stages: [ChainStage] = [
        ChainStage(id: "s0", index: 0,
                   title: tl("权限面测绘"),
                   goal: tl("确定该构建上的实际起点：进程持有哪些 entitlement、沙盒放行到哪一层、mach 命名空间如何组织。后续每一步的收益都要以该基线折算。"),
                   moduleIDs: ["probe.privset", "kern.baseline"],
                   unlock: tl("缺少该基线，无法区分「漏洞所得」与「签名所授」。")),

        ChainStage(id: "s1", index: 1,
                   title: tl("信息泄露"),
                   goal: tl("先取得地址与内容。decmpfs 欠产出将内核页缓冲尾部交回用户态；TIFF 截断条带与 EXIF 短读将进程堆残留交回图像与元数据；CoreMedia bytestream 与 sandbox_extension 越过沙盒边界取回文件内容。"),
                   moduleIDs: ["kern.decmpfs", "iio.tiff.trunc", "iio.jpeg.comment",
                               "cm.fdleak", "sbx.toctou"],
                   unlock: tl("在取得稳定泄露之后，才有条件讨论将溢出写成什么值；否则只能触发崩溃。")),

        ChainStage(id: "s2", index: 2,
                   title: tl("溢出阈值标定"),
                   goal: tl("Type-5 阴影的写入是值可控的，但短溢出会被相邻 VLA 吸收。逐级抬升 R，确定该构建上栈布局开始失效的维度。"),
                   moduleIDs: ["cg.shading.sweep"],
                   unlock: tl("该阈值决定后续所有负载的长度预算。")),

        ChainStage(id: "s3", index: 3,
                   title: tl("值可控写"),
                   goal: tl("在标定所得长度上，以 PDF 中选定的 double 位模式决定被覆盖的指针。崩溃地址即证据 —— 它证明写入内容由攻击者控制，而非仅证明发生了崩溃。"),
                   moduleIDs: ["cg.shading"],
                   unlock: tl("值可控写与地址泄露相加，构成构造可控状态的全部要素；所缺的是将写转为执行的环节。")),

        ChainStage(id: "s4", index: 4,
                   title: tl("内核面"),
                   goal: tl("用户态可触及的内核入口数量有限。ipc_port 请求表索引竞态无 entitlement 门槛；decmpfs 已在泄露层验证。本层度量的是「能否将用户态的错误转为内核侧的状态变化」。"),
                   moduleIDs: ["kern.ipc"],
                   unlock: tl("需达到可复现阈值；低于该阈值时，越狱路径不成立。")),

        ChainStage(id: "s5", index: 5,
                   title: tl("解析器面"),
                   goal: tl("libarchive 的 2 字节堆越界与 CoreMedia 的 28 字节结构体外写，是整套中仅有的两个「写穿过对象边界」的形状。前者精确但浅，后者深且落在保存寄存器区。同一 CVE 下的 CAB 站点与 GPT 分区名越界读一并标定。"),
                   moduleIDs: ["arc.iso.stress", "arc.cab", "cm.rpu.sweep", "kext.gpt"],
                   unlock: tl("两者都需要稳定的堆布局控制，而这正是上一阶段泄露所提供的。")),

        ChainStage(id: "s6", index: 6,
                   title: tl("工具链落地"),
                   goal: tl("将上述产物转为可用形式：IPA 改包、二进制注入、字节级替换、属性改写、数据库读取。本层不依赖任何漏洞，但它是「漏洞能力」最终交付到手上的形态。"),
                   moduleIDs: ["tool.ipa", "tool.zip", "tool.hex", "tool.macho", "tool.paths"],
                   unlock: tl("自检全绿意味着工具链本身可信 —— 此后出现的问题是选择问题，不是工具问题。")),
    ]

    static func modules(for stage: ChainStage) -> [ExploitModule] {
        stage.moduleIDs.compactMap { Catalog.byID[$0] }
    }
}

struct ChainView: View {
    @EnvironmentObject private var engine: LabEngine

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    ForEach(ChainPlan.stages) { stage in
                        stageCard(stage)
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("chain.title"))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func stageCard(_ stage: ChainStage) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Text("\(stage.index)")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(T.ember)
                        .frame(width: 20, height: 20)
                        .background(Circle().fill(T.ember.opacity(0.16)))
                    Text(stage.title)
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundColor(.white)
                    Spacer()
                }
                Text(stage.goal)
                    .font(T.body)
                    .foregroundColor(.white.opacity(0.66))
                    .fixedSize(horizontal: false, vertical: true)

                ForEach(ChainPlan.modules(for: stage)) { module in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(engine.journal.verdict(for: module.id).tint)
                            .frame(width: 5, height: 5)
                        Text(module.title).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                            .lineLimit(1)
                        Spacer()
                        Text(engine.journal.verdict(for: module.id).label)
                            .font(T.monoSm)
                            .foregroundColor(engine.journal.verdict(for: module.id).tint)
                    }
                }

                Text("→ " + stage.unlock)
                    .font(T.tiny)
                    .foregroundColor(.white.opacity(0.34))
                    .fixedSize(horizontal: false, vertical: true)

                RunButton(title: t("chain.stage.run"), systemImage: "play.fill", tint: T.ember) {
                    engine.runSequence(ChainPlan.modules(for: stage), label: stage.title)
                }
            }
        }
    }
}

// MARK: - File preview

struct FilePreviewView: View {
    let item: FileItem
    @EnvironmentObject private var browser: FileBrowser
    @Environment(\.dismiss) private var dismiss
    @State private var mode = 0
    @State private var text: String?
    @State private var hex: String?
    @State private var info: [(String, String)] = []
    @State private var editing = false
    @State private var draft = ""
    @State private var status = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("", selection: $mode) {
                    Text(t("files.info")).tag(0)
                    Text(t("files.text")).tag(1)
                    Text(t("files.hex")).tag(2)
                    Text(t("files.package")).tag(3)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)

                if !status.isEmpty {
                    Text(status).font(T.monoSm)
                        .foregroundColor(status.hasPrefix("✓") ? T.good : T.warn)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16).padding(.bottom, 6)
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        switch mode {
                        case 0:
                            Card {
                                VStack(alignment: .leading, spacing: 2) {
                                    ForEach(Array(info.enumerated()), id: \.offset) { _, row in
                                        KeyValueRow(key: row.0, value: row.1)
                                    }
                                }
                            }
                        case 1:
                            if editing {
                                Card {
                                    TextEditor(text: $draft)
                                        .font(.system(size: 11, design: .monospaced))
                                        .frame(minHeight: 320)
                                        .scrollContentBackground(.hidden)
                                        .background(T.panelHi)
                                        .cornerRadius(8)
                                }
                            } else {
                                Card {
                                    Text(text ?? "—")
                                        .font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.7))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        case 2:
                            Card {
                                Text(hex ?? "—")
                                    .font(.system(size: 9.5, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.7))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        default:
                            Card {
                                let entries = PackageTool.list(item.path)
                                VStack(alignment: .leading, spacing: 3) {
                                    if entries.isEmpty {
                                        Text("—").font(T.monoSm).foregroundColor(.white.opacity(0.4))
                                    } else {
                                        ForEach(entries.prefix(300)) { e in
                                            Text("\(e.name)  \(e.size) B")
                                                .font(T.monoSm)
                                                .foregroundColor(.white.opacity(0.6))
                                                .lineLimit(1)
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    .padding(16)
                }
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(item.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    if mode == 1 && browser.writable {
                        Button(editing ? t("files.cancel") : t("files.save")) {
                            if editing { save() } else { editing = true; draft = text ?? "" }
                        }.tint(T.ember)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("module.close")) { dismiss() }.tint(T.ember)
                }
            }
            .onAppear(perform: load)
        }
    }

    private func load() {
        info = browser.fileInfo(item)
        switch FileLoader.kind(of: item.path) {
        case .plist: text = FileLoader.plist(at: item.path) ?? FileLoader.text(at: item.path)
        default: text = FileLoader.text(at: item.path)
        }
        hex = FileLoader.hexDump(at: item.path)
    }

    private func save() {
        // Validate a plist before writing so a typo cannot break a preference file.
        if item.name.hasSuffix(".plist") {
            guard let data = draft.data(using: .utf8),
                  (try? PropertyListSerialization.propertyList(from: data, format: nil)) != nil else {
                status = tl("plist 语法错误，未写入")
                return
            }
        }
        let backup = item.path + ".cinder27.bak"
        if !FileManager.default.fileExists(atPath: backup) {
            try? FileManager.default.copyItem(atPath: item.path, toPath: backup)
        }
        do {
            try Container.write(Data(draft.utf8), to: item.path)
            status = "✓ \(t("files.save")) · \(t("files.backup"))"
            text = draft
            editing = false
            browser.reload()
        } catch {
            status = Container.describe(errno)
        }
    }
}
