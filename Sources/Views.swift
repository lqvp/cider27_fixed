import SwiftUI

@main
struct Cinder27App: App {
    @StateObject private var engine = LabEngine()
    @StateObject private var browser: FileBrowser
    @StateObject private var clipboard = FileClipboard()
    @StateObject private var bookmarks = Bookmarks()
    @StateObject private var l10n = L10n.shared

    init() {
        _browser = StateObject(wrappedValue: FileBrowser(path: Container.documents.path))
    }

    var body: some Scene {
        WindowGroup {
            GateView()
                .environmentObject(engine)
                .environmentObject(browser)
                .environmentObject(clipboard)
                .environmentObject(bookmarks)
                .environmentObject(l10n)
                .environment(\.layoutDirection, Lang.resolved.isRTL ? .rightToLeft : .leftToRight)
                .preferredColorScheme(.dark)
                .id(Lang.resolved)      // rebuild the tree on language change
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.gateInfo) private var gate
    @State private var tab = Int(ProcessInfo.processInfo.environment["CINDER27_TAB"] ?? "0") ?? 0

    var body: some View {
        TabView(selection: $tab) {
            DashboardView().tabItem {
                Label(t("tab.overview"), systemImage: "square.grid.2x2.fill")
            }.tag(0)

            LabView().tabItem {
                Label(t("tab.lab"), systemImage: "ant.fill")
            }.tag(1)

            ChainView().tabItem {
                Label(t("tab.chain"), systemImage: "link")
            }.tag(2)

            ModView().tabItem {
                Label(t("tab.mod"), systemImage: "wrench.and.screwdriver.fill")
            }.tag(3)

            SystemView().tabItem {
                Label(t("tab.system"), systemImage: "cpu")
            }.tag(4)
        }
        .tint(T.ember)
        .onAppear {
            Container.ensureAll()
            runAutorunIfRequested()
            styleTabBar()
        }
    }

    private func styleTabBar() {
        let appearance = UITabBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = UIColor(red: 0.055, green: 0.055, blue: 0.068, alpha: 1)
        UITabBar.appearance().standardAppearance = appearance
        UITabBar.appearance().scrollEdgeAppearance = appearance
    }

    /// Nothing in this app runs on its own. Every primitive stays at "not run" until the
    /// user presses Execute.
    ///
    /// The only exception is an opt-in harness for automated testing, and it needs *two*
    /// independent conditions: the environment variable `CINDER27_AUTORUN` naming a module,
    /// and a file called `enable-autorun` sitting in the container. A shipped build has
    /// neither, so a normal launch cannot execute anything.
    private func runAutorunIfRequested() {
        let env = ProcessInfo.processInfo.environment
        guard let id = env["CINDER27_AUTORUN"], !id.isEmpty else { return }

        let marker = Container.appSupport.appendingPathComponent("enable-autorun")
        guard FileManager.default.fileExists(atPath: marker.path) else { return }
        guard let module = Catalog.byID[id] else { return }

        print("[AUTORUN] \(id)")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            engine.run(module)
            if env["CINDER27_AUTORUN_EXIT"] == "1" {
                DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) {
                    print("[AUTORUN] exit")
                    exit(0)
                }
            }
        }
    }
}

// MARK: - Dashboard

struct DashboardView: View {
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.gateInfo) private var gate
    @State private var device = DeviceModel.current()

    private var tested: Int { Catalog.all.filter { engine.journal.verdict(for: $0.id) != .untested }.count }
    private var died: Int { Catalog.all.filter { engine.journal.verdict(for: $0.id) == .processDied }.count }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    header
                    deviceCard
                    capabilityCard

                    HStack(spacing: 12) {
                        statTile(t("ov.modules"), "\(Catalog.all.count)", T.info)
                        statTile(t("ov.tested"), "\(tested)", T.warn)
                        statTile(t("ov.died"), "\(died)", T.ember)
                    }

                    if tested > 0 {
                        RunButton(title: t("ov.reset"), systemImage: "arrow.counterclockwise",
                                  tint: T.info) {
                            engine.journal.clear()
                        }
                    }

                    if !engine.journal.recovered.isEmpty { interruptedCard }
                    logCard
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle("Cinder27")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(t("ov.headline"))
                .font(T.title)
                .foregroundColor(.white)
                .fixedSize(horizontal: false, vertical: true)
            Text(String(format: t("ov.sub"), Catalog.all.count, Catalog.locatedFixes))
                .font(T.tiny)
                .foregroundColor(.white.opacity(0.4))
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var deviceCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionLabel(text: t("ov.target"))
                    Spacer()
                    Pill(text: device.vulnerabilityClass == "VULNERABLE" ? t("verdict.vulnerable")
                         : device.vulnerabilityClass == "PATCHED" ? t("verdict.patched") : t("verdict.unknown"),
                         color: device.vulnerabilityClass == "VULNERABLE" ? T.ember : T.good)
                }
                KeyValueRow(key: t("ov.model"), value: "\(device.marketingName) (\(device.machine))")
                KeyValueRow(key: t("ov.os"), value: "iOS \(device.osVersion)  (\(device.osBuild))")
                KeyValueRow(key: t("ov.kernel"), value: device.kernel)
                KeyValueRow(key: t("ov.memory"),
                            value: ByteCountFormatter.string(fromByteCount: Int64(device.physicalMemory),
                                                            countStyle: .memory))
            }
        }
    }

    private var capabilityCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionLabel(text: t("ov.capabilities"))
                ForEach(Capability.matrix()) { row in
                    HStack(spacing: 10) {
                        Text(row.level)
                            .font(T.monoSm)
                            .foregroundColor(row.achieved ? T.good : .white.opacity(0.25))
                            .frame(width: 24, alignment: .leading)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.name).font(T.body)
                                .foregroundColor(row.achieved ? .white.opacity(0.9) : .white.opacity(0.4))
                            Text(row.detail).font(T.monoSm)
                                .foregroundColor(.white.opacity(0.28))
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        Spacer()
                        Image(systemName: row.achieved ? "checkmark.circle.fill" : "lock.fill")
                            .font(.system(size: 12))
                            .foregroundColor(row.achieved ? T.good : .white.opacity(0.18))
                    }
                }
            }
        }
    }

    private var interruptedCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel(text: t("ov.interrupted"))
                ForEach(engine.journal.recovered) { e in
                    HStack {
                        Circle().fill(T.ember).frame(width: 6, height: 6)
                        Text(e.moduleID).font(T.mono)
                        Spacer()
                        Text(e.detail).font(T.monoSm).foregroundColor(.white.opacity(0.4))
                    }
                }
                Text(t("ov.interrupted.note"))
                    .font(T.tiny).foregroundColor(.white.opacity(0.35))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var logCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel(text: t("ov.log"))
                if engine.logLines.isEmpty {
                    Text(t("ov.log.empty")).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                } else {
                    ForEach(Array(engine.logLines.suffix(8).enumerated()), id: \.offset) { _, line in
                        Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.55))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    private func statTile(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Text(value).font(.system(size: 22, weight: .bold, design: .rounded)).foregroundColor(color)
            Text(title).font(T.tiny).foregroundColor(.white.opacity(0.4))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(T.panel))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(T.stroke, lineWidth: 1))
    }
}
