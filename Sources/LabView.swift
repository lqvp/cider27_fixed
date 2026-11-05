import SwiftUI

extension Reach {
    var tint: Color {
        switch self {
        case .inProcess: return T.good
        case .systemProcess: return T.info
        case .kernel: return T.bad
        case .entitlementGated: return T.warn
        case .radio: return T.violet
        case .peripheral: return T.emberSoft
        }
    }
}

extension PrimitiveKind {
    var tint: Color {
        switch self {
        case .oobWrite: return T.ember
        case .oobRead: return T.warn
        case .uaf: return T.bad
        case .infoLeak: return T.violet
        case .typeConfusion: return T.info
        case .intOverflow: return T.emberSoft
        case .probe: return .white.opacity(0.5)
        }
    }
}

extension LabVerdict {
    var tint: Color {
        switch self {
        case .untested: return .white.opacity(0.3)
        case .running: return T.info
        case .completed: return T.good
        case .refused: return T.warn
        case .processDied: return T.ember
        }
    }
}

// MARK: - Lab

struct LabView: View {
    @EnvironmentObject private var engine: LabEngine
    @State private var selected: ExploitModule?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    ForEach(Catalog.groups, id: \.0) { group in
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: group.0)
                            ForEach(group.1) { module in
                                Button {
                                    selected = module
                                } label: {
                                    moduleRow(module)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("lab.title"))
            .navigationBarTitleDisplayMode(.inline)
            .sheet(item: $selected) { module in
                ModuleDetailView(module: module)
                    .environmentObject(engine)
                    .presentationDetents([.large])
            }
        }
    }

    private func moduleRow(_ module: ExploitModule) -> some View {
        let verdict = engine.journal.verdict(for: module.id)
        let isRunning = engine.running.contains(module.id)
        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Text(module.title)
                    .font(.system(size: 13.5, weight: .semibold, design: .rounded))
                    .foregroundColor(.white.opacity(0.92))
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 4)
                if isRunning {
                    ProgressView().scaleEffect(0.6)
                } else {
                    Pill(text: t(verdict.key), color: verdict.tint)
                }
            }
            HStack(spacing: 6) {
                Pill(text: module.primitive.label, color: module.primitive.tint)
                Pill(text: module.reach.label, color: module.reach.tint)
                Text(module.cve)
                    .font(T.monoSm)
                    .foregroundColor(.white.opacity(0.3))
                    .lineLimit(1)
            }
            Text(module.component)
                .font(T.monoSm)
                .foregroundColor(.white.opacity(0.28))
                .lineLimit(1)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(T.panel))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(T.stroke, lineWidth: 1))
    }
}

struct ModuleDetailView: View {
    let module: ExploitModule
    @EnvironmentObject private var engine: LabEngine
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Card {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 6) {
                                Pill(text: module.primitive.label, color: module.primitive.tint)
                                Pill(text: module.reach.label, color: module.reach.tint)
                                Pill(text: "T\(module.tier)", color: .white.opacity(0.5))
                            }
                            Text(module.title)
                                .font(.system(size: 19, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                            Text(module.component)
                                .font(T.mono)
                                .foregroundColor(.white.opacity(0.4))
                            Text(module.cve)
                                .font(T.mono)
                                .foregroundColor(T.emberSoft)
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("module.primitive"))
                            Text(module.summary)
                                .font(T.body)
                                .foregroundColor(.white.opacity(0.8))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("module.notes"))
                            Text(module.notes)
                                .font(T.body)
                                .foregroundColor(.white.opacity(0.65))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    if let outcome = engine.outcome(for: module.id) {
                        Card {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    SectionLabel(text: t("module.result"))
                                    Spacer()
                                    Text("\(outcome.elapsedMs) ms").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                }
                                Text(outcome.headline)
                                    .font(.system(size: 15, weight: .semibold, design: .rounded))
                                    .foregroundColor(outcome.failed ? T.bad : T.good)
                                if !outcome.detail.isEmpty {
                                    Text(outcome.detail)
                                        .font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.6))
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                ForEach(Array(outcome.evidence.enumerated()), id: \.offset) { _, line in
                                    Text("· \(line)")
                                        .font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.42))
                                }
                            }
                        }
                    }

                    let history = engine.journal.history(for: module.id)
                    if !history.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 6) {
                                SectionLabel(text: t("module.history"))
                                ForEach(history.suffix(6)) { entry in
                                    HStack(spacing: 8) {
                                        Text(entry.phase)
                                            .font(T.monoSm)
                                            .foregroundColor(entry.phase == "died" ? T.ember : .white.opacity(0.4))
                                            .frame(width: 46, alignment: .leading)
                                        Text(entry.detail)
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.35))
                                            .lineLimit(1)
                                    }
                                }
                            }
                        }
                    }

                    RunButton(title: engine.running.contains(module.id) ? t("module.running") : t("module.run"),
                              systemImage: "bolt.fill",
                              tint: module.primitive.tint,
                              disabled: engine.running.contains(module.id)) {
                        engine.run(module)
                    }

                    Text(t("module.warning"))
                        .font(T.tiny)
                        .foregroundColor(.white.opacity(0.32))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("tab.lab"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("module.close")) { dismiss() }.tint(T.ember)
                }
            }
        }
    }
}
