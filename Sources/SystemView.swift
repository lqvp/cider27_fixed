import SwiftUI

struct SystemView: View {
    @EnvironmentObject private var engine: LabEngine
    @State private var device = DeviceModel.current()
    @State private var probes: [PathProbe] = []
    @State private var entitlements: [String: Any] = [:]
    @State private var codeSign = CodeSign.current()
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: t("sys.device"))
                            KeyValueRow(key: t("ov.model"), value: "\(device.marketingName) · \(device.machine)")
                            KeyValueRow(key: t("ov.os"), value: "iOS \(device.osVersion)")
                            KeyValueRow(key: t("gate.build"), value: device.osBuild)
                            KeyValueRow(key: t("ov.kernel"), value: device.kernel)
                            KeyValueRow(key: "CPU", value: "\(device.cpuCount)" + tl(" 核"))
                            KeyValueRow(key: t("ov.memory"), value: ByteCountFormatter.string(fromByteCount: Int64(device.physicalMemory), countStyle: .memory))
                            KeyValueRow(key: t("ov.verdict"),
                                        value: device.vulnerabilityClass == "VULNERABLE" ? t("verdict.vulnerable")
                                             : device.vulnerabilityClass == "PATCHED" ? t("verdict.patched") : t("verdict.unknown"),
                                        tint: device.vulnerabilityClass == "VULNERABLE" ? T.ember : T.good)
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: t("sys.signature"))
                            KeyValueRow(key: "csflags", value: "0x" + String(codeSign.flags, radix: 16))
                            KeyValueRow(key: "Flags", value: codeSign.descriptions.isEmpty ? "—" : codeSign.descriptions.joined(separator: " "))
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                SectionLabel(text: t("sys.entitlements"))
                                Spacer()
                                Pill(text: "\(entitlements.count)", color: T.info)
                            }
                            if entitlements.isEmpty {
                                Text(t("common.none"))
                                    .font(T.monoSm).foregroundColor(.white.opacity(0.4))
                            } else {
                                ForEach(entitlements.keys.sorted(), id: \.self) { key in
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(key).font(T.monoSm).foregroundColor(T.emberSoft)
                                        Text("\(String(describing: entitlements[key]!))")
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.42))
                                            .lineLimit(3)
                                    }
                                    .padding(.vertical, 2)
                                }
                            }
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                SectionLabel(text: t("sys.sandbox"))
                                Spacer()
                                Button {
                                    scan()
                                } label: {
                                    Image(systemName: "arrow.clockwise")
                                        .font(.system(size: 12, weight: .bold))
                                }.tint(T.ember)
                            }
                            if probes.isEmpty {
                                Text(t("common.loading")).font(T.monoSm).foregroundColor(.white.opacity(0.35))
                            } else {
                                ForEach(probes) { probe in
                                    HStack(spacing: 8) {
                                        Image(systemName: probe.readable ? (probe.writable ? "checkmark.circle.fill" : "eye.fill") : "xmark.circle")
                                            .font(.system(size: 11))
                                            .foregroundColor(probe.readable ? (probe.writable ? T.good : T.warn) : .white.opacity(0.2))
                                            .frame(width: 16)
                                        Text(probe.path)
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(probe.readable ? 0.7 : 0.28))
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                        Spacer()
                                        Text(probe.readable ? "\(probe.entryCount)" : probe.note)
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.3))
                                    }
                                }
                            }
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("sys.log"))
                            ScrollView {
                                VStack(alignment: .leading, spacing: 2) {
                                    if engine.logLines.isEmpty {
                                        Text(t("common.none")).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                    }
                                    ForEach(Array(engine.logLines.enumerated()), id: \.offset) { _, line in
                                        Text(line)
                                            .font(T.monoSm)
                                            .foregroundColor(.white.opacity(0.5))
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                            }
                            .frame(maxHeight: 260)
                        }
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("sys.title"))
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                if probes.isEmpty { scan() }
            }
        }
    }

    private func scan() {
        device = DeviceModel.current()
        codeSign = CodeSign.current()
        entitlements = Entitlements.dump()
        probes = Probe.interestingRoots.map { Probe.path($0) }
    }
}
