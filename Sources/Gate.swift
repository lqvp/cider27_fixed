import SwiftUI

// MARK: - Launch gate
//
// The tool is only meaningful below 27.2: every primitive here demonstrates a check Apple
// added in 27.2. On 27.2+ nothing fires, so the honest behaviour is to say so and stop —
// not to show a workbench full of buttons that can only fail.

enum VersionGate {
    enum Result {
        case supported(major: Int, minor: Int, patch: Int, build: String)
        case unsupported(major: Int, minor: Int, patch: Int, build: String)
    }

    /// "27.0" for a zero patch, "27.0.1" when there is one. The patch is part of the
    /// answer — a 27.0.1 device that reports "27.0" is a false reading.
    static func versionString(major: Int, minor: Int, patch: Int) -> String {
        patch != 0 ? "\(major).\(minor).\(patch)" : "\(major).\(minor)"
    }

    static func evaluate() -> Result {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let build = sysctlString("kern.osversion") ?? "—"
        // Supported window: 17.0 through 27.1.
        //
        // The lower bound is the app's own deployment target — below 17.0 the binary will
        // not launch at all, so it cannot be reached from here. Between 17.0 and 26.x the
        // fix window has not happened yet, so every primitive in this build is live. 27.0
        // and 27.1 sit immediately before the 27.2 gate wave and are the primary targets.
        // From 27.2 onward every check these primitives demonstrate already shipped.
        let supported: Bool
        if v.majorVersion < 17 {
            supported = false                      // below the deployment target
        } else if v.majorVersion < 27 {
            supported = true                       // 17.0 … 26.x — fixes not yet shipped
        } else if v.majorVersion == 27 {
            supported = v.minorVersion < 2         // 27.0, 27.1
        } else {
            supported = false                      // 27.2+ / 28+ — patched
        }
        // An explicit override exists for research builds where the version string lies.
        if ProcessInfo.processInfo.environment["CINDER27_FORCE_GATE"] == "1" {
            return .supported(major: v.majorVersion, minor: v.minorVersion, patch: v.patchVersion, build: build)
        }
        return supported
            ? .supported(major: v.majorVersion, minor: v.minorVersion, patch: v.patchVersion, build: build)
            : .unsupported(major: v.majorVersion, minor: v.minorVersion, patch: v.patchVersion, build: build)
    }

    static var isSupported: Bool {
        if case .supported = evaluate() { return true }
        return false
    }
}

struct GateView: View {
    @State private var phase: Phase = .checking
    @State private var entered = false

    enum Phase {
        case checking
        case supported(major: Int, minor: Int, patch: Int, build: String)
        case unsupported(major: Int, minor: Int, patch: Int, build: String)
    }

    var body: some View {
        ZStack {
            T.bg.ignoresSafeArea()

            if entered, case let .supported(major, minor, patch, build) = phase {
                RootView()
                    .environment(\.gateInfo, GateInfo(major: major, minor: minor, patch: patch, build: build))
                    .transition(.opacity)
            } else {
                content
                    .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.25), value: entered)
        .onAppear(perform: check)
        .onChange(of: phaseText) { _, _ in
            // Headless harness: CINDER27_AUTOENTER=1 walks through the gate so tab
            // screenshots and autoruns do not need a tap.
            if ProcessInfo.processInfo.environment["CINDER27_AUTOENTER"] == "1",
               case .supported = phase, !entered {
                entered = true
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        VStack(spacing: 22) {
            Spacer()

            VStack(spacing: 10) {
                Text("Cinder27")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                Text(t("ov.headline"))
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundColor(.white.opacity(0.4))
                    .multilineTextAlignment(.center)
            }

            switch phase {
            case .checking:
                VStack(spacing: 12) {
                    ProgressView().tint(T.ember)
                    Text(t("gate.checking"))
                        .font(T.body).foregroundColor(.white.opacity(0.5))
                }
                .padding(.top, 20)

            case let .supported(major, minor, patch, build):
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 14))
                                .foregroundColor(T.good)
                            Text(t("gate.supported"))
                                .font(.system(size: 15, weight: .semibold, design: .rounded))
                                .foregroundColor(T.good)
                        }
                        KeyValueRow(key: t("gate.detected"), value: VersionGate.versionString(major: major, minor: minor, patch: patch))
                        KeyValueRow(key: t("gate.build"), value: build)
                        KeyValueRow(key: t("gate.required"), value: "17.0 – 27.1")
                    }
                }
                .padding(.horizontal, 24)

                RunButton(title: t("gate.enter"), systemImage: "arrow.right.circle.fill", tint: T.ember) {
                    entered = true
                }
                .padding(.horizontal, 24)

            case let .unsupported(major, minor, patch, build):
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            Image(systemName: "xmark.octagon.fill")
                                .font(.system(size: 14))
                                .foregroundColor(T.bad)
                            Text(t("gate.unsupported.title"))
                                .font(.system(size: 15, weight: .semibold, design: .rounded))
                                .foregroundColor(T.bad)
                        }
                        KeyValueRow(key: t("gate.detected"), value: VersionGate.versionString(major: major, minor: minor, patch: patch), tint: T.bad)
                        KeyValueRow(key: t("gate.build"), value: build)
                        KeyValueRow(key: t("gate.required"), value: "17.0 – 27.1")
                        Divider().overlay(T.stroke)
                        Text(t("gate.unsupported.body"))
                            .font(T.body)
                            .foregroundColor(.white.opacity(0.62))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.horizontal, 24)

                RunButton(title: t("gate.recheck"), systemImage: "arrow.clockwise", tint: T.info) {
                    check()
                }
                .padding(.horizontal, 24)
            }

            Spacer()

            Text("Cinder27 · \(Lang.resolved.native)")
                .font(T.tiny)
                .foregroundColor(.white.opacity(0.22))
                .padding(.bottom, 18)
        }
    }

    private var phaseText: String {
        switch phase {
        case .checking: return "checking"
        case let .supported(m, n, p, _): return "ok-\(m).\(n).\(p)"
        case let .unsupported(m, n, p, _): return "no-\(m).\(n).\(p)"
        }
    }

    private func check() {
        phase = .checking
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) {
            switch VersionGate.evaluate() {
            case let .supported(major, minor, patch, build):
                phase = .supported(major: major, minor: minor, patch: patch, build: build)
            case let .unsupported(major, minor, patch, build):
                phase = .unsupported(major: major, minor: minor, patch: patch, build: build)
            }
        }
    }
}

struct GateInfo {
    let major: Int
    let minor: Int
    let patch: Int
    let build: String

    /// The full detected version, patch included — what the gate actually read.
    var osVersion: String { VersionGate.versionString(major: major, minor: minor, patch: patch) }
}

private struct GateInfoKey: EnvironmentKey {
    static let defaultValue = GateInfo(major: 0, minor: 0, patch: 0, build: "—")
}

extension EnvironmentValues {
    var gateInfo: GateInfo {
        get { self[GateInfoKey.self] }
        set { self[GateInfoKey.self] = newValue }
    }
}
