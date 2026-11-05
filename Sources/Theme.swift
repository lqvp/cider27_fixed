import SwiftUI

enum T {
    static let bg = Color(red: 0.047, green: 0.047, blue: 0.058)
    static let panel = Color(red: 0.094, green: 0.094, blue: 0.110)
    static let panelHi = Color(red: 0.140, green: 0.140, blue: 0.162)
    static let stroke = Color.white.opacity(0.075)
    static let ember = Color(red: 1.00, green: 0.42, blue: 0.16)
    static let emberSoft = Color(red: 1.00, green: 0.60, blue: 0.32)
    static let good = Color(red: 0.32, green: 0.85, blue: 0.55)
    static let warn = Color(red: 1.00, green: 0.76, blue: 0.28)
    static let bad = Color(red: 1.00, green: 0.34, blue: 0.34)
    static let info = Color(red: 0.44, green: 0.70, blue: 1.00)
    static let violet = Color(red: 0.68, green: 0.52, blue: 1.00)

    static let mono = Font.system(size: 12, design: .monospaced)
    static let monoSm = Font.system(size: 10.5, design: .monospaced)
    static let monoLg = Font.system(size: 14, weight: .medium, design: .monospaced)
    static let title = Font.system(size: 26, weight: .bold, design: .rounded)
    static let head = Font.system(size: 15, weight: .semibold, design: .rounded)
    static let body = Font.system(size: 13, weight: .regular, design: .rounded)
    static let tiny = Font.system(size: 10.5, weight: .medium, design: .rounded)
}

struct Card<Content: View>: View {
    var padding: CGFloat = 14
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(T.panel))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(T.stroke, lineWidth: 1))
    }
}

struct Pill: View {
    let text: String
    var color: Color = T.info

    var body: some View {
        Text(text)
            .font(T.tiny)
            .foregroundColor(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.14)))
            .overlay(Capsule().strokeBorder(color.opacity(0.35), lineWidth: 0.6))
    }
}

struct SectionLabel: View {
    let text: String

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10.5, weight: .bold, design: .rounded))
            .kerning(1.1)
            .foregroundColor(.white.opacity(0.34))
    }
}

struct KeyValueRow: View {
    let key: String
    let value: String
    var mono: Bool = true
    var tint: Color = .white.opacity(0.86)

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(key)
                .font(T.body)
                .foregroundColor(.white.opacity(0.42))
                .frame(width: 108, alignment: .leading)
            Text(value)
                .font(mono ? T.mono : T.body)
                .foregroundColor(tint)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 3)
    }
}

struct RunButton: View {
    let title: String
    var systemImage: String = "bolt.fill"
    var tint: Color = T.ember
    var disabled: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 7) {
                Image(systemName: systemImage).font(.system(size: 12, weight: .bold))
                Text(title).font(.system(size: 13, weight: .semibold, design: .rounded))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(disabled ? T.panelHi : tint.opacity(0.18)))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(disabled ? T.stroke : tint.opacity(0.5), lineWidth: 1))
            .foregroundColor(disabled ? .white.opacity(0.25) : tint)
        }
        .disabled(disabled)
    }
}
