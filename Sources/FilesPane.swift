import SwiftUI
import UniformTypeIdentifiers

// MARK: - File manager
//
// Full-featured within what the sandbox actually permits: navigate anywhere readable,
// jump by typing a path, bookmark locations, and perform the standard mutations with a
// real write probe behind every claim. Nothing here pretends to reach past L1.

// MARK: Clipboard for copy / move

final class FileClipboard: ObservableObject {
    enum Mode { case none, copy, move }
    @Published private(set) var mode: Mode = .none
    @Published private(set) var paths: [String] = []

    func stage(_ paths: [String], mode: Mode) {
        self.paths = paths
        self.mode = mode
    }

    func clear() {
        paths = []
        mode = .none
    }

    var isEmpty: Bool { paths.isEmpty }
}

// MARK: Bookmarks

final class Bookmarks: ObservableObject {
    @Published private(set) var items: [String] = []

    private let key = "cinder27.bookmarks"

    init() {
        items = UserDefaults.standard.stringArray(forKey: key) ?? []
        if items.isEmpty {
            items = [
                Container.documents.path,
                Container.appSupport.path,
                Container.work.path,
                "/System/Library/Frameworks",
                "/usr/lib",
                "/private/etc",
                "/tmp",
                "/",
            ]
        }
    }

    func add(_ path: String) {
        guard !items.contains(path) else { return }
        items.append(path)
        persist()
    }

    func remove(_ path: String) {
        items.removeAll { $0 == path }
        persist()
    }

    private func persist() {
        UserDefaults.standard.set(items, forKey: key)
    }
}

// MARK: - The pane

struct FilesPane: View {
    @EnvironmentObject private var browser: FileBrowser
    @EnvironmentObject private var clipboard: FileClipboard
    @EnvironmentObject private var bookmarks: Bookmarks

    @State private var jumpShown = false
    @State private var jumpPath = ""
    @State private var newFolderShown = false
    @State private var newFolderName = ""
    @State private var renameTarget: FileItem?
    @State private var renameName = ""
    @State private var preview: FileItem?
    @State private var info: FileItem?
    @State private var status: String?
    @State private var confirmDelete: FileItem?
    @State private var searchText = ""
    @State private var selecting = false
    @State private var selection = Set<String>()
    @State private var sortMode = 0

    private var visible: [FileItem] {
        var list = browser.items
        if !searchText.isEmpty {
            list = list.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
        }
        switch sortMode {
        case 1: list.sort { $0.size > $1.size }
        case 2: list.sort { ($0.modified ?? .distantPast) > ($1.modified ?? .distantPast) }
        case 3: list.sort { $0.name.localizedStandardCompare($1.name) == .orderedDescending }
        default: break
        }
        return list
    }

    var body: some View {
        VStack(spacing: 0) {
            bookmarkBar
            pathBar
            searchBar

            if let status = status {
                HStack(spacing: 6) {
                    Image(systemName: status.hasPrefix("✓") ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 10))
                    Text(status).font(T.monoSm).lineLimit(2)
                    Spacer()
                    Button { self.status = nil } label: {
                        Image(systemName: "xmark").font(.system(size: 9, weight: .bold))
                    }
                }
                .foregroundColor(status.hasPrefix("✓") ? T.good : T.warn)
                .padding(.horizontal, 16).padding(.bottom, 6)
            }

            if let error = browser.error {
                Text(error).font(T.monoSm).foregroundColor(T.bad)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 6)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if !clipboard.isEmpty {
                clipboardBar
            }

            List {
                ForEach(visible) { item in
                    row(item)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .refreshable { browser.reload() }
        }
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Menu {
                    Button { jumpShown = true } label: { Label(t("files.jump"), systemImage: "arrow.right.to.line") }
                    Button { newFolderShown = true } label: { Label(t("files.newFolder"), systemImage: "folder.badge.plus") }
                    Divider()
                    Button { bookmarks.add(browser.path); status = tl("✓ 已加入书签") } label: {
                        Label(t("files.bookmarks"), systemImage: "bookmark")
                    }
                    Divider()
                    Picker("", selection: $sortMode) {
                        Text(t("files.name")).tag(0)
                        Text("Size").tag(1)
                        Text("Date").tag(2)
                        Text("Z→A").tag(3)
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }.tint(T.ember)
            }
        }
        .sheet(isPresented: $jumpShown) { jumpSheet }
        .sheet(item: $preview) { item in
            FilePreviewView(item: item).environmentObject(browser)
        }
        .sheet(item: $info) { item in
            FileInfoSheet(item: item, browser: browser)
        }
        .alert(t("files.newFolder"), isPresented: $newFolderShown) {
            TextField(t("files.name"), text: $newFolderName)
            Button(t("common.ok")) {
                if let err = browser.makeDirectory(newFolderName) {
                    status = err
                } else {
                    status = tl("✓ 已创建 ") + "\(newFolderName)"
                }
                newFolderName = ""
            }
            Button(t("files.cancel"), role: .cancel) { newFolderName = "" }
        }
        .alert(t("files.rename"), isPresented: Binding(
            get: { renameTarget != nil },
            set: { if !$0 { renameTarget = nil } })) {
            TextField(t("files.name"), text: $renameName)
            Button(t("common.ok")) {
                if let target = renameTarget {
                    if let err = browser.rename(target, to: renameName) {
                        status = err
                    } else {
                        status = "✓ \(t("files.renamed")) → \(renameName)"
                    }
                }
                renameTarget = nil
            }
            Button(t("files.cancel"), role: .cancel) { renameTarget = nil }
        }
        .alert("\(t("files.delete"))?", isPresented: Binding(
            get: { confirmDelete != nil },
            set: { if !$0 { confirmDelete = nil } })) {
            Button(t("files.delete"), role: .destructive) {
                if let target = confirmDelete {
                    if let err = browser.delete(target) {
                        status = err
                    } else {
                        status = "✓ \(t("files.deleted")) \(target.name)"
                    }
                }
                confirmDelete = nil
            }
            Button(t("files.cancel"), role: .cancel) { confirmDelete = nil }
        } message: {
            Text(confirmDelete?.path ?? "")
        }
    }

    // MARK: Bars

    private var bookmarkBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                ForEach(bookmarks.items, id: \.self) { path in
                    Button {
                        browser.chdir(path)
                    } label: {
                        Pill(text: (path as NSString).lastPathComponent.isEmpty ? "/" : (path as NSString).lastPathComponent,
                             color: browser.path == path ? T.ember : .white.opacity(0.45))
                    }
                    .contextMenu {
                        Button(t("files.delete"), role: .destructive) { bookmarks.remove(path) }
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
    }

    private var pathBar: some View {
        HStack(spacing: 8) {
            Button { browser.up() } label: {
                Image(systemName: "arrow.up").font(.system(size: 12, weight: .bold))
            }.tint(T.ember)

            Button {
                jumpPath = browser.path
                jumpShown = true
            } label: {
                HStack(spacing: 4) {
                    Text(browser.path)
                        .font(T.monoSm)
                        .foregroundColor(.white.opacity(0.5))
                        .lineLimit(1)
                        .truncationMode(.head)
                    Image(systemName: "chevron.down").font(.system(size: 8, weight: .bold))
                        .foregroundColor(.white.opacity(0.3))
                }
            }
            .buttonStyle(.plain)

            Spacer()

            if browser.writable {
                Pill(text: t("files.writable"), color: T.good)
            } else {
                Pill(text: t("files.readonly"), color: T.warn)
            }

            Button { browser.reload() } label: {
                Image(systemName: "arrow.clockwise").font(.system(size: 12, weight: .bold))
            }.tint(T.ember)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 6)
    }

    private var searchBar: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundColor(.white.opacity(0.3))
            TextField(t("files.name"), text: $searchText)
                .font(T.monoSm)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            if !searchText.isEmpty {
                Button { searchText = "" } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 11))
                }.tint(.white.opacity(0.3))
            }
            Text("\(visible.count)").font(T.monoSm).foregroundColor(.white.opacity(0.25))
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 9).fill(T.panel))
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }

    private var clipboardBar: some View {
        HStack(spacing: 8) {
            Image(systemName: clipboard.mode == .copy ? "doc.on.doc" : "arrow.right.doc.on.clipboard")
                .font(.system(size: 11))
                .foregroundColor(T.info)
            Text("\(clipboard.paths.count) · \(clipboard.mode == .copy ? t("files.copy") : t("files.move"))")
                .font(T.monoSm).foregroundColor(.white.opacity(0.6))
            Spacer()
            Button(t("files.paste")) { paste() }
                .font(.system(size: 11, weight: .semibold)).tint(T.ember)
            Button(t("files.cancel")) { clipboard.clear() }
                .font(.system(size: 11)).tint(.white.opacity(0.4))
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 9).fill(T.info.opacity(0.1)))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(T.info.opacity(0.3), lineWidth: 1))
        .padding(.horizontal, 16).padding(.bottom, 8)
    }

    // MARK: Row

    private func row(_ item: FileItem) -> some View {
        Button {
            if item.isDirectory { browser.enter(item) } else { preview = item }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: item.icon)
                    .font(.system(size: 13))
                    .foregroundColor(item.isDirectory ? T.ember : .white.opacity(0.4))
                    .frame(width: 20)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.name)
                        .font(T.body)
                        .foregroundColor(.white.opacity(0.86))
                        .lineLimit(1)
                    HStack(spacing: 6) {
                        if !item.isDirectory { Text(item.displaySize) }
                        if item.isSymlink { Text("→") }
                        if let m = item.modified {
                            Text(FileBrowser.dateFormatter.string(from: m))
                        }
                    }
                    .font(T.monoSm)
                    .foregroundColor(.white.opacity(0.26))
                }
                Spacer()
                if item.isDirectory {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.white.opacity(0.18))
                }
            }
        }
        .listRowBackground(T.panel)
        .contextMenu {
            Button { info = item } label: { Label(t("files.info"), systemImage: "info.circle") }
            Button {
                renameTarget = item
                renameName = item.name
            } label: { Label(t("files.rename"), systemImage: "pencil") }
            Button {
                clipboard.stage([item.path], mode: .copy)
                status = "✓ \(t("files.copied")) \(item.name)"
            } label: { Label(t("files.copy"), systemImage: "doc.on.doc") }
            Button {
                clipboard.stage([item.path], mode: .move)
                status = "→ \(t("files.move")) \(item.name)"
            } label: { Label(t("files.move"), systemImage: "arrow.right.doc.on.clipboard") }
            Button { duplicate(item) } label: { Label(t("files.duplicate"), systemImage: "plus.square.on.square") }
            if item.isDirectory {
                Button {
                    bookmarks.add(item.path)
                    status = tl("✓ 书签 ") + "\(item.name)"
                } label: { Label(t("files.bookmarks"), systemImage: "bookmark") }
            }
            Divider()
            Button(role: .destructive) { confirmDelete = item } label: {
                Label(t("files.delete"), systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) { confirmDelete = item } label: {
                Label(t("files.delete"), systemImage: "trash")
            }
            Button {
                renameTarget = item
                renameName = item.name
            } label: { Label(t("files.rename"), systemImage: "pencil") }
                .tint(T.info)
        }
        .swipeActions(edge: .leading) {
            Button {
                clipboard.stage([item.path], mode: .copy)
            } label: { Label(t("files.copy"), systemImage: "doc.on.doc") }
                .tint(T.ember)
        }
    }

    // MARK: Jump sheet

    private var jumpSheet: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            SectionLabel(text: t("files.path"))
                            TextField("/path/to/directory", text: $jumpPath)
                                .font(T.mono)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .padding(9)
                                .background(RoundedRectangle(cornerRadius: 8).fill(T.panelHi))
                            HStack(spacing: 8) {
                                Button(t("files.done")) {
                                    browser.chdir(jumpPath)
                                    jumpShown = false
                                }
                                .font(.system(size: 13, weight: .semibold))
                                .tint(T.ember)
                                Spacer()
                                Button("~/Documents") {
                                    jumpPath = Container.documents.path
                                }.font(T.monoSm).tint(.white.opacity(0.4))
                                Button("/") { jumpPath = "/" }
                                    .font(T.monoSm).tint(.white.opacity(0.4))
                            }
                        }
                    }

                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionLabel(text: t("files.bookmarks"))
                            ForEach(bookmarks.items, id: \.self) { path in
                                Button {
                                    browser.chdir(path)
                                    jumpShown = false
                                } label: {
                                    HStack(spacing: 8) {
                                        Image(systemName: "folder.fill")
                                            .font(.system(size: 11)).foregroundColor(T.ember)
                                        Text(Container.shortPath(URL(fileURLWithPath: path)))
                                            .font(T.monoSm).foregroundColor(.white.opacity(0.7))
                                            .lineLimit(1).truncationMode(.middle)
                                        Spacer()
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(t("files.jump"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("files.cancel")) { jumpShown = false }.tint(T.ember)
                }
            }
        }
    }

    // MARK: Operations

    private func paste() {
        let fm = FileManager.default
        var ok = 0
        var failed: [String] = []
        for source in clipboard.paths {
            let name = (source as NSString).lastPathComponent
            let dest = (browser.path as NSString).appendingPathComponent(name)
            guard dest != source else { continue }
            do {
                if fm.fileExists(atPath: dest) {
                    // never silently overwrite
                    let stem = (name as NSString).deletingPathExtension
                    let ext = (name as NSString).pathExtension
                    var n = 2
                    var candidate = dest
                    while fm.fileExists(atPath: candidate) {
                        let newName = ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)"
                        candidate = (browser.path as NSString).appendingPathComponent(newName)
                        n += 1
                    }
                    if clipboard.mode == .copy {
                        try fm.copyItem(atPath: source, toPath: candidate)
                    } else {
                        try fm.moveItem(atPath: source, toPath: candidate)
                    }
                } else {
                    if clipboard.mode == .copy {
                        try fm.copyItem(atPath: source, toPath: dest)
                    } else {
                        try fm.moveItem(atPath: source, toPath: dest)
                    }
                }
                ok += 1
            } catch {
                failed.append("\(name): \(Container.describe(errno))")
            }
        }
        browser.reload()
        if failed.isEmpty {
            status = "✓ \(clipboard.mode == .copy ? t("files.copied") : t("files.moved")) \(ok)"
            clipboard.clear()
        } else {
            status = failed.joined(separator: " · ")
        }
    }

    private func duplicate(_ item: FileItem) {
        let fm = FileManager.default
        let dir = (item.path as NSString).deletingLastPathComponent
        let stem = (item.name as NSString).deletingPathExtension
        let ext = (item.name as NSString).pathExtension
        var n = 2
        var candidate = ""
        repeat {
            let name = ext.isEmpty ? "\(stem) \(n)" : "\(stem) \(n).\(ext)"
            candidate = (dir as NSString).appendingPathComponent(name)
            n += 1
        } while fm.fileExists(atPath: candidate)

        do {
            try fm.copyItem(atPath: item.path, toPath: candidate)
            browser.reload()
            status = "✓ \(t("files.copied")) \((candidate as NSString).lastPathComponent)"
        } catch {
            status = Container.describe(errno)
        }
    }
}

// MARK: - Info sheet

struct FileInfoSheet: View {
    let item: FileItem
    @ObservedObject var browser: FileBrowser
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(browser.fileInfo(item).enumerated()), id: \.offset) { _, row in
                                KeyValueRow(key: row.0, value: row.1)
                            }
                        }
                    }
                    if !item.isDirectory {
                        Card {
                            VStack(alignment: .leading, spacing: 6) {
                                SectionLabel(text: t("files.hex"))
                                Text(FileLoader.hexDump(at: item.path, limit: 2048) ?? "—")
                                    .font(.system(size: 9.5, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.6))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(item.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("module.close")) { dismiss() }.tint(T.ember)
                }
            }
        }
    }
}
