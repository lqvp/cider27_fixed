import SwiftUI
import CryptoKit

// MARK: - Hashing helpers

extension Data {
    var sha256Hex: String {
        SHA256.hash(data: self).map { String(format: "%02x", $0) }.joined()
    }

    var sha1Hex: String {
        Insecure.SHA1.hash(data: self).map { String(format: "%02x", $0) }.joined()
    }

    var md5Hex: String {
        Insecure.MD5.hash(data: self).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Apps

struct AppsPane: View {
    @State private var apps: [InstalledApp] = []
    @State private var query = ""
    @State private var selected: InstalledApp?
    @State private var loading = true

    private var filtered: [InstalledApp] {
        guard !query.isEmpty else { return apps }
        return apps.filter {
            $0.displayName.localizedCaseInsensitiveContains(query) ||
            $0.bundleID.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundColor(.white.opacity(0.3))
                TextField("bundle id / name", text: $query)
                    .font(T.body)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if loading { ProgressView().scaleEffect(0.6) }
                Text("\(filtered.count)").font(T.monoSm).foregroundColor(.white.opacity(0.25))
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(T.panel))
            .padding(.horizontal, 16)

            List {
                ForEach(filtered) { app in
                    Button { selected = app } label: {
                        HStack(spacing: 10) {
                            Image(systemName: app.isSystem ? "gearshape.2.fill" : "app.fill")
                                .font(.system(size: 13))
                                .foregroundColor(app.isSystem ? T.info : T.ember)
                                .frame(width: 20)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(app.displayName).font(T.body).foregroundColor(.white.opacity(0.88))
                                Text(app.bundleID).font(T.monoSm).foregroundColor(.white.opacity(0.32))
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            if !app.version.isEmpty {
                                Text(app.version).font(T.monoSm).foregroundColor(.white.opacity(0.25))
                            }
                        }
                    }
                    .listRowBackground(T.panel)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .onAppear {
            guard apps.isEmpty else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let list = AppCensus.installed()
                DispatchQueue.main.async { apps = list; loading = false }
            }
        }
        .sheet(item: $selected) { app in
            AppDetailView(app: app).presentationDetents([.large])
        }
    }
}

struct AppDetailView: View {
    let app: InstalledApp
    @Environment(\.dismiss) private var dismiss
    @State private var files: [String] = []
    @State private var note = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: t("pane.apps"))
                            KeyValueRow(key: t("files.name"), value: app.displayName, mono: false)
                            KeyValueRow(key: "Bundle ID", value: app.bundleID)
                            KeyValueRow(key: "Version", value: app.version.isEmpty ? "—" : app.version)
                            KeyValueRow(key: "Type", value: app.isSystem ? "System" : (app.isPlaceholder ? "Placeholder" : "User"))
                        }
                    }
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: "Container")
                            KeyValueRow(key: "Bundle", value: app.bundlePath.isEmpty ? "—" : app.bundlePath)
                            KeyValueRow(key: "Data", value: app.dataPath.isEmpty ? "—" : app.dataPath)
                        }
                    }
                    Card {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionLabel(text: "Contents")
                            if files.isEmpty {
                                Text(note.isEmpty ? t("cap.no") : note)
                                    .font(T.monoSm).foregroundColor(.white.opacity(0.4))
                            } else {
                                ForEach(files, id: \.self) { line in
                                    Text(line).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                }
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(app.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("module.close")) { dismiss() }.tint(T.ember)
                }
            }
            .onAppear(perform: load)
        }
    }

    private func load() {
        guard !app.dataPath.isEmpty else { note = "no data container"; return }
        do {
            files = try FileManager.default.contentsOfDirectory(atPath: app.dataPath).sorted()
        } catch {
            note = "\(Container.describe(errno))"
        }
    }
}

// MARK: - Preferences

struct PrefsPane: View {
    @State private var entries: [FileItem] = []
    @State private var current = ""
    @State private var editing: FileItem?
    @State private var status = ""

    private let candidates = [
        "/private/var/mobile/Library/Preferences",
        "/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
        "/private/var/mobile/Library/Preferences/com.apple.Accessibility.plist",
        "/private/var/mobile/Library/Preferences/com.apple.UIKit.plist",
        "/private/var/mobile/Library/Preferences/com.apple.keyboard.plist",
    ]

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 7) {
                    ForEach(candidates, id: \.self) { path in
                        Button { load(path) } label: {
                            Pill(text: (path as NSString).lastPathComponent,
                                 color: current == path ? T.ember : .white.opacity(0.45))
                        }
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
            }

            if !status.isEmpty {
                Text(status).font(T.monoSm).foregroundColor(T.warn)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 6)
                    .fixedSize(horizontal: false, vertical: true)
            }

            List {
                ForEach(entries) { item in
                    Button { editing = item } label: {
                        HStack(spacing: 10) {
                            Image(systemName: item.isDirectory ? "folder.fill" : "list.bullet.rectangle")
                                .font(.system(size: 12))
                                .foregroundColor(item.isDirectory ? T.ember : .white.opacity(0.4))
                                .frame(width: 18)
                            Text(item.name).font(T.body).foregroundColor(.white.opacity(0.85)).lineLimit(1)
                            Spacer()
                            Text(item.displaySize).font(T.monoSm).foregroundColor(.white.opacity(0.25))
                        }
                    }
                    .listRowBackground(T.panel)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .onAppear { if current.isEmpty { load(candidates[0]) } }
        .sheet(item: $editing) { item in
            PlistEditorView(item: item).presentationDetents([.large])
        }
    }

    private func load(_ path: String) {
        current = path
        entries = []
        status = ""
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
            status = "\(path) — \(Container.describe(ENOENT))"
            return
        }
        if isDir.boolValue {
            guard let names = try? fm.contentsOfDirectory(atPath: path) else {
                status = "\(path) — \(Container.describe(errno))"
                return
            }
            entries = names.compactMap { name -> FileItem? in
                let full = (path as NSString).appendingPathComponent(name)
                var d: ObjCBool = false
                _ = fm.fileExists(atPath: full, isDirectory: &d)
                let size = ((try? fm.attributesOfItem(atPath: full))?[.size] as? NSNumber)?.int64Value ?? 0
                return FileItem(name: name, path: full, isDirectory: d.boolValue, size: size,
                                modified: nil, isSymlink: false)
            }.sorted { $0.name < $1.name }
            if entries.isEmpty { status = t("files.empty") }
        } else {
            let size = ((try? fm.attributesOfItem(atPath: path))?[.size] as? NSNumber)?.int64Value ?? 0
            entries = [FileItem(name: (path as NSString).lastPathComponent, path: path,
                                isDirectory: false, size: size, modified: nil, isSymlink: false)]
        }
    }
}

struct PlistEditorView: View {
    let item: FileItem
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var editable = false
    @State private var status = ""
    @State private var dirty = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if !status.isEmpty {
                    Text(status).font(T.monoSm)
                        .foregroundColor(status.hasPrefix("✓") ? T.good : T.warn)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        .fixedSize(horizontal: false, vertical: true)
                }
                TextEditor(text: $text)
                    .font(.system(size: 11, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .background(T.bg)
                    .disabled(!editable)
                    .onChange(of: text) { _, _ in dirty = true }
            }
            .background(T.bg.ignoresSafeArea())
            .navigationTitle(item.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(editable ? "RO" : "Edit") { editable.toggle() }.tint(T.ember)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(t("files.save")) { save() }
                        .tint(dirty && editable ? T.ember : .white.opacity(0.3))
                        .disabled(!editable || !dirty)
                }
            }
            .onAppear(perform: load)
        }
    }

    private func load() {
        if let s = FileLoader.plist(at: item.path) ?? FileLoader.text(at: item.path) {
            text = s
            editable = true
            status = "\(s.count) chars"
        } else {
            text = FileLoader.hexDump(at: item.path) ?? "—"
            status = "binary"
        }
        dirty = false
    }

    private func save() {
        guard let data = text.data(using: .utf8) else { return }
        if item.name.hasSuffix(".plist"),
           (try? PropertyListSerialization.propertyList(from: data, format: nil)) == nil {
            status = "plist syntax error — not written"
            return
        }
        let backup = item.path + ".cinder27.bak"
        if !FileManager.default.fileExists(atPath: backup) {
            try? FileManager.default.copyItem(atPath: item.path, toPath: backup)
        }
        do {
            try Container.write(data, to: item.path)
            status = "✓ \(t("files.save"))"
            dirty = false
        } catch {
            status = Container.describe(errno)
        }
    }
}

// MARK: - Processes

struct ProcessPane: View {
    @State private var procs: [ProcInfo] = []
    @State private var query = ""

    private var filtered: [ProcInfo] {
        guard !query.isEmpty else { return procs }
        return procs.filter { $0.name.localizedCaseInsensitiveContains(query) || "\($0.pid)" == query }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundColor(.white.opacity(0.3))
                TextField("pid / name", text: $query).font(T.body)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("\(procs.count)").font(T.monoSm).foregroundColor(.white.opacity(0.3))
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(T.panel))
            .padding(.horizontal, 16)

            List {
                ForEach(filtered) { p in
                    HStack(spacing: 10) {
                        Text("\(p.pid)").font(T.monoSm).foregroundColor(.white.opacity(0.3))
                            .frame(width: 44, alignment: .leading)
                        Text(p.name).font(T.mono).foregroundColor(.white.opacity(0.85)).lineLimit(1)
                        Spacer()
                        Text("uid \(p.uid)").font(T.monoSm).foregroundColor(.white.opacity(0.25))
                    }
                    .listRowBackground(T.panel)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .onAppear { procs = ProcList.snapshot() }
    }
}

// MARK: - Daemons

struct DaemonPane: View {
    @State private var daemons: [LaunchCensus.Daemon] = []
    @State private var query = ""

    private var filtered: [LaunchCensus.Daemon] {
        guard !query.isEmpty else { return daemons }
        return daemons.filter { $0.label.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundColor(.white.opacity(0.3))
                TextField("label", text: $query).font(T.body)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("\(daemons.count)").font(T.monoSm).foregroundColor(.white.opacity(0.3))
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10).fill(T.panel))
            .padding(.horizontal, 16)

            List {
                ForEach(filtered) { d in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(d.label).font(T.mono).foregroundColor(.white.opacity(0.85)).lineLimit(1)
                            if d.runAtLoad { Pill(text: "RunAtLoad", color: T.good) }
                            if d.keepAlive { Pill(text: "KeepAlive", color: T.info) }
                        }
                        Text(d.program.isEmpty ? d.path : d.program)
                            .font(T.monoSm).foregroundColor(.white.opacity(0.3))
                            .lineLimit(1).truncationMode(.middle)
                    }
                    .listRowBackground(T.panel)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .onAppear { daemons = LaunchCensus.daemons() }
    }
}

// MARK: - Crashes

struct CrashPane: View {
    @State private var reports: [CrashReport] = []
    @State private var selected: CrashReport?

    var body: some View {
        List {
            if reports.isEmpty {
                Text("No crash reports in reachable paths.")
                    .font(T.monoSm).foregroundColor(.white.opacity(0.4))
                    .listRowBackground(T.panel)
            }
            ForEach(reports) { r in
                Button { selected = r } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(r.process.isEmpty ? r.name : r.process)
                                .font(T.mono).foregroundColor(.white.opacity(0.88))
                            Spacer()
                            if let d = r.date {
                                Text(FileBrowser.dateFormatter.string(from: d))
                                    .font(T.monoSm).foregroundColor(.white.opacity(0.25))
                            }
                        }
                        if !r.exception.isEmpty {
                            Text(r.exception).font(T.monoSm).foregroundColor(T.emberSoft).lineLimit(2)
                        }
                        if !r.faultingSymbol.isEmpty {
                            Text(r.faultingSymbol).font(T.monoSm).foregroundColor(.white.opacity(0.35)).lineLimit(1)
                        }
                    }
                }
                .listRowBackground(T.panel)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .onAppear { reports = CrashLogs.list() }
        .sheet(item: $selected) { r in
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        Card {
                            VStack(alignment: .leading, spacing: 2) {
                                KeyValueRow(key: "Process", value: r.process)
                                KeyValueRow(key: "Exception", value: r.exception)
                                KeyValueRow(key: "Size", value: "\(r.size) B")
                            }
                        }
                        Card {
                            VStack(alignment: .leading, spacing: 3) {
                                SectionLabel(text: "Frames")
                                ForEach(Array(r.frames.enumerated()), id: \.offset) { i, f in
                                    Text("\(i)  \(f)").font(T.monoSm).foregroundColor(.white.opacity(0.7))
                                }
                            }
                        }
                    }
                    .padding(16)
                }
                .background(T.bg.ignoresSafeArea())
                .navigationTitle(r.name)
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }
}

// MARK: - Binary

struct BinaryPane: View {
    @State private var path = ""
    @State private var info: MachOInfo?
    @State private var error = ""

    private let presets: [(String, String)] = [
        ("CoreGraphics", "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"),
        ("CoreMedia", "/System/Library/Frameworks/CoreMedia.framework/CoreMedia"),
        ("libarchive", "/usr/lib/libarchive.2.dylib"),
        ("ImageIO", "/System/Library/Frameworks/ImageIO.framework/ImageIO"),
        ("libsystem_sandbox", "/usr/lib/system/libsystem_sandbox.dylib"),
        ("Self", Bundle.main.executablePath ?? ""),
    ]

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 7) {
                        ForEach(presets, id: \.0) { p in
                            Button { path = p.1; inspect() } label: {
                                Pill(text: p.0, color: .white.opacity(0.5))
                            }
                        }
                    }
                }

                HStack(spacing: 8) {
                    TextField("/path/to/binary", text: $path)
                        .font(T.monoSm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(9)
                        .background(RoundedRectangle(cornerRadius: 8).fill(T.panel))
                    Button(t("common.ok")) { inspect() }
                        .font(.system(size: 12, weight: .semibold))
                        .tint(T.ember)
                }

                if !error.isEmpty {
                    Text(error).font(T.monoSm).foregroundColor(T.warn)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                if let info = info {
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: "Mach-O")
                            KeyValueRow(key: "Arch", value: info.isFat ? "FAT" : info.arch)
                            KeyValueRow(key: "Type", value: info.fileType)
                            KeyValueRow(key: "Platform", value: info.platform)
                            KeyValueRow(key: "MinOS", value: info.minOS)
                            KeyValueRow(key: "SDK", value: info.sdk)
                            KeyValueRow(key: "Crypt", value: info.isEncrypted ? "encrypted (\(info.cryptID))" : "plain",
                                        tint: info.isEncrypted ? T.ember : T.good)
                        }
                    }
                    if !info.linkedLibraries.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 4) {
                                SectionLabel(text: "Libraries (\(info.linkedLibraries.count))")
                                ForEach(info.linkedLibraries.prefix(40), id: \.self) { lib in
                                    Text(lib).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                }
                            }
                        }
                    }
                    if !info.rpaths.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 4) {
                                SectionLabel(text: "RPATH")
                                ForEach(info.rpaths, id: \.self) { r in
                                    Text(r).font(T.monoSm).foregroundColor(.white.opacity(0.6))
                                }
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
    }

    private func inspect() {
        error = ""
        info = nil
        guard FileManager.default.fileExists(atPath: path) else {
            error = Container.describe(ENOENT)
            return
        }
        if let result = MachOInspector.inspect(path) {
            info = result
        } else {
            error = "not Mach-O, or read denied"
        }
    }
}

// MARK: - Backup

struct BackupPane: View {
    @State private var status = ""
    @State private var busy = false
    @State private var backups: [FileItem] = []
    @State private var includeCaches = false
    @State private var restoreTarget: FileItem?

    private var backupDir: URL { Container.backups }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel(text: t("pane.backup"))
                        Text(tl("把容器内的偏好、文稿与工具产物打成 ZIP。归档走同一写入器，可被 libarchive 解回。"))
                            .font(T.body).foregroundColor(.white.opacity(0.65))
                            .fixedSize(horizontal: false, vertical: true)
                        Toggle(isOn: $includeCaches) {
                            Text("Library/Caches").font(T.body).foregroundColor(.white.opacity(0.7))
                        }.tint(T.ember)
                        RunButton(title: busy ? t("common.loading") : t("pane.backup"),
                                  systemImage: "archivebox.fill", tint: T.info, disabled: busy) { backup() }
                    }
                }

                if !status.isEmpty {
                    Card {
                        Text(status).font(T.monoSm).foregroundColor(.white.opacity(0.7))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            SectionLabel(text: "\(t("pane.backup")) (\(backups.count))")
                            Spacer()
                            Button { reload() } label: {
                                Image(systemName: "arrow.clockwise").font(.system(size: 11, weight: .bold))
                            }.tint(T.ember)
                        }
                        if backups.isEmpty {
                            Text(t("common.none")).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                        } else {
                            ForEach(backups) { b in
                                HStack(spacing: 8) {
                                    Text(b.name).font(T.monoSm)
                                        .foregroundColor(.white.opacity(0.72)).lineLimit(1)
                                    Spacer()
                                    Text(b.displaySize).font(T.monoSm).foregroundColor(.white.opacity(0.3))
                                    Button { restoreTarget = b } label: {
                                        Image(systemName: "arrow.uturn.backward.circle").font(.system(size: 13))
                                    }.tint(T.warn)
                                    Button {
                                        try? FileManager.default.removeItem(atPath: b.path)
                                        reload()
                                    } label: {
                                        Image(systemName: "trash").font(.system(size: 12))
                                    }.tint(T.bad)
                                }
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .onAppear(perform: reload)
        .alert("Restore?", isPresented: Binding(
            get: { restoreTarget != nil },
            set: { if !$0 { restoreTarget = nil } })) {
            Button("Restore", role: .destructive) {
                if let t = restoreTarget { restore(t) }
                restoreTarget = nil
            }
            Button(t("files.cancel"), role: .cancel) { restoreTarget = nil }
        } message: {
            Text(restoreTarget?.name ?? "")
        }
    }

    private func reload() {
        let fm = FileManager.default
        try? fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        let names = (try? fm.contentsOfDirectory(atPath: backupDir.path)) ?? []
        backups = names.compactMap { name -> FileItem? in
            guard name.hasSuffix(".zip") else { return nil }
            let full = backupDir.appendingPathComponent(name).path
            let size = ((try? fm.attributesOfItem(atPath: full))?[.size] as? NSNumber)?.int64Value ?? 0
            return FileItem(name: name, path: full, isDirectory: false, size: size,
                            modified: nil, isSymlink: false)
        }.sorted { $0.name > $1.name }
    }

    private func backup() {
        busy = true
        status = t("common.loading")
        let fm = FileManager.default
        let rootPath = Container.rootPath
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let target = backupDir.appendingPathComponent("cinder27-\(stamp).zip")
        let skipCaches = !includeCaches
        let backupPrefix = "Documents/Cinder27/Backups/"

        DispatchQueue.global(qos: .userInitiated).async {
            var zip = ZipWriter()
            var stored = 0
            var skipped = 0
            var bytes = 0
            let limit = 400_000_000

            if let enumerator = fm.enumerator(at: Container.root,
                                              includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                                              options: [.skipsHiddenFiles]) {
                for case let url as URL in enumerator {
                    guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                          v.isRegularFile == true else { continue }
                    let relative = url.path.replacingOccurrences(of: rootPath + "/", with: "")
                    if relative.hasPrefix(backupPrefix) { continue }
                    if skipCaches && relative.hasPrefix("Library/Caches/") { continue }
                    if let size = v.fileSize, size > 80_000_000 { skipped += 1; continue }
                    if bytes > limit { skipped += 1; continue }
                    guard let data = try? Data(contentsOf: url) else { skipped += 1; continue }
                    zip.add(relative, data)
                    stored += 1
                    bytes += data.count
                }
            }

            let archive = zip.build()
            var failure: String?
            do {
                try fm.createDirectory(at: self.backupDir, withIntermediateDirectories: true)
                try archive.write(to: target, options: .atomic)
            } catch {
                failure = Container.describe(errno)
            }
            let produced = archive.count
            DispatchQueue.main.async {
                busy = false
                status = failure.map { "\($0)" } ?? "✓ \(stored) files · \(ByteCountFormatter.string(fromByteCount: Int64(produced), countStyle: .file))" + (skipped > 0 ? " · \(skipped) skipped" : "")
                reload()
            }
        }
    }

    private func restore(_ item: FileItem) {
        busy = true
        status = t("common.loading")
        DispatchQueue.global(qos: .userInitiated).async {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: item.path)) else {
                DispatchQueue.main.async { busy = false; status = Container.describe(errno) }
                return
            }
            let result = Runners.Archive.extractAll(data, to: Container.root)
            DispatchQueue.main.async {
                busy = false
                status = "✓ \(result.count) · \(result.errors)"
            }
        }
    }
}

// MARK: - Telemetry

struct TelemetryPane: View {
    @State private var sections: [(String, [(String, String)])] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                ForEach(Array(sections.enumerated()), id: \.offset) { _, section in
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            SectionLabel(text: section.0)
                            ForEach(Array(section.1.enumerated()), id: \.offset) { _, kv in
                                KeyValueRow(key: kv.0, value: kv.1)
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .onAppear {
            sections = [
                ("Power", Telemetry.battery() + Telemetry.thermal()),
                ("Network", Telemetry.interfaces()),
            ]
        }
    }
}

// MARK: - Profiles

struct ProfilePane: View {
    @State private var profiles: [ProfileCensus.Profile] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                if profiles.isEmpty {
                    Card {
                        Text("No provisioning profiles reachable. The device-level directory requires cross-container read.")
                            .font(T.body).foregroundColor(.white.opacity(0.55))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                ForEach(Array(profiles.enumerated()), id: \.offset) { _, p in
                    Card {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.name).font(.system(size: 14, weight: .semibold, design: .rounded))
                                .foregroundColor(.white)
                            KeyValueRow(key: "UUID", value: p.uuid)
                            KeyValueRow(key: "Team", value: p.teamID)
                            KeyValueRow(key: "AppID", value: p.appID)
                            KeyValueRow(key: "Devices", value: "\(p.devices)")
                            if let e = p.expires {
                                KeyValueRow(key: "Expires", value: FileBrowser.dateFormatter.string(from: e))
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .onAppear { profiles = ProfileCensus.installed() }
    }
}
