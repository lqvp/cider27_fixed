import Foundation
import Combine

/// Write-ahead journal. Every primitive that can terminate the process arms an entry
/// before the trigger and disarms it after. An entry still armed at the next launch is a
/// process death inside that primitive — the differential oracle, generalized.
struct JournalEntry: Codable, Identifiable, Equatable {
    var id: UUID = UUID()
    var moduleID: String
    var phase: String        // armed | done | threw | died
    var armedAt: Date
    var detail: String
}

final class GuardJournal: ObservableObject {
    @Published private(set) var entries: [JournalEntry] = []
    @Published private(set) var recovered: [JournalEntry] = []

    private let url: URL
    private let lock = NSLock()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e
    }()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d
    }()

    init() {
        // Container.ensureAll() guarantees Application Support exists; the URL alone does not.
        let base = Container.appSupport
        url = base.appendingPathComponent("cinder27-journal.json")
        load()
    }

    /// Bumped whenever the primitive set changes. Results recorded under a different stamp
    /// describe a different app, so they are dropped rather than shown as if they still
    /// apply — otherwise a reinstall over an old build reports work that never happened in
    /// this one.
    static let buildStamp: String = {
        let version = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0"
        let build = (Bundle.main.infoDictionary?["CFBundleVersion"] as? String) ?? "0"
        let count = Catalog.all.count
        return "\(version).\(build).\(count)"
    }()

    private var stampURL: URL {
        url.deletingLastPathComponent().appendingPathComponent("cinder27-journal.stamp")
    }

    private func load() {
        let stored = (try? String(contentsOf: stampURL, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard stored == Self.buildStamp else {
            // First launch, or the primitive set changed: start from nothing.
            entries = []
            recovered = []
            persistLocked([])
            try? Self.buildStamp.write(to: stampURL, atomically: true, encoding: .utf8)
            return
        }
        guard let data = try? Data(contentsOf: url),
              let decoded = try? decoder.decode([JournalEntry].self, from: data) else { return }
        let died = decoded.filter { $0.phase == "armed" }
        let rewritten = decoded.map { e -> JournalEntry in
            guard e.phase == "armed" else { return e }
            var copy = e
            copy.phase = "died"
            return copy
        }
        entries = rewritten
        recovered = died
        if !died.isEmpty { persistLocked(rewritten) }
    }

    private func persistLocked(_ list: [JournalEntry]) {
        guard let data = try? encoder.encode(list) else { return }
        try? data.write(to: url, options: .atomic)
        let fd = open(url.path, O_RDONLY)
        if fd >= 0 { fsync(fd); close(fd) }
    }

    private func persist() {
        persistLocked(entries)
    }

    func arm(_ moduleID: String, _ detail: String) {
        lock.lock()
        entries.append(JournalEntry(moduleID: moduleID, phase: "armed", armedAt: Date(), detail: detail))
        persist()
        lock.unlock()
        refresh()
    }

    func disarm(_ moduleID: String, phase: String = "done", detail: String = "") {
        lock.lock()
        for i in entries.indices.reversed() where entries[i].moduleID == moduleID && entries[i].phase == "armed" {
            entries[i].phase = phase
            if !detail.isEmpty { entries[i].detail = detail }
            break
        }
        persist()
        lock.unlock()
        refresh()
    }

    func clear() {
        lock.lock()
        entries.removeAll()
        recovered.removeAll()
        persist()
        lock.unlock()
        refresh()
    }

    private func refresh() {
        let snapshot = entries
        DispatchQueue.main.async { [weak self] in
            self?.objectWillChange.send()
            self?.entries = snapshot
        }
    }

    func history(for moduleID: String) -> [JournalEntry] {
        lock.lock(); defer { lock.unlock() }
        return entries.filter { $0.moduleID == moduleID }
    }

    func verdict(for moduleID: String) -> LabVerdict {
        lock.lock(); defer { lock.unlock() }
        let mine = entries.filter { $0.moduleID == moduleID }
        guard !mine.isEmpty else { return .untested }
        if mine.contains(where: { $0.phase == "died" }) { return .processDied }
        if mine.contains(where: { $0.phase == "threw" }) { return .refused }
        if mine.contains(where: { $0.phase == "done" }) { return .completed }
        return .running
    }
}

enum LabVerdict: String, Codable {
    case untested
    case running
    case completed
    case refused
    case processDied

    /// Localization key; callers go through t().
    var key: String {
        switch self {
        case .untested: return "lab.untested"
        case .running: return "lab.running"
        case .completed: return "lab.completed"
        case .refused: return "lab.refused"
        case .processDied: return "lab.died"
        }
    }

    var label: String { t(key) }
}
