import Foundation
import Combine

enum Reach: String, Codable, CaseIterable {
    case inProcess = "进程内"
    case systemProcess = "系统进程"
    case kernel = "内核"
    case entitlementGated = "权限受限"
    case radio = "无线链路"
    case peripheral = "外设"

    /// Localized display name; rawValue stays Chinese as the stable storage key.
    var label: String { tl(rawValue) }
}

enum PrimitiveKind: String, Codable, CaseIterable {
    case oobWrite = "OOB 写"
    case oobRead = "OOB 读"
    case uaf = "UAF"
    case infoLeak = "信息泄露"
    case typeConfusion = "类型混淆"
    case intOverflow = "整数溢出"
    case probe = "探测"

    /// Localized display name; rawValue stays Chinese as the stable storage key.
    var label: String { tl(rawValue) }
}

struct ModuleOutcome {
    var headline: String
    var detail: String = ""
    var evidence: [String] = []
    var artifacts: [URL] = []
    var elapsedMs: Int = 0
    /// Set only when the module threw. The headline is display text and may be localized,
    /// so it must never be compared against a literal to detect failure.
    var failed: Bool = false
}

final class RunContext {
    let workdir: URL
    let journal: GuardJournal

    init(workdir: URL, journal: GuardJournal) {
        self.workdir = workdir
        self.journal = journal
    }

    @discardableResult
    func write(_ name: String, _ data: Data) -> URL {
        let url = workdir.appendingPathComponent(name)
        try? data.write(to: url, options: .atomic)
        return url
    }

    func seed(_ name: String) -> Data? {
        guard let url = Bundle.main.url(forResource: name, withExtension: nil) else { return nil }
        return try? Data(contentsOf: url)
    }

    func arm(_ id: String, _ detail: String) { journal.arm(id, detail) }
    func disarm(_ id: String, _ detail: String = "") { journal.disarm(id, phase: "done", detail: detail) }
    func fail(_ id: String, _ detail: String) { journal.disarm(id, phase: "threw", detail: detail) }
}

struct ExploitModule: Identifiable {
    let id: String
    /// Chinese source text. English lives in ModuleText, keyed by `id`.
    let titleZh: String
    let cve: String
    let component: String
    let primitive: PrimitiveKind
    let reach: Reach
    /// 1 = primitive fired on a device before, 2 = fix site proven at instruction level,
    /// 3 = reachability probe / honest negative.
    let tier: Int
    let summaryZh: String
    let notesZh: String
    let run: (RunContext) throws -> ModuleOutcome

    var title: String { ModuleText.resolve(id, .title, zh: titleZh) }
    var summary: String { ModuleText.resolve(id, .summary, zh: summaryZh) }
    var notes: String { ModuleText.resolve(id, .notes, zh: notesZh) }
}

struct LabError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class LabEngine: ObservableObject {
    @Published private(set) var outcomes: [String: ModuleOutcome] = [:]
    @Published private(set) var running: Set<String> = []
    @Published private(set) var logLines: [String] = []

    let journal: GuardJournal
    let workdir: URL

    init() {
        // Create every standard directory before anything writes into it. This is the single
        // place that decides whether the container is usable.
        Container.ensureAll()
        journal = GuardJournal()
        workdir = Container.work
        try? FileManager.default.createDirectory(at: workdir, withIntermediateDirectories: true)
    }

    func log(_ line: String) {
        let stamped = String(format: "[%02d:%02d:%02d] %@",
                             Calendar.current.component(.hour, from: Date()),
                             Calendar.current.component(.minute, from: Date()),
                             Calendar.current.component(.second, from: Date()),
                             line)
        DispatchQueue.main.async {
            self.logLines.append(stamped)
            if self.logLines.count > 400 { self.logLines.removeFirst(self.logLines.count - 400) }
        }
    }

    func run(_ module: ExploitModule) {
        guard !running.contains(module.id) else { return }
        running.insert(module.id)
        log("▸ " + module.title + "  [" + module.cve + "]")

        let ctx = RunContext(workdir: workdir, journal: journal)
        let started = Date()

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                var out = try module.run(ctx)
                out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
                DispatchQueue.main.async {
                    self.outcomes[module.id] = out
                    self.running.remove(module.id)
                    self.log("✓ \(module.title) — \(out.headline) (\(out.elapsedMs) ms)")
                }
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                ctx.fail(module.id, message)
                var out = ModuleOutcome(headline: tl("失败"), detail: message, failed: true)
                out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
                DispatchQueue.main.async {
                    self.outcomes[module.id] = out
                    self.running.remove(module.id)
                    self.log("✗ \(module.title) — \(message)")
                }
            }
        }
    }

    func outcome(for id: String) -> ModuleOutcome? { outcomes[id] }
}

extension LabEngine {
    /// Sequential run — used by the chain view, where stage N only means something after
    /// stage N-1 has produced its artifact.
    func runSequence(_ modules: [ExploitModule], label: String) {
        log("══ " + tl("序列开始: ") + "\(label)（\(modules.count) " + tl("个原语") + "）")
        // Kick the whole sequence off on main, then hand each stage to a background queue.
        // Never `main.sync` from the worker: that is a deadlock waiting for main to be busy
        // on something that needs the worker.
        runStage(modules, index: 0, label: label)
    }

    private func runStage(_ modules: [ExploitModule], index: Int, label: String) {
        guard index < modules.count else {
            log("══ " + tl("序列结束: ") + "\(label)")
            return
        }
        let module = modules[index]
        running.insert(module.id)
        let ctx = RunContext(workdir: workdir, journal: journal)
        let started = Date()

        DispatchQueue.global(qos: .userInitiated).async {
            var out: ModuleOutcome
            do {
                out = try module.run(ctx)
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                ctx.fail(module.id, message)
                out = ModuleOutcome(headline: tl("失败"), detail: message, failed: true)
            }
            out.elapsedMs = Int(Date().timeIntervalSince(started) * 1000)
            let finished = out
            let next = index + 1
            DispatchQueue.main.async {
                self.outcomes[module.id] = finished
                self.running.remove(module.id)
                self.log(finished.failed
                         ? "  ✗ \(module.title) — \(finished.detail)"
                         : "  ✓ \(module.title) — \(finished.headline)")
                self.runStage(modules, index: next, label: label)
            }
        }
    }
}
