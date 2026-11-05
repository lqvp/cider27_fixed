import Foundation
import SwiftUI

// MARK: - Localization
//
// A code-resident table rather than .lproj bundles: the build is a single swiftc
// invocation with no Xcode project, so resources would have to be copied by hand and
// kept in sync. One table is one source of truth.
//
// Language detection: Locale.preferredLanguages[0] → language code → match against the
// supported set → fall back to English. Region is ignored (pt-BR and pt-PT both map to
// nothing here; en-GB maps to English).
//
// Arabic forces RTL at the root view.

enum Lang: String, CaseIterable, Identifiable {
    case en, zh

    var id: String { rawValue }

    /// Endonym — a language list is only usable if each entry is written in itself.
    var native: String {
        switch self {
        case .en: return "English"
        case .zh: return "中文"
        }
    }

    /// Neither supported language is right-to-left.
    var isRTL: Bool { false }

    /// Locale used for number/date formatting.
    var locale: Locale { Locale(identifier: rawValue) }

    /// The language actually in effect (manual override, else detected).
    static var resolved: Lang { L10n.shared.resolved() }
}

final class L10n: ObservableObject {
    static let shared = L10n()

    @Published private(set) var lang: Lang
    private var override: Lang?

    private init() {
        lang = Self.detect()
    }

    static func detect() -> Lang {
        if let forced = ProcessInfo.processInfo.environment["CINDER27_LANG"],
           let l = Lang(rawValue: forced) {
            return l
        }
        // Two languages only: Chinese (any variant, including zh-Hans / zh-Hant / zh-HK)
        // maps to zh, everything else maps to English.
        for identifier in Locale.preferredLanguages {
            let code = identifier.split(separator: "-").first.map(String.init)?.lowercased() ?? ""
            if code == "zh" { return .zh }
            if code == "en" { return .en }
        }
        return .en
    }

    func set(_ language: Lang) {
        override = language
        lang = language
        UserDefaults.standard.set(language.rawValue, forKey: "cinder27.lang")
        objectWillChange.send()
    }

    /// Manual override persisted from the language picker, else the detected language.
    func resolved() -> Lang {
        if let o = override { return o }
        if let saved = UserDefaults.standard.string(forKey: "cinder27.lang"),
           let l = Lang(rawValue: saved) {
            override = l
            return l
        }
        return lang
    }
}

/// Translate a key. Unknown keys return the key itself so a missing string is visible in
/// the UI instead of silently empty.
func t(_ key: String) -> String {
    L10n.shared.string(key)
}

extension L10n {
    func string(_ key: String) -> String {
        let language = resolved()
        if let row = Table.rows[key], let value = row[language] { return value }
        if let row = Table.rows[key], let value = row[.en] { return value }
        return key
    }
}

// MARK: - Table
//
// Row order is fixed: en, zh, fr, ja, ru, de, es, ar.

enum Table {
    static let order: [Lang] = [.en, .zh]

    static func row(_ en: String, _ zh: String) -> [Lang: String] {
        [.en: en, .zh: zh]
    }

    static let rows: [String: [Lang: String]] = [
        // ---- tabs
        "tab.overview": row("Overview", "总览"),
        "tab.lab": row("POCs", "POCs"),
        "tab.chain": row("Chain", "组合"),
        "tab.mod": row("Toolkit", "改机"),
        "tab.system": row("System", "系统"),

        // ---- overview
        "ov.headline": row("Vulnerability Testing", "漏洞测试"),
        "ov.sub": row("%d primitives · %d localized 27.2 fixes", "%d 个原语 · %d 条 27.2 修复定位"),
        "ov.target": row("Target device", "目标设备"),
        "ov.model": row("Model", "机型"),
        "ov.os": row("System", "系统"),
        "ov.kernel": row("Kernel", "内核"),
        "ov.memory": row("Memory", "内存"),
        "ov.verdict": row("Verdict", "判定"),
        "ov.capabilities": row("Privilege ladder", "权限阶梯"),
        "ov.modules": row("Primitives", "模块"),
        "ov.tested": row("Run", "已运行"),
        "ov.died": row("Terminated", "进程终止"),
        "ov.reset": row("Clear all results", "清空全部结果"),
        "ov.log": row("Log", "日志"),
        "ov.log.empty": row("No runs yet", "尚无运行记录"),
        "ov.interrupted": row("Interrupted runs", "上次运行的中断记录"),
        "ov.interrupted.note": row("Armed before the trigger, never disarmed — the process died inside these.", "触发前写入、未在返回后关闭 —— 进程在它们内部终止。"),

        // ---- verdicts
        "verdict.vulnerable": row("VULNERABLE", "易受攻击"),
        "verdict.patched": row("PATCHED", "已修复"),
        "verdict.unknown": row("UNKNOWN", "未判定"),

        // ---- capability levels
        "cap.l0": row("Container read/write", "容器内读写"),
        "cap.l1": row("Read system volume", "读取系统卷"),
        "cap.l2": row("Read /private/var/mobile/Library", "读取 /private/var/mobile/Library"),
        "cap.l3": row("Read other app containers", "读取其它应用容器"),
        "cap.l4": row("Load private libraries outside the shared cache", "加载共享缓存外的私有库"),
        "cap.l5": row("Jailbreak root /private/var/jb", "越狱根目录 /private/var/jb"),
        "cap.yes": row("reachable", "可达"),
        "cap.no": row("sandbox denied", "沙盒拒绝"),
        "cap.absent": row("absent", "不存在"),
        "cap.notJailbroken": row("absent (not jailbroken)", "不存在（未越狱）"),

        // ---- lab
        "lab.title": row("Primitive lab", "漏洞实验室"),
        "lab.untested": row("not run", "未运行"),
        "lab.running": row("running", "运行中"),
        "lab.completed": row("completed", "已完成"),
        "lab.refused": row("refused", "被拒绝"),
        "lab.died": row("terminated", "进程终止"),
        "module.primitive": row("Primitive", "原语"),
        "module.notes": row("Notes", "要点"),
        "module.result": row("Result", "结果"),
        "module.history": row("Run history", "运行记录"),
        "module.run": row("Execute", "执行原语"),
        "module.running": row("Running…", "运行中…"),
        "module.close": row("Close", "关闭"),
        "module.warning": row("If the process terminates inside this primitive the app exits. Reopen it and the entry reads \"terminated\" — that is the direct evidence this build is unpatched.", "若进程在该原语内终止，App 会直接退出。重新打开后这一条会被标记为「进程终止」，这就是该构建未修复的直接证据。"),

        // ---- chain
        "chain.title": row("Chain", "组合链"),
        "chain.stage.run": row("Run this stage", "执行本阶段"),
        "chain.unlock": row("Unlocks", "解锁"),

        // ---- mod panes
        "mod.title": row("Toolkit", "改机工具"),
        "pane.files": row("Files", "文件"),
        "pane.apps": row("Apps", "应用"),
        "pane.prefs": row("Prefs", "偏好"),
        "pane.procs": row("Processes", "进程"),
        "pane.daemons": row("Daemons", "守护"),
        "pane.crashes": row("Crashes", "崩溃"),
        "pane.binary": row("Binary", "二进制"),
        "pane.backup": row("Backup", "备份"),
        "pane.ipa": row("IPA", "IPA"),
        "pane.hex": row("Hex", "十六进制"),
        "pane.xattr": row("Attrs", "属性"),
        "pane.sqlite": row("SQLite", "数据库"),
        "pane.fonts": row("Fonts", "字体"),
        "pane.telemetry": row("Telemetry", "遥测"),
        "pane.profiles": row("Profiles", "描述文件"),
        "pane.cross": row("X-sandbox", "越界读"),
        "pane.symlink": row("Symlink", "符号链接"),
        "files.backup": row("backup written", "已写备份"),
        "pane.hash": row("Hash", "哈希"),
        "pane.archive": row("Archive", "归档"),
        "pane.clipboard": row("Clipboard", "剪贴板"),
        "pane.shortcuts": row("Actions", "快捷操作"),

        // ---- files
        "files.up": row("Up", "上一级"),
        "files.jump": row("Jump", "跳转"),
        "files.path": row("Path", "路径"),
        "files.newFolder": row("New folder", "新建文件夹"),
        "files.name": row("Name", "名称"),
        "files.rename": row("Rename", "重命名"),
        "files.copy": row("Copy", "复制"),
        "files.move": row("Move", "移动"),
        "files.delete": row("Delete", "删除"),
        "files.duplicate": row("Duplicate", "创建副本"),
        "files.info": row("Info", "信息"),
        "files.text": row("Text", "文本"),
        "files.hex": row("Hex", "十六进制"),
        "files.package": row("Contents", "包内容"),
        "files.writable": row("writable", "可写"),
        "files.readonly": row("read-only", "只读"),
        "files.cancel": row("Cancel", "取消"),
        "files.save": row("Save", "保存"),
        "files.select": row("Select a file", "选择文件"),
        "files.empty": row("Empty directory", "目录为空"),
        "files.copyTo": row("Copy to…", "复制到…"),
        "files.moveTo": row("Move to…", "移动到…"),
        "files.done": row("Done", "完成"),
        "files.copied": row("Copied", "已复制"),
        "files.moved": row("Moved", "已移动"),
        "files.deleted": row("Deleted", "已删除"),
        "files.renamed": row("Renamed", "已重命名"),
        "files.paste": row("Paste here", "粘贴到此处"),
        "files.bookmarks": row("Bookmarks", "书签"),

        // ---- system
        "sys.title": row("System", "系统"),
        "sys.device": row("Device", "设备"),
        "sys.signature": row("Code signature", "签名状态"),
        "sys.entitlements": row("Entitlements", "Entitlements"),
        "sys.sandbox": row("Sandbox path matrix", "沙盒路径矩阵"),
        "sys.log": row("Log", "日志"),
        "sys.language": row("Language", "语言"),
        "sys.language.auto": row("Follow system", "跟随系统"),

        // ---- gate
        "gate.checking": row("Checking device…", "正在检测设备…"),
        "gate.unsupported.title": row("Unsupported system", "系统版本不支持"),
        "gate.unsupported.body": row("This build targets iOS 17.0 – 27.1. From 27.2 onward every fix these primitives demonstrate has already shipped, so nothing here would fire. Downgrade from 27.2 is not possible — the signing window is closed.", "本工具面向 iOS 17.0 – 27.1。自 27.2 起，这些原语所演示的全部修复均已发布，任何一条都不会触发。27.2 无法降级 —— 签名窗口已关闭。"),
        "gate.supported": row("Supported system", "系统版本符合"),
        "gate.enter": row("Enter", "进入"),
        "gate.required": row("Requires", "要求"),
        "gate.detected": row("Detected", "检测到"),
        "gate.build": row("Build", "构建号"),
        "gate.recheck": row("Re-check", "重新检测"),

        // ---- common
        "common.ok": row("OK", "确定"),
        "common.error": row("Error", "错误"),
        "common.none": row("none", "无"),
        "common.yes": row("yes", "是"),
        "common.no": row("no", "否"),
        "common.loading": row("Loading…", "载入中…"),
        "common.unknown": row("unknown", "未知"),
    ]
}
