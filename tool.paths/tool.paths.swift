// tool.paths · Probe · FileManager · —
// 原语: 探测 · 进程内 · tier 1
// Primitive: probe · in-process · tier 1
//
// [zh] 文件系统权限矩阵全扫
// 把 30 多个关键路径逐个试读试写，记录可读/可写/条目数/errno。这是改机工具的活动范围地图 —— 它决定了所有面板能做到哪里为止。
//
// [en] Filesystem permission matrix sweep
// Tries reading and writing across 30-plus key paths, recording readability, writability, entry count
// and errno. This is the activity map for the modification tool — it determines how far every panel
// can go.
// ── 判别 / oracle ──
// 结果同时会写进 Documents 里一份文本，方便对照。

import Foundation

// ── byte helpers — verbatim from Cinder27 Sources/Kit.swift ──
enum B {
    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
    static func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8 & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
    }
    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xff), UInt8(v >> 8 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 24 & 0xff)]
    }
    static func be64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (56 - UInt64($0) * 8)) & 0xff) }
    }
    static func le64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (UInt64($0) * 8)) & 0xff) }
    }
    static func both16(_ v: UInt16) -> [UInt8] { le16(v) + be16(v) }
    static func both32(_ v: UInt32) -> [UInt8] { le32(v) + be32(v) }
    static func ascii(_ s: String) -> [UInt8] { Array(s.utf8) }
}



