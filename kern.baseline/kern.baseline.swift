// kern.baseline · XNU · mach_port · —
// 原语: 探测 · 内核 · tier 3
// Primitive: probe · kernel · tier 3
//
// [zh] Mach 命名空间基线
// 读取 bootstrap 端口与自身端口命名空间，确认竞态前的起点：能不能列出端口、能拿到多少个名字。
//
// [en] Mach namespace baseline
// Reads the bootstrap port and the process's own port namespace to establish the starting point before
// any race: can ports be listed, and how many names are available.
// ── 判别 / oracle ──
// 任何一次竞态结果都要和这个基线一起看。

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



