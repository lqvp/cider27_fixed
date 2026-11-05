// tool.macho · MachO · MachOInspector · —
// 原语: 探测 · 进程内 · tier 1
// Primitive: probe · in-process · tier 1
//
// [zh] Mach-O 解析器自检
// 对系统卷上的几个真实二进制跑一遍头解析：架构、类型、平台、最低系统、SDK、加密状态、链接库、rpath。加密状态是这一整套里最有信息量的字段 —— 系统框架 cryptid 为 0，第三方
// App 的二进制不是。
//
// [en] Mach-O parser self-test
// Runs header parsing over several real binaries on the system volume: architecture, type, platform,
// minimum OS, SDK, encryption state, linked libraries, rpaths. Encryption state is the most informative
// field in the whole set — system frameworks have cryptid 0, third-party app binaries do not.
// ── 判别 / oracle ──
// 同时跑我自己写的解析器和 MachOInspector，两个结果应该一致。

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



