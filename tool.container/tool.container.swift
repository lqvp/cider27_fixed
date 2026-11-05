// tool.container · Container · ensureAll / probe / repair / normalize · —
// 原语: 探测 · 进程内 · tier 1
// Primitive: probe · in-process · tier 1
//
// [zh] 容器读写正常化（数据容器自检 + 修复）
// 把数据容器里每一个工具会用到的目录逐个解析、创建、然后真的建文件写一遍、fsync、读回、比对、删除。之前「容器内读写失败」的四个真实原因都在这里被点名：目录只是 URL 不是目录、isWritableFile
// 是坏探针、容器 UUID 会变、Library/Preferences 归 cfprefsd。
//
// [en] Container read/write normalisation (data container self-test and repair)
// Resolves every directory the tooling uses inside the data container, creates it, then actually
// creates a file, writes, fsyncs, reads back, compares and deletes. The four real reasons container
// writes failed before are all named here: a URL is not a directory, isWritableFile is a bad probe,
// container UUIDs change, and Library/Preferences belongs to cfprefsd.
// ── 判别 / oracle ──
// 跑完会留下 container_health.txt。修复动作是幂等的，每次启动都会再跑一遍。

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



