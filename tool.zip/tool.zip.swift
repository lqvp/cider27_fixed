// tool.zip · ZipWriter + libarchive · —
// 原语: 探测 · 进程内 · tier 1
// Primitive: probe · in-process · tier 1
//
// [zh] ZIP 写入器往返自检
// 用自己写的 ZIP 写入器造一个含随机内容的归档，再用 libarchive 解回来，逐字节比对。这条证明重打包不会悄悄损坏文件 —— 改机工具最怕的就是这个。
//
// [en] ZIP writer round-trip self-test
// Builds an archive of random content with the project's own ZIP writer, unpacks it with libarchive,
// and compares byte for byte. This is what proves repacking does not quietly corrupt files — the
// one failure a modification tool must never have.
// ── 判别 / oracle ──
// 64 个文件，每个 4 KB 随机内容，比对 CRC 与长度。

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



