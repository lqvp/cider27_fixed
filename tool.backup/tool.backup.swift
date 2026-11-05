// tool.backup · BackupPane · ZipWriter · libarchive · —
// 原语: 探测 · 进程内 · tier 1
// Primitive: probe · in-process · tier 1
//
// [zh] 备份 / 回滚往返自检
// 在容器里放一组已知内容的文件，打包成 ZIP，解到另一个目录，逐字节比对，再删掉。这条守的是「备份能不能真的回滚」——上一版写的是自造格式却叫 .tar，解不回来。
//
// [en] Backup and restore round-trip self-test
// Places a set of known-content files in the container, packs them into a ZIP, extracts to another
// directory, compares byte for byte, then removes them. This guards whether a backup can actually
// be restored — the previous version wrote a homegrown format under a .tar name and could not be
// read back.
// ── 判别 / oracle ──
// 同时验证解包时 ../ 与符号链接出不了目标目录。

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



