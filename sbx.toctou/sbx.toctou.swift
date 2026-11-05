// sbx.toctou · libsystem_sandbox · sandbox_extension_issue_file · 
// 原语: OOB 读 · 进程内 · tier 1
// Primitive: OOB read · in-process · tier 1
//
// [zh] sandbox_extension 符号链接 TOCTOU 越界读
//
// [en] sandbox_extension symlink TOCTOU out-of-bounds read
// sandbox_extension_issue_file resolves a symlink at issue time but does not enforce SANDBOX_EXTENSION_NOFOLLOW.
// The token it returns is therefore bound to the target resolved at issue time, and the kernel does
// not re-verify that the path used at consume time is the path the token was issued for. The sequence:
// create symlink L inside the sandbox pointing at in-sandbox file S; issue an extension for L (the
// kernel records S); repoint L at out-of-sandbox target T; consume the token and read through L.
// The kernel permits S's class while the path actually opened is T's.
// ── 判别 / oracle ──

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



