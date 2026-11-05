// probe.privset · 沙盒 / 签名 / entitlements · —
// 原语: 探测 · 进程内 · tier 3
// Primitive: probe · in-process · tier 3
//
// [zh] 本进程权限面
// 这一套漏洞链的最终权限上限，取决于进程自己已经拿到了什么。csops 标志、entitlements、以及沙盒允许的路径集合，三者一起定义了越狱工具能做到的最远处。
//
// [en] This process's privilege surface
// The final privilege ceiling of this whole chain depends on what the process already holds. The
// csops flags, the entitlements, and the set of paths the sandbox permits together define the furthest
// point a modification tool can reach.
// ── 判别 / oracle ──
// 路径矩阵里凡是「可写」的目录，就是改机工具真正的活动范围。

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



