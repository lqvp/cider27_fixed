# Cinder27

[English](README.md)

iOS 17.0–27.1 漏洞验证与设备修改工具链，**57 个模块**。主靶：**iOS 27.0.1 / iPhone 18 Pro Max**（iPhone19,7 · 24A446）。

组件覆盖：ImageIO、CoreGraphics、CoreMedia、FontParser、ArchiveUtility、VideoToolbox、AudioToolbox、Calendar、Dolby Vision RPU、XNU 内核 IPC、沙盒与文件系统、GPT / kext、HID / 外设 / 无线链路、entitlement 探测。

## 仓库结构

| 区块 | 内容 |
|---|---|
| `CVE-2026-XXXX/`（34 个） | 每个 CVE 一个文件夹，POC 本体在文件夹内：`.py` 种子构建器（可独立运行）、`.swift` 种子构造 + 触发闭包（可独立 typecheck），以及 `.c` 双子——种子 + 触发 + `main()` 自包含，在 macOS arm64 上独立编译运行 |
| `<模块名>/`（11 个） | 无 CVE 编号的模块——工具、探针、基线、沙盒原语——按模块 id 命名，同样一文件夹一文件 |
| `Sources/` `scripts/` `Resources/` `Info.plist` | Cinder27 app 主体（验证台本体，构建见下） |

共 45 个 Swift POC 文件（全部通过独立 typecheck）+ 5 个 Python 种子构建器（产物与 app 内置种子逐字节一致）+ 34 个 C POC 文件（macOS arm64 上 `clang -O2 -Wall` 零警告编译通过，各自带一份记录在案的 oracle）。

## POC 索引 — 34 个 CVE 文件夹

复合编号（如 `CVE-2026-112627 / 112561`）归并到主编号的文件夹；同一 CVE 命中多个模块时，触发闭包并列在同一文件里。

| CVE | 模块 | 组件 | 原语 | 触达 | 标题 | 文件 |
|---|---|---|---|---|---|---|
| [CVE-2026-112415](CVE-2026-112415/) | `vid.hevc` | AVD.videodecoder 插件 | OOB 读 | 系统进程 | MVHEVC 层 ID 越界 | `CVE-2026-112415.swift` · `CVE-2026-112415.c` |
| [CVE-2026-112416](CVE-2026-112416/) | `vid.avc` | AVD.videodecoder 插件（非 kext） | OOB 写 | 系统进程 | AVC 切片数量上限缺失 | `CVE-2026-112416.swift` · `CVE-2026-112416.c` |
| [CVE-2026-112485](CVE-2026-112485/) | `mdl.usda` | Model I/O · libusd_ms | OOB 读 | 进程内 | USDA 声明嵌套深度 | `CVE-2026-112485.py` · `CVE-2026-112485.swift` · `CVE-2026-112485.c` |
| [CVE-2026-112488](CVE-2026-112488/) | `iio.tiff.direntry` | ImageIO · TIFFReadDirEntry*Array | OOB 写 | 进程内 | TIFF 目录项分配 32 位截断 | `CVE-2026-112488.swift` · `CVE-2026-112488.c` |
| [CVE-2026-112507 / 112476](CVE-2026-112507/) | `kern.ipc` | XNU · ipc_port.c 请求表消费方 | UAF | 内核 | ipc_port 请求表索引竞态 | `CVE-2026-112507.swift` · `CVE-2026-112507.c` |
| [CVE-2026-112515](CVE-2026-112515/) | `probe.hid` | IOHIDFamily · caps 表查找 | OOB 读 | 外设 | IOHIDFamily 预解析数据表索引 | `CVE-2026-112515.swift` · `CVE-2026-112515.c` |
| [CVE-2026-112522](CVE-2026-112522/) | `arc.iso`, `arc.iso.stress`, `arc.cab` | libarchive · build_pathname_utf16be | OOB 写 | 进程内 | ISO9660 Joliet 路径名堆溢出 | `CVE-2026-112522.py` · `CVE-2026-112522.swift` · `CVE-2026-112522.c` |
| [CVE-2026-112546](CVE-2026-112546/) | `aud.hoa` | AudioCodecs · APACHOADecoder::Initialize | OOB 读 | 系统进程 | HOA 空间音频系数越界读 | `CVE-2026-112546.swift` · `CVE-2026-112546.c` |
| [CVE-2026-112554](CVE-2026-112554/) | `kext.gpt` | IOStorageFamily | OOB 读 | 内核 | GPT 分区名扫描 72 字节内核堆越界读 | `CVE-2026-112554.swift` · `CVE-2026-112554.c` |
| [CVE-2026-112571](CVE-2026-112571/) | `iio.jpeg.comment` | ImageIO · ReadUserComment | 信息泄露 | 进程内 | EXIF UserComment 短读 → 元数据泄露 | `CVE-2026-112571.swift` · `CVE-2026-112571.c` |
| [CVE-2026-112610](CVE-2026-112610/) | `cg.cmap` | CoreGraphics · _cmap_convert | OOB 写 | 进程内 | CMap /UseCMap 递归越界写（负结果探针） | `CVE-2026-112610.swift` · `CVE-2026-112610.c` |
| [CVE-2026-112611](CVE-2026-112611/) | `cg.shading`, `cg.shading.sweep` | CoreGraphics · _cg_shading_type5_draw | OOB 写 | 进程内 | Type-5 阴影栈溢出（值可控 OOB 写） | `CVE-2026-112611.swift` · `CVE-2026-112611.c` |
| [CVE-2026-112619](CVE-2026-112619/) | `cal.unzip` | CalendarFoundation · _UnzipArchiveWithLimits | OOB 写 | 系统进程 | 日历附件解压容器逃逸 | `CVE-2026-112619.swift` · `CVE-2026-112619.c` |
| [CVE-2026-112621](CVE-2026-112621/) | `lp.heic`, `lp.heic.fire` | LinkPresentation · LPAnimatedImageTranscoder | OOB 写 | 进程内 | 链接预览双帧尺寸不一致（后帧高于池） | `CVE-2026-112621.swift` · `CVE-2026-112621.c` |
| [CVE-2026-112625](CVE-2026-112625/) | `iio.ktx2`, `iio.pvr` | ImageIO · KTX2ReadPlugin | 整数溢出 | 进程内 | KTX2 维度/层级尺寸运算 | `CVE-2026-112625.py` · `CVE-2026-112625.swift` · `CVE-2026-112625.c` |
| [CVE-2026-112627](CVE-2026-112627/) | `iio.dds.bc7`, `iio.appx` | ImageIO · BCReadPlugin::initialize | OOB 读 | 进程内 | BC7 纹理 mip 截断 | `CVE-2026-112627.swift` · `CVE-2026-112627.c` |
| [CVE-2026-112629](CVE-2026-112629/) | `iio.jpeg.gps` | ImageIO · GPSCopy::processData | OOB 读 | 进程内 | GPS IFD 值偏移越界 | `CVE-2026-112629.swift` · `CVE-2026-112629.c` |
| [CVE-2026-112630](CVE-2026-112630/) | `iio.apng.fctl` | ImageIO · IIO_Reader_PNG::getImageCount | 信息泄露 | 进程内 | APNG fcTL 截断 → 栈上未初始化帧几何 | `CVE-2026-112630.swift` · `CVE-2026-112630.c` |
| [CVE-2026-112632](CVE-2026-112632/) | `iio.tiff.trunc` | ImageIO · decodeStripChunky | 信息泄露 | 进程内 | TIFF 截断条带 → 未初始化堆进像素 | `CVE-2026-112632.swift` · `CVE-2026-112632.c` |
| [CVE-2026-112633 / 112614](CVE-2026-112633/) | `iio.tiff.planar`, `iio.pdf.raster` | ImageIO · decodeStripPlanar | OOB 写 | 进程内 | TIFF planar 散写越界 | `CVE-2026-112633.swift` · `CVE-2026-112633.c` |
| [CVE-2026-112634](CVE-2026-112634/) | `iio.jpeg.marker` | ImageIO · _JPEGFile::processData | OOB 读 | 进程内 | JPEG 标记长度越界 | `CVE-2026-112634.swift` · `CVE-2026-112634.c` |
| [CVE-2026-112638](CVE-2026-112638/) | `aud.lc3` | AudioCodecs · ACLC3Decoder::AppendInputData | OOB 写 | 权限受限 | LC3 解码器输入缓冲溢出 | `CVE-2026-112638.swift` · `CVE-2026-112638.c` |
| [CVE-2026-112646](CVE-2026-112646/) | `sb.stash` | SpringBoard · SBHomeScreenService | OOB 写 | 系统进程 | SpringBoard 布局名 stash 校验 | `CVE-2026-112646.swift` · `CVE-2026-112646.c` |
| [CVE-2026-112656](CVE-2026-112656/) | `font.gdef` | CoreText · GetLigatureCaretPositionsForGlyph | OOB 读 | 进程内 | GDEFLigatureCaret 追链越界读 | `CVE-2026-112656.swift` · `CVE-2026-112656.c` |
| [CVE-2026-112683](CVE-2026-112683/) | `font.cff` | FontParser · charstring 解释器 | OOB 写 | 进程内 | CFF Type2 charstring 操作数栈溢出 | `CVE-2026-112683.py` · `CVE-2026-112683.swift` · `CVE-2026-112683.c` |
| [CVE-2026-112688](CVE-2026-112688/) | `cm.rpu`, `cm.rpu.sweep` | CoreMedia · hevcbridgeParseVdrDmDataPayloadExMetadataBlocks | OOB 写 | 系统进程 | Dolby Vision RPU 扩展元数据块数组越界 | `CVE-2026-112688.swift` · `CVE-2026-112688.c` |
| [CVE-2026-112696 / 84494](CVE-2026-112696/) | `probe.ane` | AppleH16ANEInterface | OOB 写 | 内核 | ANE 内核接口可达性 | `CVE-2026-112696.swift` · `CVE-2026-112696.c` |
| [CVE-2026-112705](CVE-2026-112705/) | `ave.ntl`, `ave.ntl.fire` | AppleAVE2 · VideoToolbox HEVC 编码器 | OOB 写 | 内核 | `NumberOfTemporalLayers` 16463 → 内核 data abort | `CVE-2026-112705.swift` · `CVE-2026-112705.c` |
| [CVE-2026-112706](CVE-2026-112706/) | `cm.fdleak`, `cm.fdleak.boundary` | CoreMedia · mediaplaybackd.bytestream.xpc | 信息泄露 | 系统进程 | CoreMedia bytestream XPC 跨沙盒文件描述符获取 | `CVE-2026-112706.swift` · `CVE-2026-112706.c` |
| [CVE-2026-113907](CVE-2026-113907/) | `aud.haptic`, `aud.immersive` | AudioToolbox · AVHapticServerInstance | OOB 写 | 系统进程 | AVHaptic 自定义音频事件格式校验 | `CVE-2026-113907.swift` · `CVE-2026-113907.c` |
| [CVE-2026-113910](CVE-2026-113910/) | `kern.decmpfs` | XNU · AppleFSCompressionTypeZlib | 信息泄露 | 内核 | decmpfs 分块解压欠产出 → 内核堆泄露 | `CVE-2026-113910.swift` · `CVE-2026-113910.c` |
| [CVE-2026-113912 / 86972](CVE-2026-113912/) | `aud.drc` | AudioCodecs · mpddrc::UniDrcSelection | OOB 读 | 系统进程 | MPEG-D DRC 下混矩阵系数校验 | `CVE-2026-113912.swift` · `CVE-2026-113912.c` |
| [CVE-2026-65385](CVE-2026-65385/) | `kext.iohid` | IOKit.framework · IOHIDEventAppendEvent | OOB 写 | 内核 | IOKit 事件短堆固定偏移写 | `CVE-2026-65385.swift` · `CVE-2026-65385.c` |

## 无 CVE 模块 — 11 个

| 模块 | 组件 | 标题 | 文件 |
|---|---|---|---|
| [kern.baseline](kern.baseline/) | XNU · mach_port | Mach 命名空间基线 | `kern.baseline.swift` |
| [probe.privset](probe.privset/) | 沙盒 / 签名 / entitlements | 本进程权限面 | `probe.privset.swift` |
| [arc.rr](arc.rr/) | libarchive · RockRidge CL/PL | RockRidge 重定位环（未修复孪生） | `arc.rr.py` · `arc.rr.swift` |
| [sbx.toctou](sbx.toctou/) | libsystem_sandbox · sandbox_extension_issue_file | sandbox_extension 符号链接 TOCTOU 越界读 | `sbx.toctou.swift` |
| [tool.ipa](tool.ipa/) | IPASurgeon · MachO · ZipWriter | IPA 手术自检（改包名 / 注入 / 重签名准备） | `tool.ipa.swift` |
| [tool.zip](tool.zip/) | ZipWriter + libarchive | ZIP 写入器往返自检 | `tool.zip.swift` |
| [tool.macho](tool.macho/) | MachO · MachOInspector | Mach-O 解析器自检 | `tool.macho.swift` |
| [tool.hex](tool.hex/) | HexTool | 十六进制查找替换自检 | `tool.hex.swift` |
| [tool.container](tool.container/) | Container · ensureAll / probe / repair / normalize | 容器读写正常化（数据容器自检 + 修复） | `tool.container.swift` |
| [tool.backup](tool.backup/) | BackupPane · ZipWriter · libarchive | 备份 / 回滚往返自检 | `tool.backup.swift` |
| [tool.paths](tool.paths/) | Probe · FileManager | 文件系统权限矩阵全扫 | `tool.paths.swift` |

## POC 文件解剖（.swift）

每个文件由五段构成，除注释外全部为 Cinder27 源码 verbatim 提取：

1. **双语头** — 模块 id、组件、CVE、原语 / 触达 / tier、中英文摘要
2. **判别 / oracle** — 该漏洞在本机上的可观测信号（崩溃点、返回码分布、多次解码指纹比对、超时窗口……）
3. **`enum B`** — 字节助手（来自 `Sources/Kit.swift`）
4. **种子构造** — payload 构建器及其依赖闭包（来自 `Sources/Payloads.swift` / `Payloads2.swift`；`Entry` / `BitWriter` / `PDFBuilder` 等结构体按引用自动带上）
5. **触发器** — 模块 `run` 闭包原文（注释块；引用 `RunContext` / `Runners` / `tl()`，在 app 验证台内执行）

种子组的 `.py` 是同一构建器的 Python 原文（来自 `scripts/gen_seeds.py`），带 `__main__` 写盘入口，可直接运行。

## C POC 文件（.c）的结构

每个 CVE 文件夹还带一个 C 双子——同一验证的纯 C 实现，直接在 macOS arm64 主机上编译运行（无 Swift 运行时、不依赖 app）：

1. **头部注释** —— 模块 · 框架 · 漏洞函数 · CVE，一行漏洞类别，`C twin of the Swift POC` 标注，`Build:` / `Run:` 行；多变体模块注明哪个变体在 `main()` 里跑
2. **种子构造** —— 与 Swift 构建器相同的载荷文法，纯手写：位写入器、字节缓冲、结构体发射
3. **触发** —— 漏洞入口本身。公开框架直接链接（`VTDecompressionSessionCreate`、`AudioConverterNew`、`CGFontCreateWithDataProvider`）；私有符号运行时 `dlsym` 解析（`CMGetDMVersionLevelFromRPU`、`Fig*` XPC 家族、`IOHIDEvent*`）
4. **预言机** —— 打印到 stdout：OSStatus 码、入口拒绝回执、XPC 回复类型、信号/崩溃结果
5. **`main()`** —— Swift 版可参数化的地方同样参数化（深度、块数、路径）；种子文件写入工作目录备查

34 个全部 `clang -O2 -Wall` 零警告编译通过，且都在本机跑出记录在案的 oracle。

## 运行

```bash
# Python 种子构建器 — 独立可跑
python3 CVE-2026-112522/CVE-2026-112522.py out.iso        # → joliet_path_oob.iso 字节一致
python3 CVE-2026-112485/CVE-2026-112485.py deep_nest.usda
python3 CVE-2026-112625/CVE-2026-112625.py bad_dims.ktx2
python3 CVE-2026-112683/CVE-2026-112683.py stack_bomb.cff
python3 arc.rr/arc.rr.py out.iso

# Swift POC — 独立类型检查（无 app 依赖）
xcrun swiftc -parse-as-library -swift-version 5 -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
  -target arm64-apple-macos14 -typecheck CVE-2026-112611/CVE-2026-112611.swift

# 完整触发（解码、竞态、崩溃 oracle）在 app 验证台内执行
bash scripts/build-sim.sh        # → build/sim/Cinder27.app 并安装到已启动的模拟器

# C 双子 —— 独立编译运行（macOS arm64）
clang -O2 -Wall -o /tmp/c112522 CVE-2026-112522/CVE-2026-112522.c    # 纯 C，无框架依赖
/tmp/c112522                                                        # → SIGTRAP：2 字节越界写
clang -O2 -Wall -o /tmp/c112706 CVE-2026-112706/CVE-2026-112706.c -fblocks -framework CoreFoundation
/tmp/c112706                                                        # → FigXPC 握手，'Connection invalid'
```

## 构建验证台 app

依赖：macOS + Xcode 命令行工具（`xcode-select --install`），无第三方包管理。

```bash
bash scripts/build-device.sh     # → dist/Cinder27-unsigned.ipa（arm64，iOS 17.0+，未签名）
bash scripts/build-sim.sh        # → build/sim/Cinder27.app（arm64 模拟器）
python3 scripts/gen_seeds.py     # → seeds/（app 内置种子，与 .py POC 产物逐字节一致）
```

设备安装：bundle id `com.jbjf.cinder27`（v2.3 build 7），未签名——用自有证书 + 匹配（或通配符）描述文件签名后侧载。

## 验证状态

57 模块全量回归（模拟器构建）：**51 done + 4 armed + 2 个 fire 模块按设计未运行**。两个 fire 模块是 112705 与 112621 的主动死亡 oracle，已编译进 app，需人为点按。

armed 不是超时——是**死亡 oracle 命中**：负载触发进程崩溃，journal 停在 armed、进程消失。cm.rpu / cm.rpu.sweep 的崩溃栈落在 `CMGetDMVersionLevelFromRPU` 内 SIGSEGV；C 双子钉死了机制——iOS 面是 4 参 `(bytes, count, u32*, u32*)` 形态，而 macOS 导出的是单 `CFDataRef`（反汇编验证：arg0 先走 CFRetain 式 GOT 调用才进 `FigHEVCBridge_GetRPUMetadata`），所以 Swift 的 4 参调用在模拟器的 CoreMedia 上死在入口。cg.shading / cg.shading.sweep 为 R=136 长溢出阶梯扫描，按设计在同一进程内推进到致命级。

34 个 C 双子全部零警告编译通过（`clang -O2 -Wall`，macOS arm64），且都在开发机上跑出记录在案的 oracle：112522 触发 SIGTRAP（2 字节越界写被 malloc 抓住）、112507 活过全程环竞态并带回 -300 / invalid-destination 回执、112706 回应 'Connection invalid'（macOS 无 mediaplaybackd bytestream XPC——静默服务判定）、112485 拿到 PEGTL 深度回执（`Expected } at 'def Xform "n1999"'`）、113910 读回纯 0x41，并在 16 轮扫描中报告 0 个已分类指针（macOS 上带数据的文件不走 decmpfs）；采集器现在支持 `--loop`、`--keep` 与 kernel-text/data 分类。三个新条目各自带回执：112621 造出 256×16 → 256×48 双帧容器，48 行 clear 在 guard 页前精确停下——越界 32,768 字节；84636 枚举 configd 的 `State:/Network` 树并读到 `Global/DNS` 与主服务，而宿主上 `CNCopyCurrentNetworkInfo` 不可用——真机上同一调用在无权限时返回 nil。112705 只编译不在宿主执行：`.c` 带 `--force-host` 闸门，因为帧提交会打到把本机打崩的同一个 AppleAVE2 驱动；app 里拆成属性探测与独立 fire 两个模块。其余都在入口层被拒——与 app 验证台同形回执。

高/严重条目的内核 R/W 可行性见 [docs/KERNEL-RW-ASSESSMENT.md](docs/KERNEL-RW-ASSESSMENT.md)。结论：六个内核原语里没有任何一个同时具备地址控制与值控制。113910 是可分类的堆泄漏（只读），112554 是读宽度模型，112507 是 UAF 形状的竞态回执，112705 / 65385 / 112696 分别是 DoS、可达性与诚实负结果。实验室当前能安全证明的上限是 KASLR 线索 + 竞态回执，而不是任意内核读写。

112507 的可达性已在目标机（iPhone19,7 / iOS 27.0.1）上用新增的 `kern.ipc.lifecycle` 模块与 `kern.ipc` 的 `armed` 计数重测：`mach_port_request_notification` 在所有类型/权限组合上都返回 -300（MIG_TYPE_ERROR），12,288 次注册 0 次成功。请求表从未被武装，因此无特权 app 触达不到该竞态；此前“活过交错”的结论撤回。详见 [docs/KERNEL-RW-ASSESSMENT.md](docs/KERNEL-RW-ASSESSMENT.md)。

**iOS 27.2 固件 diff（27.0.1 vs 27.2，iPhone19,7）：** [docs/IOS27.2-KERNEL-DIFF.md](docs/IOS27.2-KERNEL-DIFF.md)。本次更新含 162 条公告 CVE；303 个共有 kext 中 93 个 `__TEXT_EXEC` 尺寸变化。已确认的修复点：112705 把 `NumberOfTemporalLayers` 收紧到 0…7（断言 `iNumberOfTemporalLayers <= 7`），113910 新增 `chunk %u produced %lld of %lld expected bytes`，112507 在 `ipc_misc.c` 新增 `ipr != NULL` / `table != NULL`。kernel 里的 `__DATA_SPTM` 段两版字节一致，但独立的 `sptm.t8160` 固件从 SPTM-820.0.22 升到 **820.40.24**（+64 KiB：DART/IOMMU、TLBI 与休眠加固，不在 CVE 列表里）。SPTM/XNU 的 MIE/MTE 策略没有变化。深度分析与候选 bypass 方向见 [docs/SPTM-MIE-27.2.md](docs/SPTM-MIE-27.2.md)。

## 模块语义

- **tier 1** — 直接原语命中（OOB 写 / UAF / 类型混淆），崩溃即证据
- **tier 2** — 可观测信号（信息泄露指纹、返回码分布、超时窗口），需要比对基线
- **probe / baseline / tool** — 环境探针、内核基线采样、设备修改工具（hex 编辑、xattr / decmpfs 手术、MachO 分析、容器 / 备份 / IPA 签名 / 路径 / zip）

app 内中英双语运行时切换（`RuntimeText`，633 键全映射，无硬编码 CJK 残留）。
