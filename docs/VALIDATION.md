# 工程验证记录

验证日期：2026-10-22（Asia/Shanghai）。此记录对应当前 demo，是工程测试结果，不是独立安全认证。

## 本轮：开源 VM 保护与进程内校验

Windows Release 已接入 xollvm v0.11.1 / LLVM 22。官方归档 SHA256 为 `762eec5f8274ad45705d3294606c7e7de83c76969db57741b1789aaaa726d1f1`，源版本提交为 `eb0850bd7cc87f551ad2948826605e518f5b8aa2`；安装包与附带许可证均已核对。采用 Clang 内置管线，仅虚拟化 `cardguard_policy_allows`，未改动 Ed25519 实现或 Qt 共享库。

- Rust 格式检查、Clippy 和 **25 项单元测试**通过（客户端 13、协议核心 7、签发端 5），包含 C ABI 空指针、长度、重叠缓冲区、容量、输出完整性和异常边界。
- xollvm 报告确认策略函数的 VM pass 实际执行并改变代码；O2 后 IR 保留 VM 字节码、解释器及 Windows CFG 元数据。链接同一保护 object 的 **4174 项策略用例**通过。
- Windows **28 项集成检查**通过：真实发卡与验签、签名篡改、错误机器、异常输入、GUI 授权结果、PE 缓解标志和发行包秘密隔离。
- 删除完整测试副本中的诊断 helper 后，GUI 仍接受真实卡密、拒绝篡改卡密；放入实际能运行并永远返回成功的假 helper 后，GUI 仍拒绝篡改卡密，调用标记证明它没有运行假 helper。
- `CardGuard --stdio` 在创建 Qt 窗口前调用同源 Rust 有界协议循环。Windows 发卡和协议测试使用此入口；本机应用控制曾阻止独立诊断 CLI，未关闭系统策略。GUI 的正常校验直接通过静态链接的 Rust ABI 完成。
- 完整 ZIP 的 **86 个文件**逐一与分发目录比较 SHA256，一致。分发目录、CMake 输出目录、ZIP 解压目录都在清除 Qt/QML 配置、PATH 仅保留 Windows 系统目录时，通过原生 Windows 插件接受真实卡密，退出码均为 0。
- 证据保存在忽略的 `build/protected-windows-build.log`、`build/protected-integration.log`、`build/windows-deployment-results.json` 和 `build/protection/windows-x64/`；界面截图已遮蔽机器码和卡密。

本轮 macOS 原生构建结果待 GitHub Actions 验证后记录。以下记录保留此前版本的验证历史；旧版 Mac 制品不能当作本轮 VM 保护版的验证结果。

## 开发环境

- Windows x64；MSVC 2022 19.44，Windows SDK 10.0.26100。
- Rust / Cargo / rust-analyzer 1.98.0；rustfmt、Clippy 可用。
- Qt 6.12.0 动态库，CMake 4.4.4，Ninja 1.13.2。
- Rust 1.99.1 已下载，但其编译器 DLL 被本机 Smart App Control 拦截。1.98.0 已实测可运行并设为默认，项目固定该版本；未关闭系统安全设置。

## 已通过

1. `cargo fmt --all -- --check`。
2. `cargo clippy --locked --workspace --all-targets -- -D warnings`。
3. `cargo test --locked --workspace`：20 个测试全部通过，包括时间边界、弱公钥、跨协议签名、字段/类型/重复字段、超长输入、错误设备/产品/版本、私钥错误口令与密文篡改、KDF 资源参数和独占创建，以及 macOS UUID 解析、平台域隔离、Windows 机器码兼容、探测子进程超时和输出上限。
4. Rust Release 和 Qt Release 实际编译、动态库打包完成。
5. `scripts/test-demo.ps1`：22 项检查通过，包括本机真实发卡/验签、篡改签名、异常协议、错误设备、Qt 离屏启动、界面接受真实卡密与拒绝篡改卡密、分发目录不含签发器/私钥。
6. 对两个 EXE 检查 PE 头：Dynamic Base、NX Compatible、High Entropy VA、Control Flow Guard 均存在。
7. `scripts/audit-deps.ps1`：OSV 对 66 个锁定的 Rust registry 依赖返回无已知 advisory。查询仅发送公开包名与版本；这是当次数据库结果，不能排除未知漏洞，也不涵盖 Qt/MSVC 或应用逻辑。
8. 客户端实际依赖许可收集：37 个包（35 个 registry 包、2 个工作区包），66 份第三方通知文本，清单 `complete: true`。工作区自身发布许可未指定。
9. Qt 6.12.0 精确源码压缩包 URL 的只读 HEAD 请求返回 HTTP 200；没有下载整个源码包，也未将源码包作为本地发行物附送。完整许可文本与 Qt SPDX 已附在客户端目录，正式对外分发仍应核对源码提供义务。

## 早期 UPX 实验结果

已下载官方 UPX 5.2.1，并按官方 GitHub 发布元数据提供的 SHA256 校验。实际尝试压缩 `CardGuard.exe` 与 `license-client.exe`，两个文件均被 UPX 拒绝：

```text
CantPackException: GUARD_CF enabled PE files are not supported
```

没有使用 `--force` 关闭 CFG，也没有将结果标为“已加壳”。每次实验的副本和报告保存在 `dist/packed-<时间>/packing-report.json`。当次交付的是编译加固版本；本轮已由上述 xollvm 策略虚拟化方案更新，UPX 不再作为主要保护。商业保护壳、代码签名证书、在线授权/撤销服务和独立安全审计尚未实施。

界面截图位于 `build/gui-valid.png`、`build/gui-invalid.png`，可再次运行集成测试生成。测试卡密位于受限目录 `.local/demo-card.txt`，默认本机有效 24 小时。

## Qt 原生界面修订

2026-10-22 已移除自定义 QSS、字体、配色及卡片装饰，改用默认 QGroupBox、QFormLayout、按钮和状态栏，默认窗口 700×520。重新编译并替换客户端后，22 项集成检查全部通过；另用 Windows 原生平台插件完成真实卡密校验与窗口截图。原生截图为 `build/gui-native.png`，显示系统当前深色主题及 DPI 设置；离屏截图的样式可能不同。

## macOS 原生构建

2026-10-22 的 [GitHub Actions 运行 39770423670](https://github.com/my-learn-project/rea-test-project/actions/runs/39770423670) 已成功，应用源码提交为 `975105882e29cce7d3cc364854605250e4d4137f`。分别在原生 `macos-15` ARM64 与 `macos-15-intel` x86_64 runner 上构建，使用 Rust 1.98.0、Qt 6.12.0 和 AppleClang；没有在 Windows 上模拟执行 Mac 程序。

- 两个架构均通过 Rust 格式检查、Clippy 和 20 项单元测试。
- 两个架构均实际生成包含 Qt frameworks/plugins 与 Rust 校验器的 `CardGuard.app`，通过 `codesign --verify --deep --strict` 与 `lipo` 架构检查。
- 使用一次性 CI 签发身份验证真实授权、签名篡改、错误设备、协议异常，以及原生 Cocoa 界面；随后恢复本项目公钥重新构建并运行最终包 smoke。测试身份的程序包不上传。
- `integration.json` 和 `smoke-release.json` 分别记录完整流程与最终包测试；PNG 使用原生 Cocoa 插件，默认遮蔽机器码与卡密。本机下载的报告位于 `build/macos-ci-results/`。
- 发布 ZIP 包只包含客户端 `.app`；私钥、口令、DPAPI 文件与签发工具不随包分发。公钥指纹及源码提交记录在包内 `Contents/Resources/build-info.json`。
- 两个最终 ZIP 已下载至 `dist/macos/CardGuard-macos-<架构>/`，本地验证 CRC、SHA256、Mach-O CPU 架构、执行权限、许可清单及公钥指纹均通过；包内公钥指纹与本机发行身份一致。ARM64 / Intel 的 Rust 许可清单分别为 32 / 33 个包。两个架构的集成报告均为 19 条通过记录，最终包 smoke 均为 13 条通过记录（均含套件完成状态）。

| 最终 ZIP | SHA256 |
| --- | --- |
| `CardGuard-macos-arm64.zip` | `b321cc55f4fce5ad5ff619152e47abaddf8828da95b69b52124b1c9b30d38537` |
| `CardGuard-macos-x86_64.zip` | `6c1d4fe08b15ce7e85e9dfb1db0629d3fba44c90b5c1eb6d1f210d54b2a4ff89` |

当前 Mac 包为 **ad-hoc 签名演示版本**，未使用 Apple Developer ID，也未公证。签名结构校验通过不代表 Gatekeeper 信任或 Apple 安全认证；没有为打包关闭系统安全保护。

## Windows 直接启动与源码分支修复

2026-10-22 修复 `build/gui/CardGuard.exe` 直接打开时缺少 `Qt6Core.dll` 的问题。完整构建现将 Qt DLL、平台/样式插件、`qt.conf` 和最新 Rust 校验器同步到该目录，同时生成包含完整 `client/` 目录的 `dist/CardGuard-windows-x64.zip`。项目根目录新增 `Start-CardGuard.cmd`，检查必要文件后启动完整客户端；PowerShell 启动脚本也不再依赖 MSVC 开发环境。

- 重新完成 Windows Release 构建与 22 项集成检查。
- 原生 Windows 平台插件分别测试 `dist/client`、`build/gui`、ZIP 解压目录；子进程 PATH 仅保留 Windows 系统目录，并移除继承的 Qt/QML 路径。三个目录均成功启动、通过 Rust IPC 读取机器码并接受真实卡密，退出码均为 0。
- ZIP 的全部 84 个文件逐一与分发目录比较 SHA256，内容一致；未包含签发工具或签名秘密。
- 本轮部署验证结果与遮蔽敏感信息后的截图保存在忽略的 `build/windows-deployment-results.json`、`build/deployment-*.png`。
- 根目录启动入口也在清除 Qt SDK 路径后实测成功，启动的原生窗口正常响应。
- 完整源码已合入 `main`；通过 `git check-ignore --no-index` 检查 40 个项目文件路径均未被忽略，10 个本机工具、生成物和敏感文件样例均被忽略。GitHub Desktop 的“0 changed files”表示没有未提交修改，不表示源码缺失。
