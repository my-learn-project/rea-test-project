# 开源保护与发布边界

默认构建使用 [xollvm v0.11.1 / LLVM 22](https://github.com/und3ath/xollvm/releases/tag/v0.11.1)，将单个授权策略函数 `cardguard_policy_allows` 转换为 VM 执行形式，再作为 object 链接进 Qt 主程序。Rust 验签库同样静态链接进主程序，GUI 不调用外部 `license-client`；该 CLI 保留为诊断和集成工具。

这项保护用于增加所选函数的分析、定位与修改成本。发卡私钥仍保留在管理端，可信时间与在线撤销仍需独立机制；保护不承诺无法破解。公开源码允许移除保护后重新构建，已经控制客户端的人仍可能补丁修改验签或结果分支。协议与密钥隔离的边界见 [SECURITY.md](SECURITY.md)。

## 保护范围

受保护函数位于 `frontend/authorization_policy.cpp`，检查 Rust 校验成功、版本、产品、设备与字段结构对应的五个状态位（合计 `31`），以及签发时间、到期时间、时间上界和最长 366 天期限。GUI 的原有严格响应检查继续保留，最后还须通过该函数才能显示授权有效。当前 VM 注解关闭 anti-debug 相关选项。

整个 Rust 校验器、Ed25519 实现、Qt DLL、framework、插件及其他第三方运行库均未被这次 VM 混淆。发卡工具、签名私钥、口令、备份和管理端数据不进入客户端发行包。Qt 动态库保持独立、可替换；保护工具不会替代通知、源码获取及适用的重链接等许可义务。[Qt 官方 LGPL 义务说明](https://www.qt.io/development/open-source-lgpl-obligations)

## Windows 构建

在 README 所述开发环境安装完成后执行：

```powershell
.\scripts\install-xollvm.ps1
.\scripts\build.ps1
```

工具安装完成后，后续构建直接运行 `build.ps1` 即可。

安装脚本使用固定的官方 Windows x64 LLVM 22 归档，核对 `config/xollvm-toolchain.json` 中锁定的版本与 SHA-256，再用 Clang 内置混淆模式编译探测函数，确认实际生成 VM。该路径不执行独立的 opt.exe；本机 opt.exe 被应用控制阻止，系统策略保持不变。构建脚本读取 `.tools/xollvm/toolchain.json`，自动生成 `build/protection/windows-x64` 下的策略 object 与保护报告；不需要手工给整个 Qt 工程切换混淆编译器。

`build-policy.py` 的流程是：先编译选定策略函数的 LLVM IR，执行 xollvm 转换，再进行 O2 优化与 IR 验证。它要求优化后仍存在 `vm.bytecode` 和 `__vm_engine`，Windows 还须保留 CFG 元数据，才从这份优化后 IR 生成最终 object。构建随后链接并运行使用同一 object 的 `policy-tests`，包含 4174 个边界、状态位组合与确定性差分用例；失败会终止构建。源码注解本身不能证明保护已执行，实际结果以构建输出和 [VALIDATION.md](VALIDATION.md) 为准。

`protection.json` 记录工具版本、目标、保护范围、源码、object、优化后 IR 及工具报告摘要。它用于核对本次构建及发现陈旧或错架构对象，**不是运行时防篡改信任链**；文件与摘要一起可被修改时，摘要不能证明发布者身份。

## macOS 构建

macOS CI 先由 Windows job 使用固定 xollvm 工具链生成 `macos-arm64` 和 `macos-x86_64` 两份 Mach-O 策略 object。对应 Mac job 下载同一次工作流的对象与 `protection.json`，用 `build-policy.py --verify-only` 核对源码摘要、目标、object 摘要及保护报告，再在原生 Apple Silicon 或 Intel runner 上链接 Rust、Qt 与策略 object，运行同一组策略测试和 GUI 集成测试。这个路径不要求在 Intel Mac 上用 Homebrew 安装 LLVM 或寻找不匹配的插件。

手工构建时，将同一提交、对应架构的策略 object、`protection.json`、`xollvm-report.json` 放到 `build/protection/macos-<架构>`；也可用匹配的 LLVM 22 与 xollvm 插件通过 `build-policy.py` 自行生成。设置 `QT_ROOT` 后执行：

```bash
export CARDGUARD_POLICY_DIR="$PWD/build/protection/macos-$(uname -m)"
bash scripts/build-macos.sh
```

`CARDGUARD_POLICY_DIR` 默认即为上述目录。两个架构分别构建和测试，不是 Universal 合包。CI 配置及验证命令不等于某次 Mac 构建已经成功，是否产出制品以对应工作流结果为准。

## UPX：遗留可选压缩实验

UPX 不属于默认保护步骤。既有 UPX 5.2.1 实验未成功压缩启用 CFG 的程序，保留了原始 EXE；不能把它描述为已经完成的主保护方案。默认使用 xollvm 的构建不需要安装或运行 UPX。

需要重现该压缩实验时，可单独执行 `scripts/install-upx.ps1` 和 `scripts/pack.ps1`。后者在新目录对 GUI 与诊断 CLI 的副本尝试压缩，不处理 Qt DLL、插件或签发工具；逐文件结果记录在 `packing-report.json`，失败项恢复原始文件。不使用 `--force`，不为压缩关闭 CFG，也不要求关闭系统安全防护。

`upx --test` 只检查压缩结构，不能证明授权逻辑、兼容性或系统缓解措施正确；若以后得到可用压缩版本，仍需重新运行最终制品的业务和安全回归。UPX 官方明确说明它不提供保护或加密功能。[UPX 官方项目说明](https://github.com/upx/upx)

## 分发与签名

Windows 的 `dist/CardGuard-windows-x64.zip` 包含完整 `client` 目录，部署依赖由匹配 Qt SDK 的 `windeployqt` 收集；保留 `qt.conf`、平台/样式插件和许可通知。Qt 替换方式见 [THIRD_PARTY.md](THIRD_PARTY.md)。Rust 已编译进 GUI，不再依赖诊断 CLI 的返回值。

macOS 使用 `macdeployqt` 部署共享 Qt，保留 `.app` 的 framework 链接和签名。默认 ad-hoc 签名仅供本地演示；Developer ID 签名、Hardened Runtime 与 Apple 公证各有独立步骤，脚本不自动提交公证。

正式签名应在代码变换、链接和可选压缩结束后进行；签名后修改文件会使签名失效。构建报告与同目录 SHA-256 清单只记录制品，不能代替操作系统代码签名或可信更新通道。[Microsoft 签名验证说明](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature)、[Qt 官方 macOS 部署说明](https://doc.qt.io/qt-6/macos-deployment.html)
