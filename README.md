# CardGuard · Qt + Rust 授权卡密 Demo

Windows x64 与 macOS（Apple Silicon / Intel）桌面软件授权示例：Qt 6 Widgets 提供中文校验界面，静态链接的 Rust 库负责 Ed25519 验签、机器绑定和有效期校验，独立管理工具负责签发授权卡密。这里的“发卡”指软件授权码。

界面采用 Qt Widgets 平台默认样式，使用标准分组框、表单和按钮，字体与配色跟随系统，不加载自定义 QSS 主题。

默认保护采用开源 xollvm v0.11.1 / LLVM 22，仅虚拟化最终授权策略函数；没有混淆整个 Rust 验签器或 Qt 库。客户端只含公钥，发行私钥、口令和发行工具不进入 `dist/client`。保护用于提高所选代码的分析和修改成本，不能阻止有源码的人移除保护重新构建，也不能代替密钥隔离、可信时间或服务端鉴权。详见 [安全设计](docs/SECURITY.md) 和 [开源保护说明](docs/PACKING.md)。

## 快速使用

已有构建时，双击项目根目录的 **`Start-CardGuard.cmd`** 即可启动。它会检查必需的 Qt DLL 和平台插件，并从 `dist/client` 运行完整程序，不需要先导入 Rust、Qt 或 MSVC 开发环境。Rust 校验代码已经编译进 GUI；主程序也提供不创建窗口的 `--stdio` 诊断入口，Windows 发卡和测试脚本使用该入口。外部 `license-client.exe` 为同源可选工具，GUI 不调用它。

在项目目录使用 **PowerShell 7.2+**：

```powershell
.\scripts\init-demo.ps1
# 首次安装保护工具，已安装可跳过这一行：
.\scripts\install-xollvm.ps1
.\scripts\build.ps1
.\scripts\test-demo.ps1

# 签发本机 24 小时卡密，结果保存在 .local/demo-card.txt：
.\scripts\issue-demo.ps1 -Subject '演示用户' -ValidHours 24

# 打开 Qt 界面，粘贴卡密并校验：
.\scripts\run-demo.ps1
```

直接运行 `dist/client/CardGuard.exe` 也可以。分发时使用构建生成的 **`dist/CardGuard-windows-x64.zip`**：完整解压后运行其中的 `client/CardGuard.exe`；也可复制整个 `dist/client` 目录。EXE 依赖同目录的 Qt DLL、`qt.conf` 和平台/样式插件目录，单独复制 EXE 会报缺少 `Qt6Core.dll`。测试机器若缺少 MSVC 运行库，可使用包内微软官方 `vc_redist.x64.exe` 安装。

`build/gui` 是 CMake 构建目录；`scripts/build.ps1` 现在也会向该目录同步运行依赖，便于直接测试。只执行 CMake 编译时，请继续使用完整的构建脚本完成部署。

授权需要使用目标机器显示的机器码重新签发：

```powershell
.\scripts\issue-demo.ps1 -Subject '测试用户' -DeviceId '<64位小写十六进制机器码>' -ValidHours 24
```

机器码来自 Windows MachineGuid 或 macOS IOPlatformUUID 的带产品域哈希，仅用于 demo 设备绑定；它不是硬件防伪证明。复制 Mac 界面上的机器码，也可用上面的 Windows 发卡命令签发。

## 源码与 Git 分支

完整项目已整合到 `main`，Qt 源码位于 `frontend/`，Rust 源码位于 `crates/`。`.gitignore` 忽略的是工具链、构建产物、缓存和本机发行身份，源码、`Cargo.lock`、构建脚本及 `.github/workflows/` 都应被跟踪。

GitHub Desktop 的“0 changed files”表示没有待提交修改；已提交的源码可在 **History**、**Show in Explorer** 或 GitHub 仓库文件页查看。

## macOS 构建

GitHub Actions 工作流 [Build macOS](.github/workflows/build-macos.yml) 在推送 `main` 或 `codex/**` 分支的相关代码后，先由 Windows job 使用固定 xollvm 工具链生成两架构的 Mach-O 策略 object，再由原生 Apple Silicon 和 Intel runner 核对、链接和测试。Mac job 无需在 Intel Homebrew 环境安装 LLVM。仓库变量 `CARDGUARD_PUBLIC_KEY_HEX` 必须设置为当前 `config/trusted-public-key.hex` 的 64 位公钥；私钥与 DPAPI 文件留在本机。

成功运行的 Artifacts 中有 `CardGuard-macos-arm64`、`CardGuard-macos-x86_64` 两个下载项。各自包含 `.app` 的 ZIP 和 SHA256 文件；下载后解开外层 Actions ZIP，再在 Mac 上解开内层程序 ZIP，保留执行权限、framework 链接和签名。两个版本分别适用于 Apple Silicon 和 Intel；并非 Universal 二合一包。

工作流配置为先用临时测试身份验证真实发卡、验签、篡改、错误设备和原生 Cocoa 界面，再恢复项目公钥重新构建最终客户端。上传的客户端只来自最后一次构建；测试私钥、口令和测试版程序均不上传。GUI 测试截图会遮蔽机器码和卡密。配置了这些检查不等于某次构建已经通过，请以 Actions 结果和 [验证记录](docs/VALIDATION.md) 为准。

也可在安装 Xcode Command Line Tools、Rust 1.98.0、CMake、Ninja、Python 3.10+ 和 Qt 6 共享 SDK 的 Mac 上执行：

```bash
# 先复制现有发行身份的公钥到 config/trusted-public-key.hex
export QT_ROOT="$HOME/Qt/6.12.0/macos"
# 将同提交、对应架构的 authorization_policy.o、protection.json、xollvm-report.json
# 从 CI 放入下述目录，或使用匹配 LLVM 22 + xollvm 插件自行生成：
export CARDGUARD_POLICY_DIR="$PWD/build/protection/macos-$(uname -m)"
bash scripts/build-macos.sh
```

脚本默认构建本机架构，核对策略 object 的源码、目标与文件摘要，再运行链接同一对象的策略测试；产物在 `dist/macos-<架构>-<随机后缀>/`。Rust 验签库与保护后的策略 object 链接进 `CardGuard.app` 内的 GUI，另保留同源诊断 CLI；程序使用 macOS 默认 Qt 样式。macOS 打包采用 `macdeployqt`，不使用 UPX。

默认产物使用 ad-hoc 签名供演示测试，**没有 Apple Developer ID 签名或公证**，从互联网下载后可能被 Gatekeeper 拦截。正式分发需要开发者证书与公证；脚本可通过 `CARDGUARD_SIGN_IDENTITY` 使用已有钥匙串证书启用 Hardened Runtime 签名，但不会自动提交公证。构建签名与卡密签发密钥是两套不同用途的身份。

## 环境安装与构建

```powershell
# Rust、Cargo、Clippy、rustfmt、rust-analyzer、MSVC 2022、Windows SDK：
.\scripts\setup-dev.ps1 -Phase Toolchain

# Qt SDK、CMake 和 Ninja（已有 Python 3.10+）：
.\scripts\setup-dev.ps1 -Phase Qt -PythonExe '<Python解释器绝对路径>' -QtVersion 6.12.0

# 默认授权策略保护工具（Qt 辅助 Python 环境安装好后）：
.\scripts\install-xollvm.ps1
```

Rust 安装到当前用户 `.cargo` / `.rustup`；MSVC 安装到 `C:\BuildTools`；Qt 和构建辅助工具安装到本项目 `.tools`。构建脚本自动导入 MSVC 开发环境。新终端会读取用户 PATH 中的 Cargo；Qt 不必加入全局 PATH。

本机最新 Rust 1.99.1 的编译器 DLL 被 Windows Smart App Control 拦截（Code Integrity 3077，`0xc0e90002`）。官方 Rust 1.98.0 已能正常启动，因此项目和安装脚本固定为 1.98.0，保留系统安全保护。升级前应先检查新工具链是否能运行。

Qt 6.12 官方仓库已经改为按编译器分目录，aqt 3.3 尚不支持。因此 `install-qt.py` 从官方元数据选择三个必要归档，使用 HTTPS 和官方逐文件校验值下载，保留归档并设置可迁移 `qt.conf`。不关闭 TLS 验证。

`build.ps1` 默认执行格式检查、Clippy、Rust 单元测试，再构建 Rust 静态库、受保护的策略 object、Qt Release 和动态 Qt 分发目录，并离线收集客户端 Rust 依赖的许可证文本。构建要求运行使用同一策略 object 的 4174 个边界、状态组合与差分用例；`build-policy.py` 检查 O2 后 VM 代码和 Windows CFG 元数据仍保留。`test-demo.ps1` 检查真实签发/验签、篡改签名、错误机器、异常输入、Qt 启动、分发包隔离和 Windows PE 安全标志。具体通过情况以实际记录为准。`audit-deps.ps1` 可按锁定版本向 OSV 查询已知漏洞，查询失败不会报告通过。

## 发行密钥

`init-demo.ps1` 首次生成随机 Ed25519 私钥，以 Argon2id（64 MiB、3 次、单线程）派生密钥，使用 ChaCha20-Poly1305 加密私钥。随机口令由当前 Windows 用户 DPAPI 保护，演示文件放在受限 ACL 的 `.local`，不会提交 Git。

这是开发便利模式：同一 Windows 用户的进程可以解密 DPAPI 口令，因此它不能替代独立生产签发服务或 HSM。请备份演示身份；若初始化中断，脚本会报告部分身份存在，不会静默覆盖。

生产签发可以使用独立机器上的 CLI，交互输入口令，不使用开发 DPAPI 文件：

```powershell
.\target\release\license-issuer.exe keygen --private-key '<安全目录>\issuer.private.json' --public-key '<安全目录>\public.hex'
.\target\release\license-issuer.exe issue --private-key '<安全目录>\issuer.private.json' --subject '用户' --device-id '<机器码>' --license-id 'LICENSE-001' --valid-hours 24
```

把所选公钥复制到 `config/trusted-public-key.hex` 后重新构建客户端。公钥编译进验证器；运行时不存在可以替换的公钥配置入口。不同公钥签发的卡密不能混用。交互口令至少 12 个字符，不通过命令行参数传递。

## 开源保护与分发

Release 启用 LTO、单代码生成单元、移除符号、整数溢出检查，以及 Windows ASLR、DEP、High Entropy VA、CFG。Qt 使用动态库部署。

默认保护已集成进 `build.ps1`：xollvm 只转换 `cardguard_policy_allows`，检查已验证授权状态位和期限，再作为 object 链接到 GUI。Rust/Ed25519 实现和 Qt 动态库保持原有代码；客户端不依赖外部 CLI 返回的 JSON。工具固定为 v0.11.1，许可为 `Apache-2.0 WITH LLVM-exception`。[xollvm 固定版本](https://github.com/und3ath/xollvm/releases/tag/v0.11.1)

`build/protection/<目标>/protection.json` 的摘要用于记录和核对构建，不能作为运行时防篡改信任链。保护提高的是分析成本；公开源码可以移除保护，已经控制本机的人仍可能修改最终分支。没有“顶尖”或无法破解的保证。

UPX 仅保留为遗留可选压缩实验，通过 `install-upx.ps1` / `pack.ps1` 单独运行；既有 CFG 制品的压缩实验未成功，不能将其作为默认保护或已经加壳成功的依据。默认构建无需 UPX，也不会为压缩关闭 CFG。详细范围和构建流程见 [PACKING.md](docs/PACKING.md)。

分发保留 Qt 许可证、替换动态库的能力和精确版本源码获取说明，详见 [第三方说明](docs/THIRD_PARTY.md)。正式发布还需要软件签名证书、依赖漏洞扫描、服务端激活/撤销设计及独立安全审计；当前 demo 未提供这些服务。

本应用源码未预设开源发布许可，发布方式由项目所有者决定；第三方依赖保留各自许可。当前验证结果见 [VALIDATION.md](docs/VALIDATION.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `frontend/main.cpp` | Qt Widgets 校验界面 |
| `crates/license-core` | 协议、验证与安全单元测试 |
| `frontend/authorization_policy.cpp` | 由 xollvm 独立虚拟化的最终策略函数 |
| `crates/license-client` | 编译公钥、本机身份、Rust 静态库 ABI 与同源诊断 CLI |
| `crates/license-issuer` | 加密密钥生成及卡密签发 |
| `scripts` | 安装、构建、签发、测试和打包 |
| `.local` | 本机演示密钥和卡密，禁止分发 |
| `dist/client` | 桌面校验端 |

进程内 ABI 使用 JSON 请求 `{"op":"device"}` 或 `{"op":"verify","token":"..."}`，成功返回 `{"ok":true,"result":{...}}`，失败返回 `{"ok":false,"error":{"code":"...","message":"..."}}`；诊断 CLI 继续支持同样内容的 JSON-lines 协议。签名覆盖带产品域分隔符的原始 payload 字节；解析拒绝额外字段、过长输入和未知版本。GUI 使用有上限的后台 ABI 调用，失败、超时或迟到结果均不能授予授权。
