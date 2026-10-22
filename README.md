# CardGuard · Qt + Rust 授权卡密 Demo

Windows x64 与 macOS（Apple Silicon / Intel）桌面软件授权示例：Qt 6 Widgets 提供中文校验界面，Rust 负责 Ed25519 验签、机器绑定、有效期校验，以及独立的授权卡密签发工具。这里的“发卡”指软件授权码。

界面采用 Qt Widgets 平台默认样式，使用标准分组框、表单和按钮，字体与配色跟随系统，不加载自定义 QSS 主题。

客户端只含公钥。发行私钥、口令和发行工具不进入 `dist/client`。安全性基于公开算法和密钥隔离；离线程序仍可被管理员修改、回拨时间或伪造设备标识，不能承诺“顶尖”或无法破解。详见 [安全设计](docs/SECURITY.md) 和 [加壳说明](docs/PACKING.md)。

## 快速使用

在项目目录使用 **PowerShell 7.2+**：

```powershell
.\scripts\init-demo.ps1
.\scripts\build.ps1
.\scripts\test-demo.ps1

# 签发本机 24 小时卡密，结果保存在 .local/demo-card.txt：
.\scripts\issue-demo.ps1 -Subject '演示用户' -ValidHours 24

# 打开 Qt 界面，粘贴卡密并校验：
.\scripts\run-demo.ps1
```

直接运行 `dist/client/CardGuard.exe` 也可以。复制整个 `dist/client` 目录给测试机器；授权需要使用目标机器显示的机器码重新签发：

```powershell
.\scripts\issue-demo.ps1 -Subject '测试用户' -DeviceId '<64位小写十六进制机器码>' -ValidHours 24
```

机器码来自 Windows MachineGuid 或 macOS IOPlatformUUID 的带产品域哈希，仅用于 demo 设备绑定；它不是硬件防伪证明。复制 Mac 界面上的机器码，也可用上面的 Windows 发卡命令签发。

## macOS 构建

GitHub Actions 工作流 [Build macOS](.github/workflows/build-macos.yml) 在推送 `main` 或 `codex/**` 分支的相关代码后，分别使用原生 Apple Silicon 和 Intel runner 构建。仓库变量 `CARDGUARD_PUBLIC_KEY_HEX` 必须设置为当前 `config/trusted-public-key.hex` 的 64 位公钥；私钥与 DPAPI 文件留在本机。

成功运行的 Artifacts 中有 `CardGuard-macos-arm64`、`CardGuard-macos-x86_64` 两个下载项。各自包含 `.app` 的 ZIP 和 SHA256 文件；下载后解开外层 Actions ZIP，再在 Mac 上解开内层程序 ZIP，保留执行权限、framework 链接和签名。两个版本分别适用于 Apple Silicon 和 Intel；并非 Universal 二合一包。

工作流先用临时测试身份验证真实发卡、验签、篡改、错误设备和原生 Cocoa 界面，再恢复项目公钥重新构建最终客户端。上传的客户端只来自最后一次构建；测试私钥、口令和测试版程序均不上传。GUI 测试截图会遮蔽机器码和卡密。

也可在安装 Xcode Command Line Tools、Rust 1.98.0、CMake、Ninja、Python 3.10+ 和 Qt 6 共享 SDK 的 Mac 上执行：

```bash
# 先复制现有发行身份的公钥到 config/trusted-public-key.hex
export QT_ROOT="$HOME/Qt/6.12.0/macos"
bash scripts/build-macos.sh
```

脚本默认构建本机架构，产物在 `dist/macos-<架构>-<随机后缀>/`。Qt 与 Rust 校验器一起放入 `CardGuard.app`；程序保留 macOS 默认 Qt 样式。macOS 打包采用 `macdeployqt`，不使用 Windows UPX 流程。

默认产物使用 ad-hoc 签名供演示测试，**没有 Apple Developer ID 签名或公证**，从互联网下载后可能被 Gatekeeper 拦截。正式分发需要开发者证书与公证；脚本可通过 `CARDGUARD_SIGN_IDENTITY` 使用已有钥匙串证书启用 Hardened Runtime 签名，但不会自动提交公证。构建签名与卡密签发密钥是两套不同用途的身份。

## 环境安装与构建

```powershell
# Rust、Cargo、Clippy、rustfmt、rust-analyzer、MSVC 2022、Windows SDK：
.\scripts\setup-dev.ps1 -Phase Toolchain

# Qt SDK、CMake 和 Ninja（已有 Python 3.10+）：
.\scripts\setup-dev.ps1 -Phase Qt -PythonExe '<Python解释器绝对路径>' -QtVersion 6.12.0
```

Rust 安装到当前用户 `.cargo` / `.rustup`；MSVC 安装到 `C:\BuildTools`；Qt 和构建辅助工具安装到本项目 `.tools`。构建脚本自动导入 MSVC 开发环境。新终端会读取用户 PATH 中的 Cargo；Qt 不必加入全局 PATH。

本机最新 Rust 1.99.1 的编译器 DLL 被 Windows Smart App Control 拦截（Code Integrity 3077，`0xc0e90002`）。官方 Rust 1.98.0 已能正常启动，因此项目和安装脚本固定为 1.98.0，保留系统安全保护。升级前应先检查新工具链是否能运行。

Qt 6.12 官方仓库已经改为按编译器分目录，aqt 3.3 尚不支持。因此 `install-qt.py` 从官方元数据选择三个必要归档，使用 HTTPS 和官方逐文件校验值下载，保留归档并设置可迁移 `qt.conf`。不关闭 TLS 验证。

`build.ps1` 默认执行格式检查、Clippy、Rust 单元测试，再构建 Rust Release、Qt Release 和动态 Qt 分发目录，并离线收集客户端 Rust 依赖的许可证文本。`test-demo.ps1` 检查真实签发/验签、篡改签名、错误机器、异常输入、Qt 离屏启动、分发包隔离和 Windows PE 安全标志。`audit-deps.ps1` 可按锁定版本向 OSV 查询已知漏洞，查询失败不会报告通过。

## 发行密钥

`init-demo.ps1` 首次生成随机 Ed25519 私钥，以 Argon2id（64 MiB、3 次、单线程）派生密钥，使用 ChaCha20-Poly1305 加密私钥。随机口令由当前 Windows 用户 DPAPI 保护，演示文件放在受限 ACL 的 `.local`，不会提交 Git。

这是开发便利模式：同一 Windows 用户的进程可以解密 DPAPI 口令，因此它不能替代独立生产签发服务或 HSM。请备份演示身份；若初始化中断，脚本会报告部分身份存在，不会静默覆盖。

生产签发可以使用独立机器上的 CLI，交互输入口令，不使用开发 DPAPI 文件：

```powershell
.\target\release\license-issuer.exe keygen --private-key '<安全目录>\issuer.private.json' --public-key '<安全目录>\public.hex'
.\target\release\license-issuer.exe issue --private-key '<安全目录>\issuer.private.json' --subject '用户' --device-id '<机器码>' --license-id 'LICENSE-001' --valid-hours 24
```

把所选公钥复制到 `config/trusted-public-key.hex` 后重新构建客户端。公钥编译进验证器；运行时不存在可以替换的公钥配置入口。不同公钥签发的卡密不能混用。交互口令至少 12 个字符，不通过命令行参数传递。

## 加壳与分发

Release 启用 LTO、单代码生成单元、移除符号、整数溢出检查，以及 Windows ASLR、DEP、High Entropy VA、CFG。Qt 使用动态库部署。

```powershell
.\scripts\install-upx.ps1
.\scripts\pack.ps1
```

`pack.ps1` 在新目录操作，只尝试压缩 GUI 与验证器；不修改原客户端，不处理 Qt DLL 或签发工具。UPX 与 CFG 可能不兼容，脚本不会通过 `--force` 关闭保护；以生成的 `packing-report.json` 为准，失败项保留原始加固二进制。UPX 是压缩壳，不提供密码学保护。商业保护壳需要合法许可证和单独兼容性测试。

分发保留 Qt 许可证、替换动态库的能力和精确版本源码获取说明，详见 [第三方说明](docs/THIRD_PARTY.md)。正式发布还需要软件签名证书、依赖漏洞扫描、服务端激活/撤销设计及独立安全审计；当前 demo 未提供这些服务。

本应用源码未预设开源发布许可，发布方式由项目所有者决定；第三方依赖保留各自许可。当前验证结果见 [VALIDATION.md](docs/VALIDATION.md)。

## 目录

| 路径 | 内容 |
| --- | --- |
| `frontend/main.cpp` | Qt Widgets 校验界面 |
| `crates/license-core` | 协议、验证与安全单元测试 |
| `crates/license-client` | 编译公钥、读取本机身份、JSON IPC |
| `crates/license-issuer` | 加密密钥生成及卡密签发 |
| `scripts` | 安装、构建、签发、测试和打包 |
| `.local` | 本机演示密钥和卡密，禁止分发 |
| `dist/client` | 桌面校验端 |

协议请求为单行 JSON：`{"op":"device"}` 或 `{"op":"verify","token":"..."}`，成功返回 `{"ok":true,"result":{...}}`，失败返回 `{"ok":false,"error":{"code":"...","message":"..."}}`。签名覆盖带产品域分隔符的原始 payload 字节；解析拒绝额外字段、过长输入和未知版本。
