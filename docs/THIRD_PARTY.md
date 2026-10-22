# 第三方组件与分发说明

本 Demo 的 Windows x64 MSVC 2022 客户端与 macOS Apple Silicon / Intel 构建流程统一使用 Qt 6.12.0 共享 SDK；macOS 将共享 Qt frameworks 部署到 `.app` 中。主程序采用动态链接，Qt 库与插件应保持独立、可替换。本文件是组件通知和工程说明，完整许可文本以发行目录中的实际文件及组件源码为准。macOS 每次构建的实际 Qt 版本与对应源码目录记录在 `Contents/Resources/build-info.json` 中。

## Qt

客户端使用 Qt Core、Gui、Widgets 及其所需插件；开源许可选项为 GNU Lesser General Public License version 3（LGPLv3），相应 Qt 模块亦有其他可选许可。Qt 与插件内含的第三方代码分别适用各自许可，不应将 Qt SDK 的全部组件一概视为同一许可。

构建脚本复制项目自带的 `docs/licenses/LGPL-3.0.txt`、`GPL-3.0.txt` 与本说明，并收集实际 Qt SDK 中存在的许可文件及 SBOM：例如 `licenses`、`share/licenses` 和 `sbom`。Windows 通知位于客户端 `licenses`，macOS 位于 `CardGuard.app/Contents/Resources/licenses`。当前下载的 SDK 可能不含顶层 `licenses` 目录；项目附带的 GPL/LGPL 文本及 SDK SBOM 仍不能替代实际组件所需的全部版权与第三方通知，正式分发前须审核并补齐。[Qt 官方许可与 SBOM 说明](https://doc.qt.io/qt-6/licensing.html)

本次使用的 Qt 版本为 6.12.0；官方对应源码地址：

- [Qt 6.12.0 源码目录](https://download.qt.io/official_releases/qt/6.12/6.12.0/single/)
- [qt-everywhere-src-6.12.0.tar.xz](https://download.qt.io/official_releases/qt/6.12/6.12.0/single/qt-everywhere-src-6.12.0.tar.xz)

上述压缩包 URL 已于 2026-10-22 经只读 HEAD 请求确认返回 HTTP 200，本地未下载整个源码包。正式分发前应校验其摘要，并保证用户能获得与实际分发库对应的完整源码。正式发行应随包提供对应源码或落实适用许可要求的有效源码提供方式；不能只依赖本说明中的一个上游链接来宣称全部义务已经履行。若修改 Qt，还须保留并提供对应修改及必要构建信息。Qt 版本改变时，应同步本说明与源码副本。

Windows 替换 Qt 动态库的方法：

1. 关闭 CardGuard，备份客户端目录。
2. 使用兼容的 Windows x64 MSVC 共享构建，保持模块、编译配置与二进制接口兼容。
3. 替换客户端根目录中的 `Qt6Core.dll`、`Qt6Gui.dll`、`Qt6Widgets.dll` 及需配套更新的 Qt 库和插件（如 `platforms/qwindows.dll`）。
4. 保留插件目录结构并重新启动。版本或 ABI 不兼容时应恢复备份，或从项目源码重新构建应用与库。

macOS 同样允许替换共享 Qt：关闭程序并备份 `.app`，使用匹配架构和 ABI 的共享构建，替换 `Contents/Frameworks` 中的 `QtCore.framework`、`QtGui.framework`、`QtWidgets.framework` 及所需配套库与插件，例如 `Contents/PlugIns/platforms/libqcocoa.dylib`。保留 framework 的目录、符号链接及装载路径；也可用包含修改的 Qt SDK 的 `macdeployqt` 重新部署依赖。替换文件会使原签名失效，需从内部 frameworks、插件与 `Contents/MacOS/license-client` 到外层 `.app` 重新签名；本地测试可使用 `macdeployqt CardGuard.app -always-overwrite -codesign=-` 进行临时签名，并用 `codesign --verify --deep --strict CardGuard.app` 检查。临时签名不等于 Developer ID 签名或 Apple 公证，项目当前不承诺公证状态。[Qt 官方 macOS 部署说明](https://doc.qt.io/qt-6/macos-deployment.html)

本项目不对 Qt DLL、framework 或插件加壳，也不通过自定义完整性校验阻止用户替换这些动态库。用户可以为修改 Qt 或调试这些修改而进行适用许可允许的逆向工程。更多义务见 [Qt 官方 LGPL 说明](https://www.qt.io/development/open-source-lgpl-obligations)。

## Microsoft Visual C++ 运行时

Windows x64 客户端由 MSVC 构建，需要匹配架构、且版本不低于实际编译工具链要求的 Microsoft Visual C++ v14 Redistributable。推荐使用微软官方安装程序进行集中部署；不要从任意 Windows 系统目录复制 DLL，也不要分发 Debug 运行库。

微软对运行库、合并模块及单独二进制文件的再分发有许可限制，发布者应核对实际 Visual Studio/Build Tools 许可及可再分发文件清单。客户端构建成功不自动证明发布者获得了全部再分发权利。[Microsoft 再分发与许可说明](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)

下载与版本要求见 [Microsoft 官方 Visual C++ Redistributable 页面](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)。运行时安装程序适用微软自己的许可，不适用本项目的应用源码许可。

## Rust 组件

Rust 客户端及发卡工具的直接与间接依赖由 `Cargo.lock` 锁定。正式发布时应基于本次实际构建的依赖图，生成版本、来源、许可证表达式及版权/完整许可文本清单，并保留所需通知。不能只列直接依赖，也不能把所有 Rust crates 一概写成 MIT。

`scripts/collect-notices.py` 根据锁定的离线客户端依赖图收集通知文件，macOS 构建显式传入其 Rust target；在各平台发行包的 `licenses/rust` 目录生成 `inventory.json`、`inventory.md` 及按包版本归档的许可文本。JSON 中 `complete: true` 表示所列缓存依赖均有许可证表达式与可收集通知文件，不代表法律审核完成。每次更改 `Cargo.lock` 后应重新运行收集，并审阅清单；发卡端独有依赖不混入客户端清单。发卡程序及其私钥、DPAPI 文件均不属于客户端发行内容。

## UPX

UPX 是可选构建时工具，不是客户端授权协议的一部分。其许可及可执行文件压缩例外以 [UPX 官方许可](https://github.com/upx/upx/blob/devel/LICENSE) 为准。若随安装包分发 UPX 工具本体，还需履行工具本体相应的分发义务。

UPX 不提供加密或防破解保证。若当前 UPX 拒绝处理启用 Control Flow Guard（CFG）的程序，保留已加固的原始 EXE，并记录“压缩未完成”。不使用 `--force`，不为压缩关闭 CFG；执行和结果记录方式见开发仓库的 `docs/PACKING.md`。
