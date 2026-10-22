# 加壳与发布边界

本项目中的“加壳”限定为可选的 UPX 可执行文件压缩演示。UPX 官方明确说明它不提供保护或加密功能，因此不能把压缩后的 Demo 描述为“防破解”或“已达到顶尖安全”。[UPX 官方项目说明](https://github.com/upx/upx)

## 允许处理的文件

仅压缩客户端 Qt GUI 和 Rust 校验程序的副本。原始 Release 制品应保留，以便调试、比较和兼容性回退。不得扫描整个目录后对所有 EXE 或 DLL 批量处理，避免把管理端发卡程序或第三方运行库误纳入。

以下内容不参与加壳，也不应因加壳而混入客户端安装包：

- 发卡工具、签名私钥、私钥口令、私钥备份和管理端数据。
- Qt DLL、Qt 插件及其他第三方运行库；保持动态链接库可替换，并保留许可证信息。
- 调试符号、构建缓存、源代码中的开发机绝对路径及其他仅开发时需要的文件。

Qt 的开源 LGPL 许可包含通知、源码获取及替换/重链接等义务，动态链接并不自动满足全部要求。发布时应核对实际使用模块的许可、附上库的许可证与对应源码或合规获取说明，并确保用户能使用修改后的 Qt 库。以上是项目工程约束，具体发行方式仍须按适用许可核对。[Qt 官方 LGPL 义务说明](https://www.qt.io/development/open-source-lgpl-obligations)

## 本地演示流程

先按 README 构建并验证原始客户端，再使用项目提供的可选打包命令。启用 UPX 后，打包步骤应遵循下面的次序：

```powershell
pwsh -File scripts/install-upx.ps1
pwsh -File scripts/pack.ps1
```

脚本固定使用 UPX 5.2.1，在 `dist/packed-时间戳` 创建副本；只尝试处理 `CardGuard.exe` 和 `license-client.exe`，逐文件记录 `packing-report.json`。`packed: true` 表示压缩命令和 UPX 结构测试通过，`packed: false` 表示该文件未压缩并已从原始发行目录恢复。不要因为目录名含 `packed` 就认定加壳完成。

若 UPX 拒绝启用 CFG（Control Flow Guard）的 PE 文件，项目保留原有缓解措施，不使用 `--force`，也不为压缩关闭 CFG。此时实际结果应报告“保留原始加固版本，UPX 压缩未完成”，以报告中的每个 EXE 结果为准。

完整发布验证的建议步骤：

1. 创建客户端发行副本，只包含明确列入清单的 GUI、校验程序及其运行依赖。
2. 对可兼容的 GUI 与校验程序执行 UPX 压缩，并执行 `upx --test`。拒绝处理时保留原文件。此测试检查压缩文件结构，不能证明业务或安全机制正确，也不单独证明 CFG 等缓解措施完整保留。
3. 对压缩版本重新验证：合法卡密成功；篡改、过期、错误产品、错误设备和错误签名失败；程序启动、中文输入、错误反馈与超时处理正常。
4. 对最终文件生成 SHA-256 清单，记录 Rust、Qt、编译器、依赖和 UPX 版本。校验和须通过可信渠道交付，单独附在同一可修改目录中不构成签名信任链。
5. 若要正式签名，应先完成压缩再签名，并通过 `signtool verify /pa /v` 等工具验证签名。签名后再次压缩或改写文件通常会破坏现有签名。[Microsoft 签名验证说明](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature)

UPX 具有解压能力；把它当作秘密存储、隐藏算法或阻止程序分析的机制是不成立的。压缩后的文件还需要在目标 Windows 环境中进行兼容性测试。不要因为压缩或安全软件的判断而要求用户关闭安全防护。

Qt 运行依赖应由匹配版本的 `windeployqt` 收集，并在没有开发环境的 Windows 机器上验证。仍需检查 Rust 校验程序等额外组件与 Visual C++ 运行时；依赖收集不等于已经完成安装器与许可证合规。采用 Qt 官方部署工具的依据见 [Qt Windows 部署说明](https://doc.qt.io/qt-6/windows-deployment.html)。

## 商业保护工具

VMProtect 等商业软件保护工具需要用户拥有对应许可证、下载渠道和适用版本；本 Demo 不预装盗版、不伪造商业加壳结果。取得许可后，应先明确保护范围与性能预算，再对合法授权、异常处理、更新、崩溃诊断、代码签名和 Qt 动态库替换能力做回归。版本与许可类型可参考 [VMProtect 官方购买说明](https://www.vmpsoft.com/vmprotect/purchase)。

无论是否使用商业保护工具，授权私钥仍不得部署在客户端，客户端校验仍可能被补丁绕过。要提高实际授权安全性，应优先实施 [SECURITY.md](SECURITY.md) 中的在线激活、短期租约与服务端鉴权。
