# 公开的 demo 测试身份

这个目录中的签发身份已刻意公开，只用于克隆仓库后构建、签发和验证演示：

| 文件 | 用途 |
| --- | --- |
| `demo.private.json` | 现有 demo 身份的加密 Ed25519 私钥 |
| `demo.public.hex` | 与该私钥对应的验签公钥 |
| `demo.passphrase.txt` | 已公开的明文测试口令，用来解密该私钥 |

虽然私钥文件仍采用 Argon2id + ChaCha20-Poly1305 加密格式，配套口令也已公开，**任何人都可以解密并签出这套身份的测试卡密**。不能将这套身份用于正式授权、收费服务或真实用户的签发者身份认证。正式使用须另外生成独立私钥，以其公钥重新构建客户端。

在项目根目录运行：

```bash
python3 scripts/prepare-demo.py
```

它只在 `config/trusted-public-key.hex` 缺失时复制这里的公钥，已有相同公钥可以继续，已有不同公钥时拒绝覆盖。脚本不会修改现有 Windows `.local` 身份或上传 DPAPI 文件；DPAPI 文件仍只在本机使用。

按[项目 README](../../README.md) 准备 Mac 的 Rust、Qt 与策略 object 并完成本机构建后，使用本次应用路径签发和测试：

```bash
APP='<本次 CardGuard.app 的绝对路径>'
python3 scripts/issue-demo.py --app "$APP"
python3 scripts/test-macos.py --app "$APP" --token-file .local/demo-card.txt \
  --report build/macos-local-test.json
```

`issue-demo.py` 默认使用这里的私钥与口令，将卡密写入 `.local/demo-card.txt`，不向终端输出卡密；可通过 `--issuer`、`--subject`、`--valid-hours` 和 `--output` 调整测试。`--device-id` 可替代 `--app` 为其他机器签卡，二者互斥。`--app` 模式会先回验新卡；若应用内置公钥不匹配，会拒绝写卡并提示重建。把文件内容粘贴到界面即可校验。

本地 Mac ad-hoc 代码签名不需要 Apple Developer ID 私钥。Apple 代码签名与这里的 Ed25519 测试卡签发没有共用身份或密钥。CI 默认使用这里的公钥，仓库变量可覆盖最终客户端的验签公钥；覆盖后须使用匹配的签发身份。

这些公开文件属于源码测试材料，不应复制到客户端发行包；正式私钥及口令仍不得提交。安全边界见 [SECURITY.md](../../docs/SECURITY.md)。
