# 制章者证书的离线检查

打开 OFD，在右侧签章面板展开 **选择 CA 和 CRL（可选）**，按角色选择材料，然后点击 **验证签章与制章者证书**。在 **M4：制章者证书检查** 中选择内嵌或外置印章，查看该印章制章者证书的结果。每个签章单独报告。界面显示本次验证时刻，来自本机时钟。

| 检查 | 通过的条件 | 其他结果举例 |
| --- | --- | --- |
| 有效期 | 验证时刻在证书的起止时间内，含两个端点 | 过期或尚未生效时为失败 |
| 制章签名密钥用法 | KeyUsage 含 digitalSignature 或 contentCommitment，且没有需复核的专用 EKU | 两个签名用途位均未设置时为失败。缺少 KeyUsage、专用 EKU 与业务的映射不明时为无法确定 |
| 证书路径 | OpenSSL 按本次时刻及 X.509 严格路径检查，验证证书签名及相关 CA 约束，并到达用户选定的信任锚 | 无对应锚、缺中间 CA 或算法配置无法确认时为无法确定。已确认的过期、签名错误或 CA 约束违反会报告失败 |
| 制章者证书吊销状态 | 已认证直接颁发者及 CRL，清单在验证时刻有效、覆盖该证书且未列出其序列号 | 经验证的清单已列出该证书时为失败。材料过期、签名错误、缺失或适用范围不明时为无法确定 |

四项检查独立记录。例如，证书已过期，仍可在颁发者能被独立认证时检查其吊销记录。无法读取制章者证书时，四项都说明跳过原因。OFD 未声明外置印章时，该资源显示不适用。

## 选择材料

- **信任锚**是用户明确选择的信任起点。**中间 CA** 仅用于构建路径。两类证书都需要声明 CA 身份。使用前请自行确认锚的来源。
- **CRL** 由制章者证书的直接颁发者签发。工具核对颁发者名称、密钥标识、cRLSign、清单签名和适用范围，以及 `thisUpdate ≤ 验证时刻 < nextUpdate`。同一颁发者提供多份不同清单时，结果保留为无法确定，提示用户核对。
- 每份文件接受一个 PEM 或 DER 对象。一轮最多 32 份，总计 4 MiB。单张 CA 证书最多 128 KiB，单份 CRL 最多 1 MiB、10,000 个条目。材料清单列出所选角色、序号、文件指纹及读取结果。
- 只使用本轮明确选择的材料。在浏览器中更换材料或 SM2 用户标识时，原验证结果清除。重新打开文件会清除材料选择。验证过程中均在本机处理。

## 用合成样例验收

```powershell
.\.venv\Scripts\python.exe examples/create_maker_demo.py local-data/maker-demo
.\.venv\Scripts\python.exe -m sealverify view local-data/maker-demo/maker.ofd
```

1. 直接点击验证。没有材料时，证书有效期与密钥用法仍会检查，路径和吊销状态显示“无法确定”。
2. 依次选择示例目录中的 `anchor.cer`、`intermediate.cer` 和 `current.crl`，重新验证。内嵌、外置印章的制章者证书四项均应通过。
3. 把 CRL 换成 `revoked.crl` 并重新验证。吊销状态应为“失败”，其他三项仍然通过。切换签章可检查第二个签章的明细。

命令行的三类材料参数均可重复使用。

```powershell
.\.venv\Scripts\python.exe -m sealverify verify local-data/maker-demo/maker.ofd --anchor local-data/maker-demo/anchor.cer --intermediate local-data/maker-demo/intermediate.cer --crl local-data/maker-demo/current.crl
```

JSON 中每个签章的 `maker_certificate_validation.embedded` 和 `.external` 含该资源的四项明细。顶层同名对象记录材料及阶段汇总。整份文件的结果见 `verification_summary.overall_status`。确认失败时为 `failed`，其余结果为 `incomplete`，因为签章者证书信任和时间证据仍待验证。这两种情况的 CLI 退出码均为 1。

## 标准和支持范围

电子印章验证中的制章者证书检查对应 GB/T 38540—2020 第 6.3 c) 项。密钥用法、路径和 CRL 的处理参考 RFC 5280 第 4.2.1.3、5 和 6 节。当前支持一组可离线复核的配置，业务证书策略与专用 EKU 映射仍需按应用要求确认。[GB/T 38540—2020](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=EBF1360C272E40E7A8B9B32ED0724AB1) · [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

路径算法由安装的 OpenSSL 后端决定。回归覆盖 RSA/SHA-256 证书链，以及 OpenSSL 4 环境中使用 `1234567812345678` 的 SM2/SM3 证书签名。SM2 CRL 采用该标识核验，OFD 面板的签章标识只影响 M3 运算。旧版 OpenSSL 的默认标识可能不同，无法验证的 SM2 路径显示“无法确定”。[OpenSSL 的 SM2 标识说明](https://docs.openssl.org/4.0/man7/EVP_PKEY-SM2/)

吊销检查针对制章者这张证书，仅覆盖可认证的直接完整 CRL。链上 CA 的吊销、增量或间接 CRL、限定分发点/原因、OCSP、联网获取材料、历史签章时刻和时间戳仍待实现。当前时刻的结果不能证明历史签章时刻可信。
