# 签章者证书检查

选择一个签章，点击 **验证签章与证书**，展开 **M4：签章者证书检查**。此处使用该签章 `SignedValue` 中的 `SES_Signature.cert` 原始证书。每个签章独立报告证书有效期、签名密钥用途、至选定信任锚的路径和证书吊销状态。

阅读器和 `sealverify verify` 使用同一组离线信任锚、中间 CA 与 CRL。两类证书由不同 CA 颁发时，请分别提供对应的颁发者材料。一份清单只对可核验的直接颁发者生效。材料格式、大小及支持的算法与制章者检查一致。[离线材料和算法范围](m4-maker-certificate.md)

## 如何判断结果

| 当前检查结果 | 在签章报告中的含义 |
| --- | --- |
| 四项通过 | 该证书在本次验证时刻通过已支持的检查。文件仍需历史时间、链上 CA 吊销等证据 |
| 缺少 CA 或可用 CRL | 对应项显示“无法确定”，有效期、用途和其他签章继续检查 |
| 确认路径签名错误或明确禁止签名用途 | 记录失败，文件汇总为失败。仍保留其他独立检查 |
| 签章者证书当前已过期或已吊销 | 标出当前失败项。路径若仅因该叶证书过期而失败，也进入历史复核。已核验的吊销条目显示撤销时间。仅有这类失败时，文件汇总为未完成 |
| 原始签章者证书缺失或损坏 | 四项均给出跳过原因，继续检查制章者证书和其他签章 |

GB/T 38540—2020 第 7.3 e) 项要求检查签章者证书。当前过期或已吊销时，e) 第 3 项转入 f) 判断签章时刻的状态。此版本先记录需要复核的项目。阅读器取本机验证时间；文件声明的签章时间尚无可信时间证明。[GB/T 38540—2020](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=EBF1360C272E40E7A8B9B32ED0724AB1) · [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

## 用两个签章者验收

```powershell
.\.venv\Scripts\python.exe examples/create_maker_demo.py local-data/signer-demo
.\.venv\Scripts\python.exe -m sealverify view local-data/signer-demo/maker.ofd
```

1. 选择 `anchor.cer`、`intermediate.cer` 和 `current.crl` 后验证。分别查看两个签章，签章者和制章者的证书检查均应通过。
2. 把清单换成 `signer-revoked.crl`，重新验证。第一个签章者的吊销项失败，标记为需复核签章时刻。第二个签章者和制章者的检查仍通过。
3. 换成 `revoked.crl` 后重新验证。这份清单列出的是制章者证书，两位签章者的吊销检查仍通过。

```powershell
.\.venv\Scripts\python.exe -m sealverify verify local-data/signer-demo/maker.ofd --anchor local-data/signer-demo/anchor.cer --intermediate local-data/signer-demo/intermediate.cer --crl local-data/signer-demo/signer-revoked.crl
```

每个签章的 `signer_certificate_validation.checks` 包含结果与字段位置。该对象的 `checked_status` 表示当前证书状态，`signing_time_review_checks` 列出需要按签章时刻复核的检查，`definitive_failure` 表示是否另有已确认、影响文件汇总的签章者证书失败项。顶层同名对象汇总各签章的当前结果，整份文件的结论见 `verification_summary.overall_status`。
