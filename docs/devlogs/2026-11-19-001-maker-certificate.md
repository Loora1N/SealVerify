# M4 首项：制章者证书离线验证

## 基本信息

- 日期 2026-11-19（Asia/Shanghai），同日编号 001
- 类型为功能开发。制章者证书检查已通过本地验收，进入 PR 审查。
- 任务来源为 M4 证书与时间证据里程碑。

## 目标与范围

对版本 4 OFD 签章中的内嵌印章和外置印章分别检查制章者证书。缺少材料、某项失败或证书不可读时，仍保留其他资源和签章的结果。对应 GB/T 38540—2020 第 6.3 c) 项。

## 实际改动

| 文件或目录 | 变更说明 |
| --- | --- |
| `src/sealverify/maker_certificate.py`、`verification.py` | 读取各资源的原始制章者证书，报告有效期、密钥用途、证书路径、直接完整 CRL 和整份文件汇总 |
| `src/sealverify/cli.py`、`reader.py`、`frontend/signatures.js`、`src/sealverify/web/` | 命令行和阅读器按角色接收离线材料，材料与 OFD 随同一次本机验证请求处理，更换输入时清除旧结果 |
| `examples/create_maker_demo.py`、`examples/create_verified_demo.py` | 生成带真实数学签名的合成文档、CA 链及两份可替换的 CRL |
| `tests/`、`frontend/tests/` | 覆盖有无材料、过期、错误用途、清单签名、范围、明确吊销、多签章切换与重新打开文件 |
| `pyproject.toml`、`README.md`、`docs/` | 版本升至 0.7.0，增加路径验证依赖、使用说明及标准边界 |

## 关键决策

信任锚由用户明确指定，中间 CA 只参与建链。证书有效期与吊销情况使用同一验证时刻。清单必须能关联到已认证的直接颁发者，且签名、权限、范围与更新时刻均可核验。结果按证书、签章和整份文件分层，制章者四项通过时仍保留整体验证的待办项。[检查规则与复现步骤](../m4-maker-certificate.md)

## 验证记录

| 命令或检查方式 | 实际结果 |
| --- | --- |
| 项目虚拟环境中运行 `python -m unittest discover -s tests` | 156 项通过。覆盖 RSA 证书链、SM2/SM3 签名的证书和 CRL、已吊销与无法确定等状态 |
| 前端目录中运行 `npm run build`、`npm test` | 离线资源成功构建，23 项 Chromium 合成回归通过 |
| 前端目录中运行 `npm run test:local` | 两个指定 OFD 基准通过，含原件指纹、逐页渲染、签章定位、既有 M3 预期与无材料时的制章者诊断 |
| CLI 验证合成文档 | 无材料、有效 CRL、吊销 CRL 的制章者阶段依次为 incomplete、passed、failed，文件汇总依次为 incomplete、incomplete、failed |
| `python -m pip check`、wheel 构建和内容核对 | 依赖一致。wheel 包含证书验证模块及离线阅读资源 |

## 已知限制与未完成项

本次吊销结果针对制章者这张证书，支持直接完整 CRL。多份不同的同颁发者清单、增量、间接和受限范围等配置需要复核。SM2 证书链受安装的 OpenSSL 后端和签名标识影响。两个业务附件缺少配套信任锚与 CRL，有材料时的正反例通过合成样例验证。

## 后续事项

继续 M4 的签章者证书、链上 CA 吊销、历史签章时间与时间戳验证。

## 交付记录

- 提交主题为 `feat: verify maker certificates with offline CA and CRL materials`。
- 任务分支为 `Loora1N/SealVerify:codex/m4-maker-certificate`，目标分支为 `main`。该分支复用 M3 PR #7 的验证入口。
- [查看任务分支的远程 PR 和检查状态](https://github.com/Loora1N/SealVerify/pulls?q=is%3Apr+head%3Acodex%2Fm4-maker-certificate)
