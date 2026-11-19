# M4 签章者证书检查

## 基本信息

- 日期为 2026-11-19（Asia/Shanghai），同日编号 002。
- 类型为功能开发，任务来源为 M4 证书与时间证据里程碑。
- 本项已完成本地验收，提交独立 PR 审查。

## 目标与范围

从每个版本 4 电子签章取得签章者证书，检查本次验证时刻的有效期、密钥用途、路径与吊销状态。在同一份文档中分别展示每位签章者及制章者的结果，按 GB/T 38540—2020 第 7.3 e) 项区分当前证书失败和需要转入 f) 的历史判断。

## 实际改动

| 文件或目录 | 变更说明 |
| --- | --- |
| `src/sealverify/verification.py`、`maker_certificate.py` | 从原始 SES_Signature 读取签章者 cert，复用离线证书验证，输出逐签章、阶段和文件汇总 |
| `src/sealverify/cli.py`、`frontend/signatures.js`、`src/sealverify/web/` | 更新验证入口，阅读器按签章展示当前四项检查、撤销时间和历史复核提示 |
| `examples/create_verified_demo.py`、`create_maker_demo.py` | 生成由两个不同证书签名的合成文档，分别配制章者、签章者的吊销清单与正常清单 |
| `tests/`、`frontend/tests/` | 增加正常、损坏、撤销、过期、用途错误、不同 CA、多签章选择与真实附件本地回归 |
| `README.md`、`docs/`、`pyproject.toml` | 新增使用和验收说明，更新阅读入口与项目版本 0.8.0 |

## 关键决策

按照第 7.3 e) 第 3 项，签章者的叶证书过期或已吊销时保留当前失败明细，记录需要转入 f) 复核的检查标识。只有这些失败时，文件汇总仍为未完成。独立确认的用途错误或颁发者签名错误仍会使文件汇总失败。读取不到原始证书时，报告给出跳过原因，继续检查证书可读的其他资源。[检查说明与标准依据](../m4-signer-certificate.md)

## 验证记录

| 命令或检查方式 | 实际结果 |
| --- | --- |
| 在项目虚拟环境运行 `python -m unittest discover -s tests` | 163 项通过，涵盖证书来源、路径、不同颁发者、吊销、时间复核分支、坏证书和多个签章 |
| 前端运行 `npm run build`、`npm test` | 离线资源构建成功，24 项 Chromium 合成测试通过 |
| 前端运行 `npm run test:local` | 两个指定附件完成本地基准回归，检查原件指纹、阅读渲染、M3 预期及逐签章证书结果 |
| CLI 依次选择三种合成 CRL | 正常清单下两位签章者均通过。仅吊销第一位签章者时，文件汇总为未完成。吊销制章者时仍保留原有失败汇总 |
| `python -m pip check`、`python -m pip wheel . --no-deps -w dist` | 安装依赖一致，0.8.0 wheel 构建成功 |

## 已知限制与未完成项

当前只验证可认证的直接完整 CRL，沿用现有路径和算法支持范围。基准附件未随附信任锚和适用 CRL，具备材料时的成功及吊销情况通过合成文档验证。

## 后续事项

继续 M4 的签章时刻证书与印章状态、可信时间戳以及链上 CA 吊销状态。

## 交付记录

- 提交主题为 `feat: verify each document signer's certificate`。
- 远程分支为 `Loora1N/SealVerify:codex/m4-signer-certificate`，目标为 `main`。本次增量基于 PR #8 的证书验证模块。
- [查看任务分支的 PR 和检查状态](https://github.com/Loora1N/SealVerify/pulls?q=is%3Apr+head%3Acodex%2Fm4-signer-certificate)
