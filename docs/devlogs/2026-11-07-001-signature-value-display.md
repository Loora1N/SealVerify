# 按算法展示完整签名值

## 基本信息

- 日期：2026-11-07（Asia/Shanghai）
- 同日编号：001
- 类型：功能、界面、测试、文档
- 状态：实现及本地验证完成，交付 PR #4 审查
- 任务来源：签名值不再显示 SHA-256 和截断预览，改为 SM2 的 r/s 与 RSA 的完整十六进制。

## 目标与范围

对电子签章、印章制章签名和可读证书的颁发者签名，按各对象自身的签名算法解码并完整展示。签章者、制章者和授权列表内证书使用同一解析入口，明确区分签名角色。本次是未合并的 M2b PR 的界面与解析补充，继续使用 `codex/signature-inspection` 和版本 0.3.0，不扩展到密码验签。

## 实际改动

| 文件或目录 | 变更说明 |
| --- | --- |
| `src/sealverify/inspection/asn1.py` | SM2 DER 两整数解码、RSA 完整字节、未知/坏编码提示和展示上限；新增证书颁发者签名 |
| `frontend/signatures.js`、`src/sealverify/web/reader.css`、`reader.js` | 分角色签名卡片、完整可选择十六进制及换行；移除卡片内摘要与截断预览，重建离线资源 |
| `examples/create_signed_demo.py` | 合成 SM2 INTEGER 正号补零和短分量；增加 `--rsa` 完整字节样例 |
| `tests/test_signature_values.py` | 11 项解析、算法分派、异常边界及基准兼容性测试 |
| `frontend/tests/signatures.spec.js`、`samples.local.js` | 合成样例与本地附件的完整值、角色及卡片内容检查 |
| `tools/check_local_samples.py` | 保留原基准比较，独立重新编码 SM2 并核对原件中的证书签名 |
| `README.md`、`docs/signature-inspection.md`、`docs/images/signature-value-sm2.png` | 使用方式、字段契约、编码依据与合成界面截图 |
| `docs/devlogs/README.md`、本篇日志 | 新任务记录与索引 |

## 关键决策

- SM2/SM3 OID 对应的签名字节按 DER `SEQUENCE { r INTEGER, s INTEGER }` 拆分；去除正号补零，再按 32 字节无符号大端值显示。负数、非最短编码、错误标签、截断、尾随内容及超长分量明确报错，不猜测 64 字节原始 r/s 格式。
- RSA 保留所有原始字节，不对看似 DER 的内容再次解码。证书按颁发者签名算法处理，不按证书主体公钥算法猜测。
- 证书、制章和电子签章签名分别命名，避免嵌套属性布局混淆签名归属。卡片不再显示摘要；整个证书等其他对象仍可查看原有数据摘要。
- JSON schema 1 保留旧摘要字段，新增 `decoded` 与 `certificate_signature`。旧基准清单未重写：只从兼容比较中投影新增字段，再用独立 ASN.1 类型和原件证书核对新增内容。定向测试证明修改 r/s 或证书签名将被新检查发现，原有页面字段仍受旧比较保护。
- 编码依据包括 GB/T 38540—2020 第 6.1、7.1 节、GmSSL 的 SM2 DER 编解码实现和 RFC 8017 第 8 节、附录 A.2.3/A.2.4；链接和边界见 [签章属性说明](../signature-inspection.md)。

## 验证记录

| 命令或检查方式 | 实际结果 |
| --- | --- |
| `.\.venv\Scripts\python.exe -m unittest discover -s tests` | Windows / Python 3.12.9 的 77 项测试通过 |
| `cd frontend` 后 `npm run build`、`npm test` | 离线资源构建成功，14 项实际 Chromium 公共回归通过 |
| `.\.venv\Scripts\python.exe tools/check_local_samples.py` | 两个本地包原件、既有属性和页面关联一致；完整 r/s 重新编码与原始签名一致，新增证书签名与原件一致 |
| `cd frontend` 后 `npm run test:local` | 两项实际 Chromium 回归通过，全页绘制、签章/证书属性、定位及完整签名卡片可用；无远程请求，原件不变 |
| 合成界面视觉检查 | SM2 r/s 和完整 256 字节 RSA 可见且换行，无摘要/截断预览；仅合成截图进入文档 |
| `.\.venv\Scripts\python.exe -m pip wheel . --no-deps --wheel-dir dist` | wheel 构建成功；20 个条目，其中 15 个包文件逐字节匹配当前源码/离线资源，无私有目录 |
| 远程 Python 3.9 / 3.12 与 Chromium | 由现有 Actions 对本次提交执行；结果以 [PR #4 Checks](https://github.com/Loora1N/SealVerify/pull/4/checks) 为准，不沿用旧提交结果 |

新增本地浏览器检查初次因 Chromium 响应缓存淘汰而无法读取响应体；改为由本机解析器独立生成内存预期，再逐字符核对界面，修正后两项通过。未改动业务原件、既有预期或忽略失败。

## 已知限制与未完成项

- 本次仅展示结构，不验证签名数学关系、r/s 有效范围、RSA 长度与密钥匹配、算法参数、证书链或信任状态；全部保持未验证。
- SM2 仅拆分已识别的 SM2/SM3 DER 编码；其他算法给出完整原始字节及未支持提示。单个签名超过 64 KiB 明确不展示，无部分预览。
- 本地样本原有日期和空注释提示保留。真实业务文件、清单及运行结果不公开，公共 CI 只使用合成数据。
- 本次本机未安装 wheel 运行；包文件已逐字节核对，安装后端到端验证由对应提交的 CI 执行。

## 后续事项

维护者通过 PR #4 验收与合并；密码验签按 M3 单独实施。

## 交付记录

- 本地提交主题：`feat: display SM2 components and complete RSA signatures`，日志同批提交。
- 远程仓库与分支：`Loora1N/SealVerify` 的 `codex/signature-inspection`。
- 上传状态：本篇随实现更新 [PR #4](https://github.com/Loora1N/SealVerify/pull/4)；实际上传结果与远程验证见该 PR 的最新提交及 Checks。
