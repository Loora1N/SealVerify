# M3 密码验签、授权与原文杂凑

## 基本信息

- 日期：2026-11-09（Asia/Shanghai）
- 同日编号：002
- 类型：功能
- 状态：实现及本地验收完成，待 PR 审查
- 任务来源：完成开发路线 M3，在记录错误后继续全部独立检查。

## 目标与范围

此前可阅读 OFD、显示属性和两步格式诊断，但未执行密码运算。本次增加制章/签章数学验签、证书授权匹配、当前印章有效期、内外印章一致性及已支持 OFD 配置的原字节杂凑检查。保持阅读、定位和多签章诊断，正常 M3 结果仍明确完整验证未完成。

## 实际改动

| 文件或目录 | 变更说明 |
| --- | --- |
| `src/sealverify/crypto.py` | SM2/SM3 与 RSA PKCS #1 v1.5 后端、严格签名编码/公钥检查、明确算法映射 |
| `src/sealverify/verification.py` | 原始 DER 验签、授权、当前有效期、内外一致、Signature.xml 与 References、持续诊断与汇总 |
| `src/sealverify/cli.py`、`reader.py` | `verify` 命令、本机 HTTP 入口、SM2 标识设置，保留原属性接口 |
| `frontend/signatures.js`、`src/sealverify/web/` | 验证按钮、明细、能力边界、重试与迟到响应隔离；重新构建离线资源 |
| `examples/create_verified_demo.py`、`tests/fixtures/openssl-vectors.json` | 临时内存密钥产生的真实签名合成 OFD，以及独立 OpenSSL 公钥验证向量；不包含私钥 |
| `tests/test_verification.py`、`tests/test_reader.py`、`tests/test_cli.py` | 密码边界、篡改/缺失/多错/未知配置/异常/限额、服务和 CLI 验证 |
| `frontend/tests/`、`tools/check_local_verification.py` | 浏览器公开合成测试；本地 M3 固定预期回归，原属性基准保留 |
| `pyproject.toml` | 版本 0.6.0；添加 gmalg 与 cryptography 运行依赖 |
| `README.md`、`docs/m3-verification.md`、相关格式/阅读/属性说明、`docs/third-party.md` | 实际能力、操作、算法/保护范围、M4 边界、授权声明及合成截图 |

## 关键决策

- 依据 GB/T 38540—2020 6.1.5、6.3 b)/d)、7.1.5、7.3 b)/c)/g)，制章与签章分别使用原始 SES_SealInfo、TBS_Sign DER；授权按完整证书或其明确算法的摘要匹配，不以相同公钥代替。
- 支持 SM2/SM3、RSA PKCS #1 v1.5；PSS 缺少完整参数时无法确定，不猜测。SM2 用户标识默认 `1234567812345678`，可调整，一次运行共用一个标识。
- OFD 目前支持 propertyInfo 指向当前 Signature.xml 的包根绝对路径；杂凑原字节，再独立核对 References。未知厂商范围或转换不猜测通过；未引用内容不推断为受保护。
- 采用 gmalg 1.1.2、cryptography `>=45,<50`，保留底层实现边界并通过独立 OpenSSL 向量与交叉计算核验。
- 明确区分当前印章有效期与历史签章有效性。M4 证书链、吊销、证书用途/有效期及可信时间未完成，`overall_status` 不会因数学计算通过而成为 passed。
- 单项异常、缺失资源或错误不中断独立检查。未知配置与资源限额为无法确定，已省略的失败仍影响汇总。

## 验证记录

| 命令或检查方式 | 实际结果 |
| --- | --- |
| `.\.venv\Scripts\python.exe -m unittest discover -s tests -q` | 147 项通过；其中 25 项 M3 定向测试，覆盖双算法、独立向量、DER/公钥边界、授权、原字节变更、连续诊断、限额及未知配置 |
| `cd frontend; npm run build; npm test` | 构建完成，22 项 Chromium 合成场景通过；截图调整后再运行 M3 的 4 项测试，全部通过 |
| `tools/check_local_samples.py` | 两个本地原件、既有属性、完整签名展示及格式基准通过，未更改原清单 |
| `tools/check_local_verification.py` | 两个本地附件的 M3 逐项结果与独立登记预期一致；基准通过不等于各附件整体有效 |
| `cd frontend; npm run test:local` | 两个基准全部页面、定位、属性与 M3 界面回归通过，无外部请求，原件不变 |
| 独立 OpenSSL 交叉核验 | 对本地样本核验 9 个签名、21 次原字节摘要，另独立进行 3 次完整证书授权比较；预期与实现一致，业务结果不上传 |
| `python -m pip check`（项目虚拟环境） | 依赖一致；本机 Python 3.12.9、gmalg 1.1.2、cryptography 49.0.0 |
| `python -m sealverify --version`（项目虚拟环境） | `SealVerify 0.6.0` |
| `python -m pip wheel . --no-deps --wheel-dir dist`（项目虚拟环境） | wheel 构建成功；逐字节核对包内 18 个源码/静态资源，未混入本地材料 |
| 合成截图人工检查 | 阅读区域与 M3 失败明细可读，截图仅含合成内容 |

最终自检包括差异、文档链接与待提交文件隐私检查。远程 Windows Python 3.9/3.12、Chromium 与资源重建的结果以本 PR 当前提交的 Checks 为准，不以历史提交结果代替。

## 已知限制与未完成项

证书信任路径、CRL、证书有效期/用途、可信签章时间、时间戳签名与绑定及印章历史状态属于 M4，尚未实现。未知算法/参数、厂商保护范围、转换、版本和实现限额不能得出完整验证结论。RSA 数学支持不等于安全强度或业务政策符合。

SM2 一次运行采用同一用户标识，不支持不同签章/制章者分别设置标识。公开 OFD 合成样例的数学签名真实计算，但证书颁发者签名为占位数据；不可作为有效证书链样例。独立安装程序和报告导出仍待后续阶段。

## 后续事项

在 M4 中分别处理证书路径、信任锚、吊销材料与可信时间证据，继续保持单项失败后完整输出。其他 OFD 保护范围或密码算法参数应在取得明确配置及独立样例后扩展。

## 交付记录

- 本地提交：`feat: complete M3 signature and document verification`（与本日志同批提交）。
- 远程仓库与分支：`Loora1N/SealVerify`，`codex/m3-verification`。
- 上传状态：提交后推送本任务分支并创建 PR，最终上传与当前提交 CI 状态记录在 PR；维护者审查后决定合并。
