# OFD 签章属性解析与页面定位

## 基本信息

- 日期：2026-11-06（Asia/Shanghai）
- 同日编号：003
- 类型：功能、界面、测试、文档
- 状态：本地功能与回归完成，正在准备 PR 与远程检查
- 任务来源：继续完成 M2b，并以本地 OFD 样本建立持续回归。

## 目标与范围

在现有 OFD 阅读器中识别并分别展示签章、内嵌印章、外置印章、证书、引用和时间戳属性，关联到对应页面；损坏内容不能阻断其他独立内容。本阶段读取结构，不执行密码验签、信任路径、吊销或可信时间检查。

任务从已合并的 PR #3 对应 `e42b912` 创建 `codex/signature-inspection`；版本升为 0.3.0。

## 实际改动

| 文件或目录 | 变更说明 |
| --- | --- |
| `src/sealverify/inspection/` | 有界只读 ZIP/XML、签章/页面清单、版本 4 ASN.1、X.509/CMS 元数据、逐字段问题及 JSON 契约 |
| `src/sealverify/cli.py`、`reader.py` | `inspect` 命令、本机接收字节的解析接口、长度/类型/来源边界，不保存业务文件 |
| `frontend/signatures.js`、`reader.js`、`src/sealverify/web/` | 签章选择、预览、属性/证书/引用、问题位置、高亮定位，原始包与多文档阅读副本分开处理 |
| `frontend/build.mjs` | 修复固定版本渲染引擎把资源准备取消误报为字体/图片损坏；保留实际错误 |
| `examples/create_signed_demo.py`、`tests/test_inspection.py`、`tests/test_reader.py` | 合成版本 4 印章/签名/证书/时间戳，多文档和损坏输入，CLI 与服务测试 |
| `frontend/tests/`、`playwright*.config.js`、`package.json` | 属性与页面定位端到端测试、独立的本地样本回归入口 |
| `tools/check_local_samples.py` | 对本地清单核对原件哈希、已登记属性、页面关联；缺失或变化直接失败 |
| `pyproject.toml` | 固定 asn1crypto 1.5.1、defusedxml 0.7.1；保持 Python >=3.9 |
| `README.md`、`docs/` | 使用方式、结构/状态说明、标准对应、隐私流向、限制、第三方依赖及开发日志 |

## 关键决策

- 直接核对 GB/T 38540—2020 第 6.1、7.1 节的版本 4 ASN.1；OFD XML 元素与可选性另对照 OFDRW 上游实现。依据和未实现项见 [签章属性说明](../signature-inspection.md)。
- `parse_status` 与 `verification` 分开。始终标记 `not_performed`，不将引用目标存在、声明时间、证书可读或图像可见当成有效性结论。
- 内嵌和外置印章分别展示；不比较一致性，不解释厂商定义的原文属性为已确认的完整保护范围。
- 默认页面关联来自 `StampAnnot.PageRef` 和文档页清单；不依赖大纲标题推测页码。重复页面 ID 或坏矩形禁用定位。
- 不解压到磁盘；禁用 XML 实体、越界路径和重名 ZIP 文件的猜测读取；对资源、结构层级和清单数量设置限额并报告。
- 本地基准清单与业务原件保留在忽略目录。公共源码和 CI 只含合成数据，截图只使用合成内容。

## 验证记录

| 命令或检查方式 | 实际结果 |
| --- | --- |
| `.\.venv\Scripts\python.exe -m unittest discover -s tests` | Windows / Python 3.12.9 的 66 项测试通过，含页面/模板/公共物理边界回退 |
| `npm run build`、`npm test` | 离线资源构建成功；实际 Chromium 的 12 项测试通过；额外连续切换回归重复 3 次通过 |
| `tools/check_local_samples.py` | 两个本地包的原件 SHA-256、完整预期属性及页面关联一致；分别含 1 与 2 个签章，每包 2 页 |
| `npm run test:local` | 两项实际 Chromium 回归通过，全部页面有绘制、签章选择/证书/页面定位可用、无远程请求、原件不变 |
| 确定种子的 500 次合成 DER 字节变异 | 首轮发现缺少 TSTInfo 时的未捕获异常；修复并加入定向测试后，500 次均无未捕获异常 |
| 视觉检查 | 核对合成界面与本地样本的页面、印章预览和高亮；实际内容截图仅本地保留 |
| `pip check` | Python 依赖一致性通过 |
| wheel 安装、包内容与源码 | 20 个条目，源码和离线资源逐字节匹配，无私有文件；在根目录 .venv 安装后执行 Python/浏览器/本地基准回归 |
| Python 3.9 语法及本地文档链接 | 15 个 Python 文件通过语法检查；30 个文档链接目标存在。实际 Python 3.9 运行以 CI 为准 |
| 远程 CI | 尚未执行，待推送任务分支后检查 |

## 已知限制与未完成项

- 没有密码验签、原文杂凑重算、印章授权匹配、证书路径/吊销或可信时间验证。
- 只支持版本 4 与已说明的 ASN.1 标记形式；旧版、其他容器/扩展和不受支持的图像给出提示。不是完整格式符合性认证。
- 本地样本自身包含非规范元数据日期和空注释外观，阅读器保留提示；正文和签章仍可阅读。未修改原件或把这些提示屏蔽。
- 页面高亮使用外观边界，不代表保护范围；印章 SVG 等活动图像不内联；浏览器及物理打印限制延续 M2a。
- 本地业务基准不在公共 CI 上运行；缺少本地清单时显式本地回归失败，公共合成测试仍可独立执行。

## 后续事项

维护者通过 PR 验收签章选择、属性与页面定位；M3 接入电子印章、电子签章及原文杂凑的实际验证，M4 接入信任材料和可信时间。

## 交付记录

- 本地提交：待提交，计划主题 `feat: inspect OFD signature attributes and locate stamps`。
- 远程仓库与分支：`Loora1N/SealVerify` / `codex/signature-inspection`。
- 上传状态：准备提交 PR，未推送 main，不自动合并。
