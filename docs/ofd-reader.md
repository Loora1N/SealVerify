# OFD 阅读器

## 打开和阅读

首次按 README 安装后，Windows 双击根目录 `打开OFD阅读器.cmd`。也可执行：

```powershell
.\.venv\Scripts\python.exe -m sealverify view
.\.venv\Scripts\python.exe -m sealverify view "C:\文档\示例.ofd"
.\.venv\Scripts\python.exe -m sealverify view --demo
```

- 点击“打开 OFD”或把一个 OFD 拖入页面。使用缩略图、上一页/下一页或页码框导航，也可连续滚动阅读。
- 工具栏支持适合页面、适合宽度、缩放、旋转、全文查找、文字选择和打印；扫描图片没有可查找文字时不会自动 OCR。
- “大纲”展示文件自身的大纲信息。一个 OFD 包包含多个文档时，用上方“包内文档”分别打开，每份文档的全部页面都可阅读。
- “签章信息”展示当前文档的签章、印章、证书和引用；选择签章后可定位到页面区域。操作与限制见 [签章属性说明](signature-inspection.md)。
- 内置四页示例包含中文、模板页、曲线、图片、透明图形、注释、纵向和横向页面；全部内容人工合成。
- “阅读提示”保留缺失资源、解析异常、无法绘制的内容及限额提示。页面错误后可以继续打开其他独立页面；不要把带提示的页面视为原件的完全复现。
- 使用“关闭文档”清除当前阅读内容；“退出阅读器”结束本地服务，再关闭标签页。仅关闭标签页不会结束服务。

默认自动选择空闲端口并打开浏览器。使用 `--no-browser` 可只打印地址，`--port 8765` 可指定本机端口。浏览器推荐当前 Chrome 或 Edge。

## 阅读与验证的界限

阅读器展示文档内容，不产生密码验签结论。签章图像可见也不能证明签章有效。第三方组件的验证面板、自动验签、签章详情和附件导出均关闭；项目自身的面板使用 Python 解析原始包，并可通过“执行 M3 验证”进行 [验签、授权及原字节杂凑检查](m3-verification.md)。完整信任与时间证据验证仍未完成。

按 OFD 版式渲染正文、模板、图片、矢量图和注释。兼容性依赖 OFDRW 0.1.7 的实现，不声称已经完成所有标准元素与厂商扩展的符合性测试。

- 加密 OFD 当前会拒绝打开，暂不提供口令或证书解密。
- 原文未嵌入字体时使用附带的 Noto Sans CJK SC，中文可读但字形可能不同；未覆盖的字符仍会提示。未请求读取用户全部本机字体。
- 视频、特殊厂商扩展、罕见图像编码及复杂字形仍需更多样例确认。本地业务基准用于离线回归，公共 CI 仅使用合成样例。
- 文件大小上限 256 MiB；引擎默认最多 20,000 个条目、单条目 64 MiB、累计解压 512 MiB、压缩比 200。多文档包切换需要在内存生成阅读副本，累计解压限制为 128 MiB。
- 单页画布限制 32 百万像素、已渲染画布预算 96 百万像素；高倍率超限时降低清晰度并提示，远离视野的页面按需释放。
- 多文档切换只改变内存阅读副本的入口，原始文件不修改。为避免误把副本当作签名原件，当前关闭组件的文件/图片导出入口。
- 打印使用浏览器与系统打印流程，实际纸张、边距和驱动由用户选择；本次不对物理打印机做验收。

## 本地数据流

Python 仅绑定 `127.0.0.1`，提供固定允许列表中的页面资源和启动参数明确指定的一个文件。每次启动生成随机访问路径，并检查 Host/Origin。另提供接收文件字节的本机 `inspect` 解析接口，不提供目录浏览、任意路径读取或文件保存接口。

界面选择的文件由浏览器读取，并将原始字节通过回环连接交给 Python 解析签章；启动参数指定的文件由 Python 原样读取，通过回环连接交给浏览器。无远程上传、CDN、在线字体或业务运行日志，页面使用 CSP 限制外部连接。文件与渲染状态保留在当前进程/浏览器内存；浏览器或操作系统自身的历史和内存管理不由本工具控制。

## 开发、重建和测试

Python 环境始终使用仓库根目录 `.venv`。普通用户不需要 Node.js；修改前端资源时使用 Node.js 24 和锁文件：

```powershell
cd frontend
npm ci --ignore-scripts
npm run build
npx playwright install chromium
npm test
cd ..
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`frontend/reader.js`、`document.js` 和 `signatures.js` 为宿主源码；`build.mjs` 将固定版本的运行依赖打包为 `src/sealverify/web/reader.js`，同时生成样式和第三方声明。打包后的静态资源提交到 Git 并进入 wheel，避免普通安装依赖 Node.js 或联网下载渲染器。CI 检查前端重建无差异，并使用安装后的 Python 包运行浏览器测试。

可以重新生成合成示例：

```powershell
.\.venv\Scripts\python.exe examples/create_reading_demo.py src/sealverify/web/demo.ofd
.\.venv\Scripts\python.exe examples/create_reading_demo.py local-data/multi.ofd --multiple-documents
```

浏览器测试使用真实 Chromium，检查画布颜色、中文文字层、四页与横向页面、缩放旋转、查找、大纲、多文档、内嵌字体、错误恢复与外部请求拦截；截图与临时样例保留在忽略目录。Python 测试检查服务生命周期、访问边界、原件字节、输入限制及原有结果模型。

## 渲染引擎集成依据

- [OFDRW 阅读器接口](https://github.com/ofdrw/ofdrw-viewer/blob/main/packages/ofdrw-viewer-ui/skills/API.md)：来源、功能开关、字体、导航与事件。
- [OFDRW 引擎接口](https://github.com/ofdrw/ofdrw-viewer/blob/main/packages/ofdrw-viewer-engine/skills/API.md)：容器、资源限额及页面渲染。
- [GB/T 33190—2016 标准信息](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=3AF6682D939116B6F5EED53D01A9DB5D)：本次核对格式标准号和现行状态，不新增密码标准条款映射。

固定版本的引擎在页面任务取消后，可能先把模板加载取消报告成“模板加载失败”，再处理取消。构建脚本在模板结果处理前补一次取消检查；没有屏蔽正常加载失败。补丁仅适用于 0.1.7，构建时校验匹配位置，升级引擎必须复核。浏览器回归同时检查正常模板无误报及损坏页仍有提示。

签章面板伸缩和快速切换文件也可能取消正在加载的资源。M2b 在注释、字体批量加载、普通图片和印章解码四个边界继续传播 `OFD_ABORTED` / `OFD_CLOSED`，避免把取消误报为资源损坏；正常解码失败仍显示阅读提示。构建会检查补丁唯一匹配。文件中的非规范日期或空注释仍保留对应提示，不因为页面可读而隐藏。
