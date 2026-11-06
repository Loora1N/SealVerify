# 第三方阅读资源

项目自身的许可证尚未选定。以下声明适用于随阅读器分发的第三方部分，不代表其作者为本项目背书。

| 资源 | 固定版本/来源 | 授权与位置 |
| --- | --- | --- |
| OFDRW UI、engine、crypto | `@ofdrw/ofdrw-viewer-*` 0.1.7，来自 npm；[源码](https://github.com/ofdrw/ofdrw-viewer) | MIT，声明与实际打包的传递依赖见下方文件 |
| fflate 及其他传递依赖 | 具体版本与完整性哈希记录在 `frontend/package-lock.json` | 构建脚本根据实际 bundle 输入收集声明 |
| Noto Sans CJK SC Regular | [noto-cjk](https://github.com/notofonts/noto-cjk)，提交 `f8d157532fbfaeda587e826d4cd5b21a49186f7c` 的 `Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf` | SIL OFL 1.1，保留原始字体文件和授权 |

- [JavaScript 第三方声明](../src/sealverify/web/vendor/THIRD_PARTY_NOTICES.txt)
- [字体授权](../src/sealverify/web/fonts/OFL.txt)
- [前端依赖锁文件](../frontend/package-lock.json)

字体 SHA-256：`2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b`。字体未做子集裁剪或修改，随包附带以支持离线中文阅读；它不是 Windows 系统字体的复制。

部分 npm 包未附单独 LICENSE 文件：`dfa`、`fontkit` 的包元数据和 README 声明 MIT，记录原作者及 MIT 授权正文；`saxes` 的 ISC 声明取自其上游仓库。`brotli` 的包元数据声明 MIT，解码源码另保留 Google 2013 年 Apache-2.0 声明，故同时保留两类说明。补充文本保存在 `frontend/licenses/`，构建不会静默漏掉未知依赖的授权。

渲染引擎的取消检查补丁保存在 `frontend/build.mjs`，随宿主资源构建应用；具体原因见 [阅读器说明](ofd-reader.md)。第三方 crypto 为 UI 的传递依赖，当前不启用其验签或解密功能。
