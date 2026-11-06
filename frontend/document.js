import { openZipVirtualContainer } from '@ofdrw/ofdrw-viewer-engine';
import { zip } from 'fflate';

export const MAX_FILE_BYTES = 256 * 1024 * 1024;
const NS = 'http://www.ofdspec.org/2016';

// 先通过引擎容器检查 ZIP 限额，再读取目录 XML。原始文件始终只读。
export async function inspectDocument(file) {
  if (!/\.ofd$/i.test(file.name)) throw new Error('请选择 .ofd 文件。');
  if (!file.size) throw new Error('文件为空，无法打开。');
  if (file.size > MAX_FILE_BYTES) throw new Error('文件超过 256 MiB 的阅读上限。');
  const container = await openZipVirtualContainer({ kind: 'blob', blob: file });
  try {
    if (container.encrypted) throw new Error('此文件已加密，当前阅读器暂不支持解密。');
    const root = new TextDecoder().decode(await container.read('OFD.xml'));
    if (/<!DOCTYPE|<!ENTITY/i.test(root)) throw new Error('OFD.xml 包含不支持的 DTD 或实体声明。');
    const xml = new DOMParser().parseFromString(root, 'application/xml');
    if (xml.querySelector('parsererror') || xml.documentElement.localName !== 'OFD') {
      throw new Error('OFD.xml 格式损坏，无法读取文档目录。');
    }
    const bodies = [...xml.documentElement.children].filter(n => n.localName === 'DocBody');
    if (!bodies.length) throw new Error('OFD.xml 没有可阅读的文档。');
    const documents = bodies.map((body, index) => {
      const title = body.getElementsByTagNameNS(NS, 'Title')[0]?.textContent?.trim();
      return { title: title || `文档 ${index + 1}` };
    });
    return { file, documents, xml };
  } finally { await container.close(); }
}

export async function documentSource(inspected, index) {
  if (!Number.isInteger(index) || index < 0 || index >= inspected.documents.length) {
    throw new Error('文档编号无效。');
  }
  if (inspected.documents.length === 1) return inspected.file;
  // UI 当前只展示包中首个 DocBody；仅在内存中生成所选文档的阅读副本。
  // 禁止导出此副本为 OFD，也不对副本做签章验证。
  const container = await openZipVirtualContainer({ kind: 'blob', blob: inspected.file }, {
    limits: { maxTotalUncompressedBytes: 128 * 1024 * 1024 },
  });
  try {
    const xml = inspected.xml.cloneNode(true);
    [...xml.documentElement.children].filter(n => n.localName === 'DocBody')
      .forEach((body, i) => { if (i !== index) body.remove(); });
    const entries = Object.create(null);
    for (const entry of container.list()) {
      if (entry.path === 'OFD.xml') continue;
      entries[entry.path] = await container.read(entry.path);
    }
    entries['OFD.xml'] = new TextEncoder().encode(new XMLSerializer().serializeToString(xml));
    return await new Promise((resolve, reject) => zip(entries, { level: 0 },
      (error, bytes) => error ? reject(error) : resolve(bytes)));
  } finally { await container.close(); }
}
