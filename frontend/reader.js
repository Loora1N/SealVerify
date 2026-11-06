import { OFDViewer } from '@ofdrw/ofdrw-viewer-ui';
import { inspectDocument, documentSource } from './document.js';

// 禁止第三方组件根据 ?file= 读取远程来源；文件只能由本页明确选取。
history.replaceState(null, '', location.pathname);
const status = document.querySelector('#status');
const fileInput = document.querySelector('#file');
const docSelect = document.querySelector('#documents');
const diagnostics = document.querySelector('#diagnostics');
const messages = document.querySelector('#messages');
const controls = [...document.querySelectorAll('[data-open]')];
let inspected = null;
let busy = false;
let warningKeys = new Set();

function message(text, error = false) {
  status.textContent = text;
  status.classList.toggle('error', error);
}
function diagnose(issue) {
  const text = `${issue.code || '阅读提示'}${issue.pageNumber ? ` · 第 ${issue.pageNumber} 页` : ''}：${issue.message || issue}`;
  if (warningKeys.has(text) || warningKeys.size >= 100) return;
  warningKeys.add(text);
  const li = document.createElement('li');
  li.textContent = text;
  messages.append(li);
  diagnostics.hidden = false;
  document.querySelector('#diagnostic-count').textContent = String(warningKeys.size);
}
const viewer = new OFDViewer({
  container: '#viewer', theme: 'light', locale: 'zh-CN', initialScale: 'page-fit',
  sidebar: 'thumbnails', updateHash: false,
  features: { verification: false, signatures: false, export: false, attachments: false },
  crypto: { enabled: false, autoVerify: false },
  layerPanel: { enabled: false },
  maxCanvasPixels: 32_000_000, pageCachePixelBudget: 96_000_000,
  fonts: {
    default: [{ url: new URL('fonts/NotoSansCJKsc-Regular.otf', location.href).href }],
  },
  debug: { console: false }, onWarning: diagnose,
  onError: error => { diagnose(error); message('部分内容未能显示，请查看阅读提示。', true); },
});
// 未指定初始文件时，组件的 ready 会以 OFD_INVALID_OPTION 拒绝；外壳仍可 open。
await viewer.ready.catch(error => {
  if (error.code !== 'OFD_INVALID_OPTION') throw error;
});
viewer.on('documentopen', () => {
  document.querySelector('#empty').hidden = true;
  document.querySelector('#close').disabled = false;
  message(`已打开 · 共 ${viewer.getPageCount()} 页`);
});
// 对外仅提供阅读器调试状态，供自动化回归验证实际渲染；不包含文件字节。
window.sealverifyReader = viewer;

function setBusy(value) {
  busy = value;
  controls.forEach(button => { button.disabled = value; });
  docSelect.disabled = value;
  document.querySelector('#close').disabled = value || !inspected;
}
function resetMessages() {
  warningKeys = new Set(); messages.replaceChildren(); diagnostics.hidden = true;
}
async function showDocument(index) {
  resetMessages();
  const source = await documentSource(inspected, index);
  document.querySelector('#document-name').textContent = inspected.file.name;
  await viewer.open(source);
  if (!viewer.getPageCount()) throw new Error('所选文档没有可阅读的页面。');
  message(`已打开 · 共 ${viewer.getPageCount()} 页`);
}
async function openFile(file) {
  if (!file || busy) return;
  setBusy(true); message('正在读取文档…');
  try {
    // 无效输入不会先关闭原文档；通过容器预检后再切换。
    const next = await inspectDocument(file);
    inspected = next;
    docSelect.replaceChildren(...next.documents.map((doc, index) => {
      const option = document.createElement('option'); option.value = index;
      option.textContent = `${index + 1}. ${doc.title}`; return option;
    }));
    document.querySelector('#document-picker').hidden = next.documents.length < 2;
    await showDocument(0);
  } catch (error) {
    message(`打开失败：${error.message || error}`, true);
    diagnose(error);
  } finally { setBusy(false); fileInput.value = ''; }
}
document.querySelector('#open').addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => openFile(fileInput.files[0]));
document.querySelector('#demo').addEventListener('click', async () => {
  try {
    const response = await fetch('demo.ofd');
    if (!response.ok) throw new Error('无法读取示例，请重新启动阅读器。');
    await openFile(new File([await response.blob()], '阅读示例.ofd'));
  } catch (error) { message(error.message, true); }
});
docSelect.addEventListener('change', async () => {
  if (busy || !inspected) return;
  setBusy(true); message('正在切换文档…');
  try { await showDocument(Number(docSelect.value)); }
  catch (error) { message(`打开失败：${error.message}`, true); diagnose(error); }
  finally { setBusy(false); }
});
document.addEventListener('dragover', event => { event.preventDefault(); });
document.addEventListener('drop', event => {
  event.preventDefault();
  if (event.dataTransfer.files.length !== 1) return message('请一次打开一个 OFD 文件。', true);
  openFile(event.dataTransfer.files[0]);
});
document.querySelector('#close').addEventListener('click', async () => {
  if (busy) return;
  await viewer.close(); inspected = null; resetMessages();
  document.querySelector('#document-name').textContent = 'OFD 阅读器';
  document.querySelector('#document-picker').hidden = true;
  document.querySelector('#empty').hidden = false;
  document.querySelector('#close').disabled = true;
  message('已关闭文档');
});
document.querySelector('#exit').addEventListener('click', async () => {
  viewer.destroy(); inspected = null;
  try { await fetch('shutdown', { method: 'POST' }); } catch { /* 服务可能已退出。 */ }
  document.body.replaceChildren();
  const notice = document.createElement('p');
  notice.className = 'exit-message'; notice.textContent = '阅读器已退出，可以关闭此标签页。';
  document.body.append(notice);
});
try {
  const response = await fetch('session.json');
  if (!response.ok) throw new Error('阅读服务已关闭，请重新启动。');
  const session = await response.json();
  if (session.hasDocument) {
    const documentResponse = await fetch('document.ofd');
    if (!documentResponse.ok) throw new Error('无法读取启动时指定的文档。');
    await openFile(new File([await documentResponse.blob()], session.name));
  }
} catch (error) { message(error.message, true); }
