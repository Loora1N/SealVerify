import { test, expect } from '@playwright/test';
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const python = process.env.SEALVERIFY_PYTHON || path.join(root, '.venv', 'Scripts', 'python.exe');
const fixtures = path.join(root, 'local-data', 'browser-fixtures');
let server, url;
test.beforeAll(async () => {
  mkdirSync(fixtures, { recursive: true });
  for (const [name, flags] of [['multi', ['--multiple-documents']], ['broken', ['--broken-page']],
    ['embedded', ['--embedded-font', path.join(root, 'src/sealverify/web/fonts/NotoSansCJKsc-Regular.otf')]]]) {
    execFileSync(python, [path.join(root, 'examples/create_reading_demo.py'), path.join(fixtures, name + '.ofd'), ...flags]);
  }
  server = spawn(python, ['-m', 'sealverify', 'view', '--no-browser'], {
    cwd: root, env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
  });
  url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('阅读服务未启动')), 15_000);
    server.once('error', reject);
    server.once('exit', code => reject(new Error(`阅读服务退出：${code}`)));
    server.stdout.on('data', data => {
      const match = data.toString().match(/http:\/\/127\.0\.0\.1:\d+\/[^\s]+/);
      if (match) { clearTimeout(timer); resolve(match[0]); }
    });
  });
});
test.afterAll(async () => {
  if (url) await fetch(url + 'shutdown', { method: 'POST' }).catch(() => {});
  if (server && server.exitCode === null) server.kill();
});
test.beforeEach(async ({ page }) => {
  await page.goto(url);
  await page.waitForFunction(() => window.sealverifyReader);
});

async function openDemo(page) {
  await page.getByRole('button', { name: '阅读示例', exact: true }).click();
  await expect(page.locator('#status')).toContainText('共 4 页');
  await expect(page.locator('.ofd-page__canvas').first()).toBeVisible();
  await page.waitForFunction(() => window.sealverifyReader.getRenderStats().completed > 0);
}
async function pageNumber(page, number) {
  const input = page.getByRole('spinbutton', { name: '页码', exact: true });
  await input.fill(String(number)); await input.press('Enter');
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getPageNumber())).toBe(number);
}
async function pixel(page, pageIndex, xMm, yMm, widthMm) {
  return page.locator('.ofd-page').nth(pageIndex).locator('canvas').evaluate((canvas, p) => {
    const factor = canvas.width / p.widthMm;
    return [...canvas.getContext('2d').getImageData(Math.floor(p.xMm * factor), Math.floor(p.yMm * factor), 1, 1).data];
  }, { xMm, yMm, widthMm });
}

test('离线打开四页：中文、矢量、图片、注释与横向末页均实际绘制', async ({ page }) => {
  const remote = [], errors = [];
  page.on('request', request => { if (/^https?:/.test(request.url()) && !request.url().startsWith(new URL(url).origin)) remote.push(request.url()); });
  page.on('pageerror', error => errors.push(error.message));
  await openDemo(page);
  await expect(page.locator('.ofd-page').first()).toContainText('你好，OFD。');
  await expect.poll(() => pixel(page, 0, 20, 82, 210)).toEqual([23, 92, 99, 255]);
  await page.getByRole('button', { name: '下一页', exact: true }).click();
  await expect.poll(() => pixel(page, 1, 40, 100, 210)).toEqual([28, 130, 174, 255]);
  await expect.poll(() => pixel(page, 1, 160, 240, 210)).toEqual([190, 40, 50, 255]);
  await pageNumber(page, 4);
  await expect(page.locator('#status')).toHaveText('已打开 · 共 4 页');
  await expect(page.locator('.ofd-page').nth(3)).toContainText('已到达最后一页。');
  await expect.poll(() => pixel(page, 3, 20, 122, 297)).toEqual([23, 92, 99, 255]);
  await expect(page.locator('#diagnostics')).toBeHidden();
  expect(remote).toEqual([]); expect(errors).toEqual([]);
  await page.screenshot({ path: path.join(root, 'local-data', 'reader-last-page.png') });
});

test('缩略图、缩放、旋转、全文查找与大纲导航', async ({ page }) => {
  await openDemo(page);
  await page.getByRole('option', { name: '第 3 页，共 4 页', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getPageNumber())).toBe(3);
  await page.getByRole('combobox', { name: '缩放模式' }).selectOption('scale:1.5');
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getScale())).toBe(1.5);
  await page.getByRole('button', { name: '顺时针旋转 90°' }).click();
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getRotation())).toBe(90);
  await page.getByRole('button', { name: '查找', exact: true }).click();
  await page.getByLabel('在文档中查找', { exact: true }).fill('阅读测试');
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getFindState().total)).toBe(13);
  await page.getByRole('button', { name: '关闭查找', exact: true }).click();
  await page.getByRole('tab', { name: '大纲', exact: true }).click();
  await page.getByText('阅读终点', { exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getPageNumber())).toBe(4);
});

test('读取用户所选文件并在多个 DocBody 之间切换，原件不变', async ({ page }) => {
  const file = path.join(fixtures, 'multi.ofd');
  const original = readFileSync(file);
  await page.locator('#file').setInputFiles(file);
  await expect(page.locator('#status')).toContainText('共 4 页');
  await page.getByRole('combobox', { name: '包内文档' }).selectOption('1');
  await expect(page.locator('#status')).toContainText('共 1 页');
  await expect(page.locator('.ofd-page').first()).toContainText('第二份文档：包内文档切换成功');
  await page.getByRole('combobox', { name: '包内文档' }).selectOption('0');
  await expect(page.locator('#status')).toContainText('共 4 页');
  expect(readFileSync(file)).toEqual(original);
});

test('内嵌字体文档可读；关闭后释放内容且可重新打开', async ({ page }) => {
  await page.locator('#file').setInputFiles(path.join(fixtures, 'embedded.ofd'));
  await expect(page.locator('#status')).toContainText('共 4 页');
  await expect(page.locator('.ofd-page').first()).toContainText('你好，OFD。');
  await page.getByRole('button', { name: '关闭文档', exact: true }).click();
  await expect(page.locator('#empty')).toBeVisible();
  expect(await page.evaluate(() => window.sealverifyReader.getPageCount())).toBe(0);
  await openDemo(page);
});

test('损坏输入给出提示，原文档可继续阅读，损坏单页不阻断其他页', async ({ page }) => {
  await openDemo(page);
  await page.locator('#file').setInputFiles({ name: '损坏.ofd', mimeType: 'application/ofd', buffer: Buffer.from('not zip') });
  await expect(page.locator('#status')).toContainText('打开失败');
  expect(await page.evaluate(() => window.sealverifyReader.getPageCount())).toBe(4);
  await page.locator('#file').setInputFiles(path.join(fixtures, 'broken.ofd'));
  await expect(page.locator('#status')).toContainText('共 4 页');
  await pageNumber(page, 2);
  await expect(page.locator('#diagnostics')).toBeVisible();
  await pageNumber(page, 4);
  await expect(page.locator('.ofd-page').nth(3)).toContainText('已到达最后一页。');
});

test('外部来源查询参数不被加载，阅读不产生验签通过状态', async ({ page }) => {
  let external = false;
  await page.route('https://example.com/**', route => { external = true; return route.abort(); });
  await page.goto(url + '?file=https://example.com/secret.ofd');
  await page.waitForFunction(() => window.sealverifyReader);
  await openDemo(page);
  expect(external).toBe(false);
  expect(await page.evaluate(() => window.sealverifyReader.isFeatureEnabled('verification'))).toBe(false);
  await expect(page.getByText('本机阅读 · 签章尚未验证')).toBeVisible();
});

test('拖放 OFD 并退出阅读器', async ({ page }) => {
  const bytes = readFileSync(path.join(root, 'src/sealverify/web/demo.ofd'));
  const transfer = await page.evaluateHandle(data => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([new Uint8Array(data)], '拖放示例.ofd'));
    return transfer;
  }, [...bytes]);
  await page.dispatchEvent('body', 'drop', { dataTransfer: transfer });
  await expect(page.locator('#status')).toContainText('共 4 页');
  await expect(page.locator('#document-name')).toHaveText('拖放示例.ofd');
  await page.getByRole('button', { name: '退出阅读器', exact: true }).click();
  await expect(page.getByText('阅读器已退出，可以关闭此标签页。')).toBeVisible();
});
