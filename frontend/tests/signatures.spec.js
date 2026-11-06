import { test, expect, root, python } from './support.js';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
const fixture = name => path.join(root, 'local-data/browser-fixtures', name + '.ofd');
test.beforeAll(() => {
  for (const [name, flags] of [['signed', []], ['signed-broken', ['--broken']], ['signed-multi', ['--multiple-documents']]]) {
    execFileSync(python, ['examples/create_signed_demo.py', fixture(name), ...flags], { cwd: root });
  }
});
test.beforeEach(async ({ page, readerURL }) => {
  await page.goto(readerURL); await page.waitForFunction(() => window.sealverifyReader);
});

test('多签章属性、证书、时间戳、引用与旋转后的高亮定位', async ({ page, readerURL }) => {
  const remote = [], errors = [];
  page.on('request', request => { if (/^https?:/.test(request.url()) && !request.url().startsWith(new URL(readerURL).origin)) remote.push(request.url()); });
  page.on('pageerror', error => errors.push(error.message));
  const original = readFileSync(fixture('signed'));
  await page.locator('#file').setInputFiles(fixture('signed'));
  await expect(page.locator('#signature-status')).toHaveText('本份文档发现 2 个签章 · 均未验证');
  await expect(page.locator('#signature-content')).toContainText('Synthetic signer 1');
  await page.getByRole('combobox', { name: '选择签章' }).selectOption('1');
  await expect(page.locator('#signature-content')).toContainText('Synthetic signer 2');
  await expect(page.locator('#signature-content')).toContainText('2026-01-01T00:00:00+00:00');
  await page.getByRole('button', { name: '定位第 4 页 · 标记 1' }).click();
  const highlight = page.locator('.signature-highlight');
  await expect(highlight).toBeVisible();
  await expect(highlight).toHaveAttribute('data-page-number', '4');
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getPageNumber())).toBe(4);
  const initial = await highlight.boundingBox();
  await page.getByRole('button', { name: '顺时针旋转 90°' }).click();
  await expect.poll(() => page.evaluate(() => window.sealverifyReader.getRotation())).toBe(90);
  await expect.poll(async () => {
    const rect = await highlight.boundingBox(); return Math.abs(rect.width / rect.height - 25 / 40);
  }).toBeLessThan(0.01);
  expect(initial.width / initial.height).toBeCloseTo(40 / 25, 1);
  await page.getByText('内嵌电子印章与制章者证书', { exact: true }).click();
  await expect(page.getByAltText('电子印章图像（未验证）').first()).toBeVisible();
  await page.getByText('文件引用清单', { exact: true }).click();
  await expect(page.locator('#signature-content')).toContainText('目标存在 · 未验证');
  await page.screenshot({ path: path.join(root, 'local-data/signature-panel.png') });
  expect(remote).toEqual([]); expect(errors).toEqual([]);
  await expect(page.locator('#messages')).not.toContainText('渲染已取消');
  expect(readFileSync(fixture('signed'))).toEqual(original);
});

test('坏签章继续显示外置印章与其他签章，关闭后清除属性', async ({ page }) => {
  await page.locator('#file').setInputFiles(fixture('signed-broken'));
  await expect(page.locator('#signature-status')).toContainText('解析不完整');
  await expect(page.locator('#signature-content')).toContainText('此签章的解析问题');
  await expect(page.locator('#signature-content')).toContainText('OFD 外置电子印章');
  await page.getByRole('combobox', { name: '选择签章' }).selectOption('1');
  await expect(page.locator('#signature-content')).toContainText('结构解析：已读取');
  await page.getByRole('button', { name: '定位第 4 页 · 标记 1' }).click();
  await expect(page.locator('.ofd-page').nth(3)).toContainText('已到达最后一页。');
  await page.getByRole('button', { name: '关闭文档', exact: true }).click();
  await expect(page.locator('#signature-panel')).toBeHidden();
  await expect(page.locator('#signature-content')).toBeEmpty();
  await expect(page.locator('.signature-highlight')).toHaveCount(0);
});

test('切换 DocBody 使用原始包的签章及页面映射', async ({ page }) => {
  await page.locator('#file').setInputFiles(fixture('signed-multi'));
  await expect(page.locator('#signature-status')).toContainText('2 个签章');
  await page.getByRole('combobox', { name: '包内文档' }).selectOption('1');
  await expect(page.locator('#signature-status')).toContainText('1 个签章');
  await page.getByRole('button', { name: '定位第 1 页 · 标记 1' }).click();
  await expect(page.locator('#signature-content')).toContainText('页面 ID 900');
  await expect(page.locator('.ofd-page').first()).toContainText('第二份文档：包内文档切换成功');
  await page.getByRole('combobox', { name: '包内文档' }).selectOption('0');
  await expect(page.locator('#signature-status')).toContainText('2 个签章');
  await expect(page.locator('.signature-highlight')).toHaveCount(0);
});

test('本机解析服务失败时仍可阅读，不误报无签章', async ({ page }) => {
  await page.route('**/inspect', route => route.fulfill({ status: 500, body: 'test failure' }));
  await page.locator('#file').setInputFiles(fixture('signed'));
  await expect(page.locator('#signature-status')).toContainText('签章解析失败');
  await expect(page.locator('#status')).toContainText('共 4 页');
  await expect(page.locator('.ofd-page').first()).toContainText('你好，OFD。');
});

test('签章面板伸缩和连续切换文件不误报渲染取消', async ({ page }) => {
  for (let round = 0; round < 3; round++) {
    await page.locator('#file').setInputFiles(fixture(round % 2 ? 'signed-multi' : 'signed'));
    await expect(page.locator('#signature-status')).toContainText('2 个签章');
    await page.getByRole('button', { name: '签章信息', exact: true }).click();
    await page.evaluate(() => {
      window.sealverifyReader.goToPage(4, { smooth: false });
      window.sealverifyReader.setScale(1.5);
      window.sealverifyReader.goToPage(1, { smooth: false });
    });
    await page.getByRole('button', { name: '签章信息', exact: true }).click();
  }
  await page.getByText('正在打开文档…', { exact: true }).waitFor({ state: 'hidden' });
  await expect(page.locator('#messages')).not.toContainText('渲染已取消');
  await expect(page.locator('#messages')).not.toContainText('字体批量加载失败');
});
