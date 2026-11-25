import { test, expect, root, python } from './support.js';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
const fixture = name => path.join(root, 'local-data/browser-fixtures', name + '.ofd');

test.beforeAll(() => {
  for (const [name, flags] of [['verified-sm2', []], ['verified-rsa', ['--algorithm', 'rsa', '--digest-list']],
    ['verified-tampered', ['--tampered']]]) {
    execFileSync(python, ['examples/create_verified_demo.py', fixture(name), ...flags], { cwd: root });
  }
});
test.beforeEach(async ({ page, readerURL }) => {
  await page.goto(readerURL); await page.waitForFunction(() => window.sealverifyReader);
});

test('SM2 与 RSA 真签名、授权及杂凑执行，整体保持未完成', async ({ page }) => {
  for (const name of ['verified-sm2', 'verified-rsa']) {
    const original = readFileSync(fixture(name));
    await page.locator('#file').setInputFiles(fixture(name));
    await expect(page.locator('#verify-m3')).toBeEnabled();
    await page.getByRole('combobox', { name: '选择签章' }).selectOption('1');
    await page.locator('#verify-m3').click();
    await expect(page.locator('.verification-controls')).toContainText('M3 检查结束');
    const result = page.locator('[data-format-role="m3"]');
    await expect(result).toHaveAttribute('data-checked-status', 'passed');
    await expect(result).toHaveAttribute('data-format-status', 'incomplete');
    await expect(page.getByRole('combobox', { name: '选择签章' })).toHaveValue('1');
    await expect(result).toContainText('证书信任、吊销和可信时间尚未完成');
    await result.getByText('查看通过与不适用项目', { exact: true }).click();
    for (const key of ['signature_value', 'seal/embedded/signature_value', 'seal/external/signature_value',
      'authorization', 'document_digest', 'references/binding']) {
      await expect(result.locator(`[data-check-id="${key}"]`)).toHaveAttribute('data-check-status', 'passed');
    }
    await page.getByRole('button', { name: '定位第 4 页 · 标记 1' }).click();
    await expect(page.locator('.signature-highlight')).toHaveAttribute('data-page-number', '4');
    expect(readFileSync(fixture(name)).equals(original)).toBe(true);
  }
});

test('内容篡改失败后仍验签并继续其他引用、后续签章和阅读', async ({ page }) => {
  await page.locator('#file').setInputFiles(fixture('verified-tampered'));
  await page.locator('#verify-m3').click();
  const result = page.locator('[data-format-role="m3"]');
  await expect(result).toHaveAttribute('data-checked-status', 'failed');
  await expect(result.locator('[data-check-status="failed"]')).toHaveCount(1);
  await expect(result.locator('[data-check-status="failed"]')).toContainText('杂凑与 CheckValue 不一致');
  await expect(result.locator('[data-check-id="signature_value"]')).toHaveAttribute('data-check-status', 'passed');
  await page.getByText('第一步：电子签章数据格式验证', { exact: true }).click();
  await page.getByText('第二步：电子印章数据格式验证', { exact: true }).click();
  await page.getByText('M3：密码验签、授权与原文杂凑', { exact: true }).evaluate(node => node.parentElement.scrollIntoView({ block: 'start' }));
  await page.screenshot({ path: path.join(root, 'local-data/m3-tampered.png') });
  await page.getByRole('combobox', { name: '选择签章' }).selectOption('1');
  await expect(result).toHaveAttribute('data-checked-status', 'failed');
  await expect(result.locator('[data-check-id="document_digest"]')).toHaveAttribute('data-check-status', 'passed');
  await page.getByRole('button', { name: '定位第 4 页 · 标记 1' }).click();
  await expect(page.locator('.signature-highlight')).toBeVisible();
});

test('SM2 用户标识明确参与运算，错误后可修正重试', async ({ page }) => {
  await page.locator('#file').setInputFiles(fixture('verified-sm2'));
  await page.getByLabel('SM2 用户标识', { exact: true }).fill('wrong');
  await page.locator('#verify-m3').click();
  const result = page.locator('[data-format-role="m3"]');
  await expect(result.locator('[data-check-id="signature_value"]')).toHaveAttribute('data-check-status', 'failed');
  await expect(result.locator('[data-check-id="document_digest"]')).toHaveAttribute('data-check-status', 'passed');
  await page.getByLabel('SM2 用户标识', { exact: true }).fill('1234567812345678');
  await page.locator('#verify-m3').click();
  await expect(result).toHaveAttribute('data-checked-status', 'passed');
});

test('验证服务失败仍可阅读，旧文件的迟到结果不会覆盖新文件', async ({ page }) => {
  await page.locator('#file').setInputFiles(fixture('verified-sm2'));
  await page.route('**/verify', route => route.fulfill({ status: 500, body: 'synthetic failure' }));
  await page.locator('#verify-m3').click();
  await expect(page.locator('.verification-controls')).toContainText('可继续阅读并重试');
  await expect(page.locator('[data-format-role="m3"]')).toHaveCount(0);
  await page.unroute('**/verify');
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/verify', async route => { await pending; await route.fulfill({ json: { documents: [], issues: [] } }); });
  await page.locator('#verify-m3').click();
  await expect(page.locator('.verification-controls')).toContainText('正在执行 M3');
  await page.locator('#file').setInputFiles(fixture('verified-rsa'));
  await expect(page.locator('#verify-m3')).toBeEnabled();
  release();
  await expect(page.locator('#signature-status')).toContainText('2 个签章');
  await expect(page.locator('[data-format-role="m3"]')).toHaveCount(0);
});
