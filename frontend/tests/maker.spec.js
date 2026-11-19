import { test, expect, root, python } from './support.js';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const directory = path.join(root, 'local-data', 'browser-fixtures', 'maker');
const file = name => path.join(directory, name);

test.beforeAll(() => {
  execFileSync(python, ['examples/create_maker_demo.py', directory], { cwd: root });
});

test('离线材料按角色生效，更换清单后重新检查，打开文件清空材料', async ({ page, readerURL }) => {
  await page.goto(readerURL);
  await page.waitForFunction(() => window.sealverifyReader);
  await page.locator('#file').setInputFiles(file('maker.ofd'));
  const verify = page.getByRole('button', { name: '验证签章与制章者证书' });
  const results = page.locator('[data-stage="maker-certificate"]');
  const signature = page.getByRole('combobox', { name: '选择签章' });
  async function checkRole(role, pathStatus, crlStatus) {
    const list = results.locator(`[data-seal-role="${role}"]`);
    for (const [id, status] of Object.entries({
      validity: 'passed', key_usage: 'passed', path: pathStatus, revocation: crlStatus,
    })) {
      await expect(list.locator(`[data-check-id="${id}"]`)).toHaveAttribute('data-check-status', status);
    }
  }
  await verify.click();
  await checkRole('embedded', 'indeterminate', 'indeterminate');
  await page.getByText('选择 CA 和 CRL（可选）', { exact: true }).click();
  await page.locator('#material-anchor').setInputFiles(file('anchor.cer'));
  await page.locator('#material-intermediate').setInputFiles(file('intermediate.cer'));
  await page.locator('#material-crl').setInputFiles(file('current.crl'));
  await expect(results).toHaveCount(0);
  await verify.click();
  await checkRole('embedded', 'passed', 'passed');
  await checkRole('external', 'passed', 'passed');
  await expect(page.locator('.verification-controls')).toContainText('整体验证尚未完成');
  await signature.selectOption('1');
  await page.locator('#material-crl').setInputFiles(file('revoked.crl'));
  await expect(results).toHaveCount(0);
  await verify.click();
  await expect(signature).toHaveValue('1');
  await expect(page.locator('.verification-controls')).toContainText('发现失败项');
  await checkRole('embedded', 'passed', 'failed');
  await expect(page.locator('[data-format-role="m3"]')).toHaveAttribute('data-checked-status', 'passed');
  await signature.selectOption('0');
  await checkRole('external', 'passed', 'failed');
  await page.locator('#file').setInputFiles(file('maker.ofd'));
  await expect(verify).toBeEnabled();
  await expect(results).toHaveCount(0);
  for (const role of ['anchor', 'intermediate', 'crl']) {
    await expect(page.locator('#material-' + role)).toHaveValue('');
  }
});
