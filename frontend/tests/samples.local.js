import { test, expect, root, python } from './support.js';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
// 显式运行时必须具备本地清单；不以 skip 掩盖缺失。CI 只运行 *.spec.js 合成样例。
const manifest = JSON.parse(readFileSync(path.join(root, 'local-data/local-samples.json'), 'utf8'));
test.beforeAll(() => {
  execFileSync(python, ['tools/check_local_samples.py'], { cwd: root });
});
for (const [number, sample] of manifest.samples.entries()) {
  test(`本地基准 ${number + 1}：全页可读、签章属性与定位`, async ({ page, readerURL }) => {
    const remote = [], errors = [];
    page.on('request', request => { if (/^https?:/.test(request.url()) && !request.url().startsWith(new URL(readerURL).origin)) remote.push(request.url()); });
    page.on('pageerror', error => errors.push(error.message));
    const file = path.join(root, sample.path), original = readFileSync(file);
    // 单独读取预期，避免 Chromium 的响应缓存淘汰导致拿不到 /inspect 的响应体。
    const parsed = JSON.parse(execFileSync(python, ['-c',
      'import json, sys; from pathlib import Path; from sealverify.inspection import inspect_ofd; print(json.dumps(inspect_ofd(Path(sys.argv[1]).read_bytes())))', file],
    { cwd: root, encoding: 'utf8' }));
    await page.goto(readerURL); await page.waitForFunction(() => window.sealverifyReader);
    await page.locator('#file').setInputFiles(file);
    const expected = sample.expected.documents[0];
    await expect(page.locator('#status')).toContainText(`共 ${expected.pages.length} 页`);
    await expect(page.locator('#signature-status')).toHaveText(`本份文档发现 ${expected.signatures.length} 个签章 · 均未验证`);
    for (let index = 0; index < expected.pages.length; index++) {
      await page.evaluate(n => window.sealverifyReader.goToPage(n, { smooth: false }), index + 1);
      await expect.poll(() => page.locator('.ofd-page').nth(index).locator('canvas').evaluate(canvas => {
        const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
        let ink = 0;
        for (let i = 0; i < pixels.length; i += 16) if (pixels[i + 3] > 100 && pixels[i] + pixels[i + 1] + pixels[i + 2] < 650) ink++;
        return ink;
      })).toBeGreaterThan(100);
    }
    for (const [index, sig] of expected.signatures.entries()) {
      await page.getByRole('combobox', { name: '选择签章' }).selectOption(String(index));
      // 断言值来自私有清单，不写入公开源码或截图。
      await expect(page.locator('#signature-content')).toContainText(sig.signed_value.signer_certificate.subject);
      const stamp = sig.placements[0];
      await page.getByRole('button', { name: `定位第 ${stamp.page_number} 页 · 标记 1` }).click();
      await expect(page.locator('.signature-highlight')).toBeVisible();
      await expect.poll(() => page.evaluate(() => window.sealverifyReader.getPageNumber())).toBe(stamp.page_number);
      const position = await page.locator('.signature-highlight').evaluate(node => ({ left: parseFloat(node.style.left), top: parseFloat(node.style.top) }));
      expect(position.left).toBeCloseTo(stamp.boundary_mm[0] / stamp.page_box_mm[2] * 100, 2);
      expect(position.top).toBeCloseTo(stamp.boundary_mm[1] / stamp.page_box_mm[3] * 100, 2);
      await page.getByText('电子签章属性与签章者证书', { exact: true }).click();
      await page.getByText('内嵌电子印章与制章者证书', { exact: true }).click();
      const decoded = parsed.documents[0].signatures[index].signed_value;
      for (const [kind, expectedValue] of [['document', decoded.signature], ['seal', decoded.seal.signature]]) {
        const card = page.locator(`[data-signature-kind="${kind}"]`).first();
        for (const component of ['r_hex', 's_hex']) {
          const displayed = await card.locator(`[data-component="${component}"]`).textContent();
          // 敏感值只在内存比较；失败输出仅显示布尔值，不打印证书或签名内容。
          expect(displayed === expectedValue.decoded[component]).toBe(true);
          expect(displayed.length).toBe(64);
        }
        await expect(card).not.toContainText('SHA-256');
        await expect(card).not.toContainText('预览');
      }
      const certificateCards = await page.locator('[data-signature-kind="certificate"]').all();
      expect(certificateCards.length).toBeGreaterThan(0);
      for (const card of certificateCards) {
        expect(await card.locator('[data-component="r_hex"]').count()).toBe(1);
        await expect(card).not.toContainText('SHA-256');
      }
    }
    expect(remote).toEqual([]); expect(errors).toEqual([]);
    await expect(page.locator('#messages')).not.toContainText('渲染已取消');
    expect(readFileSync(file)).toEqual(original);
  });
}
