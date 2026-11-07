import { test as base, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const python = process.env.SEALVERIFY_PYTHON || path.join(root, '.venv', 'Scripts', 'python.exe');
export { expect };
export const test = base.extend({
  readerURL: [async ({}, use) => {
    const server = spawn(python, ['-m', 'sealverify', 'view', '--no-browser'], {
      cwd: root, env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    });
    let url;
    try {
      url = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('阅读服务未启动')), 15_000);
        const fail = error => { clearTimeout(timer); reject(error); };
        server.once('error', fail); server.once('exit', code => fail(new Error(`阅读服务退出：${code}`)));
        server.stdout.on('data', data => {
          const match = data.toString().match(/http:\/\/127\.0\.0\.1:\d+\/[^\s]+/);
          if (match) { clearTimeout(timer); resolve(match[0]); }
        });
      });
      await use(url);
    } finally {
      if (url) await fetch(url + 'shutdown', { method: 'POST' }).catch(() => {});
      if (server.exitCode === null) server.kill();
    }
  }, { scope: 'worker' }],
});
