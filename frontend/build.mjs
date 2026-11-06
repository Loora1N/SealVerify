import { build } from 'esbuild';
import { readFile, writeFile, copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.chdir(path.dirname(fileURLToPath(import.meta.url)));
const output = '../src/sealverify/web';
await mkdir(`${output}/vendor`, { recursive: true });
const result = await build({
  entryPoints: ['reader.js'], outfile: `${output}/reader.js`, bundle: true,
  minify: true, format: 'esm', platform: 'browser', target: ['chrome110', 'edge110'],
  legalComments: 'inline', metafile: true,
  plugins: [{ name: 'cancelled-template-diagnostics', setup(build) {
    build.onLoad({ filter: /ofdrw-viewer-engine[\\/]dist[\\/]index\.js$/ }, async args => {
      let contents = await readFile(args.path, 'utf8');
      const marker = '  templateResults.forEach((result, index) => {';
      if (contents.split(marker).length !== 2) throw new Error('上游模板准备逻辑已改变，请复核取消处理补丁。');
      contents = contents.replace(marker, '  throwIfAborted2();\n' + marker);
      return { contents, loader: 'js' };
    });
  }}],
});
await copyFile('node_modules/@ofdrw/ofdrw-viewer-ui/dist/style.css', `${output}/vendor/viewer.css`);
const packages = new Set(Object.keys(result.metafile.inputs).filter(p => p.startsWith('node_modules/'))
  .map(p => p.split('/').slice(0, p.split('/')[1].startsWith('@') ? 3 : 2).join('/')));
const notices = [];
for (const dir of [...packages].sort()) {
  const pkg = JSON.parse(await readFile(`${dir}/package.json`, 'utf8'));
  let license;
  for (const name of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENSE-MIT', 'LICENCE_MIT', 'license']) {
    try { license = await readFile(`${dir}/${name}`, 'utf8'); break; } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }
  if (!license && pkg.name === 'brotli') license = await readFile('licenses/brotli.txt', 'utf8') + '\n' + await readFile('licenses/MIT.txt', 'utf8');
  if (!license && pkg.name === 'saxes') license = await readFile('licenses/saxes.txt', 'utf8');
  if (!license && ['dfa', 'fontkit'].includes(pkg.name)) {
    license = `Author (package.json): ${pkg.author}\nUpstream README license: MIT.\n`
      + await readFile('licenses/MIT.txt', 'utf8');
  }
  if (!license) throw new Error(`缺少许可证：${pkg.name}`);
  notices.push(`${pkg.name}@${pkg.version} (${pkg.license})\n${license.trim()}`);
}
await writeFile(`${output}/vendor/THIRD_PARTY_NOTICES.txt`, notices.join('\n\n' + '='.repeat(72) + '\n\n') + '\n');
console.log(`已生成离线阅读资源，保留 ${packages.size} 个运行依赖的许可证。`);
