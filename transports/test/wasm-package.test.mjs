// Offline tests for the browser (.wasm) extension packages. Pure Node (>= 20), no Go, no network:
//   node --test transports/test/wasm-package.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateManifest, KNOWN_CAPABILITIES } from '../tools/ntx.mjs';

const transports = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = (...a) => spawnSync(process.execPath, [path.join(transports, 'build-wasm.mjs'), ...a], { encoding: 'utf8' });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ntx-test-'));

// Minimal zip reader (central directory), enough for .ntx packages.
function unzip(buf) {
  const files = {}; let e = buf.length - 22;
  while (e >= 0 && buf.readUInt32LE(e) !== 0x06054b50) e--;
  assert.ok(e >= 0, 'no end-of-central-directory record');
  const n = buf.readUInt16LE(e + 10); let p = buf.readUInt32LE(e + 16);
  for (let i = 0; i < n; i++) {
    assert.equal(buf.readUInt32LE(p), 0x02014b50, 'bad central directory entry');
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), nl = buf.readUInt16LE(p + 28), xl = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), lo = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nl);
    const start = lo + 30 + buf.readUInt16LE(lo + 26) + buf.readUInt16LE(lo + 28), raw = buf.subarray(start, start + csize);
    files[name] = method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw);
    p += 46 + nl + xl + cl;
  }
  return files;
}

const outDir = tmp();
const r = build('--out', outDir);
const packages = fs.readdirSync(outDir).filter((f) => f.endsWith('.ntx')).sort();

test('build succeeds and writes at least one package + SHA256SUMS', () => {
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.ok(packages.length >= 1);
  const sums = fs.readFileSync(path.join(outDir, 'SHA256SUMS'), 'utf8').trim().split('\n');
  assert.equal(sums.length, packages.length);
});

for (const file of packages) {
  const z = unzip(fs.readFileSync(path.join(outDir, file)));
  const manifest = JSON.parse(z['manifest.json']?.toString() ?? 'null');

  test(`${file}: layout is exactly manifest.json + the .wasm entry`, () => {
    validateManifest(manifest, { wasm: true });
    assert.deepEqual(Object.keys(z).sort(), ['manifest.json', manifest.entry].sort());
    assert.equal(path.basename(file, '.ntx'), manifest.id);
  });

  test(`${file}: ABI-v1 policy (no network, message only, distinct from the native id)`, () => {
    // WASM ABI v1 has no sockets, fetch, filesystem or transfer ops, so a browser package
    // must not claim what it cannot do (the native package carries those).
    assert.deepEqual(manifest.permissions, [], 'browser package cannot hold network/storage permissions');
    assert.deepEqual(manifest.capabilities, ['message'], 'ABI v1 only implements message');
    assert.match(manifest.id, /-wasm$/);
    const ext = fs.readdirSync(transports, { withFileTypes: true }).filter((d) => d.isDirectory() && fs.existsSync(path.join(transports, d.name, 'wasm', 'manifest.json')))
      .find((d) => JSON.parse(fs.readFileSync(path.join(transports, d.name, 'wasm', 'manifest.json'), 'utf8')).id === manifest.id);
    assert.ok(ext, 'package has a source directory');
    const nativeManifest = path.join(transports, ext.name, 'manifest.json');
    if (fs.existsSync(nativeManifest)) assert.notEqual(JSON.parse(fs.readFileSync(nativeManifest, 'utf8')).id, manifest.id);
  });

  test(`${file}: module is sandboxed and works as a loopback queue`, async () => {
    const bytes = z[manifest.entry];
    assert.ok(WebAssembly.validate(bytes));
    const mod = await WebAssembly.compile(bytes);
    assert.deepEqual(WebAssembly.Module.imports(mod).map((i) => `${i.module}.${i.name}`).filter((i) => i !== 'ntx.log'), [], 'only ntx.log may be imported');
    const names = WebAssembly.Module.exports(mod).map((x) => x.name);
    for (const n of ['memory', 'ntx_init', 'ntx_caps', 'ntx_start', 'ntx_stop', 'ntx_status', 'ntx_send', 'ntx_attach', 'ntx_detach', 'ntx_poll']) assert.ok(names.includes(n), `missing ${n}`);

    const ex = (await WebAssembly.instantiate(mod, { ntx: { log() {} } })).exports;
    const mem = () => new Uint8Array(ex.memory.buffer);
    const put = (d) => { const p = ex.ntx_alloc(d.length) >>> 0; mem().set(d, p); return p; };
    const blob = (v) => { const u = BigInt.asUintN(64, v); return mem().slice(Number(u >> 32n), Number(u >> 32n) + Number(u & 0xffffffffn)); };
    assert.equal(ex.ntx_init(put(new Uint8Array(0)), 0), 0);
    const caps = new TextDecoder().decode(blob(ex.ntx_caps())).split(',');
    for (const c of caps) { assert.ok(KNOWN_CAPABILITIES.includes(c)); assert.ok(manifest.capabilities.includes(c), 'module claims a capability the manifest lacks'); }
    const mb = new Uint8Array(16).fill(1), rcp = new Uint8Array(32).fill(7), f1 = Uint8Array.from([3, 1, 2, 3]), f2 = Uint8Array.from([1, 9]);
    assert.equal(ex.ntx_send(put(f1), f1.length, put(rcp), 32), 1, 'send before start is refused');
    assert.equal(ex.ntx_start(), 0); assert.equal(ex.ntx_status(), 1);
    assert.equal(ex.ntx_attach(put(mb), put(new Uint8Array(32).fill(2)), 0, 0, 0, 0), 0);
    assert.equal(ex.ntx_send(put(f1), f1.length, put(rcp), 32), 0);
    assert.equal(ex.ntx_send(put(f2), f2.length, put(rcp), 32), 0);
    assert.deepEqual([...blob(ex.ntx_poll(32, put(mb), 1))], [0, 0, 0, 4, 3, 1, 2, 3, 0, 0, 0, 2, 1, 9], 'frames come back BE32-prefixed, in order');
    assert.equal(blob(ex.ntx_poll(32, put(mb), 1)).length, 0, 'poll drains');
    assert.equal(ex.ntx_detach(put(mb)), 0); assert.equal(ex.ntx_stop(), 0); assert.equal(ex.ntx_status(), 0);
  });
}

test('builds are reproducible (same sha256 twice)', () => {
  const a = tmp(), b = tmp();
  assert.equal(build('--out', a).status, 0); assert.equal(build('--out', b).status, 0);
  assert.equal(fs.readFileSync(path.join(a, 'SHA256SUMS'), 'utf8'), fs.readFileSync(path.join(b, 'SHA256SUMS'), 'utf8'));
});

test('--version stamps the manifest and bad versions are rejected', () => {
  const o = tmp(); assert.equal(build('--version', '9.8.7-rc.1', '--out', o).status, 0);
  const f = fs.readdirSync(o).find((x) => x.endsWith('.ntx'));
  assert.equal(JSON.parse(unzip(fs.readFileSync(path.join(o, f)))['manifest.json']).version, '9.8.7-rc.1');
  assert.notEqual(build('--version', 'v1', '--out', tmp()).status, 0);
  assert.notEqual(build('--version').status, 0);
});

test('an unknown extension name fails instead of silently building nothing', () => {
  assert.notEqual(build('--out', tmp(), 'does-not-exist').status, 0);
});
