#!/usr/bin/env node
// Build the browser (WebAssembly) package of every extension under transports/
// into transports/dist/*.ntx — no Go, TinyGo, wat2wasm or network needed.
//
// Discovery (no registry to maintain): every directory next to this file that
// has a wasm/manifest.json is a browser extension.
//
//   <ext>/wasm/manifest.json   browser package manifest (id must differ from the native one)
//   <ext>/wasm/build.mjs       node build.mjs <outDir>  -> must write <outDir>/<manifest.entry>
//   <ext>/wasm/verify.json     optional { "loopback": true } extra conformance checks
//
// Every package is validated with NexTalk's own manifest rules and ABI-v1-verified
// before it is written. Output is reproducible (fixed timestamps), so the sha256
// NexTalk pins at install is stable; dist/SHA256SUMS lists every pin.
//
// The native (process-model) packages are unchanged and still built by package.sh /
// package.ps1 / the release workflow. Only the extension is built for the browser —
// the relay servers themselves never run there.
//
//   node build-wasm.mjs                      # every browser extension
//   node build-wasm.mjs nextalk-relay        # only the named extension(s)
//   node build-wasm.mjs --version 1.4.0      # stamp manifest.version (release builds)
//   node build-wasm.mjs --out /tmp/x         # output directory (default: ./dist)
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { writeNtx, validateManifest } from './tools/ntx.mjs';
import { verifyWasm } from './tools/verify-wasm.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); if (i < 0) return null; const v = args[i + 1]; if (!v || v.startsWith('--')) { console.error(`${name} needs a value`); process.exit(2); } return v; };
const version = opt('--version'), outOpt = opt('--out');
const dist = path.resolve(outOpt || path.join(root, 'dist'));
const skipIdx = new Set(); for (const f of ['--version', '--out']) { const i = args.indexOf(f); if (i >= 0) { skipIdx.add(i); skipIdx.add(i + 1); } }
const only = args.filter((a, i) => !a.startsWith('--') && !skipIdx.has(i));
if (version !== null && !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) { console.error(`--version must look like 1.2.3 or 1.2.3-rc.1, got ${JSON.stringify(version)}`); process.exit(2); }

const readJSON = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const exts = fs.readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !['dist', 'node_modules', 'tools', 'test'].includes(d.name) && !d.name.startsWith('.'))
  .map((d) => d.name).filter((n) => fs.existsSync(path.join(root, n, 'wasm', 'manifest.json')))
  .filter((n) => only.length === 0 || only.includes(n)).sort();
if (!exts.length) { console.error('no browser extensions found' + (only.length ? ` matching ${only.join(', ')}` : '')); process.exit(1); }

fs.rmSync(dist, { recursive: true, force: true }); fs.mkdirSync(dist, { recursive: true });
const sums = []; let failed = 0;
const fail = (m) => { failed++; console.error('FAIL ' + m); };

for (const name of exts) {
  const wdir = path.join(root, name, 'wasm');
  console.log(`\n== ${name} (browser)`);
  try {
    const raw = readJSON(path.join(wdir, 'manifest.json'));
    const manifest = validateManifest(version ? { ...raw, version } : raw, { wasm: true });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ntx-'));
    try {
      const entryPath = path.join(tmp, manifest.entry);
      if (fs.existsSync(path.join(wdir, 'build.mjs'))) {
        const r = spawnSync(process.execPath, [path.join(wdir, 'build.mjs'), tmp], { stdio: 'inherit', cwd: wdir });
        if (r.status !== 0) throw new Error('wasm/build.mjs failed');
      } else if (fs.existsSync(path.join(wdir, manifest.entry))) fs.copyFileSync(path.join(wdir, manifest.entry), entryPath);
      if (!fs.existsSync(entryPath)) throw new Error(`wasm/build.mjs must write ${manifest.entry} into its output dir`);
      const bytes = fs.readFileSync(entryPath);
      const extra = fs.existsSync(path.join(wdir, 'verify.json')) ? readJSON(path.join(wdir, 'verify.json')) : {};
      const fails = await verifyWasm(bytes, { manifestCaps: manifest.capabilities, loopback: !!extra.loopback });
      if (fails.length) throw new Error('ABI v1 verification:\n  - ' + fails.join('\n  - '));
      const res = writeNtx(dist, manifest, bytes, { wasm: true });
      sums.push(`${res.hash}  ${path.basename(res.file)}`);
      console.log(`ok   ${path.relative(process.cwd(), res.file) || res.file}  v${manifest.version}  sha256 ${res.hash.slice(0, 16)}…  (${bytes.length} B wasm)`);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  } catch (e) { fail(`${name}: ${e.message}`); }
}
fs.writeFileSync(path.join(dist, 'SHA256SUMS'), sums.sort().join('\n') + '\n');
console.log(`\n${sums.length} package(s) in ${dist} ${failed ? `— ${failed} FAILED` : '— all ok'}`);
process.exit(failed ? 1 : 0);
