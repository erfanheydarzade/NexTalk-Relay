// Builds this extension's browser module with NO toolchain (no TinyGo, wat2wasm or Go):
// the ABI v1 queue module is assembled by ../../tools/wasmasm.mjs.
//   node build.mjs <outDir>      (transports/build-wasm.mjs calls it this way)
//
// What it is: a process-wide FIFO — send() appends, poll() drains, whatever the
// recipient or mailbox. It runs entirely inside the tab and never contacts a
// Router or shard: WASM transport ABI v1 gives a module linear memory plus an
// optional ntx.log import and nothing else (no sockets, no fetch). The native
// package of this extension (manifest.json next to ../) is what talks to the relay.
import fs from 'node:fs';
import path from 'node:path';
import { buildQueueModule } from '../../tools/wasmasm.mjs';
import { fileURLToPath } from 'node:url';

const out = process.argv[2] || path.dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(fs.readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, manifest.entry), buildQueueModule(manifest.capabilities.join(',')));
