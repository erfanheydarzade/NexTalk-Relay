# nextalk-relay — NexTalk transport package (`.ntx`)

Lets NexTalk send and receive messages through a **Relay** (a Cloudflare
Workers Router + shard). It installs into NexTalk like a plugin: no NexTalk
rebuild needed. Build the bridge, zip it with the manifest, install.

- [Use a prebuilt package](#use-a-prebuilt-package-no-build-needed) · [Quick start](#quick-start-chat-by-peer-id)
- [Which command do I need?](#which-command-do-i-need)
- [Troubleshooting](#troubleshooting) · [Local development](#local-development)
- [Two-user offline scenario](#advanced-out-of-band-addressing-courier-mode)
- [Build & package](#build--package) · [Browser (WASM) package](#browser-webassembly-package)

---

## Use a prebuilt package (no build needed)

You do **not** need Go to use this transport. Every [GitHub release](https://github.com/erfanheydarzade/NexTalk-Relay/releases) ships ready-made packages:

1. Open the [latest release](https://github.com/erfanheydarzade/NexTalk-Relay/releases/latest) and download the `.ntx` for your OS and CPU (the release has one per platform; the file name says which).
2. *(Recommended)* Check it against the SHA-256 checksum file attached to the same release:
   ```bash
   sha256sum -c SHA256SUMS --ignore-missing      # Linux / macOS
   ```
   ```powershell
   Get-FileHash -Algorithm SHA256 .\nextalk-relay.ntx    # Windows: compare with the checksum file
   ```
3. Install the file you downloaded:
   ```bash
   nextalk transport install <path-to-downloaded>.ntx --enable
   ```

The release also contains `nextalk-relay-wasm.ntx`. That is the browser build, an in-tab loopback demo that never contacts a server. For real use, pick the native package for your OS.

Build from source only if you want to change the bridge (see [Build & package](#build--package)).

---

## Quick start: chat by peer ID

This is what most people want: `peer connect <peer-id>` and `message send`.

**Every person who wants to be reachable registers their identity once, on
the same Router.** Both sides must do this, not just you.

```bash
# 1. Install the bridge (prebuilt .ntx from Releases, or one you built) and point it at your Router
nextalk transport install nextalk-relay.ntx --enable
nextalk transport config nextalk-relay '{"router_url":"https://<your-router>.workers.dev"}'
```

PowerShell needs the quotes escaped:

```powershell
.\nextalk.exe transport config nextalk-relay '{\"router_url\":\"https://<your-router>.workers.dev\"}'
```

```bash
# 2. Register YOUR identity with the Router (once per identity, per Router)
nextalk transport register-identity nextalk-relay -i <YOUR-ID> --router https://<your-router>.workers.dev

# 3. Check it worked (should print a mailbox + shard, no "not confirmed" note)
nextalk transport resolve nextalk-relay --to <YOUR-ID> --router https://<your-router>.workers.dev
```

Then in the NexTalk shell:

```
identity load <YOUR-ID>
use relay nextalk-relay
peer connect <PEER-ID>        # the peer must have done step 2 too
transport poll                # both sides poll to finish the handshake
message send <PEER-ID> hello
```

> `register-identity` needs a NexTalk core build that includes the alias fix
> in `internal/transportops/register.go`. Older builds fail with
> `router returned malformed mailbox_id`.

---

## Which command do I need?

| I want to… | Use | Why |
|---|---|---|
| Chat with someone using only their peer ID | `transport register-identity` | Registers your real identity key. Anyone can compute your mailbox address from your peer ID, so `peer connect` finds you automatically. |
| Send/receive files, or script transfers without tying the mailbox to my identity | `transport register` (alias `xfer-register`) | Registers a throwaway key owned by the bridge. Nobody can derive the address from your peer ID, so you must give the alias + shard to the sender (e.g. inside a transfer ticket). |
| Check whether someone is reachable | `transport resolve --to <id>` | Asks the Router where that identity's mailbox is. |
| Remove a dead mailbox from my local state | `transport detach --mailbox <alias>` | See [Troubleshooting](#troubleshooting). |

**The most common mistake:** running `transport register` and expecting
`peer connect` to work. They use different mailboxes, so `peer connect`
answers `recipient mailbox is not registered`. You can use both side by side
(identity registration for chat, plain register for files).

Registrations are **per Router**. A mailbox registered on your deployed Router
does not exist on your local dev Router, and the other way round.

---

## How it works

`nextalk-relay-bridge` is a **courier** transport (`message` capability,
`network` + `storage` permissions). It speaks the NexTalk transport API v1
(stdio RPC, schemas 100–112 + 123–126) to NexTalk and the Relay Router + shard
JSON API to the network. It implements ops 1–10 (initialize, start/stop, send,
attach, detach, poll, status, capabilities, register, resolve); anything else
answers op 0 + `SchemaError`.

**Trust model**, same as FileRelay's bridge:

- The bridge has its own throwaway ed25519 keys and **never sees your identity
  private key**. NexTalk core passes it opaque frames, recipient pubkeys,
  per-mailbox `read_secret` bearers and URLs.
- `courier.key` (sends) and `scoped-<tag>.key` (plain `register`) live next to
  the installed binary with mode `0600`. They control mailbox registration and
  courier-signed sends only. They cannot decrypt NexTalk traffic or
  impersonate your identity.
- `register-identity` is signed by NexTalk core, where the identity key lives.
  The bridge only receives the resulting mailbox details.
- The true sender lives inside the end-to-end-encrypted NexTalk frame. The
  bridge treats it as opaque bytes (base64-wrapped for the shard, like every
  other Relay client).

**Mailbox aliases.** Relay mailbox IDs are 32 bytes, but the transport API only
has room for 16. The bridge gives NexTalk a deterministic 16-byte alias
(`sha256(fullID)[:16]`) and remembers alias → full ID in `mailbox-map.json`
(`0600`, next to the binary). It is updated on every register / resolve /
attach. If you delete it, run `register-identity` or `transport resolve`
again to rebuild it.

**Polling.** Relay `/read` is burn-after-read and drains everything, with no
server-side limit, so the bridge returns the whole backlog instead of dropping
messages to honor a poll hint. Mailboxes hold at most 50 messages server-side.

---

## Troubleshooting

| Message | What it means | Fix |
|---|---|---|
| `recipient mailbox is not registered on the relay` | The **recipient** (the peer you are connecting to, not you) has no identity mailbox on this Router. | They run `transport register-identity` against the **same** Router. Verify with `transport resolve --to <their-id>`. |
| `unknown mailbox alias (re-run register/resolve for this bridge)`, or `replay attach <alias>` failing on every command | NexTalk replays the mailboxes saved in `state.json` each time it starts the bridge. They are stale: the Router/shard was reset or `SERVER_SECRET` changed, or `mailbox-map.json` was deleted. | `transport detach nextalk-relay --mailbox <32-hex>` for each stale entry, then run `register-identity` again. If `detach` fails with the same error, close NexTalk and delete the `"attach"` block in `state.json` (see below). |
| `router returned malformed mailbox_id` | Old NexTalk core that cannot map the Router's 32-byte mailbox ID to an alias. | Update NexTalk core (`internal/transportops/register.go` fix) and rebuild. |
| `resolving own mailbox alias failed` | The Router could not confirm your mailbox on a shard right after registering. | Make sure the shard is running and its `ROUTER_SIGNING_PUBLIC` matches the Router's. |
| `no router_url` | No Router configured. | Run `transport config …` or pass `--router`. |
| Works in the web messenger, not in the CLI (or the reverse) | They are talking to different Routers. | Use the same Router URL everywhere. |

Where `state.json` lives: `os.UserConfigDir()/nextalk/transports/` (on Windows
`%APPDATA%\nextalk\transports\`), unless `NEXTALK_TRANSPORTS_DIR` is set.

---

## Local development

Run the Router and shard locally and point NexTalk at them:

| Service | Address |
|---|---|
| Router (`wrangler dev`) | `http://127.0.0.1:8787` |
| Shard (`wrangler dev --port 8788`) | `http://127.0.0.1:8788` |

- Start the shard with `--port 8788`. Its `wrangler.toml` defaults to 8787,
  which collides with the Router.
- `wrangler dev` stores its data under `.wrangler/state`. Deleting it, or
  changing `SERVER_SECRET` in `.dev.vars`, invalidates every registration and
  leaves stale entries in NexTalk's `state.json`. Detach them and register again.
- Register both identities against the local Router before testing
  `peer connect`.

---

## Advanced: out-of-band addressing (courier mode)

Plain `register` gives you a mailbox that only people you tell can reach.
Share the alias and shard with the sender; they send with
`--mailbox <alias> --shard <url>` instead of looking you up by peer ID.

```bash
nextalk transport register nextalk-relay --id <YOU> --router https://<your-router>.workers.dev
# -> {"mailbox_id":"<32-hex alias>","read_secret":"...","shard_url":"..."}
#    share alias + shard with senders; keep read_secret private
nextalk transport poll nextalk-relay -i <YOU>
nextalk transport send-frame nextalk-relay --to <PEER> -f frame.bin
```

`send-frame --to` accepts a peer ID or a 64-hex Ed25519 pubkey (the bridge
resolves it via the Router, which requires that peer to have run
`register-identity`). `--mailbox <alias> --shard <url>` targets an explicit
address the recipient shared out-of-band.

### Two-user scenario (Alice ↔ Bob, same machine)

```bash
mkdir alice bob && cd alice && nextalk offline init          # -> ALICE
cd ../bob && nextalk offline init                            # -> BOB
cd ../alice && nextalk offline offer -i ALICE -r BOB -o offer.bin
cd ../bob && nextalk offline accept -i BOB -f ../alice/offer.bin -o answer.bin
cd ../alice && nextalk offline finish -i ALICE -f ../bob/answer.bin

cd ../alice
nextalk transport register nextalk-relay --id ALICE --router <ROUTER>
nextalk transport attach nextalk-relay --mailbox <ALIAS> --secret <SECRET> --shard <SHARD> --router <ROUTER>
cd ../bob
nextalk transport register nextalk-relay --id BOB --router <ROUTER>
nextalk transport attach nextalk-relay --mailbox <ALIAS> --secret <SECRET> --shard <SHARD> --router <ROUTER>

cd ../alice
nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin
nextalk-relay-bridge wrap --type 3 -f msg.bin > frame.bin
nextalk transport send-frame nextalk-relay --to BOB -f frame.bin
cd ../bob && nextalk transport poll nextalk-relay -i BOB
# [+] Message from <ALICE> (utf-8) — stored in mailbox
```

---

## Build & package

> Skip this section if you use a [prebuilt package](#use-a-prebuilt-package-no-build-needed).

```bash
cd transports/nextalk-relay
go build -o nextalk-relay-bridge ./bridge
go test ./...
```

Windows: `go build -o nextalk-relay-bridge.exe ./bridge` (and use
`manifest.windows.json`, whose `entry` is the `.exe` name).

`.ntx` is a zip with the manifest at its root:

```bash
./package.sh        # -> nextalk-relay.ntx (manifest.json + nextalk-relay-bridge)
```

```powershell
.\package.ps1       # -> nextalk-relay.ntx (manifest.windows.json renamed to
                    #    manifest.json + nextalk-relay-bridge.exe)
```

Both scripts run `go vet` + `go test` first and refuse to package on failure.
Never commit the built `.ntx`, `*.key` or `mailbox-map.json` (the root
`.gitignore` excludes them).

After rebuilding the bridge you must **reinstall** it
(`nextalk transport install nextalk-relay.ntx --enable`): it is a separate
executable, so a new `nextalk.exe` does not update it.

---

## Browser (WebAssembly) package

NexTalk's browser build cannot spawn processes or touch a filesystem, so it only
runs `.wasm` packages. The extension therefore also ships as
**`nextalk-relay-wasm.ntx`**, built with Node alone (no Go, TinyGo or
wat2wasm) and reproducible byte-for-byte:

```bash
cd transports
node build-wasm.mjs                  # -> dist/nextalk-relay-wasm.ntx + dist/SHA256SUMS
node build-wasm.mjs --version 1.4.0  # stamp manifest.version (the release workflow does this)
node --test test/wasm-package.test.mjs
```

Every package is validated with NexTalk's manifest rules and checked against
WASM transport **ABI v1** (exports, sandboxed imports, behaviour) before it is
written. CI: `.github/workflows/wasm-extension.yml` builds, tests and uploads it
on every change; `release.yml` attaches it to each release.

**What it does, and what it does not.** ABI v1 gives a module linear memory plus
an optional `ntx.log` import: no sockets, no `fetch`, no filesystem. So
`nextalk-relay-wasm` is an **in-memory loopback queue** (`message` only, no
permissions): frames sent in a tab come back out of the same tab. It is useful
for trying the transport flow and for two identities in one tab, but it never
contacts a Router or shard. **Use the native `nextalk-relay.ntx` package for the
real relay.** The ids differ (`nextalk-relay` vs `nextalk-relay-wasm`), so both
can be installed side by side. A networked browser build needs a host-mediated
network import in the ABI first.

Only the *extension* is built for the browser; the relay servers themselves are
never compiled to or run in WebAssembly.

---

## Files

```
transports/nextalk-relay/
├── manifest.json          # linux/macOS package metadata (entry: nextalk-relay-bridge)
├── manifest.windows.json  # same, entry: nextalk-relay-bridge.exe
├── go.mod / go.sum        # module (nanopack only)
├── bridge/
│   ├── main.go            # stdio loop, courier/scoped keys, alias map, dispatch
│   ├── rpc.go             # transport API v1 codec (schemas 100–112, 123–126)
│   ├── relay.go           # Router/shard JSON client (register/resolve/send/read)
│   └── bridge_test.go     # codec + signing-format + httptest end-to-end
├── wasm/                  # browser package: manifest.json, build.mjs, verify.json
├── package.sh / package.ps1
└── README.md              # this file
```