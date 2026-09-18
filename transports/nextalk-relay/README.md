# nextalk-relay — NexTalk transport package (`.ntx`)

The NexTalk-Relay mailbox service as an installable NexTalk transport. No
NexTalk rebuild, ever: build this bridge, zip it with the manifest, install.

## What it is

`nextalk-relay-bridge` is a courier transport (`message` capability,
`network` + `storage` permissions) that speaks the NexTalk transport API v1
(stdio RPC, schemas 100–112 + 123–126) on one side and the Relay Router +
shard JSON API on the other. It implements ops 1–10 (initialize, start/stop,
send, attach, detach, poll, status, capabilities, register, resolve);
anything else answers op 0 + `SchemaError`.

Trust model — courier, same as FileRelay's bridge:

- The bridge owns its own throwaway ed25519 identities and **never sees
  user private keys**. Core passes opaque frames, recipient pubkeys,
  per-mailbox `read_secret` bearers, and URLs.
- `courier.key` (sends) and `scoped-<tag>.key` (per-user-tag Router
  registration) live next to the installed binary, `0600`. They control
  mailbox registration and courier-signed sends only — they cannot decrypt
  NexTalk traffic and cannot impersonate the NexTalk identity.
- The true sender lives inside the E2E-encrypted NexTalk frame, which the
  bridge treats as opaque bytes (base64-wrapped for the shard, exactly like
  every other Relay client).

Mailbox aliasing: Relay mailbox IDs are 32 bytes but the transport API
fixes mailbox fields at 16 bytes. The bridge hands core deterministic
16-byte aliases (`sha256(fullID)[:16]`) and keeps the alias → full-ID
binding in `mailbox-map.json` (`0600`) beside the binary, written at every
register/resolve/attach. If the map is deleted, re-run
`transport register` / `transport resolve` to rebuild it — attach of an
unknown alias fails closed with a clear error.

Poll semantics: Relay `/read` is burn-after-read full-drain with no
server-side limit, so the bridge returns the whole backlog rather than
dropping consumed messages to honor a poll hint. Mailboxes cap at 50
server-side; core dispatches batches.

## Build

```bash
cd transports/nextalk-relay
go build -o nextalk-relay-bridge ./bridge
go test ./...
```

Windows: `go build -o nextalk-relay-bridge.exe ./bridge` (and use
`manifest.windows.json`, whose `entry` is the `.exe` name).

## Package (`.ntx` = zip, manifest at root)

```bash
./package.sh        # -> nextalk-relay.ntx (manifest.json + nextalk-relay-bridge)
```

```powershell
.\package.ps1       # -> nextalk-relay.ntx (manifest.windows.json renamed to
                    #    manifest.json + nextalk-relay-bridge.exe)
```

Both scripts run `go vet` + `go test` first and refuse to package on
failure. Never commit the built `.ntx` or `*.key` / `mailbox-map.json`
(the root `.gitignore` excludes them).

## Install & use (in NexTalk, no rebuild)

```bash
nextalk transport install nextalk-relay.ntx --enable
nextalk transport config nextalk-relay '{"router_url":"https://<your-router>.workers.dev"}'
nextalk transport register nextalk-relay --user alice --router https://<your-router>.workers.dev
# -> {"mailbox_id":"<32-hex alias>","read_secret":"...","shard_url":"..."}  (share alias+shard with senders)
nextalk transport poll nextalk-relay -i <YOU>        # like worker listen
nextalk transport send-frame nextalk-relay --to <PEER> -f frame.bin
```

Two-user scenario (Alice ↔ Bob, same machine):

```bash
mkdir alice bob && cd alice && nextalk offline init          # -> ALICE
cd ../bob && nextalk offline init                            # -> BOB
cd ../alice && nextalk offline offer -i ALICE -r BOB -o offer.bin
cd ../bob && nextalk offline accept -i BOB -f ../alice/offer.bin -o answer.bin
cd ../alice && nextalk offline finish -i ALICE -f ../bob/answer.bin

cd ../alice
nextalk transport register nextalk-relay --user alice --router <ROUTER>
nextalk transport attach nextalk-relay --mailbox <ALIAS> --secret <SECRET> --shard <SHARD> --router <ROUTER>
cd ../bob
nextalk transport register nextalk-relay --user bob --router <ROUTER>
nextalk transport attach nextalk-relay --mailbox <ALIAS> --secret <SECRET> --shard <SHARD> --router <ROUTER>

cd ../alice
nextalk offline encrypt -i ALICE -r BOB -m "hello bob" -o msg.bin
nextalk-relay-bridge wrap --type 3 -f msg.bin > frame.bin
nextalk transport send-frame nextalk-relay --to BOB -f frame.bin
cd ../bob && nextalk transport poll nextalk-relay -i BOB
# [+] Message from <ALICE> (utf-8) — stored in mailbox
```

`send-frame --to` accepts a peer ID or 64-hex Ed25519 pubkey (the bridge
resolves via the Router itself); `--mailbox <alias> --shard <url>` targets
an explicit address the recipient shared out-of-band.

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
├── package.sh / package.ps1
└── README.md              # this file
```
