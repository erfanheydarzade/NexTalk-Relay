#!/usr/bin/env bash
# Package the nextalk-relay transport as nextalk-relay.ntx
# (zip with manifest.json + entry binary at root). Refuses to package
# unless vet + tests pass.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> go vet"
go vet ./...
echo "==> go test"
go test ./...

echo "==> build nextalk-relay-bridge"
go build -o nextalk-relay-bridge ./bridge

echo "==> zip nextalk-relay.ntx"
rm -f nextalk-relay.ntx
zip -j nextalk-relay.ntx manifest.json nextalk-relay-bridge
echo "packaged: nextalk-relay.ntx"
unzip -l nextalk-relay.ntx
