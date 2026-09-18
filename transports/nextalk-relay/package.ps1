# Package the nextalk-relay transport as nextalk-relay.ntx
# (zip with manifest.json + entry binary at root). Refuses to package
# unless vet + tests pass. Run from transports\nextalk-relay\.
$ErrorActionPreference = "Stop"

Write-Host "==> go vet"
go vet ./...
if (!$?) { exit 1 }
Write-Host "==> go test"
go test ./...
if (!$?) { exit 1 }

Write-Host "==> build nextalk-relay-bridge.exe"
go build -o nextalk-relay-bridge.exe ./bridge
if (!$?) { exit 1 }

Write-Host "==> zip nextalk-relay.ntx"
if (Test-Path "nextalk-relay.ntx") { Remove-Item "nextalk-relay.ntx" }
# The installed manifest must be named manifest.json with the .exe entry.
New-Item -ItemType Directory -Force -Path ".ntx-stage" | Out-Null
Copy-Item -Force "manifest.windows.json" ".ntx-stage\manifest.json"
Copy-Item -Force "nextalk-relay-bridge.exe" ".ntx-stage\"
Compress-Archive -Path ".ntx-stage\manifest.json", ".ntx-stage\nextalk-relay-bridge.exe" -DestinationPath "nextalk-relay.zip" -Force
Remove-Item -Recurse -Force ".ntx-stage"
Rename-Item -Force "nextalk-relay.zip" "nextalk-relay.ntx"
Write-Host "packaged: nextalk-relay.ntx"
