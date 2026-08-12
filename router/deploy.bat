@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: router\deploy.bat — setup, local testing (wrangler dev), and real deploy
:: for the NexTalk Router. Run from inside the router\ folder (next to
:: wrangler.toml). Everything is menu-driven, no arguments required.
:: ============================================================================

set "HERE=%~dp0"
cd /d "%HERE%"

:menu
cls
echo ============================================================
echo   NexTalk ROUTER — setup / dev / deploy
echo   Folder: %CD%
echo ============================================================
call :check_wrangler_toml
echo   1. First-time setup checklist (KV namespaces + secrets)
echo   2. Run LOCAL DEV server (wrangler dev)          [testing]
echo   3. Deploy to Cloudflare (wrangler deploy)        [real]
echo   4. Set/rotate secrets (SERVER_SECRET etc.)
echo   5. Create KV namespace (ROUTER_ADMIN_KV)
echo   6. Tail live logs (wrangler tail)
echo   7. Show deployed Worker info / URL
echo   8. Open router-admin panel (panel.bat)
echo   0. Exit
echo ============================================================
set /p CHOICE="Choose an option: "

if "%CHOICE%"=="1" goto :first_time_setup
if "%CHOICE%"=="2" goto :run_dev
if "%CHOICE%"=="3" goto :run_deploy
if "%CHOICE%"=="4" goto :set_secrets
if "%CHOICE%"=="5" goto :create_kv
if "%CHOICE%"=="6" goto :tail_logs
if "%CHOICE%"=="7" goto :whoami_info
if "%CHOICE%"=="8" goto :open_panel
if "%CHOICE%"=="0" goto :eof
echo Invalid choice.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:check_wrangler_toml
if not exist "%HERE%wrangler.toml" (
    echo   [!] wrangler.toml not found here.
    echo       Copy wrangler.toml.example to wrangler.toml and edit it first.
    echo.
)
where wrangler >nul 2>nul
if errorlevel 1 (
    echo   [!] wrangler CLI not found on PATH. Run: npm install -g wrangler
    echo.
)
exit /b

:: ────────────────────────────────────────────────────────────────────────
:first_time_setup
cls
echo ============================================================
echo   ROUTER first-time setup checklist
echo ============================================================
where wrangler >nul 2>nul
if errorlevel 1 (
    echo [1/6] wrangler CLI missing.
    set /p DOIT="Install now with npm? (y/n): "
    if /i "!DOIT!"=="y" call npm install -g wrangler
) else (
    echo [1/6] wrangler CLI found: OK
)

echo.
echo [2/6] Checking Cloudflare login...
call wrangler whoami
echo    If that failed or shows no account, run: wrangler login
pause

echo.
echo [3/6] wrangler.toml
if not exist "%HERE%wrangler.toml" (
    if exist "%HERE%wrangler.toml.example" (
        copy "%HERE%wrangler.toml.example" "%HERE%wrangler.toml" >nul
        echo    Copied wrangler.toml.example -^> wrangler.toml. EDIT IT NOW:
        echo      - name
        echo      - SHARD_URLS  (fill in after shards are deployed)
        echo      - ROUTER_SIGNING_PUBLIC (fill in after you generate the keypair)
        notepad "%HERE%wrangler.toml"
    ) else (
        echo    [!] wrangler.toml.example missing, can't bootstrap it.
    )
) else (
    echo    wrangler.toml already exists: OK
)

echo.
echo [4/6] Ed25519 signing keypair for the Router (needed for
echo       ROUTER_SIGNING_KEY secret and ROUTER_SIGNING_PUBLIC var).
where openssl >nul 2>nul
if errorlevel 1 (
    echo    [!] openssl not found on PATH. Install Git for Windows or
    echo        generate the keypair manually, then come back to option 4.
) else (
    set /p GENKEY="Generate a new signing keypair now? (y/n): "
    if /i "!GENKEY!"=="y" (
        openssl genpkey -algorithm ed25519 -outform DER -out "%HERE%router_signing_key.der"
        openssl pkey -in "%HERE%router_signing_key.der" -inform DER -pubout -outform DER -out "%HERE%router_signing_pub.der"
        echo.
        echo    Private key written to router_signing_key.der
        echo    Public key written to  router_signing_pub.der
        echo.
        echo    Next: base64-encode the PRIVATE key for the ROUTER_SIGNING_KEY
        echo    secret, and hex-encode the last 32 bytes of the PUBLIC key for
        echo    ROUTER_SIGNING_PUBLIC in wrangler.toml. In Git Bash / WSL:
        echo      base64 -w0 router_signing_key.der
        echo      python3 -c "print(open('router_signing_pub.der','rb').read()[-32:].hex())"
        echo.
        echo    router_signing_key.der contains your PRIVATE key — do NOT
        echo    commit it. Delete it after copying the base64 into the secret.
        pause
    )
)

echo.
echo [5/6] KV namespace (ROUTER_ADMIN_KV) for live shard/version control.
set /p DOKV="Create it now? (y/n): "
if /i "!DOKV!"=="y" call :create_kv_inline

echo.
echo [6/6] Secrets: SERVER_SECRET, ROUTER_SIGNING_KEY, ROUTER_SHARED_SECRET
set /p DOSECRETS="Set them now? (y/n): "
if /i "!DOSECRETS!"=="y" call :set_secrets_inline

echo.
echo Setup checklist done. Deploy shards first if you haven't, put their
echo URLs in SHARD_URLS, then use option 3 to deploy the Router.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:run_dev
cls
echo ============================================================
echo   ROUTER — local dev server (wrangler dev)
echo ============================================================
echo   This runs against Miniflare locally. Local KV is separate from
echo   production KV, so ROUTER_ADMIN_KV live-updates won't reflect
echo   production. Secrets can be supplied via a local .dev.vars file
echo   (create one next to wrangler.toml if you don't have secrets set).
echo.
set /p DEVPORT="Port to listen on (default 8787, blank = default): "
if "%DEVPORT%"=="" set "DEVPORT=8787"
echo.
echo Starting: wrangler dev --port %DEVPORT%
echo Press Ctrl+C to stop the dev server.
echo ------------------------------------------------------------
call wrangler dev --port %DEVPORT%
echo.
echo Dev server stopped.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:run_deploy
cls
echo ============================================================
echo   ROUTER — DEPLOY TO CLOUDFLARE (real, live)
echo ============================================================
if not exist "%HERE%wrangler.toml" (
    echo [!] wrangler.toml missing. Run option 1 first.
    pause
    goto :menu
)
echo This will publish the Router to your Cloudflare account using the
echo current wrangler.toml and whatever secrets are already set.
echo.
set /p CONFIRM="Type DEPLOY to confirm: "
if not "%CONFIRM%"=="DEPLOY" (
    echo Aborted.
    pause
    goto :menu
)
call wrangler deploy
echo.
echo If this is the first deploy, note the *.workers.dev URL above — you
echo need it in each shard's ROUTER_SIGNING_PUBLIC step and in your
echo router-admin.bat / panel.bat config.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:set_secrets
cls
call :set_secrets_inline
pause
goto :menu

:set_secrets_inline
echo.
echo Setting Router secrets one at a time. Leave a prompt empty (just
echo press Enter at the wrangler prompt) to skip that one.
echo.
echo --- SERVER_SECRET (HMAC key, e.g. output of: openssl rand -hex 32) ---
call wrangler secret put SERVER_SECRET
echo.
echo --- ROUTER_SIGNING_KEY (base64 PKCS8 Ed25519 private key) ---
call wrangler secret put ROUTER_SIGNING_KEY
echo.
echo --- ROUTER_SHARED_SECRET (optional, gates /status and /admin/config) ---
set /p SETSHARED="Set ROUTER_SHARED_SECRET now? (y/n): "
if /i "%SETSHARED%"=="y" call wrangler secret put ROUTER_SHARED_SECRET
exit /b

:: ────────────────────────────────────────────────────────────────────────
:create_kv
cls
call :create_kv_inline
pause
goto :menu

:create_kv_inline
echo.
echo Creating KV namespace ROUTER_ADMIN_KV...
call wrangler kv namespace create ROUTER_ADMIN_KV
echo.
echo Copy the "id" printed above into the [[kv_namespaces]] block of
echo wrangler.toml under binding = "ROUTER_ADMIN_KV".
set /p OPENIT="Open wrangler.toml now to paste it in? (y/n): "
if /i "%OPENIT%"=="y" notepad "%HERE%wrangler.toml"
exit /b

:: ────────────────────────────────────────────────────────────────────────
:tail_logs
cls
echo Tailing live production logs. Ctrl+C to stop.
call wrangler tail
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:whoami_info
cls
call wrangler deployments list
echo.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:open_panel
if exist "%HERE%panel.bat" (
    call "%HERE%panel.bat"
) else (
    echo panel.bat not found in %HERE%
    pause
)
goto :menu