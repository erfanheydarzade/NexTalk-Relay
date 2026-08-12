@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: shard\deploy.bat — setup, local testing (wrangler dev), and real deploy
:: for a NexTalk mailbox SHARD. Run from inside the shard\ folder (next to
:: wrangler.toml). Everything is menu-driven, no arguments required.
:: Each shard is independent — safe to copy this whole folder out to a
:: community operator's own machine/account and run it there unmodified.
:: ============================================================================

set "HERE=%~dp0"
cd /d "%HERE%"

:menu
cls
echo ============================================================
echo   NexTalk SHARD — setup / dev / deploy
echo   Folder: %CD%
echo ============================================================
call :check_wrangler_toml
echo   1. First-time setup checklist (KV namespace + router public key)
echo   2. Run LOCAL DEV server (wrangler dev)          [testing]
echo   3. Deploy to Cloudflare (wrangler deploy)        [real]
echo   4. Set/rotate secrets (ROUTER_SHARED_SECRET)
echo   5. Create KV namespace (MAILBOX_KV)
echo   6. Tail live logs (wrangler tail)
echo   7. Show deployed Worker info / URL
echo   8. Health check this shard over HTTP
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
if "%CHOICE%"=="8" goto :health_check
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
echo   SHARD first-time setup checklist
echo ============================================================
where wrangler >nul 2>nul
if errorlevel 1 (
    echo [1/5] wrangler CLI missing.
    set /p DOIT="Install now with npm? (y/n): "
    if /i "!DOIT!"=="y" call npm install -g wrangler
) else (
    echo [1/5] wrangler CLI found: OK
)

echo.
echo [2/5] Checking Cloudflare login...
call wrangler whoami
echo    If that failed or shows no account, run: wrangler login
echo    (Each shard can be logged into a DIFFERENT Cloudflare account —
echo     that's the point, no cross-account binding needed.)
pause

echo.
echo [3/5] wrangler.toml
if not exist "%HERE%wrangler.toml" (
    if exist "%HERE%wrangler.toml.example" (
        copy "%HERE%wrangler.toml.example" "%HERE%wrangler.toml" >nul
        echo    Copied wrangler.toml.example -^> wrangler.toml. EDIT IT NOW:
        echo      - name
        echo      - ROUTER_SIGNING_PUBLIC  (get this from the Router operator —
        echo        it's the SAME public hex value on every shard)
        notepad "%HERE%wrangler.toml"
    ) else (
        echo    [!] wrangler.toml.example missing, can't bootstrap it.
    )
) else (
    echo    wrangler.toml already exists: OK
    set /p CHECKPUB="Open it now to double-check ROUTER_SIGNING_PUBLIC? (y/n): "
    if /i "!CHECKPUB!"=="y" notepad "%HERE%wrangler.toml"
)

echo.
echo [4/5] KV namespace (MAILBOX_KV) for message storage.
set /p DOKV="Create it now? (y/n): "
if /i "!DOKV!"=="y" call :create_kv_inline

echo.
echo [5/5] Secret: ROUTER_SHARED_SECRET (optional, health-check gating).
set /p DOSECRETS="Set it now? (y/n): "
if /i "!DOSECRETS!"=="y" call :set_secrets_inline

echo.
echo Setup checklist done. After deploying (option 3), send this shard's
echo *.workers.dev URL to the Router operator to add via router-admin panel.
pause
goto :menu

:: ────────────────────────────────────────────────────────────────────────
:run_dev
cls
echo ============================================================
echo   SHARD — local dev server (wrangler dev)
echo ============================================================
echo   Runs against Miniflare locally with a local, separate KV store.
echo   Useful for testing /create /send /read /exists /health against a
echo   locally-signed capability (see the Router's dev server for that).
echo.
set /p DEVPORT="Port to listen on (default 8788, blank = default): "
if "%DEVPORT%"=="" set "DEVPORT=8788"
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
echo   SHARD — DEPLOY TO CLOUDFLARE (real, live)
echo ============================================================
if not exist "%HERE%wrangler.toml" (
    echo [!] wrangler.toml missing. Run option 1 first.
    pause
    goto :menu
)
echo This will publish this shard to your Cloudflare account using the
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
echo Note the *.workers.dev URL above. Give it to the Router operator to
echo append to SHARD_URLS (router\panel.bat -^> add shard). It must be
echo added at the END of the list, never inserted or reordered.
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
echo --- ROUTER_SHARED_SECRET (optional, must match what the Router uses
echo     to poll this shard's /health) ---
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
echo Creating KV namespace MAILBOX_KV...
call wrangler kv namespace create MAILBOX_KV
echo.
echo Copy the "id" printed above into the [[kv_namespaces]] block of
echo wrangler.toml under binding = "MAILBOX_KV".
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
:health_check
cls
set /p SHARD_URL="This shard's URL (e.g. https://nextalk-shard-a.example.workers.dev): "
if "%SHARD_URL%"=="" (
    echo No URL entered.
    pause
    goto :menu
)
set /p HEALTH_SECRET="ROUTER_SHARED_SECRET (leave blank if not set): "
echo.
echo GET %SHARD_URL%/health
if "%HEALTH_SECRET%"=="" (
    curl -s "%SHARD_URL%/health"
) else (
    curl -s -H "Authorization: Bearer %HEALTH_SECRET%" "%SHARD_URL%/health"
)
echo.
echo.
pause
goto :menu