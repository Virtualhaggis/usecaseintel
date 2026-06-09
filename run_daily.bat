@echo off
REM Daily run: validate, regenerate, emit digest, auto-commit refreshed
REM intel/ catalog/ daily_digest.md back to GitHub.
REM
REM Pipeline coverage (must remain wired into every run):
REM   1. SOURCES (in generate.py):
REM        - The Hacker News, BleepingComputer, Microsoft Security Blog
REM        - IOC-rich research feeds: Cisco Talos, Securelist (Kaspersky),
REM          SentinelLabs, Unit 42 (Palo Alto), ESET WeLiveSecurity
REM        - CISA KEV (authoritative exploited-vuln feed)
REM   2. Full article-body fetch (FETCH_FULL_BODY=1 default) so IOC
REM      extraction sees hashes / defanged IPs / domains in the body, not
REM      just the truncated RSS preview. Cache lives at
REM      intel/.article_cache/ (gitignored).
REM   3. requirements.txt: feedparser, requests, pyyaml.
REM Set THN_FETCH_FULL_BODY=0 to disable body fetch (debug / offline only).
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

REM Route every LLM call through Claude Code OAuth (claude-agent-sdk +
REM the user's Claude Code session). Without this flag, generate.py's
REM article-bespoke [LLM] UC generator silently no-ops on any article
REM not already in cache — same fall-through path as having no
REM ANTHROPIC_API_KEY. The other wrappers (run_once.bat, biweekly.bat,
REM loop_pipeline.sh) already set this; the scheduled daily run was
REM missing it, which is why the [LLM] count was decaying as cache
REM entries got invalidated.
REM Dual-account failover. See run_once.bat for the protocol; same
REM PRIMARY=A / SECONDARY=B config-dir pair used across every scheduled
REM batch so a sticky switch persists for the rest of the daily run.
REM Dual-account failover enabled: setup_dual_account.ps1 has provisioned
REM both per-account config dirs. Same PRIMARY=A / SECONDARY=B pair used
REM across every scheduled batch so a sticky switch persists for the run.
REM To revert to default %USERPROFILE%\.claude, re-comment both lines.
set USECASEINTEL_CLAUDE_CONFIG_DIR_PRIMARY=%USERPROFILE%\.claude-acct-a
set USECASEINTEL_CLAUDE_CONFIG_DIR_SECONDARY=%USERPROFILE%\.claude-acct-b
set USECASEINTEL_USE_CLAUDE_OAUTH=1

for /f %%a in ('powershell -nop -c "Get-Date -Format yyyy-MM-dd"') do set TS=%%a
set LOG=logs\daily_%TS%.log

>>"%LOG%" echo === %date% %time% ===================================

REM ---- Branch guard: skip the run if the checked-out branch has no
REM      upstream (push would fail silently; see run_once.bat).
git rev-parse --abbrev-ref --symbolic-full-name @{u} 1>nul 2>nul
if errorlevel 1 (
  >>"%LOG%" echo [!] BRANCH GUARD: current branch has no upstream -- aborting run
  start "" /b msg %USERNAME% "Clankerusecase daily run ABORTED: repo is on a branch with no upstream. Check out main."
  exit /b 3
)

>>"%LOG%" echo [validate]
py validate.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] validate.py FAILED.
  echo [!] validate.py FAILED. See "%LOG%". 1>&2
  exit /b 1
)
>>"%LOG%" echo [generate]
py generate.py 1>>"%LOG%" 2>>&1
>>"%LOG%" echo [digest]
py digest.py 1>>"%LOG%" 2>>&1

REM ---- Auto-commit refreshed exports to the repo ---------------------
>>"%LOG%" echo [git] checking for refreshed intel/ catalog/ files
git diff --quiet -- intel/ catalog/ briefings/ daily_digest.md index.html 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [git] changes detected, committing and pushing
  git add intel/ catalog/ briefings/ daily_digest.md data/ index.html 1>>"%LOG%" 2>>&1
  git commit -m "auto: refresh IOCs, catalog, and briefings (%TS%)" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [git] push failed - resolve manually.
    echo push-failed %TS% > "%~dp0.push_failed"
    start "" /b msg %USERNAME% "Clankerusecase daily run: git push FAILED (%TS%). See logs."
  ) else (
    >>"%LOG%" echo [git] pushed.
    if exist "%~dp0.push_failed" del "%~dp0.push_failed"
  )
) else (
  >>"%LOG%" echo [git] no changes to commit.
)
>>"%LOG%" echo [done]
endlocal