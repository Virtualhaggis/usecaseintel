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
set USECASEINTEL_USE_CLAUDE_OAUTH=1

for /f %%a in ('powershell -nop -c "Get-Date -Format yyyy-MM-dd"') do set TS=%%a
set LOG=logs\daily_%TS%.log

>>"%LOG%" echo === %date% %time% ===================================
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
  git add intel/ catalog/ briefings/ daily_digest.md index.html 1>>"%LOG%" 2>>&1
  git commit -m "auto: refresh IOCs, catalog, and briefings (%TS%)" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [git] push failed - resolve manually.
  ) else (
    >>"%LOG%" echo [git] pushed.
  )
) else (
  >>"%LOG%" echo [git] no changes to commit.
)
>>"%LOG%" echo [done]
endlocal