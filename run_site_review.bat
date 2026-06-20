@echo off
REM Daily site-review loop -- invoked by Windows Task Scheduler (1x/day).
REM Runs the deterministic lint, applies only safe Tier-1 auto-fixes, records
REM Tier-2 suggestions + Tier-3 (approval-only) prompt proposals, writes the
REM report, and commits/pushes the record. site_review.py does its own git +
REM lock handling; this wrapper only adds the branch guard, env, and alerting.
REM
REM Schedule it OFFSET from run_once.bat (e.g. 05:15) so it never overlaps the
REM 2h pipeline render. site_review.py also self-skips if the pipeline lock is
REM held by a live run, so a collision is harmless either way.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs
for /f "delims=" %%t in ('powershell -nop -c "Get-Date -Format yyyy-MM-ddTHH:mm:ss"') do set TS=%%t
set LOG=logs\site_review.log
>>"%LOG%" echo.
>>"%LOG%" echo === run_site_review start %TS% ===

REM Branch guard: a detached/no-upstream branch makes `git push` fail silently.
git rev-parse --abbrev-ref --symbolic-full-name @{u} 1>nul 2>nul
if errorlevel 1 (
  >>"%LOG%" echo [!] BRANCH GUARD: no upstream -- aborting
  exit /b 3
)

REM LLM lens review (Tier 2) + prompt-proposal drafting (Tier 3) use the same
REM dual-account Claude OAuth path as the pipeline. Drop --with-llm below to run
REM deterministic-only (no LLM cost): the lint, auto-fix, and proposal RECORDING
REM all work without it; only the LLM-authored suggestions/drafts are skipped.
set USECASEINTEL_CLAUDE_CONFIG_DIR_PRIMARY=%USERPROFILE%\.claude-acct-a
set USECASEINTEL_CLAUDE_CONFIG_DIR_SECONDARY=%USERPROFILE%\.claude-acct-b
set USECASEINTEL_USE_CLAUDE_OAUTH=1

py -u site_review.py --with-llm 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] site_review.py FAILED rc=%errorlevel%
  echo review-failed %TS% > "%~dp0.review_failed"
  start "" /b msg %USERNAME% "Clankerusecase site-review FAILED (%TS%). See logs\site_review.log"
  exit /b 1
)
if exist "%~dp0.review_failed" del "%~dp0.review_failed"
>>"%LOG%" echo === run_site_review done ===
endlocal
