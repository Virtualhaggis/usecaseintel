@echo off
REM Off-hour quality-review pass — invoked by ClankerusecaseQualityReview
REM scheduled task at xx:30 on the alternate 2-hour boundaries from the
REM main pipeline (07:30, 09:30, 11:30, ..., 05:30).
REM
REM Reads the most recent pipeline run's article list, runs an LLM
REM peer review per article, writes verdicts + new-UC suggestions to
REM intel/quality_review/ and intel/quality_suggestions.jsonl.
REM
REM The script honours intel/.pipeline.lock — if a pipeline run is
REM still in progress it exits cleanly without touching the caches.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

for /f "delims=" %%t in ('powershell -nop -c "Get-Date -Format yyyy-MM-ddTHH:mm:ss"') do set TS=%%t
set LOG=logs\review.log

>>"%LOG%" echo.
>>"%LOG%" echo === run_review start %TS% ===
REM Dual-account failover. See run_once.bat for the protocol. Review-pass
REM LLM calls (Haiku reviewer via gen._call_claude_cli) also honour the
REM sticky switch because the failover lives inside _call_claude_cli.
REM Dual-account failover enabled: setup_dual_account.ps1 has provisioned
REM both per-account config dirs. Review-pass LLM calls (Haiku reviewer)
REM honour the sticky switch via _call_claude_cli. To revert to default
REM %USERPROFILE%\.claude, re-comment both lines.
set USECASEINTEL_CLAUDE_CONFIG_DIR_PRIMARY=%USERPROFILE%\.claude-acct-a
set USECASEINTEL_CLAUDE_CONFIG_DIR_SECONDARY=%USERPROFILE%\.claude-acct-b
set USECASEINTEL_USE_CLAUDE_OAUTH=1
REM `py -u` forces unbuffered stdout so progress lands in the log
REM immediately, same convention as the main pipeline.
py -u quality_review.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] quality_review.py FAILED rc=%errorlevel%
  exit /b 1
)

REM Refresh the operator dashboard so the Usage tab includes this review's
REM rows. pipeline.html is intentionally not committed (operator-internal).
py -u build_pipeline_docs.py 1>>"%LOG%" 2>>&1

REM Stage and push the review output. intel/quality_suggestions.jsonl
REM is committed so the next pipeline run can read it; intel/quality_review/
REM and intel/.pipeline.lock are gitignored, so they stay local.
git add intel/quality_suggestions.jsonl 1>>"%LOG%" 2>>&1
git diff --cached --quiet
if errorlevel 1 (
  >>"%LOG%" echo [git] suggestions log updated -- committing
  git commit -m "review: quality-review pass %TS%" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [!] push FAILED -- resolve manually
    exit /b 2
  )
  >>"%LOG%" echo [git] pushed
) else (
  >>"%LOG%" echo [git] no suggestions log changes
)
>>"%LOG%" echo === run_review done ===
endlocal
