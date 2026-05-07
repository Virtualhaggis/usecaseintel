@echo off
REM Bi-weekly threat-synthesis -- invoked by Windows Task Scheduler.
REM Clusters the last 14 days of articles into themes and asks the LLM
REM to write one high-fidelity multi-platform UC per theme, then commits
REM the new use_cases/weekly/<YYYY-WW>/ and briefings/_weekly/ files.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

for /f "delims=" %%t in ('powershell -nop -c "Get-Date -Format yyyy-MM-ddTHH:mm:ss"') do set TS=%%t
set LOG=logs\biweekly.log

>>"%LOG%" echo.
>>"%LOG%" echo === biweekly start %TS% ===
set USECASEINTEL_USE_CLAUDE_OAUTH=1
py biweekly_review.py --apply 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] biweekly_review.py FAILED rc=%errorlevel%
  exit /b 1
)

REM Stage just the new weekly outputs.
git add use_cases/weekly/ briefings/_weekly/ 1>>"%LOG%" 2>>&1
git diff --cached --quiet
if errorlevel 1 (
  >>"%LOG%" echo [git] new weekly UCs -- committing
  git commit -m "weekly: bi-weekly threat synthesis %TS%" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [!] push FAILED -- resolve manually
    exit /b 2
  )
  >>"%LOG%" echo [git] pushed -- pipeline regen will pick them up
) else (
  >>"%LOG%" echo [git] no new weekly UCs
)
>>"%LOG%" echo === biweekly done ===
endlocal