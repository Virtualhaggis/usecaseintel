@echo off
REM Single pipeline iteration — invoked by Windows Task Scheduler.
REM Runs generate.py with OAuth so LLM bespoke UCs come through, then
REM commits + pushes any refreshed intel/ catalog/ briefings/ index.html
REM back to GitHub Pages so the site stays live and current.
REM
REM Logs each run to logs\auto_<date>.log so failures are traceable.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

set TS=%date:~10,4%-%date:~4,2%-%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TS=%TS: =0%
set LOG=logs\auto_%TS%.log

>>"%LOG%" echo === run_once start %date% %time% ===
set USECASEINTEL_USE_CLAUDE_OAUTH=1
py generate.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] generate.py FAILED
  exit /b 1
)

REM Stage just the regenerated outputs — never sweep up unrelated edits.
git add intel/ catalog/ briefings/ daily_digest.md index.html 1>>"%LOG%" 2>>&1
git diff --cached --quiet
if errorlevel 1 (
  >>"%LOG%" echo [git] changes detected — committing
  git commit -m "auto: scheduled pipeline run (%TS%)" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [!] push FAILED — resolve manually
    exit /b 2
  )
  >>"%LOG%" echo [git] pushed
) else (
  >>"%LOG%" echo [git] no changes
)
>>"%LOG%" echo === run_once done %date% %time% ===
endlocal
