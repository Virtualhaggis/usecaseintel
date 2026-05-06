@echo off
REM Single pipeline iteration -- invoked by Windows Task Scheduler.
REM Runs generate.py, then commits + pushes any refreshed pipeline
REM output back to GitHub Pages so the site stays live and current.
REM
REM Locale-independent timestamp via PowerShell (the previous %date%
REM slicing broke on UK / non-US date formats and produced an invalid
REM logfile path that silently dropped the output).
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

for /f "delims=" %%t in ('powershell -nop -c "Get-Date -Format yyyy-MM-ddTHH:mm:ss"') do set TS=%%t
set LOG=logs\auto.log

>>"%LOG%" echo.
>>"%LOG%" echo === run_once start %TS% ===
set USECASEINTEL_USE_CLAUDE_OAUTH=1
py generate.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] generate.py FAILED rc=%errorlevel%
  exit /b 1
)

REM Stage just the regenerated outputs -- never sweep up unrelated edits.
REM daily_digest.md is gitignored; sitemap.xml is regenerated each run.
git add intel/ catalog/ briefings/ rule_packs/ share/ index.html sitemap.xml 1>>"%LOG%" 2>>&1
git diff --cached --quiet
if errorlevel 1 (
  >>"%LOG%" echo [git] changes detected -- committing
  git commit -m "auto: scheduled pipeline run %TS%" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [!] push FAILED -- resolve manually
    exit /b 2
  )
  >>"%LOG%" echo [git] pushed
) else (
  >>"%LOG%" echo [git] no changes
)
>>"%LOG%" echo === run_once done ===
endlocal