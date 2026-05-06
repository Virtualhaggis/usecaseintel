@echo off
REM Single pipeline iteration — invoked by Windows Task Scheduler.
REM Runs generate.py with OAuth so LLM bespoke UCs come through, then
REM commits + pushes any refreshed intel/ catalog/ briefings/ index.html
REM back to GitHub Pages so the site stays live and current.
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

REM Stage just the regenerated outputs — never sweep up unrelated edits.
REM daily_digest.md is gitignored; sitemap.xml is regenerated each run.
>>"%LOG%" echo [git] cwd=%CD%
>>"%LOG%" echo [git] pre-add status:
git status --short 2>&1 | findstr /n "^" | findstr /v ":$" 1>>"%LOG%" 2>>&1
git add intel/ catalog/ briefings/ rule_packs/ index.html sitemap.xml 1>>"%LOG%" 2>>&1
set ADD_RC=%ERRORLEVEL%
>>"%LOG%" echo [git] add exit=%ADD_RC%
>>"%LOG%" echo [git] post-add diff --cached:
git diff --cached --stat 1>>"%LOG%" 2>>&1
git diff --cached --quiet
set DIFF_RC=%ERRORLEVEL%
>>"%LOG%" echo [git] diff --cached --quiet exit=%DIFF_RC%
if %DIFF_RC% neq 0 (
  >>"%LOG%" echo [git] changes detected — committing
  git commit -m "auto: scheduled pipeline run %TS%" 1>>"%LOG%" 2>>&1
  git push 1>>"%LOG%" 2>>&1
  if errorlevel 1 (
    >>"%LOG%" echo [!] push FAILED — resolve manually
    exit /b 2
  )
  >>"%LOG%" echo [git] pushed
) else (
  >>"%LOG%" echo [git] no changes
)
>>"%LOG%" echo === run_once done ===
endlocal
