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
REM Dual-account failover: point at two Claude CLI config dirs (each
REM holding its own logged-in session). generate.py routes the first
REM `claude -p` call through PRIMARY and sticky-switches to SECONDARY
REM on credit/quota exhaustion. Leave PRIMARY/SECONDARY unset to fall
REM back to legacy single-account behaviour (default ~/.claude).
REM Dual-account failover enabled: setup_dual_account.ps1 has provisioned
REM both per-account config dirs. generate.py routes via PRIMARY first and
REM sticky-switches to SECONDARY on credit/quota exhaustion for the rest
REM of the run. To revert to default %USERPROFILE%\.claude, re-comment both.
set USECASEINTEL_CLAUDE_CONFIG_DIR_PRIMARY=%USERPROFILE%\.claude-acct-a
set USECASEINTEL_CLAUDE_CONFIG_DIR_SECONDARY=%USERPROFILE%\.claude-acct-b
set USECASEINTEL_USE_CLAUDE_OAUTH=1
REM `py -u` forces unbuffered stdout. Without this, Python fully buffers
REM output when redirected to a file (>>"%LOG%"), so progress only lands
REM on disk when the process exits cleanly. A crash mid-loop strands all
REM the buffered lines and we can't see where it died — exactly what hid
REM the render_nav KeyError that blocked Thursday's pipeline.
py -u generate.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] generate.py FAILED rc=%errorlevel%
  exit /b 1
)

REM Rebuild the SOC cheat sheet so curated query bundles stay current.
REM Cheap (~1s) and idempotent -- only writes when content actually changed.
py -u build_soc_cheatsheet.py 1>>"%LOG%" 2>>&1

REM Refresh the operator dashboard so the Usage tab reflects this run.
REM pipeline.html is intentionally not committed (operator-internal page);
REM it just gets re-rendered locally from intel/.usage_log.jsonl.
py -u build_pipeline_docs.py 1>>"%LOG%" 2>>&1

REM Stage just the regenerated outputs -- never sweep up unrelated edits.
REM daily_digest.md is gitignored; sitemap.xml is regenerated each run.
git add intel/ catalog/ briefings/ rule_packs/ share/ techniques/ actors/ targets/ index.html sitemap.xml cheatsheet.html 1>>"%LOG%" 2>>&1
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