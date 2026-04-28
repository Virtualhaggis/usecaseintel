@echo off
REM Daily run: validate, regenerate, emit digest, auto-commit refreshed
REM intel/ catalog/ daily_digest.md back to GitHub.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

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
git diff --quiet -- intel/ catalog/ briefings/ daily_digest.md 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [git] changes detected, committing and pushing
  git add intel/ catalog/ briefings/ daily_digest.md 1>>"%LOG%" 2>>&1
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