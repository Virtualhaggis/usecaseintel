@echo off
REM Daily run: validate, regenerate site, emit digest.
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
>>"%LOG%" echo [done]
endlocal