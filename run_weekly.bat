@echo off
REM Weekly run: refresh upstream sources first, then run daily flow.
setlocal
cd /d "%~dp0"
if not exist logs mkdir logs

for /f %%a in ('powershell -nop -c "Get-Date -Format yyyy-MM-dd"') do set TS=%%a
set LOG=logs\weekly_%TS%.log

>>"%LOG%" echo === %date% %time% ===================================
>>"%LOG%" echo [sync]
py sync.py 1>>"%LOG%" 2>>&1
if errorlevel 1 (
  >>"%LOG%" echo [!] sync.py FAILED.
  echo [!] sync.py FAILED. See "%LOG%". 1>&2
  exit /b 1
)
>>"%LOG%" echo [daily flow]
call "%~dp0run_daily.bat"
endlocal