# verify_dual_account.ps1
# ---------------------------------------------------------------------
# Quick health-check for the dual Claude-Pro setup. Pings each account
# independently via `claude -p`, prints which one(s) currently respond,
# and tails the most recent pipeline log for [CLAUDE-AUTH] events so
# you can see whether a switch happened during the last scheduled run.
#
# Safe to run any time. Does NOT trigger /login or modify anything.
# ---------------------------------------------------------------------

$ErrorActionPreference = "Continue"

$primary   = Join-Path $env:USERPROFILE ".claude-acct-a"
$secondary = Join-Path $env:USERPROFILE ".claude-acct-b"

function Test-Account($label, $dir) {
  if (-not (Test-Path $dir)) {
    Write-Host "[$label]  MISSING dir: $dir  (run setup_dual_account.ps1 first)"
    return
  }
  $env:CLAUDE_CONFIG_DIR = $dir
  Write-Host "[$label]  $dir"
  try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $out = & claude -p "Reply with the single word: pong" --output-format text 2>&1
    $sw.Stop()
    $reply = ($out | Out-String).Trim()
    if ($reply -match "(credit|quota|usage[_\s]*limit|rate[_\s-]*limit|upgrade|payment|429|402)") {
      Write-Host "  STATUS: EXHAUSTED   ($($sw.Elapsed.TotalSeconds.ToString('0.0'))s)"
      Write-Host "  reply : $reply"
    } elseif ($reply.Length -gt 0) {
      Write-Host "  STATUS: HEALTHY     ($($sw.Elapsed.TotalSeconds.ToString('0.0'))s)"
      Write-Host "  reply : $reply"
    } else {
      Write-Host "  STATUS: NO REPLY    ($($sw.Elapsed.TotalSeconds.ToString('0.0'))s)"
    }
  } catch {
    Write-Host "  STATUS: ERROR"
    Write-Host "  detail: $($_.Exception.Message)"
  } finally {
    Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
  }
  Write-Host ""
}

Write-Host "=== Account health ==="
Test-Account "PRIMARY  (Account A)" $primary
Test-Account "SECONDARY(Account B)" $secondary

Write-Host "=== Last pipeline run - [CLAUDE-AUTH] events ==="
$logs = @("logs\auto.log", "logs\review.log", "logs\biweekly.log") +
        (Get-ChildItem "logs\daily_*.log" -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object FullName)
foreach ($log in $logs | Where-Object { $_ -and (Test-Path $_) }) {
  $hits = Select-String -Path $log -Pattern "\[CLAUDE-AUTH\]" -ErrorAction SilentlyContinue
  if ($hits) {
    Write-Host "  $log"
    foreach ($h in ($hits | Select-Object -Last 4)) {
      Write-Host "    $($h.Line)"
    }
  }
}
Write-Host ""
Write-Host "Tip: 'active account = primary' at the start of each run is normal."
Write-Host "     A 'switching to secondary account' line means failover fired."
