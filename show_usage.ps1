# show_usage.ps1
# ---------------------------------------------------------------------
# Render the last N pipeline runs as a usage table. Reads the JSONL
# rolling log written by generate._emit_usage_summary at process exit.
#
# Each row in intel/.usage_log.jsonl is one run (scheduled pipeline,
# quality review, or biweekly synthesis). Columns:
#   ts              run end time, UTC
#   script          which entry point (generate.py / quality_review.py / ...)
#   wall_s          total wall-clock seconds for the run
#   switched        Y if dual-account failover fired, else .
#   acct_end        account in use when the run finished
#   calls           total `claude -p` invocations
#   in/out tokens   summed across every call
#   cache_r         cached prompt tokens reused (cheap re-reads)
#   top_kind        the kind that consumed the most output tokens
#
# Usage:
#   .\show_usage.ps1                # last 10 runs
#   .\show_usage.ps1 -Last 25       # last 25 runs
#   .\show_usage.ps1 -ByKind        # per-kind breakdown of the latest run
# ---------------------------------------------------------------------

[CmdletBinding()]
param(
  [int]    $Last = 10,
  [switch] $ByKind
)

$logPath = Join-Path $PSScriptRoot 'intel\.usage_log.jsonl'
if (-not (Test-Path $logPath)) {
  Write-Host "No usage log yet. Run the pipeline once and it will be created at:"
  Write-Host "  $logPath"
  exit 0
}

$rows = Get-Content $logPath -Encoding UTF8 | Where-Object { $_ -and $_.Trim() } | ForEach-Object {
  try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_ -ne $null }

if (-not $rows -or $rows.Count -eq 0) {
  Write-Host "Usage log is empty or unparseable: $logPath"
  exit 0
}

# Newest first.
$rows = $rows | Sort-Object -Property ts -Descending

if ($ByKind) {
  $latest = $rows[0]
  Write-Host ""
  Write-Host "=== Latest run: $($latest.ts)   script=$($latest.script)   wall=$($latest.wall_seconds_total)s ==="
  $bk = $latest.by_kind
  if (-not $bk) { Write-Host "(no per-kind data)"; exit 0 }
  $fmt = "{0,-10} {1,6} {2,5} {3,12} {4,12} {5,12} {6,8}  {7}"
  Write-Host ($fmt -f 'kind','calls','errs','input','output','cache_r','wall_s','by_account')
  Write-Host ('-' * 88)
  foreach ($name in ($bk | Get-Member -MemberType NoteProperty | ForEach-Object Name | Sort-Object)) {
    $slot = $bk.$name
    $ba   = $slot.by_account
    $baStr = "p=$($ba.primary) s=$($ba.secondary)"
    Write-Host ($fmt -f $name,
      ('{0,6}' -f $slot.calls),
      ('{0,5}' -f $slot.errors),
      ('{0,12:N0}' -f $slot.input_tokens),
      ('{0,12:N0}' -f $slot.output_tokens),
      ('{0,12:N0}' -f $slot.cache_read),
      ('{0,8:N0}' -f $slot.wall_seconds),
      $baStr)
  }
  exit 0
}

$display = $rows | Select-Object -First $Last

Write-Host ""
Write-Host "=== Last $($display.Count) runs (newest first) ==="
$fmt = "{0,-20} {1,-18} {2,7} {3,8} {4,8} {5,7} {6,12} {7,12} {8,12}  {9}"
Write-Host ($fmt -f 'ts (UTC)','script','wall_s','switched','acct_end','calls','input','output','cache_r','top_kind_by_output')
Write-Host ('-' * 140)

foreach ($r in $display) {
  $t = $r.totals
  $bk = $r.by_kind
  $topKind = '-'
  if ($bk) {
    $topKind = ($bk | Get-Member -MemberType NoteProperty | ForEach-Object {
      [pscustomobject]@{ name = $_.Name; out = [int64]$bk.($_.Name).output_tokens }
    } | Sort-Object -Property out -Descending | Select-Object -First 1).name
  }
  $script = if ($r.script) { $r.script } else { '?' }
  $switched = if ($r.account_switched) { 'Y' } else { '.' }
  Write-Host ($fmt -f $r.ts,
    $script,
    ('{0,7:N0}' -f $r.wall_seconds_total),
    $switched,
    $r.active_at_end,
    ('{0,7:N0}' -f $t.calls),
    ('{0,12:N0}' -f $t.input_tokens),
    ('{0,12:N0}' -f $t.output_tokens),
    ('{0,12:N0}' -f $t.cache_read),
    $topKind)
}

Write-Host ""
Write-Host "Tip: '.\show_usage.ps1 -ByKind' shows the per-stage breakdown of the latest run."
