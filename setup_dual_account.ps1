# setup_dual_account.ps1
# ---------------------------------------------------------------------
# One-time wiring for the dual Claude-Pro-account failover. Run this
# from a *fresh* PowerShell window (NOT inside an active Claude Code
# session — that session has its own claude binary attached and would
# fight with the interactive /login flow we need below).
#
# What it does:
#   1. Creates two per-account Claude CLI config dirs:
#        %USERPROFILE%\.claude-acct-a   <- "primary"   (Account A)
#        %USERPROFILE%\.claude-acct-b   <- "secondary" (Account B)
#   2. Walks you through `claude /login` for each, isolating their
#      sessions via the CLAUDE_CONFIG_DIR env var.
#   3. Pings each account with `claude -p "say hi"` so you see at a
#      glance which one is healthy and which one is credit-exhausted.
#
# Once this is done, the four scheduled batch files
# (run_once.bat / run_daily.bat / run_review.bat / biweekly.bat) will
# point generate.py at PRIMARY first, and sticky-switch to SECONDARY
# on the first credit/quota error for the remainder of that run.
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"

$primary   = Join-Path $env:USERPROFILE ".claude-acct-a"
$secondary = Join-Path $env:USERPROFILE ".claude-acct-b"

function Write-Section($title) {
  Write-Host ""
  Write-Host "==============================================================="
  Write-Host " $title"
  Write-Host "==============================================================="
}

Write-Section "Step 1 / 3 - Create per-account config directories"
New-Item -ItemType Directory -Force $primary   | Out-Null
New-Item -ItemType Directory -Force $secondary | Out-Null
Write-Host "  PRIMARY   dir: $primary"
Write-Host "  SECONDARY dir: $secondary"

Write-Section "Step 2 / 3 - Log into each account in its own dir"
Write-Host ""
Write-Host "You will now be dropped into an interactive 'claude' session"
Write-Host "TWICE - once per account. In each session:"
Write-Host "  1. Run    /login"
Write-Host "  2. Pick the appropriate account."
Write-Host "  3. Run    /exit   (or close the prompt)."
Write-Host ""
Write-Host "First session: log in as Account A (the depleted one)."
Read-Host "Press Enter to launch the Account A login"

$env:CLAUDE_CONFIG_DIR = $primary
& claude
Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Second session: log in as Account B (the fresh one)."
Read-Host "Press Enter to launch the Account B login"

$env:CLAUDE_CONFIG_DIR = $secondary
& claude
Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue

Write-Section "Step 3 / 3 - Smoke-ping both accounts"
function Test-Account($label, $dir) {
  Write-Host ""
  Write-Host "[$label]  CLAUDE_CONFIG_DIR=$dir"
  $env:CLAUDE_CONFIG_DIR = $dir
  try {
    $out = & claude -p "Reply with the single word: pong" --output-format text 2>&1
    Write-Host "  reply: $out"
  } catch {
    Write-Host "  ERROR: $($_.Exception.Message)"
  } finally {
    Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
  }
}
Test-Account "PRIMARY  (Account A)" $primary
Test-Account "SECONDARY(Account B)" $secondary

Write-Host ""
Write-Host "Done. Expected result right now:"
Write-Host "  PRIMARY   - credit-exhausted error (or similar quota message)"
Write-Host "  SECONDARY - the literal word 'pong' or close to it"
Write-Host ""
Write-Host "Next: trigger run_once.bat to confirm the pipeline switches"
Write-Host "from PRIMARY to SECONDARY on the first failed call. The log"
Write-Host "(logs\auto.log) should contain a [CLAUDE-AUTH] switch line."
