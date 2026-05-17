# Local Setup Notes

Operator-focused setup notes for running the pipeline on a fresh Windows
machine. The main project documentation is in `README.md`; this file
covers the local-environment quirks that aren't part of the codebase
itself.

## Microsoft Defender exclusion (required on Windows)

Defender's heuristic engine routinely flags this repository because the
generated detection content contains strings that look like attack
patterns — references to `lsass`, `mimikatz`, encoded PowerShell, named
threat actors, malware family names in IOC lists, etc. These are
threat-intel artefacts being *described*, not executed, but Defender
can't tell the difference. Symptoms include:

- Briefings disappearing after a scheduled pipeline run
- `intel/.llm_*_cache/` files quarantined mid-write
- `share/uc/*.html` stubs vanishing
- Pipeline runs failing with `[!] git add` errors when a quarantined
  file gets removed from disk

**The fix is a folder-level Defender exclusion. Two ways:**

### Option A — PowerShell one-liner (recommended)

Open PowerShell **as Administrator** (right-click the Start menu →
Terminal (Admin) or PowerShell (Admin)) and run:

```powershell
Add-MpPreference -ExclusionPath "C:\Users\mckec\Downloads\DexCore 1.1.9\thn-usecases"
```

Replace the path with wherever you've cloned/extracted the project.
Verify it took:

```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

Your project folder should appear in the list. To remove later:

```powershell
Remove-MpPreference -ExclusionPath "C:\Users\mckec\Downloads\DexCore 1.1.9\thn-usecases"
```

### Option B — Windows Security UI

1. `Settings → Privacy & security → Windows Security`
2. `Virus & threat protection`
3. Under "Virus & threat protection settings", click `Manage settings`
4. Scroll to "Exclusions" → `Add or remove exclusions`
5. `Add an exclusion → Folder`
6. Pick the `thn-usecases` directory

### If something already got quarantined

In an admin PowerShell:

```powershell
Get-MpThreatDetection | Where-Object Resources -Match "thn-usecases"
```

If anything's in the list, restore it from quarantine via Windows
Security:

`Windows Security → Virus & threat protection → Protection history → click the item → Actions → Allow / Restore`

## Python + dependencies

The pipeline runs under Python 3.11+. The Windows scheduled tasks
(`ClankerusecasePipeline`, `ClankerusecaseQualityReview`) invoke the
project via `py -u generate.py` and `py -u quality_review.py`, which
uses the Python launcher from the standard Windows install.

Required Python packages (install with `py -m pip install`):
- `feedparser` — RSS source ingestion
- `requests` — HTTP fetches with retries
- `beautifulsoup4` — article body extraction
- `pyyaml` — use-case and rule YAML loading
- `anthropic` (optional) — only for the `ANTHROPIC_API_KEY` fallback
  path; not needed when running through the Claude Code OAuth session

## Claude Code CLI (for the OAuth path)

The pipeline calls `claude -p` directly via subprocess (see
`_call_claude_cli` in `generate.py`) — there is no `claude-agent-sdk`
dependency in the runtime path any more.

Requirements:
- Claude Code installed and signed in on the same Windows user as the
  scheduled task (`schtasks /Query /TN ClankerusecasePipeline /FO LIST
  /V` shows the "Run As User"; that account needs an active Claude Code
  session)
- `claude` on PATH (verify with `claude --version`)

The pipeline strips `CLAUDECODE` and `CLAUDE_CODE_ENTRYPOINT` env vars
from the spawned subprocess so the CLI starts a fresh session rather
than refusing because it thinks it's already inside one. No action
needed on the operator's side — this is automatic.

## Scheduled tasks

Two Windows Task Scheduler tasks should be active:

| Task | Schedule | Action |
|---|---|---|
| `ClankerusecasePipeline` | Every 2h at `xx:30` (06:30, 08:30, …) | `run_once.bat` — main generation pipeline |
| `ClankerusecaseQualityReview` | Every 2h at `xx:30` offset (07:30, 09:30, …) | `run_review.bat` — off-hour quality-review pass |

Both honour `intel/.pipeline.lock` so they won't race even if a run
overruns. Verify with:

```powershell
schtasks /Query /TN "ClankerusecasePipeline" /FO LIST /V | Select-String "Next Run|Status"
schtasks /Query /TN "ClankerusecaseQualityReview" /FO LIST /V | Select-String "Next Run|Status"
```

## Logs

- `logs/auto.log` — main pipeline output (scheduled-task and manual
  runs that go through `run_once.bat`)
- `logs/review.log` — quality-review pass output
- `logs/manual_run*.stdout.log` / `.stderr.log` — direct `py -u
  generate.py` invocations (when launched outside `run_once.bat`)

The pipeline uses `py -u` everywhere to disable Python's output
buffering — without this, crash traces never reach disk because they
sit in stdout buffer until the process exits cleanly.
