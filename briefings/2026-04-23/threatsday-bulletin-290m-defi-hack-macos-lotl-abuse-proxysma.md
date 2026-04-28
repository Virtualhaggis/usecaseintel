<!-- curated:true -->
# [MED] ThreatsDay Bulletin: $290M DeFi Hack, macOS LotL Abuse, ProxySmart SIM Farms + 25 More

**Source:** The Hacker News
**Published:** 2026-04-23
**Article:** https://thehackernews.com/2026/04/threatsday-bulletin-290m-defi-hack.html
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

A weekly digest piece — themes worth tagging:

1. **$290M DeFi hack** — yet another smart-contract / bridge / oracle exploit; mostly relevant to crypto-native orgs.
2. **macOS Living-off-the-Land (LotL) abuse** — adversaries chaining built-in macOS binaries (`osascript`, `curl`, `softwareupdate`, `nscurl`, `mdfind`) instead of dropping malware. **High SOC value** — most macOS detection is built around malicious-binary signatures, missing LotL chains entirely.
3. **ProxySmart SIM farms** — telephony fraud at scale; relevant to anti-fraud teams more than enterprise SOC.
4. **+25 supporting stories** — the detection backlog is shaped by repeating themes (supply-chain compromise, package compromise, edge-device exploitation).

For SOC operations, the **macOS LotL** thread is the actionable take. We've kept severity **MED** because the digest format is broad rather than specific, but flagged macOS LotL detection as the single most-leveraged item.

## Indicators of Compromise

- _Cross-reference to specific stories — most have their own briefings or will._
- macOS LotL fingerprints (more durable than per-incident IOCs):
  - `osascript -e` running `curl` / `do shell script` / multi-line AppleScript with reverse-shell pattern.
  - `softwareupdate --list` / `--install` from non-`launchd` parents.
  - `mdfind` / `find` enumerating broad filesystem paths from non-Spotlight contexts.
  - `nscurl` (rare; native HTTP fetcher) with non-Apple destinations.

## MITRE ATT&CK (analyst-validated)

- **T1059.002** — AppleScript (osascript)
- **T1059.004** — Unix Shell (bash, sh, zsh)
- **T1218** — System Binary Proxy Execution (LotL category)
- **T1083** — File and Directory Discovery (mdfind / find / locate)
- **T1195.002** — Compromise Software Supply Chain
- **T1657** — Financial Theft (the DeFi-hack thread)

## Recommended SOC actions (priority-ordered)

1. **Build macOS LotL detection** — see queries below. This is the single highest-leverage macOS detection investment for the year.
2. **Audit your macOS endpoint coverage.** If you don't have process-event telemetry from your Mac fleet, build that integration first; LotL detection is impossible without it.
3. **Run the `osascript -e` hunt** with content patterns matching reverse-shell / network-fetch — high-fidelity for malicious AppleScript.
4. **Cross-reference to per-story briefings** — DeFi / SIM-farm / supply-chain stories have dedicated detection content elsewhere.

## Splunk SPL — macOS osascript with shell / network content

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name="osascript"
      AND (Processes.process="*do shell script*"
        OR Processes.process="*do JavaScript*"
        OR Processes.process="*curl*"
        OR Processes.process="*wget*"
        OR Processes.process="*nc*"
        OR Processes.process="*bash -i*"
        OR Processes.process="*/dev/tcp/*"
        OR Processes.process="*tell application*"
        OR Processes.process="*exec*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — macOS softwareupdate from non-system parent

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where Processes.process_name="softwareupdate"
      AND Processes.parent_process_name!="launchd"
      AND Processes.parent_process_name!="systemstats"
      AND Processes.parent_process_name!="System Preferences"
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Splunk SPL — macOS broad mdfind / find enumeration

```spl
| tstats `summariesonly` count
    from datamodel=Endpoint.Processes
    where (Processes.process_name="mdfind"
        OR Processes.process_name="find")
      AND (Processes.process="* / *"
        OR Processes.process="*/Users*"
        OR Processes.process="*kMDItemKind*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process,
       Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

## Defender KQL — macOS osascript with shell content

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName == "osascript"
| where ProcessCommandLine has_any (
    "do shell script", "do JavaScript", "curl ", "wget ", " nc ",
    "bash -i", "/dev/tcp/", "tell application", "exec ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — macOS softwareupdate from non-system parent

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName == "softwareupdate"
| where InitiatingProcessFileName !in~ ("launchd","systemstats","System Preferences")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Defender KQL — macOS Spotlight enumeration from non-Spotlight contexts

```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where FileName in~ ("mdfind","find")
| where ProcessCommandLine has_any (" / ", "/Users", "kMDItemKind")
| where InitiatingProcessFileName !in~ ("Spotlight","mds","mdworker","Finder")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

Digest articles are best read as a **scope-broadening exercise**: do my detections cover the full picture? The macOS LotL thread is the most actionable item in this week's bulletin because:

1. It's a generalised TTP class (not one actor's tooling).
2. Most enterprise SOCs have weak macOS LotL coverage.
3. The detections are simple, high-fidelity, and easy to baseline.

Run the `osascript` hunt this week as a self-audit. If you have *any* hits where `osascript` is invoking shell or network commands from non-developer endpoints, you have macOS adversary tradecraft on your fleet. Most likely it's adware or commodity stealer; occasionally it's APT.
