# [HIGH] GhostAction Campaign: Over 3,000 Secrets Stolen Through Malicious GitHub Workflows

**Source:** StepSecurity
**Published:** 2025-09-19
**Article:** https://www.stepsecurity.io/blog/ghostaction-campaign-over-3-000-secrets-stolen-through-malicious-github-workflows

## Threat Profile

Back to Blog Threat Intel GhostAction Campaign: Over 3,000 Secrets Stolen Through Malicious GitHub Workflows GitGuardian researchers discover massive supply chain attack affecting 817 repositories across 327 GitHub users. Malicious workflows exfiltrated 3,325 secrets including PyPI, npm, and DockerHub tokens through compromised developer accounts. Ashish Kurmi View LinkedIn September 5, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `45.139.104.115`
- **Domain (defanged):** `bold-dhawan.45-139-104-115.plesk.page`
- **Domain (defanged):** `objective-hopper.45-139-104-115.plesk.page`
- **Domain (defanged):** `carte-avantage.com`
- **Domain (defanged):** `493networking.cc`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1546** — Event Triggered Execution
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1609** — Container Administration Command
- **T1119** — Automated Collection
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GhostAction malicious workflow file added with curl POST to Plesk infrastructure

`UC_785_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_path="*\\.github\\workflows\\*" Filesystem.file_name="*.yml" by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | join type=inner dest [ search index=* sourcetype=*github_actions_workflow OR (source=*.yml) ("bold-dhawan.45-139-104-115.plesk.page" OR "objective-hopper.45-139-104-115.plesk.page" OR "45.139.104.115" OR "carte-avantage.com" OR "493networking.cc") | stats values(host) as host by host | rename host as dest ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has @"\.github\workflows\" or FolderPath has "/.github/workflows/"
| where FileName endswith ".yml" or FileName endswith ".yaml"
| where InitiatingProcessFileName in~ ("git.exe", "git", "code.exe", "devenv.exe", "explorer.exe", "gh.exe")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### GhostAction C2 egress to Plesk-hosted exfiltration infrastructure

`UC_785_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.src) as src from datamodel=Network_Traffic where (All_Traffic.dest="bold-dhawan.45-139-104-115.plesk.page" OR All_Traffic.dest="objective-hopper.45-139-104-115.plesk.page" OR All_Traffic.dest="*.45-139-104-115.plesk.page" OR All_Traffic.dest="carte-avantage.com" OR All_Traffic.dest="493networking.cc" OR All_Traffic.dest_ip="45.139.104.115") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("bold-dhawan.45-139-104-115.plesk.page", "objective-hopper.45-139-104-115.plesk.page", "45-139-104-115.plesk.page", "carte-avantage.com", "493networking.cc")
    or RemoteIP == "45.139.104.115"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### GhostAction curl/wget POST of CI/CD secret token to Plesk endpoint

`UC_785_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="curl.exe" OR Processes.process_name="curl" OR Processes.process_name="wget.exe" OR Processes.process_name="wget") (Processes.process="*bold-dhawan.45-139-104-115.plesk.page*" OR Processes.process="*objective-hopper.45-139-104-115.plesk.page*" OR Processes.process="*45.139.104.115*" OR Processes.process="*carte-avantage.com*" OR Processes.process="*493networking.cc*") by Processes.dest Processes.process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe", "curl", "wget.exe", "wget")
| where ProcessCommandLine has_any ("bold-dhawan.45-139-104-115.plesk.page", "objective-hopper.45-139-104-115.plesk.page", "45.139.104.115", "carte-avantage.com", "493networking.cc")
| where ProcessCommandLine matches regex @"(?i)(TOKEN|API_KEY|SECRET|PASSWORD|PAT|ACCESS_KEY)\s*="
    or ProcessCommandLine has_any ("-X POST", "--data", "--data-raw", " -d ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### GitHub Actions self-hosted runner spawning curl/wget POST to non-allowlisted egress

`UC_785_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="curl.exe" OR Processes.process_name="curl" OR Processes.process_name="wget.exe" OR Processes.process_name="wget") (Processes.parent_process_name="Runner.Worker.exe" OR Processes.parent_process_name="Runner.Listener.exe" OR Processes.parent_process_name="Runner.Worker" OR Processes.parent_process_name="actions-runner") (Processes.process="*-X POST*" OR Processes.process="*--data*" OR Processes.process="* -d *") NOT (Processes.process="*github.com*" OR Processes.process="*githubusercontent.com*" OR Processes.process="*azureedge.net*" OR Processes.process="*blob.core.windows.net*" OR Processes.process="*pypi.org*" OR Processes.process="*npmjs.org*" OR Processes.process="*docker.io*" OR Processes.process="*ghcr.io*") by Processes.dest Processes.process_name Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl.exe", "curl", "wget.exe", "wget")
| where InitiatingProcessFileName has_any ("Runner.Worker.exe", "Runner.Listener.exe", "Runner.Worker", "actions-runner", "runsvc")
| where ProcessCommandLine has_any ("-X POST", "--data", "--data-raw", "--data-binary")
| where not(ProcessCommandLine has_any ("github.com", "githubusercontent.com", "azureedge.net", "blob.core.windows.net", "pypi.org", "files.pythonhosted.org", "npmjs.org", "registry.npmjs.org", "docker.io", "registry-1.docker.io", "ghcr.io", "actions.githubusercontent.com", "pkg.actions.githubusercontent.com"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### GhostAction GitHub workflow secret-enumeration commit pattern

`UC_785_6` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype=*github* (source=*.yml OR source=*.yaml) ("secrets." OR "${{ secrets.") ("curl " OR "wget ") path=".github/workflows/*" | rex max_match=20 field=_raw "secrets\.(?<secret_name>[A-Z0-9_]+)" | stats dc(secret_name) as unique_secrets values(secret_name) as secret_names values(host) as host by source repo commit_sha author | where unique_secrets >= 3 | sort - unique_secrets
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has @"\.github\workflows\" or FolderPath has "/.github/workflows/"
| where FileName endswith ".yml" or FileName endswith ".yaml"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("git.exe", "git", "gh.exe")
    | where ProcessCommandLine has_any ("commit", "push")
    | project DeviceId, GitTime = Timestamp, InitiatingProcessAccountName, ProcessCommandLine
) on DeviceId
| where abs(datetime_diff('second', Timestamp, GitTime)) < 120
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.139.104.115`, `bold-dhawan.45-139-104-115.plesk.page`, `objective-hopper.45-139-104-115.plesk.page`, `carte-avantage.com`, `493networking.cc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
