# [HIGH] GitHub Secret Scanning Public Monitoring for Enterprises: Coverage and Gaps

**Source:** StepSecurity
**Published:** 2026-07-12
**Article:** https://www.stepsecurity.io/blog/github-secret-scanning-public-monitoring-for-enterprises-coverage-and-gaps

## Threat Profile

Back to Blog Resources GitHub Secret Scanning Public Monitoring for Enterprises: Coverage and Gaps GitHub's new public monitoring finds your enterprise's leaked secrets anywhere on github.com. Here is what it covers, what it cannot see, and how to close the exfiltration gap Eromosele Akhigbe View LinkedIn July 6, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
GitHub's new public monitoring finds your enterprise's leaked secre…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **IPv4 (defanged):** `45.139.104.115`
- **IPv4 (defanged):** `216.126.225.129`
- **Domain (defanged):** `bold-dhawan.45-139-104-115.plesk.page`
- **Domain (defanged):** `objective-hopper.45-139-104-115.plesk.page`
- **Domain (defanged):** `carte-avantage.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1543** — Create or Modify System Process
- **T1102** — Web Service
- **T1485** — Data Destruction
- **T1070.004** — Indicator Removal: File Deletion
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sha1-Hulud 2.0 npm worm payload files (setup_bun.js / bun_environment.js) written or executed

`UC_237_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("setup_bun.js","bun_environment.js") OR Filesystem.file_hash IN ("a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("setup_bun.js","bun_environment.js")
   or SHA256 in~ ("a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Cloud IMDS credential harvesting by node/npm/bun during package install (Sha1-Hulud/Megalodon)

`UC_237_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest="169.254.169.254" AND All_Traffic.app IN ("node.exe","node","npm","npm.cmd","bun","bun.exe","yarn","pnpm") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "169.254.169.254" or RemoteUrl has "metadata.google.internal"
| where InitiatingProcessFileName in~ ("node.exe","node","npm","npm.cmd","bun","bun.exe","yarn","pnpm")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### TruffleHog secret scanner spawned from an npm/bun package-install context (Sha1-Hulud)

`UC_237_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="trufflehog*" OR Processes.process="*trufflehog*") AND Processes.parent_process_name IN ("node.exe","node","bun","bun.exe","npm","npm.cmd","yarn","pnpm","sh","bash") by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has "trufflehog" or ProcessCommandLine has "trufflehog"
| where InitiatingProcessFileName in~ ("node.exe","node","bun","bun.exe","npm","npm.cmd","yarn","pnpm","sh","bash")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Malicious 'SHA1HULUD' self-hosted GitHub Actions runner installation / persistence

`UC_237_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*SHA1HULUD*" OR Processes.process="*RUNNER_ALLOW_RUNASROOT*" OR Processes.process="*.dev-env*" OR Processes.process="*actions-runner-linux-x64-2.330.0*") by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("SHA1HULUD","RUNNER_ALLOW_RUNASROOT",".dev-env","actions-runner-linux-x64-2.330.0")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Sha1-Hulud destructive wiper fallback (cipher /W, recursive del, shred over home dir)

`UC_237_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="cipher.exe" AND Processes.process="*/W:*") OR (Processes.process="*shred*" AND Processes.process="*-uvz*") OR (Processes.process="*del*" AND Processes.process="*/F*" AND Processes.process="*/Q*" AND Processes.process="*/S*" AND Processes.process="*USERPROFILE*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "cipher.exe" and ProcessCommandLine has "/W:")
    or (ProcessCommandLine has "shred" and ProcessCommandLine has "-uvz")
    or (ProcessCommandLine has_all ("del","/F","/Q","/S") and ProcessCommandLine has "USERPROFILE")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### CI/dev host exfiltrating to api.github.com shortly after cloud IMDS harvest (Sha1-Hulud exfil chain)

`UC_237_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic where All_Traffic.app IN ("node.exe","node","bun","bun.exe","npm","yarn","pnpm","git","git.exe","curl","curl.exe") by All_Traffic.src All_Traffic.dest All_Traffic.app _time span=1s
| `drop_dm_object_name(All_Traffic)`
| eval isImds=if(dest=="169.254.169.254",1,0), isGh=if(match(dest,"(?i)github\.com"),1,0)
| where isImds=1 OR isGh=1
| stats min(eval(if(isImds=1,_time,null()))) as imdsTime max(eval(if(isGh=1,_time,null()))) as ghTime values(app) as apps by src
| where isnotnull(imdsTime) AND isnotnull(ghTime) AND ghTime>=imdsTime AND (ghTime-imdsTime)<=1800
| sort - ghTime
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let WindowMinutes = 30m;
let Imds = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where RemoteIP == "169.254.169.254" or RemoteUrl has "metadata.google.internal"
    | where InitiatingProcessFileName in~ ("node.exe","node","bun","bun.exe","npm","yarn","pnpm")
    | project ImdsTime = Timestamp, DeviceId, HarvestProc = InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has_any ("api.github.com","github.com")
| where InitiatingProcessFileName in~ ("node.exe","node","bun","bun.exe","npm","yarn","pnpm","git","git.exe","curl","curl.exe")
| join kind=inner Imds on DeviceId
| where Timestamp between (ImdsTime .. ImdsTime + WindowMinutes)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, ImdsTime, HarvestProc, DelayMin = datetime_diff('minute', Timestamp, ImdsTime)
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30066`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.139.104.115`, `216.126.225.129`, `bold-dhawan.45-139-104-115.plesk.page`, `objective-hopper.45-139-104-115.plesk.page`, `carte-avantage.com`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
