# [HIGH] xygeni-action Compromised: C2 Reverse Shell Backdoor Injected via Tag Poisoning

**Source:** StepSecurity
**Published:** 2026-03-26
**Article:** https://www.stepsecurity.io/blog/xygeni-action-compromised-c2-reverse-shell-backdoor-injected-via-tag-poisoning

## Threat Profile

Back to Blog Threat Intel xygeni-action Compromised: C2 Reverse Shell Backdoor Injected via Tag Poisoning The official Xygeni GitHub Action (xygeni-action) was compromised on March 3, 2026, when an attacker using stolen maintainer credentials injected a full C2 reverse shell backdoor and silently moved the mutable v5 tag to the malicious commit - affecting all repositories referencing @v5 without any visible change to their workflow files. The v5 tag remains poisoned as of March 9; users should …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.214.78.178`
- **Domain (defanged):** `security-verify.91.214.78.178.nip`
- **SHA1:** `13c6ed2797df7d85749864e2cbcf09c893f43b23`
- **SHA1:** `ea66a5ad3128270e853f46013be382e761d930b9`
- **SHA1:** `4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1132.001** — Data Encoding: Standard Encoding
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] xygeni-action C2 callback to 91.214.78.178 (incl. nip.io wildcard)

`UC_323_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.src) as src values(All_Traffic.app) as app from datamodel=Network_Traffic where All_Traffic.dest="91.214.78.178" OR All_Traffic.dest_host="*.91.214.78.178.nip.io" OR All_Traffic.url="*91.214.78.178.nip.io*" by All_Traffic.dest All_Traffic.dest_host All_Traffic.url All_Traffic.src host | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query="*91.214.78.178.nip.io" by DNS.query DNS.src host | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// xygeni-action C2 — 91.214.78.178 + nip.io wildcard
let c2_ip = "91.214.78.178";
let c2_host_suffix = "91.214.78.178.nip.io";
union isfuzzy=true
    ( DeviceNetworkEvents
        | where Timestamp > ago(30d)
        | where RemoteIP == c2_ip
           or RemoteUrl has c2_host_suffix
        | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
                  InitiatingProcessFileName, InitiatingProcessCommandLine,
                  InitiatingProcessAccountName, InitiatingProcessFolderPath ),
    ( DeviceEvents
        | where Timestamp > ago(30d)
        | where ActionType == "DnsQueryResponse"
        | extend Q = tostring(parse_json(AdditionalFields).QueryName)
        | where Q endswith c2_host_suffix
        | project Timestamp, DeviceName, RemoteUrl=Q,
                  InitiatingProcessFileName, InitiatingProcessCommandLine,
                  InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] xygeni-action backdoor process pattern — curl with X-B auth header to /b/in|/b/q|/b/r

`UC_323_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="curl" OR Processes.process_name="curl.exe") AND (Processes.process="*91.214.78.178.nip.io*" OR Processes.process="*X-B: sL5x*" OR Processes.process="*/b/in*" OR Processes.process="*/b/q?b=*" OR Processes.process="*/b/r*") by host Processes.process_name Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// xygeni-action implant — curl/python3 invocation pattern in action.yml step
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl","curl.exe","bash","sh","dash","python3","python")
   or InitiatingProcessFileName in~ ("curl","curl.exe","bash","sh","dash")
| where ProcessCommandLine has_any (
        "91.214.78.178.nip.io",
        "91.214.78.178",
        "X-B: sL5x",       // unique authentication header from backdoor
        "sL5x#9kR!vQ2",    // header value fragment
        "/b/in","/b/q?b=","/b/r"
    )
   or InitiatingProcessCommandLine has_any (
        "91.214.78.178.nip.io","X-B: sL5x","/b/q?b="
    )
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          GrandparentFile = InitiatingProcessParentFileName,
          FolderPath
| order by Timestamp desc
```

### [LLM] Repository workflow reference to compromised xygeni-action@v5 tag

`UC_323_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.github/workflows/*.yml" OR Filesystem.file_path="*/.github/workflows/*.yaml" OR Filesystem.file_name="action.yml") AND Filesystem.action!="deleted" by host Filesystem.file_path Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=outer host [ search index=* sourcetype IN ("git_repo_files","github:audit","yaml") ("xygeni/xygeni-action@v5" OR "xygeni/xygeni-action@4bf1d4e*") | stats values(repo) as repo by host ] | where isnotnull(repo) OR searchmatch("xygeni/xygeni-action@v5") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Hunt: workflow YAML files that may still reference the poisoned xygeni-action@v5 tag
// Note: filename + path heuristic — content scan must be confirmed by repo grep.
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\.github\workflows\" or FolderPath has @"/.github/workflows/"
   or FileName =~ "action.yml" or FileName =~ "action.yaml"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "xygeni/xygeni-action@v5"
       or ProcessCommandLine has "xygeni-action@4bf1d4e"
    | project DeviceName, GitCmd = ProcessCommandLine, GitTime = Timestamp
  ) on DeviceName
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — xygeni-action Compromised: C2 Reverse Shell Backdoor Injected via Tag Poisoning

`UC_323_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — xygeni-action Compromised: C2 Reverse Shell Backdoor Injected via Tag Poisoning ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — xygeni-action Compromised: C2 Reverse Shell Backdoor Injected via Tag Poisoning
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.214.78.178`, `security-verify.91.214.78.178.nip`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `13c6ed2797df7d85749864e2cbcf09c893f43b23`, `ea66a5ad3128270e853f46013be382e761d930b9`, `4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
