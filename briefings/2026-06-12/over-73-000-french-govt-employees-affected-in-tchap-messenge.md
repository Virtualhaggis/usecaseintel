# [MED] Over 73,000 French govt employees affected in Tchap messenger breach

**Source:** BleepingComputer
**Published:** 2026-06-12
**Article:** https://www.bleepingcomputer.com/news/security/french-govt-says-tchap-breach-affected-over-73-000-accounts/

## Threat Profile

Over 73,000 French govt employees affected in Tchap messenger breach 
By Sergiu Gatlan 
June 12, 2026
03:09 AM
0 


The French government revealed that a recent breach of its Tchap encrypted messaging platform affects the accounts of over 73,000 employees in the French public sector.


DINUM, the French government's digital affairs directorate,  disclosed on Monday  that a threat actor gained access to the Tchap platform using a compromised user account and notified France's data protection …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `tchap.gouv.fr`
- **Domain (defanged):** `matrix.agent.education.tchap.gouv.fr`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1078** — Valid Accounts
- **T1566** — Phishing
- **T1087** — Account Discovery
- **T1083** — File and Directory Discovery
- **T1213** — Data from Information Repositories
- **T1552.001** — Credentials In Files
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### First-time endpoint connection to Tchap homeserver (tchap.gouv.fr) for a user

`UC_0_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.dest like "%tchap.gouv.fr" earliest=-1d by Network_Traffic.src Network_Traffic.user Network_Traffic.dest | `drop_dm_object_name(Network_Traffic)` | join type=left src user [| tstats summariesonly=true count as baselineHits from datamodel=Network_Traffic where Network_Traffic.dest like "%tchap.gouv.fr" earliest=-31d latest=-1d by Network_Traffic.src Network_Traffic.user | `drop_dm_object_name(Network_Traffic)`] | where isnull(baselineHits) OR baselineHits=0
```

**Defender KQL:**
```kql
let lookback = 1d;
let baseline = DeviceNetworkEvents
    | where Timestamp between (ago(31d) .. ago(lookback))
    | where RemoteUrl has_any ("tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr")
    | summarize by DeviceId, InitiatingProcessAccountUpn;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any ("tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr")
| where InitiatingProcessAccountName !endswith "$"
| join kind=leftanti baseline on DeviceId, InitiatingProcessAccountUpn
| summarize FirstSeen = min(Timestamp),
            ConnectionCount = count(),
            Hosts = make_set(RemoteUrl, 5),
            Clients = make_set(InitiatingProcessFileName, 5)
            by DeviceId, DeviceName, InitiatingProcessAccountUpn
| order by FirstSeen desc
```

### High-rate Matrix room/member enumeration against tchap.gouv.fr from single client

`UC_0_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.url like "%tchap.gouv.fr%" AND (Web.url like "%/_matrix/client/%/rooms%" OR Web.url like "%/joined_members%" OR Web.url like "%/members%" OR Web.url like "%/publicRooms%" OR Web.url like "%/sync%") by _time span=5m Web.src Web.user | `drop_dm_object_name(Web)` | where count > 500
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has "tchap.gouv.fr"
| where RemoteUrl has_any ("/_matrix/client", "/rooms", "/joined_members", "/members", "/publicRooms", "/sync")
| where InitiatingProcessAccountName !endswith "$"
| summarize ApiCalls = count(),
            DistinctUrls = dcount(RemoteUrl),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleUrls = make_set(RemoteUrl, 10)
            by bin(Timestamp, 5m), DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName
| where ApiCalls > 500 and DistinctUrls > 50
| extend BurstSeconds = datetime_diff('second', LastSeen, FirstSeen)
| order by ApiCalls desc
```

### PowerShell scripts embedding hardcoded LDAP credentials (Tchap-style leak)

`UC_0_4` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") AND Processes.process=*LDAP://* AND (Processes.process="*password*" OR Processes.process="*pwd*" OR Processes.process="*bindpassword*" OR Processes.process="*ConvertTo-SecureString*") by Processes.user Processes.dest Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | regex process="(?i)LDAP://[^\s\"\']+" | regex process="(?i)(password|pwd|bindpassword|secret)\s*[=:]\s*\S{4,}"
```

**Defender KQL:**
```kql
let suspectScripts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine matches regex @"(?i)LDAP://[^\s\"']+"
    | where ProcessCommandLine matches regex @"(?i)(password|pwd|bindpassword|secret|cn\s*=\s*[^,]+,\s*dc\s*=)\s*[=:]?\s*\S{4,}"
    | where AccountName !endswith "$"
    | project Timestamp, DeviceId, DeviceName, AccountName, AccountUpn,
              FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName, SHA256;
let droppedFromTchap = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName endswith ".ps1" or FileName endswith ".psm1"
    | where FileOriginUrl has_any ("tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr")
    | project Timestamp, DeviceId, DeviceName, FileName, FolderPath, FileOriginUrl,
              InitiatingProcessFileName, InitiatingProcessAccountUpn, SHA256;
suspectScripts
| union kind=outer droppedFromTchap
| order by Timestamp desc
```

### Bulk download from Tchap homeserver to single endpoint (media/attachment exfil)

`UC_0_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true sum(Web.bytes_in) as bytesIn count as hits from datamodel=Web where Web.url like "%tchap.gouv.fr%" AND (Web.url like "%/_matrix/media/%" OR Web.url like "%/download/%" OR Web.url like "%/thumbnail/%") by _time span=15m Web.src Web.user | `drop_dm_object_name(Web)` | where bytesIn > 524288000 OR hits > 2000
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has "tchap.gouv.fr"
| where RemoteUrl has_any ("/_matrix/media", "/download", "/thumbnail")
| where InitiatingProcessAccountName !endswith "$"
| summarize MediaCalls = count(),
            DistinctMedia = dcount(RemoteUrl),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Clients = make_set(InitiatingProcessFileName, 5)
            by bin(Timestamp, 15m), DeviceId, DeviceName, InitiatingProcessAccountUpn
| where MediaCalls > 2000 and DistinctMedia > 500
| extend BurstSeconds = datetime_diff('second', LastSeen, FirstSeen)
| order by MediaCalls desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `tchap.gouv.fr`, `matrix.agent.education.tchap.gouv.fr`


## Why this matters

Severity classified as **MED** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
