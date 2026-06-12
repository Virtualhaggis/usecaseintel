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
DINUM, the French government's digital affairs directorate,  disclosed on Monday  that a threat actor gained access to the Tchap platform using a compromised user account and notified France's data protection authorit…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `tchap.gouv.fr`
- **Domain (defanged):** `matrix.agent.education.tchap.gouv.fr`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1199** — Trusted Relationship
- **T1005** — Data from Local System
- **T1530** — Data from Cloud Storage
- **T1119** — Automated Collection
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1567.002** — Exfiltration to Cloud Storage
- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1087** — Account Discovery
- **T1087.004** — Account Discovery: Cloud Account
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### First-seen device/user authenticating to Tchap (tchap.gouv.fr) matrix endpoint

`UC_25_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true earliest(_time) as firstTime latest(_time) as lastTime count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr")) by All_Traffic.src All_Traffic.user All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | where firstTime > relative_time(now(), "-24h") | sort - firstTime
```

**Defender KQL:**
```kql
let LookbackBaseline = 30d;
let RecentWindow = 24h;
let TchapDomains = dynamic(["tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr"]);
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(LookbackBaseline) .. ago(RecentWindow))
    | where RemoteUrl has_any (TchapDomains)
    | summarize by DeviceId, InitiatingProcessAccountName;
DeviceNetworkEvents
| where Timestamp > ago(RecentWindow)
| where RemoteUrl has_any (TchapDomains)
| where InitiatingProcessAccountName !endswith "$"
| join kind=leftanti Baseline on DeviceId, InitiatingProcessAccountName
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### High-volume scripted access to Tchap Matrix endpoint (bulk public-room scraping)

`UC_25_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr") by All_Traffic.src All_Traffic.user _time span=1h | `drop_dm_object_name(All_Traffic)` | where count > 500 | sort - count
```

**Defender KQL:**
```kql
let TchapDomains = dynamic(["tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr"]);
let ScriptedClients = dynamic(["powershell.exe","pwsh.exe","curl.exe","wget.exe","python.exe","python3.exe","node.exe","go.exe","httpie.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (TchapDomains)
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(),
            DistinctRemoteIPs = dcount(RemoteIP),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            DurationMin = datetime_diff('minute', max(Timestamp), min(Timestamp))
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnCount > 500 or (InitiatingProcessFileName in~ (ScriptedClients) and ConnCount > 50)
| order by ConnCount desc
```

### PowerShell process invoking LDAP:// with hardcoded plaintext credential

`UC_25_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") Processes.process="*LDAP://*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | search process_cmd="*DirectoryEntry*" OR process_cmd="*DirectorySearcher*" OR process_cmd="*ConvertTo-SecureString*" OR process_cmd="*NetworkCredential*" OR process_cmd="*-Password*" OR process_cmd="*PrincipalContext*" | sort - lastTime
```

**Defender KQL:**
```kql
let LdapMarker = "LDAP://";
let CredMarkers = dynamic(["DirectoryEntry","DirectorySearcher","ConvertTo-SecureString","NetworkCredential","-Password","PrincipalContext","AccountManagement"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
   or InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has LdapMarker or InitiatingProcessCommandLine has LdapMarker
| where ProcessCommandLine has_any (CredMarkers) or InitiatingProcessCommandLine has_any (CredMarkers)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Multi-GB outbound transfer from single user to Tchap/Matrix endpoint (exfil volume)

`UC_25_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true sum(All_Traffic.bytes_in) as bytes_in sum(All_Traffic.bytes_out) as bytes_out count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr") by All_Traffic.src All_Traffic.user _time span=4h | `drop_dm_object_name(All_Traffic)` | where bytes_in > 1073741824 | eval gb_in=round(bytes_in/1073741824,2) | sort - bytes_in
```

**Defender KQL:**
```kql
let TchapDomains = dynamic(["tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (TchapDomains)
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            DurationMin = datetime_diff('minute', max(Timestamp), min(Timestamp))
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, bin(Timestamp, 4h)
| where ConnCount > 2000 and DurationMin between (5 .. 240)
| extend ConnsPerMin = round(todouble(ConnCount) / max_of(DurationMin, 1), 1)
| order by ConnCount desc
```

### Bulk Matrix profile/room-member enumeration against Tchap endpoint

`UC_25_6` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web.Web where Web.dest IN ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr") (Web.url="*/profile/*" OR Web.url="*/joined_members*" OR Web.url="*/members*" OR Web.url="*/state*" OR Web.url="*/messages*") by Web.src Web.user _time span=1h | `drop_dm_object_name(Web)` | where count > 500 | sort - count
```

**Defender KQL:**
```kql
let TchapDomains = dynamic(["tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr"]);
let ScriptedClients = dynamic(["powershell.exe","pwsh.exe","curl.exe","wget.exe","python.exe","python3.exe","node.exe","httpie.exe","go.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (TchapDomains)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName in~ (ScriptedClients)
   or InitiatingProcessCommandLine has_any ("/_matrix/client/","/joined_members","/profile/","/members")
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 1h)
| where ConnCount > 50
| order by ConnCount desc
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

Severity classified as **MED** based on: IOCs present, 7 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
