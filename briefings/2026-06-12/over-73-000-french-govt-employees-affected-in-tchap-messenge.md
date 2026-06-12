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
- **T1078** — Valid Accounts
- **T1566** — Phishing
- **T1005** — Data from Local System
- **T1530** — Data from Cloud Storage
- **T1213** — Data from Information Repositories
- **T1552.001** — Credentials In Files
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1020** — Automated Exfiltration
- **T1087.004** — Account Discovery: Cloud Account

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anomalous endpoint authentication to Tchap (tchap.gouv.fr) — possible hijacked account

`UC_16_2` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*tchap.gouv.fr*" OR Web.url="*matrix.agent.education.tchap.gouv.fr*") by Web.src Web.user Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | eventstats dc(src) as orgSrcDistinct, dc(user) as orgUserDistinct by url | where firstTime > relative_time(now(),"-7d") AND orgUserDistinct < 5 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(60d) .. ago(7d))
    | where RemoteUrl has_any ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr")
    | summarize by DeviceId, InitiatingProcessAccountUpn;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr")
| join kind=leftanti Baseline on DeviceId, InitiatingProcessAccountUpn
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Urls=make_set(RemoteUrl, 25)
          by DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteIP
| order by FirstSeen desc
```

### Bulk Matrix/Tchap public room scraping (high-volume API fetches per single account)

`UC_16_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*matrix.agent.education.tchap.gouv.fr*" OR Web.url="*tchap.gouv.fr/_matrix/*" OR Web.url="*/rooms/*/messages*" OR Web.url="*/sync*" OR Web.url="*publicRooms*") by Web.src Web.user Web.url _time span=10m | `drop_dm_object_name(Web)` | stats sum(count) as reqs dc(url) as distinctUrls by src user _time | where reqs > 500 OR distinctUrls > 50
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr")
| summarize Connections=count(), DistinctRemoteIPs=dcount(RemoteIP), Bucket=bin(Timestamp, 10m)
          by DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName
| where Connections > 500    // empirically a Tchap desktop client averages <50 conns / 10 min
| order by Connections desc
```

### PowerShell with hardcoded LDAP bind credentials (Tchap-style leak)

`UC_16_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","powershell_ise.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process, "(?i)(LDAP://|DirectoryEntry|System\.DirectoryServices|LdapConnection|PrincipalContext)") AND match(process, "(?i)(NetworkCredential|ConvertTo-SecureString|password|userPassword|-pwd|secret|bind)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
   or InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
| where ProcessCommandLine has_any ("LDAP://","DirectoryEntry","System.DirectoryServices.Protocols","System.DirectoryServices","LdapConnection","PrincipalContext")
| where ProcessCommandLine has_any ("NetworkCredential","ConvertTo-SecureString","-Password","PasswordCredential","userPassword","bindDN","secret")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Large outbound transfer from endpoint to Tchap/Matrix FQDNs (potential 13.5GB-style exfil)

`UC_16_5` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true sum(Web.bytes_in) as bytes_in count from datamodel=Web.Web where (Web.url="*tchap.gouv.fr*" OR Web.url="*matrix.agent.education.tchap.gouv.fr*") by Web.src Web.user _time span=1h | `drop_dm_object_name(Web)` | where bytes_in > 1073741824    // 1 GiB / hour from a single src is far above baseline | sort - bytes_in
```

### Bulk user-profile enumeration via Tchap Matrix /publicRooms API

`UC_16_6` · phase: **recon** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*tchap.gouv.fr*" OR Web.url="*matrix.agent.education.tchap.gouv.fr*") AND (Web.url="*publicRooms*" OR Web.url="*/joined_members*" OR Web.url="*/members*" OR Web.url="*profile*") by Web.src Web.user Web.url _time span=15m | `drop_dm_object_name(Web)` | stats sum(count) as reqs dc(url) as distinctUrls by src user _time | where reqs > 200 OR distinctUrls > 30
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("tchap.gouv.fr","matrix.agent.education.tchap.gouv.fr")
| where RemoteUrl has_any ("publicRooms","/joined_members","/members","profile")
| summarize EnumRequests=count(), DistinctUrls=dcount(RemoteUrl), Bucket=bin(Timestamp, 15m)
          by DeviceId, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName
| where EnumRequests > 200 or DistinctUrls > 30
| order by EnumRequests desc
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

Severity classified as **MED** based on: IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
