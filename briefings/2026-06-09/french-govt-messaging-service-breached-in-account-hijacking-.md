# [MED] French govt messaging service breached in account hijacking attack

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/security/french-govt-messaging-service-breached-in-account-hijacking-attack/

## Threat Profile

French govt messaging service breached in account hijacking attack 
By Sergiu Gatlan 
June 9, 2026
06:53 AM
0 
DINUM, the digital affairs directorate of the French government, warned that hackers used a hijacked user account to breach Tchap, the French government's encrypted messaging platform.
Developed in-house by DINUM in collaboration with ANSSI (the French Cybersecurity Agency) in 2018, Tchap is an instant messaging service and collaboration tool based on the decentralized Matrix protocol, …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `matrix.agent.education.tchap.gouv.fr`
- **Domain (defanged):** `tchap.gouv.fr`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1530** — Data from Cloud Storage
- **T1213.003** — Code Repositories / Internal Data Sharing
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1213** — Data from Information Repositories
- **T1087** — Account Discovery
- **T1087.003** — Email Account

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mass /_matrix/media/ bulk download from tchap.gouv.fr to a single endpoint (Tchap exfil)

`UC_24_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as downloads, dc(Web.url) as distinct_media, sum(Web.bytes_in) as bytes_pulled, values(Web.dest) as shards from datamodel=Web where Web.dest_domain="tchap.gouv.fr" OR Web.dest="*.tchap.gouv.fr" Web.url="*/_matrix/media/*download*" by Web.src, Web.user, _time span=1h | `drop_dm_object_name("Web")` | where downloads > 100 OR bytes_pulled > 1073741824 OR mvcount(shards) > 2 | sort - bytes_pulled
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "tchap.gouv.fr"
| where RemoteUrl has "/_matrix/media/" and RemoteUrl has "download"
| extend Shard = tostring(parse_url(RemoteUrl).Host)
| summarize Downloads = count(),
            DistinctMedia = dcount(RemoteUrl),
            ShardsTouched = dcount(Shard),
            ShardList = make_set(Shard, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Downloads > 100 or ShardsTouched > 2  // 100 = empirical Tchap-client baseline ceiling; >2 shards from one client is anomalous (1 user = 1 shard normally)
| order by Downloads desc
```

### PowerShell script containing hardcoded LDAP bind with plaintext password (Tchap-leak vector)

`UC_24_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as cmd, min(_time) as first_seen from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*DirectoryEntry*" OR Processes.process="*LDAP://*" OR Processes.process="*System.DirectoryServices*" OR Processes.process="*ADSI*") by Processes.user, Processes.dest, Processes.parent_process_name | `drop_dm_object_name("Processes")` | where match(cmd, "(?i)(password|pwd|secret|pass)\s*[:=]\s*[\"'][^\"']{4,}") | sort - first_seen
```

**Defender KQL:**
```kql
// Hunt PowerShell processes whose command-line carries an LDAP bind AND a plaintext-password literal
let LdapPatterns = pack_array("DirectoryEntry", "LDAP://", "System.DirectoryServices", "ADSI", "DirectorySearcher");
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (LdapPatterns)
| where ProcessCommandLine matches regex @"(?i)(password|pwd|secret|userpassword|pass)\s*[:=]\s*[\"'][^\"'\s]{4,}"
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentProcess = InitiatingProcessFileName,
          ProcessCommandLine,
          FolderPath, SHA256
| order by Timestamp desc
// Cross-pivot: same script in DeviceFileEvents writes — likely the shareable .ps1 the actor exfiltrated
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName endswith ".ps1"
    | project FileTimestamp = Timestamp, DeviceName, ScriptFile = FileName, ScriptPath = FolderPath, ScriptSHA = SHA256
  ) on DeviceName
```

### High-rate Matrix client API enumeration against tchap.gouv.fr (room/user/media scraping)

`UC_24_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as api_calls, dc(Web.url) as distinct_endpoints, values(Web.url) as urls from datamodel=Web where Web.dest_domain="tchap.gouv.fr" OR Web.dest="*.tchap.gouv.fr" (Web.url="*/_matrix/client/*/sync*" OR Web.url="*/_matrix/client/*/joined_rooms*" OR Web.url="*/_matrix/client/*/publicRooms*" OR Web.url="*/_matrix/client/*/members*" OR Web.url="*/_matrix/client/*/rooms/*/members*" OR Web.url="*/_matrix/client/*/directory/*") by Web.src, Web.user, _time span=10m | `drop_dm_object_name("Web")` | where api_calls > 500 OR distinct_endpoints > 50 | sort - api_calls
```

**Defender KQL:**
```kql
let MatrixEnumPaths = dynamic(["/_matrix/client/r0/sync", "/_matrix/client/v3/sync", "/joined_rooms", "/publicRooms", "/members", "/directory/room", "/directory/list"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "tchap.gouv.fr"
| where RemoteUrl has_any (MatrixEnumPaths)
| extend Shard = tostring(parse_url(RemoteUrl).Host),
         Endpoint = tostring(parse_url(RemoteUrl).Path)
| summarize ApiCalls = count(),
            DistinctEndpoints = dcount(Endpoint),
            ShardsTouched = dcount(Shard),
            ShardList = make_set(Shard, 10),
            EndpointSample = make_set(Endpoint, 20),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where ApiCalls > 500 or DistinctEndpoints > 50 or ShardsTouched > 2  // 500/10min ≈ 50× a Matrix client's idle sync rate
| order by ApiCalls desc
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
  - IP / domain IOC(s): `matrix.agent.education.tchap.gouv.fr`, `tchap.gouv.fr`


## Why this matters

Severity classified as **MED** based on: IOCs present, 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
