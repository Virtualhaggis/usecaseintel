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
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1078.002** — Valid Accounts: Domain Accounts
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PowerShell invoked with hardcoded LDAP bind credentials (Tchap leaked-script pattern)

`UC_6_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*LDAP://*" OR Processes.process="*DirectoryEntry*" OR Processes.process="*DirectorySearcher*" OR Processes.process="*ConvertTo-SecureString*" OR Processes.process="*PSCredential*") (Processes.process="*-AsPlainText*" OR Processes.process="*Password*" OR Processes.process="*passwd*" OR Processes.process="*BindDN*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(user,"\\$$")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("LDAP://", "DirectoryEntry", "DirectorySearcher", "ConvertTo-SecureString", "PSCredential")
| where ProcessCommandLine has_any ("-AsPlainText", "Password", "passwd", "BindDN", "-Force")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Outbound traffic to Tchap/Matrix government domains from non-baseline endpoint (breach reuse / phishing-infra check)

`UC_6_3` · phase: **c2** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url from datamodel=Web.Web where (Web.url="*tchap.gouv.fr*" OR Web.url="*matrix.agent.education.tchap.gouv.fr*") by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | rename src as dest_host | join type=outer dest_host [| tstats summariesonly=t earliest(_time) as baseline_first from datamodel=Web.Web where Web.url="*tchap.gouv.fr*" earliest=-90d@d latest=-7d@d by Web.src | rename Web.src as dest_host] | where isnull(baseline_first)
```

**Defender KQL:**
```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(90d) .. ago(7d))
    | where RemoteUrl has_any ("tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr")
    | summarize by DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("tchap.gouv.fr", "matrix.agent.education.tchap.gouv.fr")
| join kind=leftanti Baseline on DeviceId
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ConnectionCount = count(), Urls = make_set(RemoteUrl, 25)
          by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FirstSeen desc
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

Severity classified as **MED** based on: IOCs present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
