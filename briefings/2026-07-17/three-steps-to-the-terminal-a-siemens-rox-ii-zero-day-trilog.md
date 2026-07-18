# [CRIT] Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-07-17
**Article:** https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/

## Threat Profile

Threat Research Center 
Threat Research 
Vulnerabilities 
Vulnerabilities 
Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy 
9 min read 
Related Products Advanced Threat Prevention Cloud-Delivered Security Services Industrial and Operational Technology IoT Security Next-Generation Firewall 
By: Emmanuel Zhou 
Adam Robbie 
Rick Wyble 
Miguel Pereira 
Published: July 17, 2026 
Categories: Threat Research 
Vulnerabilities 
Tags: Command injection 
CVE-2025-40947 
CVE-2025-40948 
CVE-2…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-40947`
- **CVE:** `CVE-2025-40948`
- **CVE:** `CVE-2025-40949`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1005** — Data from Local System
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1548** — Abuse Elevation Control Mechanism
- **T1053.003** — Scheduled Task/Job: Cron

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Siemens ROX II xz-as-cat arbitrary disclosure of shadow/private keys (CVE-2025-40948)

`UC_20_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=xz OR Processes.process="*xz*") (Processes.process="*shadow*" OR Processes.process="*id_rsa*" OR Processes.process="*id_dsa*" OR Processes.process="*.key*" OR Processes.process="*ssl/private*" OR Processes.process="*.pem*") (Processes.process="*--decompress*" OR Processes.process="*-dc*" OR Processes.process="* -d *" OR Processes.process="*--stdout*" OR Processes.process="*-c *") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

### Siemens ROX II feature-key gpgv command injection to root (CVE-2025-40947)

`UC_20_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*feature*key*" OR Web.uri_path="*featurekey*" OR Web.uri_path="*feature-key*") (Web.uri_query="*;*" OR Web.uri_query="*$(*" OR Web.uri_query="*|*" OR Web.uri_query="*&&*" OR Web.uri_query="*%3B*" OR Web.uri_query="*%24%28*" OR Web.uri_query="*%60*" OR Web.url="*%3B*" OR Web.url="*%24%28*") by Web.src Web.dest Web.url Web.uri_query Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

### Siemens ROX II root cron persistence via web task scheduler (CVE-2025-40949)

`UC_20_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=cron OR Processes.parent_process_name=crond OR Processes.parent_process_name=CRON) (Processes.process="*wget*" OR Processes.process="*curl*" OR Processes.process="*/tmp/*" OR Processes.process="*bash -i*" OR Processes.process="*nc *" OR Processes.process="*/dev/tcp/*" OR Processes.process="*base64 -d*") by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

### Siemens ROX II three-stage zero-day chain temporal correlation (CVE-2025-40948/40947/40949)

`UC_20_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*xz*" OR Processes.process="*feature*key*" OR Processes.parent_process_name=cron OR Processes.parent_process_name=crond) by Processes.dest Processes.user Processes.process Processes.parent_process_name _time span=10m | `drop_dm_object_name(Processes)` | eval stage=case(match(process,"(?i)xz.*(shadow|id_rsa|id_dsa|private|\.key|\.pem)"),"1-disclosure", match(process,"(?i)feature.?key") AND match(process,"[;|&`$]"),"2-cmdinjection", (parent_process_name="cron" OR parent_process_name="crond") AND match(process,"(?i)(wget|curl|/tmp/|bash -i|/dev/tcp/|base64 -d)"),"3-persistence", true(),null()) | where isnotnull(stage) | stats dc(stage) as stage_count values(stage) as stages values(process) as processes min(_time) as firstTime max(_time) as lastTime by dest user | where stage_count>=2 | convert ctime(firstTime) ctime(lastTime)
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy

`UC_20_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/rev_shell.py*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/rev_shell.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-40947`, `CVE-2025-40948`, `CVE-2025-40949`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
