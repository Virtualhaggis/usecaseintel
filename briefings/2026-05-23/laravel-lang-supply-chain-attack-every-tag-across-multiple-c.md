# [HIGH] Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Rewritten to Steal CI Secrets

**Source:** StepSecurity
**Published:** 2026-05-23
**Article:** https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack

## Threat Profile

Back to Blog Threat Intel Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Rewritten to Steal CI Secrets On May 22, 2026, an attacker with push access to the Laravel-Lang GitHub organization rewrote every git tag across multiple popular Composer packages within a single 15 minute window. Anyone running composer update or installing fresh against laravel-lang/http-statuses, laravel-lang/actions, or laravel-lang/attributes now pulls a payload that exfiltrates CI secret…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`
- **SHA1:** `a5ea2e8fa92ccf29cdb1d2dadbeb27722b2bff37`
- **SHA1:** `50ac0db454d19234c835716f297bbc5363c0a25c`
- **SHA1:** `c45764e70285146da37025cd8601a921ab8a7eda`
- **SHA1:** `a9f8d88cf98e35988d3d0fd6d79547f980853041`
- **SHA1:** `bba2e443dc7ff1f8704f52a5375383e3f4f643b8`
- **SHA1:** `26c233e1a0d4fd2331e8e0f175e18f8eed904aa3`
- **SHA1:** `db0c3ef246103fd0f6c318e0d48f26b5289044c3`
- **SHA1:** `9ee599d248cc322fa26054694a83a1f4558cc716`
- **SHA1:** `6b1d5782a8c8c199d070857802d39bfe609eb6f2`
- **SHA1:** `556d2b335d4d6d92139822017ee461b668afe375`
- **SHA1:** `722cee67326d932e7f71ba3438f62a255d779aa9`
- **SHA1:** `ad24b980db8f0dca50ccb3ba6badb3c2331e0ef4`
- **SHA1:** `d59561727927117e65b35f0183cae131baad19fe`
- **SHA1:** `1713b19cbf609cb101ff5e216be41f7224269082`
- **SHA1:** `daa5212264bb73fb39fe7a36618b62717dc564a5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1568.002** — Domain Generation Algorithms / Typosquat
- **T1041** — Exfiltration Over C2 Channel
- **T1564.001** — Hidden Files and Directories
- **T1059.004** — Unix Shell
- **T1204.003** — Malicious Image / Compromised Software Supply Chain
- **T1036.005** — Match Legitimate Name or Location
- **T1070.004** — File Deletion
- **T1620** — Reflective Code Loading
- **T1078** — Valid Accounts
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Egress to typosquatted C2 flipboxstudio.info (Laravel-Lang Composer SC)

`UC_68_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*flipboxstudio.info*" OR Web.dest="flipboxstudio.info" OR Web.site="flipboxstudio.info") by Web.src, Web.dest, Web.url, Web.http_method, Web.user, Web.http_user_agent | `drop_dm_object_name("Web")` | append [| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query="flipboxstudio.info" OR DNS.query="*.flipboxstudio.info") by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name("DNS")`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "flipboxstudio.info"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] PHP CLI drops hidden /tmp dropper artefacts (Laravel-Lang autoload payload)

`UC_68_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="/tmp/.laravel_locale/*" OR Filesystem.file_path="/tmp/.*") AND Filesystem.process_name IN ("php","php7","php8","php-cli") by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.process_path, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash | `drop_dm_object_name("Filesystem")` | rex field=file_name "^(?<basename>\.?[a-f0-9]{6,12}(?:\.php)?)$" | where isnotnull(basename) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName matches regex @"^php[0-9]?$" or InitiatingProcessFileName in~ ("php-cli","php-fpm")
| where FolderPath startswith "/tmp/.laravel_locale" 
   or (FolderPath == "/tmp" and FileName matches regex @"^\.[a-f0-9]{6,12}$")
   or (FolderPath startswith "/tmp/." and FileName matches regex @"^[a-f0-9]{6,12}\.php$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Orphaned process (ppid=1) executing from /tmp hidden hex path (post-dropper stage-2)

`UC_68_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("systemd","init") OR Processes.parent_process_id=1) AND (Processes.process_path="/tmp/.*" OR Processes.process="*/tmp/.*" OR Processes.process_name="php") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_path, Processes.parent_process_name, Processes.parent_process_id | `drop_dm_object_name("Processes")` | rex field=process_path "^/tmp/\.(?<hex_name>[a-f0-9]{6,12})$" | rex field=process "/tmp/\.(?<cmd_hex>[a-f0-9]{6,12})" | where isnotnull(hex_name) OR isnotnull(cmd_hex) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("systemd","init")
| where (FolderPath matches regex @"^/tmp/\.[a-f0-9]{6,12}$")
   or (FileName matches regex @"^php[0-9]?$" and ProcessCommandLine matches regex @"/tmp/\.[a-f0-9]{6,12}(\.php)?")
   or (FolderPath startswith "/tmp/.laravel_locale")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, ProcessId, InitiatingProcessId
| order by Timestamp desc
```

### [LLM] GitHub bulk git tag force-push by single actor across multiple org repos

`UC_68_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=* sourcetype IN ("github:audit","github_audit_log","github:enterprise:audit") (action="git.push" OR action="git.create" OR action="protected_branch.policy_override") ref="refs/tags/*"
| eval repo_org=mvindex(split(repo,"/"),0)
| stats min(_time) as first_seen max(_time) as last_seen dc(repo) as repo_count dc(ref) as tag_count values(repo) as repos values(ref) as refs by actor, repo_org
| eval window_seconds = last_seen - first_seen
| where tag_count >= 10 AND repo_count >= 2 AND window_seconds <= 3600
| eval window_minutes = round(window_seconds/60, 1)
| convert ctime(first_seen) ctime(last_seen)
| sort - tag_count
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

### Article-specific behavioural hunt — Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Re

`UC_68_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Re ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.laravel_locale/*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/.laravel_locale/f3e2c293172f.php*" OR Filesystem.file_path="*/tmp/.480dc608*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Laravel-Lang Supply Chain Attack: Every Tag Across Multiple Composer Packages Re
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.laravel_locale/", "/dev/null", "/tmp/.laravel_locale/f3e2c293172f.php", "/tmp/.480dc608"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a5ea2e8fa92ccf29cdb1d2dadbeb27722b2bff37`, `50ac0db454d19234c835716f297bbc5363c0a25c`, `c45764e70285146da37025cd8601a921ab8a7eda`, `a9f8d88cf98e35988d3d0fd6d79547f980853041`, `bba2e443dc7ff1f8704f52a5375383e3f4f643b8`, `26c233e1a0d4fd2331e8e0f175e18f8eed904aa3`, `db0c3ef246103fd0f6c318e0d48f26b5289044c3`, `9ee599d248cc322fa26054694a83a1f4558cc716` _(+7 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
