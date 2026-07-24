# [HIGH] SleeperGem: Compromised git_credential_manager, Dendreo, and fastlane RubyGems Drop a Persistent Backdoor

**Source:** StepSecurity
**Published:** 2026-07-19
**Article:** https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor

## Threat Profile

Back to Blog Threat Intel SleeperGem: Compromised git_credential_manager, Dendreo, and fastlane RubyGems Drop a Persistent Backdoor Malicious versions of git_credential_manager, Dendreo, and a fastlane plugin were published to RubyGems. They fetch a second stage from a Forgejo command and control host, skip CI to target developer machines, and install a persistent daemon. StepSecurity ran them under Harden-Runner to capture the full kill chain. Varun Sharma View LinkedIn July 19, 2026
Share on X…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `git.disroot.org`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1036** — Masquerading
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1497** — Virtualization/Sandbox Evasion
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1053.003** — Scheduled Task/Job: Cron
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SleeperGem: ruby process C2 contact to Forgejo host git.disroot.org

`UC_95_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="git.disroot.org" (All_Traffic.process_name="ruby" OR All_Traffic.process_name="git-credential-manager") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "git.disroot.org" or RemoteUrl == "git.disroot.org"
| where InitiatingProcessFileName in~ ("ruby","git-credential-manager")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### SleeperGem loader: ruby install script spawns shell running deploy.sh

`UC_95_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash") Processes.process="*deploy.sh*" Processes.parent_process_name="ruby" by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sh","bash","dash")
| where ProcessCommandLine has "deploy.sh"
| where InitiatingProcessFileName has "ruby"
| where InitiatingProcessCommandLine has_any ("git_credential_manager","Dendreo","dendreo","run_tests_firebase_testlab","/bin/install")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### SleeperGem payload drop: native binary written to hidden ~/.local/share/gcm/

`UC_95_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*/.local/share/gcm/git-credential-manager" Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/.local/share/gcm/"
| where FileName == "git-credential-manager"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SleeperGem persistence: git-credential-manager daemon installs systemd + cron

`UC_95_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*git-credential-manager*" Processes.process="*--service-name=git-credential-manager*" (Processes.process="*--method=systemd*" OR Processes.process="*--method=cron*" OR Processes.process="*--daemon*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "git-credential-manager"
| where ProcessCommandLine has_any ("--method=systemd","--method=cron","--daemon")
| where ProcessCommandLine has "--service-name=git-credential-manager" or ProcessCommandLine has "--daemon"
| where FolderPath has "/.local/share/gcm/" or ProcessCommandLine has "/.local/share/gcm/"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### SleeperGem privilege escalation: setuid-root shell planted as /usr/local/sbin/ping6

`UC_95_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/usr/local/sbin/ping6" Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath == "/usr/local/sbin" and FileName == "ping6"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — SleeperGem: Compromised git_credential_manager, Dendreo, and fastlane RubyGems D

`UC_95_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — SleeperGem: Compromised git_credential_manager, Dendreo, and fastlane RubyGems D ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("deploy.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/local/sbin/ping6*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("deploy.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — SleeperGem: Compromised git_credential_manager, Dendreo, and fastlane RubyGems D
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("deploy.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/local/sbin/ping6", "/dev/null") or FileName in~ ("deploy.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `git.disroot.org`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
