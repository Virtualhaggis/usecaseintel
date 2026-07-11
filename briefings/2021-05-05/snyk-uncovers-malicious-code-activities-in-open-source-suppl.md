# [HIGH] Snyk uncovers malicious code activities in open source supply chain security on the npm registry

**Source:** Snyk
**Published:** 2021-05-05
**Article:** https://snyk.io/blog/npm-security-malicious-code-in-oss-npm-packages/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
May 5, 2021
0 mins read Open source helps developers build faster. But who’s making sure these open source dependencies (sometimes years out of development) stay secure? In a recent npm security research activity, Snyk uncovered a total of 8 npm packages which matched a specific malicious code vector of attack. This specific attack vector of the malicious packages included packages which had pre/post install scripts, which allowed them to run arbit…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/node install hook exfiltrating /etc/passwd, kube config & krb5 ticket via wget --post-file

`UC_3143_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wget Processes.process="*--post-file*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)(/etc/passwd|/etc/hosts|/tmp/krb5cc_0|\.kube/config|pipedream\.net)") | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "wget"
| where ProcessCommandLine has "--post-file"
| where ProcessCommandLine has_any ("/etc/passwd","/etc/hosts","/tmp/krb5cc_0",".kube/config","package.json") or ProcessCommandLine has "pipedream.net"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Outbound connection/DNS to npm exfil endpoint entfet95itcxpuu.m.pipedream.net

`UC_3143_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="entfet95itcxpuu.m.pipedream.net" OR All_Traffic.url="*entfet95itcxpuu*" OR All_Traffic.dest="*pipedream.net") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "entfet95itcxpuu" or (RemoteUrl endswith "pipedream.net" and InitiatingProcessFileName in~ ("wget","curl","node","npm","npx","yarn","sh","bash"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Installation of Snyk-flagged malicious npm packages (radar-cms, rcenodejs, paychex-*)

`UC_3143_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where All_Filesystem.file_path="*node_modules*" (All_Filesystem.file_path="*node_modules/radar-cms*" OR All_Filesystem.file_path="*node_modules/rcenodejs*" OR All_Filesystem.file_path="*node_modules/paychex-framework*" OR All_Filesystem.file_path="*node_modules/paychex-common-npm*" OR All_Filesystem.file_path="*node_modules/paychex-app-common-html*") by All_Filesystem.dest All_Filesystem.user All_Filesystem.file_path All_Filesystem.process_name | `drop_dm_object_name(All_Filesystem)` | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has "node_modules"
| where FolderPath has_any ("node_modules/radar-cms","node_modules/rcenodejs","node_modules/paychex-framework","node_modules/paychex-common-npm","node_modules/paychex-app-common-html")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### npm/node install lifecycle spawning interactive or reverse shell

`UC_3143_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN (node,npm,npx,yarn)) (Processes.process_name IN (sh,bash,dash,nc,ncat,socat,perl,python,python3)) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)(/dev/tcp/|mkfifo|/bin/sh -i|/bin/bash -i|sh -i >&|bash -i >&|-e /bin/sh|-e /bin/bash|socat .*exec)") | `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","npm","npx","yarn")
| where FileName in~ ("sh","bash","dash","nc","ncat","netcat","socat","perl","python","python3")
| where ProcessCommandLine has_any ("/dev/tcp/","mkfifo","/bin/sh -i","/bin/bash -i","bash -i >&","sh -i >&","-e /bin/sh","-e /bin/bash") or (FileName in~ ("nc","ncat","netcat") and ProcessCommandLine has "-e")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
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

### Article-specific behavioural hunt — Snyk uncovers malicious code activities in open source supply chain security on

`UC_3143_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk uncovers malicious code activities in open source supply chain security on ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/tmp/krb5cc_0*" OR Filesystem.file_path="*/etc/hosts*" OR Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk uncovers malicious code activities in open source supply chain security on
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd", "/tmp/krb5cc_0", "/etc/hosts") or FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
