# [HIGH] Snyk Fetch the Flag CTF 2023 writeup: Off the SETUID

**Source:** Snyk
**Published:** 2023-11-30
**Article:** https://snyk.io/blog/snyk-fetch-the-flag-ctf-2023-writeup-off-the-setuid/

## Threat Profile

Snyk Blog In this article
Written by Carlos Polop 
Yago Gutiérrez 
November 30, 2023
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF. If you were at Snyk’s 2023 Fetch the Flag and are looking for the answer to the Off the SETUID challenge, you’ve come to the right place. Let’s walk through the solution together!
You find yourself in an unfamiliar environment. Can you live off the land? Or, can you just live...
Retrieve the f…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PHP web-server process initiating outbound TCP (fsockopen reverse shell to attacker)

`UC_1495_1` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="php" All_Traffic.direction="outbound" (All_Traffic.dest_category!="internal" OR All_Traffic.dest_port IN (4444,1337,9001,9999)) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "php"
| where InitiatingProcessCommandLine has "-S"          // built-in dev server mode (e.g. php -S 0:8080)
| where ActionType in ("ConnectionSuccess","ConnectionRequest")
| where RemoteIPType == "Public" or RemotePort in (4444, 1337, 9001, 9999)   // a php -S listener should not dial out at all
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### PHP CLI dev server (php -S) spawning a shell or child interpreter (proc_open php -a)

`UC_1495_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process="*php*-S*" Processes.process_name IN ("php","sh","bash","dash","zsh","python","python3","perl","nc","ncat") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "php"
| where InitiatingProcessCommandLine has "-S"          // parent is a php built-in web server
| where FileName in~ ("php","sh","bash","dash","zsh","python","python3","perl","nc","ncat")
| where not (FileName =~ "php" and ProcessCommandLine !has "-a" and ProcessCommandLine !has "-r")  // keep php -a / php -r (interactive/inline), drop benign php worker re-exec
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — Snyk Fetch the Flag CTF 2023 writeup: Off the SETUID

`UC_1495_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk Fetch the Flag CTF 2023 writeup: Off the SETUID ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("run.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/lib*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/dev/ttyS0*" OR Filesystem.file_path="*/var/run*" OR Filesystem.file_path="*/usr/bin/php*" OR Filesystem.file_path="*/root/flag.txt*" OR Filesystem.file_name IN ("run.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk Fetch the Flag CTF 2023 writeup: Off the SETUID
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("run.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/lib", "/dev/null", "/dev/ttyS0", "/var/run", "/usr/bin/php", "/root/flag.txt") or FileName in~ ("run.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
