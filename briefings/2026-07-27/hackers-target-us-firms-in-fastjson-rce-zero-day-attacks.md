# [HIGH] Hackers target US firms in FastJson RCE zero-day attacks

**Source:** BleepingComputer
**Published:** 2026-07-27
**Article:** https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/

## Threat Profile

Hackers target US firms in FastJson RCE zero-day attacks 
By Bill Toulas 
July 27, 2026
07:49 PM
0 
Hackers are actively exploiting a vulnerability in the FastJson open-source Java library, allowing remote code execution without user interaction or elevated privileges.
The security issue affects FastJson versions 1.2.68 through 1.2.83 and is leveraged in attacks targeting various organizations in the U.S.
The malicious activity was observed last week by the agentic security company ThreatBook, a…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-16723`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1203** — Exploitation for Client Execution
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inbound FastJson @type payload with jar:/ldap:/rmi: reference to Spring Boot app (CVE-2026-16723)

`UC_22_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method IN ("POST","PUT","GET") AND Web.url="*@type*" AND (Web.url="*jar:*" OR Web.url="*ldap:*" OR Web.url="*rmi:*" OR Web.url="*JdbcRowSetImpl*" OR Web.url="*dataSourceName*") by Web.src Web.dest Web.http_method Web.url Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Spring Boot Java fat-JAR spawning shell/recon child process (FastJson CVE-2026-16723 RCE)

`UC_22_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","javaw.exe","java") AND Processes.parent_process="*-jar*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami.exe","net.exe","curl.exe","wget.exe","certutil.exe","bitsadmin.exe","nslookup.exe","ping.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","java")
| where InitiatingProcessCommandLine has "-jar"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","whoami.exe","whoami","net.exe","curl.exe","curl","wget","certutil.exe","bitsadmin.exe","nslookup.exe","ping.exe","id","uname")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Java application making outbound LDAP/RMI connection (FastJson CVE-2026-16723 remote class load)

`UC_22_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("java","java.exe","javaw.exe") AND All_Traffic.dest_port IN (389,636,1099,1389) AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","java")
| where InitiatingProcessCommandLine has "-jar"
| where RemoteIPType == "Public"
| where RemotePort in (389, 636, 1099, 1389)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Article-specific behavioural hunt — Hackers target US firms in FastJson RCE zero-day attacks

`UC_22_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers target US firms in FastJson RCE zero-day attacks ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("xxx.jar"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("xxx.jar"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers target US firms in FastJson RCE zero-day attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("xxx.jar"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("xxx.jar"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-16723`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
