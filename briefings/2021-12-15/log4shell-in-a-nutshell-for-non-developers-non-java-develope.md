# [HIGH] Log4Shell in a nutshell (for non-developers & non-Java developers)

**Source:** Snyk
**Published:** 2021-12-15
**Article:** https://snyk.io/blog/log4shell-in-a-nutshell/

## Threat Profile

Snyk Blog In this article
Written by Micah Silverman 
December 15, 2021
0 mins read Editor's note (28 Dec 2021 at 7:35 p.m. GMT): The Log4j team released a new security update that found 2.17.0 to be vulnerable to remote code execution, identified by CVE-2021-44832. We recommend upgrading to the latest version, which at this time is 2.17.1. 
Editor's note (18 Dec 2021 at 6:55 p.m. GMT): The Log4j situation is rapidly changing and we are updating our blogs as new information becomes available. It…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`
- **CVE:** `CVE-2021-45046`
- **CVE:** `CVE-2021-45105`
- **CVE:** `CVE-2021-44832`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Log4Shell JNDI lookup injection string in HTTP requests / process cmdline (${jndi:ldap})

`UC_2715_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*${jndi:ldap*" OR Processes.process="*${jndi:rmi*" OR Processes.process="*${jndi:dns*" OR Processes.process="*${jndi:ldaps*" OR Processes.process="*${jndi:nis*" OR Processes.process="*${jndi:iiop*" OR Processes.process="*${${*" OR Processes.process="*${lower:*" OR Processes.process="*${upper:*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("${jndi:ldap","${jndi:rmi","${jndi:dns","${jndi:ldaps","${jndi:nis","${jndi:iiop","${jndi:","${${","${lower:","${upper:","${::-")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Java process making outbound LDAP/RMI connection (Log4Shell second-stage class fetch)

`UC_2715_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="java" OR All_Traffic.process_name="java.exe" OR All_Traffic.process_name="javaw.exe" OR All_Traffic.process_name="javaws.exe") (All_Traffic.dest_port=389 OR All_Traffic.dest_port=636 OR All_Traffic.dest_port=1389 OR All_Traffic.dest_port=1099 OR All_Traffic.dest_port=1100 OR All_Traffic.dest_port=9999) All_Traffic.dest!=10.0.0.0/8 All_Traffic.dest!=172.16.0.0/12 All_Traffic.dest!=192.168.0.0/16 by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","javaws.exe")
| where RemotePort in (389, 636, 1389, 1099, 1100, 9999)
| where ipv4_is_private(RemoteIP) == false and RemoteIP !in ("127.0.0.1","::1")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Java/Tomcat process spawning OS shell (Log4Shell Runtime.exec post-exploitation)

`UC_2715_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="java.exe" OR Processes.parent_process_name="javaw.exe" OR Processes.parent_process_name="javaws.exe" OR Processes.parent_process_name="tomcat9.exe") (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe" OR Processes.process_name="certutil.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="bitsadmin.exe" OR Processes.process_name="whoami.exe" OR Processes.process_name="nslookup.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","javaws.exe","tomcat9.exe","tomcat.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","sh.exe","bash.exe","wscript.exe","cscript.exe","certutil.exe","curl.exe","bitsadmin.exe","whoami.exe","nslookup.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
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

### Article-specific behavioural hunt — Log4Shell in a nutshell (for non-developers & non-Java developers)

`UC_2715_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Log4Shell in a nutshell (for non-developers & non-Java developers) ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/pwned*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Log4Shell in a nutshell (for non-developers & non-Java developers)
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/pwned"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`, `CVE-2021-45046`, `CVE-2021-45105`, `CVE-2021-44832`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
