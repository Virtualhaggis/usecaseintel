# [CRIT] Spring4Shell: The zero-day RCE in the Spring Framework explained

**Source:** Snyk
**Published:** 2022-04-01
**Article:** https://snyk.io/blog/spring4shell-zero-day-rce-spring-framework-explained/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
April 1, 2022
0 mins read On March 30, 2022, a critical remote code execution (RCE) vulnerability was found in the Spring Framework. More specifically, it is part of the spring-beans package, a transitive dependency in both spring-webmvc and spring-webflux . This vulnerability is another example of why securing the software supply chain is important to open source.
Security resources like Lunasec , Rapid7 and Praetorian confirmed that the vulne…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-22965`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1505.003** — Web Shell
- **T1059.003** — Windows Command Shell
- **T1059.004** — Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Spring4Shell (CVE-2022-22965) classLoader pipeline injection / JSP webshell call in web logs

`UC_2327_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*class.module.classLoader*" OR Web.url="*pipeline.first.pattern*" OR Web.url="*classLoader.resources*" OR Web.url="*pipeline.first.suffix*" OR (Web.url="*.jsp*" AND Web.url="*cmd=*" AND Web.url="*pwd=*")) by Web.src Web.dest Web.http_method Web.url Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

### Tomcat/Java process writing a .jsp webshell into webapps (Spring4Shell drop)

`UC_2327_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.action=created Endpoint.Filesystem.file_name="*.jsp" (Endpoint.Filesystem.file_path="*webapps*" OR Endpoint.Filesystem.file_path="*/webapps/*" OR Endpoint.Filesystem.file_path="*\\webapps\\*") by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name Endpoint.Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".jsp"
| where FolderPath has "webapps"
| where InitiatingProcessFileName has_any ("java.exe","java","tomcat","catalina") or InitiatingProcessCommandLine has_any ("catalina","tomcat","org.apache.catalina")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Tomcat/Java JVM spawning command shell (Spring4Shell webshell command execution)

`UC_2327_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process_name IN ("java.exe","java","tomcat*","catalina.sh","catalina.bat") Endpoint.Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","sh","bash","whoami","id","curl","wget") by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process_name Endpoint.Processes.process_name Endpoint.Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","java") or InitiatingProcessCommandLine has_any ("catalina","org.apache.catalina","tomcat")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","sh","bash","whoami","id","curl","wget")
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-22965`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
