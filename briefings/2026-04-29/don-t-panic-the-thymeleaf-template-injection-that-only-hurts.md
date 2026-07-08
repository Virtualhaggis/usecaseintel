# [HIGH] Don't Panic: The Thymeleaf Template Injection That Only Hurts If You Let It (CVE-2026-40478)

**Source:** Snyk
**Published:** 2026-04-29
**Article:** https://snyk.io/blog/thymeleaf-injection/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
April 29, 2026
0 mins read The Thymeleaf vulnerability with a CVSS score of 9.1 grabs your attention, as it should. But before you call the cavalry and claim this as the new Log4shell, read this first.
CVE-2026-40478 is a server-side template injection vulnerability in Thymeleaf discovered by pentester Dawid Bakaj . Thymeleaf is a templating engine in Java that is used for server-side webpage rendering. The sandbox that normally prevents arbitr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-40478`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1505.003** — Server Software Component: Web Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Thymeleaf SpEL tab-character sandbox bypass payload in HTTP request (CVE-2026-40478)

`UC_411_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.uri_query="*new%09org.springframework*" OR Web.uri_query="*new%09java.lang*" OR Web.uri_query="*FileSystemResource*getOutputStream*" OR Web.uri_query="*new\torg.springframework*" OR Web.url="*new%09org.springframework*" OR Web.http_user_agent="*FileSystemResource*") by Web.dest, Web.src, Web.url, Web.uri_query, Web.http_method, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval cve="CVE-2026-40478"
| convert ctime(firstTime) ctime(lastTime)
```

### Java/Tomcat process writes .jsp webshell file to disk (CVE-2026-40478 post-exploit drop)

`UC_411_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.jspx") AND (Filesystem.process_name IN ("java.exe","javaw.exe","tomcat.exe","tomcat9.exe","tomcat10.exe") OR Filesystem.process_path="*tomcat*" OR Filesystem.process_path="*spring-boot*" OR Filesystem.process_path="*catalina*") AND NOT (Filesystem.file_path="*\\work\\Catalina\\*" OR Filesystem.file_path="*/work/Catalina/*" OR Filesystem.file_path="*\\temp\\jsp\\*") by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name, Filesystem.process_path, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| eval cve="CVE-2026-40478"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName endswith ".jsp" or FileName endswith ".jspx"
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe", "tomcat.exe", "tomcat9.exe", "tomcat10.exe", "catalina.exe")
   or InitiatingProcessFolderPath has_any ("tomcat", "jboss", "wildfly", "spring-boot", "catalina")
| where not(FolderPath has_any (@"\work\Catalina\", @"\temp\jsp\", "/work/Catalina/", "/temp/jsp/"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Java/Tomcat process spawns OS command interpreter (post-Thymeleaf SSTI RCE)

`UC_411_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("java.exe","javaw.exe","tomcat.exe","tomcat9.exe","tomcat10.exe","catalina.exe") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","bash.exe","sh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","tasklist.exe","hostname.exe") AND Processes.user!="*$" by Processes.dest, Processes.user, Processes.parent_process, Processes.parent_process_name, Processes.process, Processes.process_name, Processes.process_hash
| `drop_dm_object_name(Processes)`
| eval cve="CVE-2026-40478"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe", "tomcat.exe", "tomcat9.exe", "tomcat10.exe", "catalina.exe")
   or InitiatingProcessFolderPath has_any ("tomcat", "catalina", "spring-boot")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bash.exe", "sh.exe", "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "tasklist.exe", "hostname.exe")
| where AccountName !endswith "$"
| where InitiatingProcessParentFileName !in~ ("services.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40478`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
