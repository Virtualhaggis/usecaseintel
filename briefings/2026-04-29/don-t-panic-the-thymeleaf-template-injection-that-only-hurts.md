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
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Thymeleaf CVE-2026-40478 SpEL sandbox bypass payload (new[TAB] + FileSystemResource) in HTTP request

`UC_239_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.status) as status values(Web.user_agent) as ua from datamodel=Web where (Web.url="*FileSystemResource*" OR Web.url="*org.springframework.core.io*" OR Web.url="*new%09*" OR Web.url="*new%5Ct*" OR Web.url="*getOutputStream*" OR Web.http_user_agent="*FileSystemResource*") by Web.src Web.dest Web.site Web.uri_path sourcetype | `drop_dm_object_name(Web)` | where (like(url,"%FileSystemResource%") AND (like(url,"%new%09%") OR like(url,"%new%5Ct%") OR like(url,"%org.springframework.core.io%"))) OR like(url,"%FileSystemResource%getOutputStream%") | sort -firstTime
```

### [LLM] JSP file written to disk by Java/Tomcat process — likely Thymeleaf CVE-2026-40478 webshell drop

`UC_239_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.jspx") AND (Filesystem.process_name IN ("java.exe","javaw.exe","java","javaw") OR Filesystem.process_name="*tomcat*" OR Filesystem.process_name="*catalina*" OR Filesystem.process_path="*tomcat*" OR Filesystem.process_path="*spring-boot*") by Filesystem.dest Filesystem.process_name Filesystem.process_id Filesystem.file_name sourcetype | `drop_dm_object_name(Filesystem)` | sort -firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType =~ "FileCreated"
| where FileName endswith ".jsp" or FileName endswith ".jspx"
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","tomcat.exe","tomcat9.exe","tomcat10.exe","tomcat11.exe","java","javaw")
   or InitiatingProcessCommandLine has_any ("spring-boot","thymeleaf","catalina","tomcat","jetty","-jar")
| where InitiatingProcessAccountName !endswith "$"
// suppress legitimate Tomcat work-dir JSP compilation (precompiled .jsp -> _jsp.class)
| where not(FolderPath has_any (@"\work\Catalina\", @"\work\catalina\", @"/work/Catalina/", @"/work/catalina/"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40478`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
