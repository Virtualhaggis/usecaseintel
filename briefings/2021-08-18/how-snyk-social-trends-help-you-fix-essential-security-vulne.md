# [HIGH] How Snyk Social Trends help you fix essential security vulnerabilities

**Source:** Snyk
**Published:** 2021-08-18
**Article:** https://snyk.io/blog/snyk-social-trends-fix-security-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
August 18, 2021
0 mins read Recently, Snyk added Social Trends to its vulnerability data . This new indicator shows you what vulnerabilities are trending so you can better prioritize remediation. Our research team found out that there is a strong correlation between socially trending vulnerabilities and the existence of exploits that can actually harm your application.
Following the social trends of security vulnerabilities makes practical sens…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-9484`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CVE-2020-9484 Tomcat session deserialization: JSESSIONID path-traversal in HTTP request

`UC_3077_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*jsessionid=*..*" by Web.src, Web.dest, Web.http_user_agent, Web.url, Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Tomcat/Java server process spawning an OS command shell (CVE-2020-9484 RCE outcome)

`UC_3077_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="java.exe" OR Processes.parent_process_name="java" OR Processes.parent_process_name="tomcat*.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","wscript.exe","cscript.exe","whoami.exe","whoami")) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","java","tomcat8.exe","tomcat9.exe","tomcat10.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","wscript.exe","cscript.exe","whoami.exe","whoami")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Attacker-staged .session deserialization payload written outside Tomcat's session store

`UC_3077_3` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.session" AND (Filesystem.file_path="*/webapps/*" OR Filesystem.file_path="*/tmp/*" OR Filesystem.file_path="*\\webapps\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*upload*") AND NOT (Filesystem.file_path="*/work/Catalina/*" OR Filesystem.file_path="*\\work\\Catalina\\*" OR Filesystem.file_path="*/sessions/*") by Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".session"
| where FolderPath has_any (@"\webapps\", "/webapps/", @"\Temp\", "/tmp/", "/upload", @"\upload")
| where not(FolderPath has_any (@"\work\Catalina\", "/work/Catalina/", @"\sessions\", "/sessions/"))
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-9484`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
