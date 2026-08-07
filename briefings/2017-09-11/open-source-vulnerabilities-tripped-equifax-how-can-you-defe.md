# [HIGH] Open source vulnerabilities tripped Equifax, how can you defend yourself?

**Source:** Snyk
**Published:** 2017-09-11
**Article:** https://snyk.io/blog/equifax-breach-vulnerable-open-source-libraries/

## Threat Profile

Snyk Blog In this article
Written by Guy Podjarny 
September 11, 2017
0 mins read Equifax, a credit monitoring giant, disclosed last week it was breached, exposing highly personal data of 143 million people, and stated the root cause was vulnerability in Apache Struts, a highly popular Java library. The company fumbled its response to the attack , and keeping our data secure is their responsibility. However, they’re definitely not the only ones exposed to Struts or other open source library vuln…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Apache Struts web app (java/Tomcat) spawning OS shell or recon — post-exploit RCE (CVE-2017-5638 / CVE-2017-9805)

`UC_3653_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","javaw.exe","tomcat9.exe","tomcat8.exe","tomcat7.exe","catalina.exe","httpd.exe","w3wp.exe","java") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","hostname.exe","nltest.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","sh","bash","whoami","id")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process | `drop_dm_object_name(Processes)` | where NOT match(parent_process, "(?i)jenkins|buildagent|teamcity|bamboo") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","tomcat9.exe","tomcat8.exe","tomcat7.exe","catalina.exe","httpd.exe","w3wp.exe","java")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","hostname.exe","nltest.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","sh","bash","whoami","id")
| where AccountName !endswith "$"
| where InitiatingProcessFolderPath !has "jenkins" and InitiatingProcessFolderPath !has "buildagent" and InitiatingProcessFolderPath !has "teamcity"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Apache Struts OGNL / XStream exploit payload in WAF & web logs (CVE-2017-5638 + CVE-2017-9805)

`UC_3653_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*java.lang.ProcessBuilder*","*@java.lang.Runtime@getRuntime*","*#cmd=*","*#cmds=*","*(#_memberAccess*","*DEFAULT_MEMBER_ACCESS*","*ognl.OgnlContext*","*<command><string>*") OR Web.http_user_agent IN ("*java.lang.ProcessBuilder*","*#cmd=*")) by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status Web.action | `drop_dm_object_name(Web)` | where NOT match(http_user_agent, "(?i)Nessus|Qualys|Nuclei|Rapid7|Acunetix") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Article-specific behavioural hunt — Open source vulnerabilities tripped Equifax, how can you defend yourself?

`UC_3653_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Open source vulnerabilities tripped Equifax, how can you defend yourself? ```
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
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Open source vulnerabilities tripped Equifax, how can you defend yourself?
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
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
