# [CRIT] Ghostcat breach affects all Tomcat versions

**Source:** Snyk
**Published:** 2020-02-26
**Article:** https://snyk.io/blog/ghostcat-breach-affects-all-tomcat-versions/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
February 26, 2020
0 mins read Apache Tomcat is an open source implementation of the Java Servlet, JavaServer Pages, Java Expression Language, and Java WebSocket technologies. Tomcat is one of the most popular Java HTTP web server environments and was released in 1998. 
Ghostcat is a high severity vulnerability in Tomcat discovered by the security researchers of Chaitin Tech on January 3rd. On February 20, the China National Vulnerability Databa…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-1938`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Server Software Component: Web Shell
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Ghostcat: inbound AJP (TCP/8009) connections from untrusted/public sources to Tomcat

`UC_3427_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8009 by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT (cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src))
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 8009
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName
| order by FirstSeen desc
```

### Ghostcat RCE: Tomcat/java process spawning a command shell (JSP webshell execution)

`UC_3427_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("java.exe","java","tomcat9.exe","tomcat8.exe","tomcat7.exe","tomcat.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","whoami.exe","net.exe","net1.exe","bash","sh","dash","whoami","id","python","python3")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("java.exe","java","tomcat9.exe","tomcat8.exe","tomcat7.exe","tomcat.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","whoami.exe","net.exe","net1.exe","bash","sh","dash","whoami","id","python","python3")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Ghostcat exposure: assets running Tomcat versions vulnerable to CVE-2020-1938

`UC_3427_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2020-1938" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2020-1938"
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, CveId
| order by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-1938`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
