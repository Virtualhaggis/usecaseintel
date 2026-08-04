# [HIGH] Why you should upgrade to Maven version 3.8.1

**Source:** Snyk
**Published:** 2021-07-19
**Article:** https://snyk.io/blog/why-you-should-upgrade-to-maven-version-3-8-1/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
July 19, 2021
0 mins read If you are working in the Java ecosystem and building your applications with an older Maven version, this message is for you.
Check your Maven version by typing mvn -version ! If you are still running on an old Maven version like 3.6.3 or below you definitely need to upgrade to version 3.8.1 because of security reasons. Be aware that to run Maven 3.8.1, Java 7+ is required.
Luckily we found out in the JVM Ecosystem rep…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-26291`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1557** — Adversary-in-the-Middle

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable Maven (<3.8.1) invocation revealed by build classpath — CVE-2021-26291

`UC_3131_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*apache-maven-*" by Processes.dest, Processes.user, Processes.process | drop_dm_object_name(Processes) | rex field=process "apache-maven-(?<MavenVersion>\d+\.\d+\.\d+)" | where isnotnull(MavenVersion) | eval p=split(MavenVersion,"."), maj=tonumber(mvindex(p,0)), minr=tonumber(mvindex(p,1)), pat=tonumber(mvindex(p,2)) | where maj<3 OR (maj==3 AND minr<8) OR (maj==3 AND minr==8 AND pat<1) | table dest, user, MavenVersion, process, count, firstTime, lastTime | sort MavenVersion
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "java.exe" or FileName =~ "javaw.exe" or InitiatingProcessFileName in~ ("mvn.cmd","mvn.exe","mvnd.exe")
| where ProcessCommandLine has "apache-maven" or ProcessCommandLine has "maven.home" or ProcessCommandLine has "plexus.classworlds"
| extend MavenVersion = extract(@"(?i)apache-maven-(\d+\.\d+\.\d+)", 1, ProcessCommandLine)
| where isnotempty(MavenVersion)
| where parse_version(MavenVersion) < parse_version("3.8.1")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, MavenVersion, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Maven fetching dependencies over cleartext HTTP (MITM-exposed artifact download) — CVE-2021-26291

`UC_3131_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_user_agent="Apache-Maven*" AND Web.dest_port=80 by Web.src, Web.dest, Web.dest_port, Web.url, Web.http_user_agent | drop_dm_object_name(Web) | where like(url,"http://%") | table firstTime, lastTime, src, dest, dest_port, http_user_agent, url, count | sort -lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 80
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","mvn.cmd","mvnd.exe")
| where InitiatingProcessCommandLine has_any ("apache-maven","plexus.classworlds","maven.home","\\.m2\\repository")
   or RemoteUrl has_any ("maven-metadata.xml","/maven2/","/repository/",".pom",".jar")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-26291`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
